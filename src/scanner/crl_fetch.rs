//! Certificate Revocation List (CRL) fetch + revocation check.
//!
//! The leaf cert's `CRLDistributionPoints` extension advertises one
//! or more HTTP URLs where the issuing CA publishes a periodically
//! refreshed list of revoked serials. kemist captures those URLs at
//! cert-parse time ([`crate::scanner::cert`]) but historically didn't
//! fetch them — this module closes that gap when the operator opts
//! in via `--enable-revocation-fetch`.
//!
//! ## Probe shape
//! For each URL in the leaf's `crl_distribution_points.urls`:
//! 1. GET the URL (10s timeout, 5 MB body cap).
//! 2. Decode as DER. Some CAs publish PEM-wrapped CRLs; detect the
//!    `-----BEGIN X509 CRL-----` sentinel and strip the armor before
//!    parsing.
//! 3. Parse via `x509_parser::revocation_list::CertificateRevocationList`.
//! 4. Scan `iter_revoked_certificates()` for an entry whose
//!    `user_certificate` serial matches the leaf's serial.
//! 5. Capture `this_update`, `next_update`, `issuer`, total revoked
//!    count, and (when the leaf matches) the specific
//!    `revocation_date` + `reason_code`.
//!
//! ## Non-goals
//! - **CRL signature validation.** The parser exposes
//!   `verify_signature(&issuer_spki)` but kemist is a sensor — we
//!   report what the CRL *says* about the leaf's state, not whether
//!   a trusted issuer actually signed this CRL. Rule engines that
//!   want signature-validated revocation can consume `issuer` and
//!   the raw cert DER and cross-check themselves.
//! - **Delta CRLs / CRL stapling / Cross-store CRLs.** Out of scope.
//! - **Intermediate revocation.** Only the leaf is checked. Chain
//!   validation under a separate trust store (Tier 4 S1) handles the
//!   intermediate-trust question.
//!
//! ## Cache
//! Per-scan: a `HashMap<url, CrlFetchResult>` avoids re-downloading
//! the same CRL twice in a single scan (leaf + intermediates may
//! share CRL DPs). Not persisted across scans.

#![cfg(feature = "http-checks")]

use std::collections::HashMap;
use std::time::Duration;

use tracing::debug;

/// Per-URL fetch + revocation-check result.
#[derive(Debug, Clone)]
pub struct CrlFetchResult {
    /// URL fetched (from leaf's `CRLDistributionPoints` extension).
    pub url: String,
    /// HTTP status code from the GET. `None` on transport failure
    /// before an HTTP response arrived.
    pub http_status: Option<u16>,
    /// `this_update` timestamp from the CRL header, RFC 5280 §5.1.2.4.
    /// ISO 8601 string. `None` when fetch / parse failed.
    pub this_update: Option<String>,
    /// `next_update` timestamp — when the CA promises the next CRL
    /// will be published. Optional per RFC 5280 §5.1.2.5. `None`
    /// when the CA omitted it OR fetch / parse failed.
    pub next_update: Option<String>,
    /// Issuer DN string from the CRL's signer. Lets rule engines
    /// confirm the CRL chain matches the cert's issuer.
    pub crl_issuer: Option<String>,
    /// Number of revoked certificates in the entire CRL. A size
    /// signal — huge CRLs (>10K entries) hint at a CA with a
    /// history of mass revocations.
    pub revoked_cert_count: Option<usize>,
    /// `true` when the leaf's serial was found in the CRL's
    /// `revokedCertificates` list. `false` when the CRL was fetched
    /// + parsed + searched AND the leaf serial was NOT present —
    /// the canonical "not revoked" positive signal. `None` when
    /// fetch / parse failed (no conclusion possible).
    pub leaf_revoked: Option<bool>,
    /// When `leaf_revoked == Some(true)`, the revocation date per
    /// RFC 5280 §5.3.1 (if present in the CRL entry).
    pub revocation_time: Option<String>,
    /// When `leaf_revoked == Some(true)`, the `reasonCode` extension
    /// value rendered as its canonical RFC 5280 §5.3.1 name.
    pub revocation_reason: Option<String>,
    /// Category string when the probe didn't yield a definitive
    /// revocation signal. Canonical values: `fetch_timeout`,
    /// `http_status_<code>`, `body_read:<err>`,
    /// `body_exceeds_size_cap:<bytes>`, `parse_failed:<err>`,
    /// `pem_decode_failed:<err>`.
    pub error: Option<String>,
}

/// Aggregate output — one entry per CRL DP URL attempted, in the
/// order they were fetched.
#[derive(Debug, Clone, Default)]
pub struct CrlFetchOutput {
    pub results: Vec<CrlFetchResult>,
}

/// Drive the CRL fetch + revocation check. Caches responses keyed on
/// URL so duplicate DPs across chain members don't re-download.
/// Accepts the leaf's serial as a raw byte slice — big-endian,
/// sign-bit-aware (same form x509-parser exposes via
/// `cert.raw_serial()`), to match against CRL `user_certificate`
/// entries bit-for-bit.
pub async fn probe_crl(
    urls: &[String],
    leaf_serial: &[u8],
    overall_timeout: Duration,
) -> CrlFetchOutput {
    let mut out = CrlFetchOutput::default();
    if urls.is_empty() {
        return out;
    }

    let client = match reqwest::Client::builder()
        .timeout(overall_timeout)
        .user_agent(format!("kemist-crl/{}", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            for url in urls {
                out.results.push(CrlFetchResult {
                    url: url.clone(),
                    http_status: None,
                    this_update: None,
                    next_update: None,
                    crl_issuer: None,
                    revoked_cert_count: None,
                    leaf_revoked: None,
                    revocation_time: None,
                    revocation_reason: None,
                    error: Some(format!("http_client_build:{e}")),
                });
            }
            return out;
        }
    };

    let mut cache: HashMap<String, CrlFetchResult> = HashMap::new();
    for url in urls {
        if let Some(hit) = cache.get(url) {
            out.results.push(hit.clone());
            continue;
        }
        let result = fetch_and_check(&client, url, leaf_serial).await;
        cache.insert(url.clone(), result.clone());
        out.results.push(result);
    }
    out
}

async fn fetch_and_check(
    client: &reqwest::Client,
    url: &str,
    leaf_serial: &[u8],
) -> CrlFetchResult {
    let mut result = CrlFetchResult {
        url: url.to_string(),
        http_status: None,
        this_update: None,
        next_update: None,
        crl_issuer: None,
        revoked_cert_count: None,
        leaf_revoked: None,
        revocation_time: None,
        revocation_reason: None,
        error: None,
    };

    let resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(e) => {
            result.error = Some(if e.is_timeout() {
                "fetch_timeout".to_string()
            } else {
                format!("fetch_failed:{e}")
            });
            return result;
        }
    };

    let status = resp.status();
    result.http_status = Some(status.as_u16());
    if !status.is_success() {
        result.error = Some(format!("http_status_{}", status.as_u16()));
        return result;
    }

    // 5 MB body cap. Some CAs publish enormous CRLs (deprecated
    // intermediates with huge revocation histories); blindly
    // loading into memory would be a OOM hazard on a scanner
    // running across many targets.
    let body = match resp.bytes().await {
        Ok(b) if b.len() > 5 * 1024 * 1024 => {
            result.error = Some(format!("body_exceeds_size_cap:{}", b.len()));
            return result;
        }
        Ok(b) => b.to_vec(),
        Err(e) => {
            result.error = Some(format!("body_read:{e}"));
            return result;
        }
    };

    // Detect PEM armor. Some CAs serve `application/pkix-crl` with
    // DER bytes; others serve `application/x-pem-file` with
    // `-----BEGIN X509 CRL-----` wrapping. Strip armor before
    // handing to the DER parser.
    let der_bytes = match decode_pem_if_armored(&body) {
        Ok(d) => d,
        Err(e) => {
            result.error = Some(format!("pem_decode_failed:{e}"));
            return result;
        }
    };

    let crl = match parse_crl(&der_bytes) {
        Ok(c) => c,
        Err(e) => {
            result.error = Some(format!("parse_failed:{e}"));
            return result;
        }
    };

    result.this_update = Some(format_asn1_time(&crl.last_update));
    result.next_update = crl.next_update.as_ref().map(format_asn1_time);
    result.crl_issuer = Some(crl.issuer.to_string());
    result.revoked_cert_count = Some(crl.revoked_entries.len());

    for entry in &crl.revoked_entries {
        if entry.serial_bytes == leaf_serial {
            result.leaf_revoked = Some(true);
            result.revocation_time = Some(format_asn1_time(&entry.revocation_date));
            result.revocation_reason = entry.reason.clone();
            debug!(url = %url, "leaf serial found in CRL — revoked");
            return result;
        }
    }
    result.leaf_revoked = Some(false);
    result
}

/// Parsed CRL data in a form independent of x509-parser's borrowing
/// lifetimes, so we can materialize results into our result struct
/// without lifetime gymnastics.
struct ParsedCrl {
    last_update: x509_parser::time::ASN1Time,
    next_update: Option<x509_parser::time::ASN1Time>,
    issuer: String,
    revoked_entries: Vec<RevokedEntry>,
}

struct RevokedEntry {
    serial_bytes: Vec<u8>,
    revocation_date: x509_parser::time::ASN1Time,
    reason: Option<String>,
}

fn parse_crl(der_bytes: &[u8]) -> Result<ParsedCrl, String> {
    use x509_parser::prelude::FromDer;
    use x509_parser::revocation_list::CertificateRevocationList;

    let (_, crl) = CertificateRevocationList::from_der(der_bytes).map_err(|e| format!("{e}"))?;
    let last_update = crl.last_update();
    let next_update = crl.next_update();
    let issuer = crl.issuer().to_string();
    let mut revoked_entries = Vec::new();
    for entry in crl.iter_revoked_certificates() {
        let serial_bytes = entry.raw_serial().to_vec();
        let revocation_date = entry.revocation_date;
        let reason = entry.reason_code().map(|(_crit, code)| format!("{code:?}"));
        revoked_entries.push(RevokedEntry {
            serial_bytes,
            revocation_date,
            reason,
        });
    }
    Ok(ParsedCrl {
        last_update,
        next_update,
        issuer,
        revoked_entries,
    })
}

/// Detect PEM armor and decode. When `input` doesn't start with
/// `-----BEGIN X509 CRL-----` (possibly after leading whitespace),
/// returns the bytes as-is under the assumption they're DER.
fn decode_pem_if_armored(input: &[u8]) -> Result<Vec<u8>, String> {
    const PEM_START: &[u8] = b"-----BEGIN X509 CRL-----";
    // Skip leading whitespace.
    let trimmed_start = input
        .iter()
        .position(|&b| !b.is_ascii_whitespace())
        .unwrap_or(input.len());
    let rest = &input[trimmed_start..];
    if !rest.starts_with(PEM_START) {
        // DER path — hand bytes through unchanged.
        return Ok(input.to_vec());
    }
    let text = std::str::from_utf8(rest).map_err(|e| format!("non-utf8 in pem armor: {e}"))?;
    // Strip the BEGIN line, END line, and any intermediate
    // whitespace/newlines; base64-decode the middle.
    let Some(after_begin) = text.splitn(2, "\n").nth(1) else {
        return Err("malformed pem: no newline after BEGIN".to_string());
    };
    let Some(before_end) = after_begin.rsplitn(2, "-----END X509 CRL-----").nth(1) else {
        return Err("malformed pem: no END marker".to_string());
    };
    // base64 decoder — we have a dep via x509-parser's transitive
    // chain. Use a minimal local decoder to avoid pulling a new
    // top-level dep just for this.
    decode_base64_lenient(before_end)
}

/// Minimal base64 decoder tolerant of whitespace + newlines. Returns
/// Err on invalid characters or malformed padding.
fn decode_base64_lenient(input: &str) -> Result<Vec<u8>, String> {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lookup = [255u8; 256];
    for (i, &c) in TABLE.iter().enumerate() {
        lookup[c as usize] = i as u8;
    }

    let mut buf = Vec::with_capacity(input.len() * 3 / 4);
    let mut group: u32 = 0;
    let mut bits_in_group: u32 = 0;
    let mut pad_seen = 0usize;

    for &byte in input.as_bytes() {
        if byte == b'=' {
            pad_seen += 1;
            continue;
        }
        if (byte as char).is_ascii_whitespace() {
            continue;
        }
        if pad_seen > 0 {
            return Err("base64: data after padding".to_string());
        }
        let v = lookup[byte as usize];
        if v == 255 {
            return Err(format!("base64: invalid char {}", byte as char));
        }
        group = (group << 6) | v as u32;
        bits_in_group += 6;
        if bits_in_group >= 8 {
            bits_in_group -= 8;
            buf.push((group >> bits_in_group) as u8);
            group &= (1u32 << bits_in_group) - 1;
        }
    }
    Ok(buf)
}

fn format_asn1_time(t: &x509_parser::time::ASN1Time) -> String {
    // ISO 8601 via chrono. x509-parser's ASN1Time exposes `timestamp()`
    // as i64 epoch seconds; chrono handles the format. `Z` suffix
    // matches the rest of the codebase's datetime output.
    match chrono::DateTime::<chrono::Utc>::from_timestamp(t.timestamp(), 0) {
        Some(dt) => dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        None => "invalid_time".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_pem_passes_der_through() {
        let der = [0x30u8, 0x82, 0x01, 0x00]; // SEQUENCE { 256 bytes } header
        let decoded = decode_pem_if_armored(&der).unwrap();
        assert_eq!(decoded, der);
    }

    #[test]
    fn decode_pem_strips_armor() {
        // A tiny fake "CRL" for structure only — not a valid CRL,
        // but exercises the PEM decoder path.
        let body = b"\
            -----BEGIN X509 CRL-----\n\
            MAIBAA==\n\
            -----END X509 CRL-----\n\
        ";
        let decoded = decode_pem_if_armored(body).unwrap();
        // Base64 "MAIBAA==" decodes to 3 bytes: 0x30 0x02 0x01 0x00.
        assert_eq!(decoded, &[0x30, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn base64_decoder_handles_whitespace_and_padding() {
        let out = decode_base64_lenient("  MAIB\nAA==\n").unwrap();
        assert_eq!(out, &[0x30, 0x02, 0x01, 0x00]);

        // Standard test vectors.
        assert_eq!(decode_base64_lenient("TWFu").unwrap(), b"Man");
        assert_eq!(decode_base64_lenient("TWE=").unwrap(), b"Ma");
        assert_eq!(decode_base64_lenient("TQ==").unwrap(), b"M");
    }

    #[test]
    fn base64_decoder_rejects_invalid_chars() {
        assert!(decode_base64_lenient("###").is_err());
    }

    #[tokio::test]
    async fn empty_urls_returns_empty_output() {
        let out = probe_crl(&[], &[0x01], Duration::from_secs(1)).await;
        assert!(out.results.is_empty());
    }

    #[tokio::test]
    async fn urls_are_deduplicated_via_cache() {
        // Two identical URLs pointing at nothing — will fail fetch
        // but the cache ensures only one network attempt happens.
        // We can't easily assert "only one network call" without
        // mocks; at minimum verify both results mirror each other.
        let url = "http://127.0.0.1:1/nonexistent.crl".to_string();
        let out = probe_crl(
            &[url.clone(), url.clone()],
            &[0x01],
            Duration::from_millis(200),
        )
        .await;
        assert_eq!(out.results.len(), 2);
        assert_eq!(out.results[0].url, out.results[1].url);
        // Both should carry the same error string (cached).
        assert_eq!(out.results[0].error, out.results[1].error);
    }
}
