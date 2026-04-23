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

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use futures::StreamExt;
use tracing::debug;

/// Upper bound on CRL body size the scanner will buffer. 5 MiB is
/// already larger than every legitimate CA CRL we've observed; anything
/// bigger is either an accidentally huge deprecated-intermediate
/// snapshot or a hostile URL trying to exhaust scanner memory.
const CRL_BODY_SIZE_CAP: usize = 5 * 1024 * 1024;

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
    /// `revokedCertificates` list. `false` when the CRL was fetched,
    /// parsed, and searched AND the leaf serial was NOT present —
    /// the canonical "not revoked" positive signal. `None` when
    /// fetch or parse failed (no conclusion possible).
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

    // Body cap. Some CAs publish enormous CRLs (deprecated
    // intermediates with huge revocation histories); blindly loading
    // into memory would be an OOM hazard on a scanner running across
    // many targets. Reject up front on `Content-Length` over the cap,
    // then stream via `bytes_stream` and tear down as soon as the
    // running byte budget is exceeded — so the buffered allocation
    // never exceeds the cap even when the server lies about length
    // or omits it entirely.
    if let Some(len) = resp.content_length() {
        if len > CRL_BODY_SIZE_CAP as u64 {
            result.error = Some(format!("body_exceeds_size_cap:{len}"));
            return result;
        }
    }
    let mut stream = resp.bytes_stream();
    let mut body = Vec::with_capacity(16 * 1024);
    loop {
        match stream.next().await {
            Some(Ok(chunk)) => {
                if body.len() + chunk.len() > CRL_BODY_SIZE_CAP {
                    result.error = Some(format!(
                        "body_exceeds_size_cap:{}",
                        body.len() + chunk.len()
                    ));
                    return result;
                }
                body.extend_from_slice(&chunk);
            }
            Some(Err(e)) => {
                result.error = Some(format!("body_read:{e}"));
                return result;
            }
            None => break,
        }
    }

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

    result.this_update = format_asn1_time(&crl.last_update);
    result.next_update = crl.next_update.as_ref().and_then(format_asn1_time);
    result.crl_issuer = Some(crl.issuer.to_string());
    result.revoked_cert_count = Some(crl.revoked_entries.len());

    for entry in &crl.revoked_entries {
        if entry.serial_bytes == leaf_serial {
            result.leaf_revoked = Some(true);
            result.revocation_time = format_asn1_time(&entry.revocation_date);
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
    let Some(after_begin) = text.split_once("\n").map(|x| x.1) else {
        return Err("malformed pem: no newline after BEGIN".to_string());
    };
    let Some(before_end) = after_begin
        .rsplit_once("-----END X509 CRL-----")
        .map(|x| x.0)
    else {
        return Err("malformed pem: no END marker".to_string());
    };
    // PEM bodies are line-wrapped; strip whitespace so the strict
    // `base64` engine below sees a canonical 4-char-quantum stream.
    // Using the `base64` crate rather than a hand-rolled decoder
    // because CRL URLs come from certificate contents kemist doesn't
    // control: a hostile responder could otherwise feed malformed
    // quanta / mis-placed `=` padding that a tolerant decoder would
    // silently coerce into bogus DER bytes, leading to misleading
    // `parse_failed` errors or worse, accidentally parseable content.
    let stripped: String = before_end.chars().filter(|c| !c.is_whitespace()).collect();
    BASE64
        .decode(stripped.as_bytes())
        .map_err(|e| format!("base64 decode: {e}"))
}

/// Render an `ASN1Time` as an ISO 8601 string, or `None` when the
/// timestamp can't be represented (out-of-range epoch seconds).
/// Returning `None` rather than a sentinel string keeps the
/// `Option<String>` fields downstream honest — a sentinel in a
/// `Some(_)` slot would contradict the doc-stated "ISO 8601"
/// invariant and quietly mislead rule engines that treat presence
/// as "successfully parsed."
fn format_asn1_time(t: &x509_parser::time::ASN1Time) -> Option<String> {
    let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(t.timestamp(), 0)?;
    Some(dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
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
        // Base64 "MAIBAA==" decodes to 4 bytes: 0x30 0x02 0x01 0x00.
        assert_eq!(decoded, &[0x30, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn decode_pem_handles_multi_line_base64_bodies() {
        // Two-line body with whitespace stripping — exercises the
        // wrap handling inside `decode_pem_if_armored`.
        let body = b"\
            -----BEGIN X509 CRL-----\n\
            MAIB\n\
            AA==\n\
            -----END X509 CRL-----\n\
        ";
        let decoded = decode_pem_if_armored(body).unwrap();
        assert_eq!(decoded, &[0x30, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn decode_pem_rejects_malformed_base64() {
        // Under the strict `base64` engine, a body with out-of-quantum
        // input or invalid characters fails the decode — previous
        // hand-rolled decoder silently produced truncated bytes.
        let bad_chars = b"\
            -----BEGIN X509 CRL-----\n\
            ###\n\
            -----END X509 CRL-----\n\
        ";
        assert!(decode_pem_if_armored(bad_chars).is_err());

        // 3 non-padding chars + no `=` — not a valid 4-char quantum.
        let truncated = b"\
            -----BEGIN X509 CRL-----\n\
            MAI\n\
            -----END X509 CRL-----\n\
        ";
        assert!(decode_pem_if_armored(truncated).is_err());
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
