//! Upstream-aware bundle fetchers for
//! `kemist --update-trust-stores` / `--update-hsts-preload`.
//!
//! One function per refreshable bundle. Each returns raw bytes to
//! write to the cache plus a [`FetchMetadata`] describing
//! provenance (source URL, fetch timestamp, entry count,
//! upstream-declared version when available).
//!
//! ## Design
//! - Fetch with a browser-style User-Agent header everywhere —
//!   some upstreams (notably DISA's DoD mirror) 403/404 on the
//!   default reqwest UA.
//! - Decode in-process: PKCS#7 via `openssl`, ZIP via the `zip`
//!   crate, CSV via `csv`. No shelling out.
//! - Never validate signatures on the fetched data — we're
//!   mirroring upstream's observations, not auditing them. The
//!   manifest's SHA-256 protects against accidental corruption on
//!   disk after the fetch, not against a compromised upstream.
//!
//! ## Feature gating
//! The whole module requires `http-checks` (for `reqwest`) and
//! `legacy-probes` (for `openssl::pkcs7`). Both are default-on.
//! Under `--no-default-features` the `--update-trust-stores` CLI
//! flag is hidden at parse time by a `#[cfg(all(...))]` on the
//! clap field.

#![cfg(all(feature = "http-checks", feature = "legacy-probes"))]

use std::io::Read;
use std::time::Duration;

use tracing::debug;

use crate::scanner::bundle_cache::BundleMetadata;

/// Shared browser-style UA for every fetch. DISA's DoD CDN
/// refuses default reqwest UA with 403; Chromium's gitiles endpoint
/// responds identically to any UA but consistency beats
/// per-fetch variance.
const UA: &str = "Mozilla/5.0 (compatible; kemist/update-bundles)";

/// Per-fetch timeout. Some upstreams (DoD bundle, Chromium preload)
/// are multi-megabyte — 60s gives slow links a fair chance.
const FETCH_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum body size accepted from any single fetch, as a guard
/// against runaway downloads. Chromium preload is ~10 MB,
/// Microsoft's decade dumps are ~10 MB each, DoD ZIP is ~120 KB —
/// 50 MB gives comfortable headroom without bounded badness.
const MAX_BODY_BYTES: usize = 50 * 1024 * 1024;

/// Fetch the Microsoft TLS trust store from CCADB. The canonical
/// flow is:
/// 1. Pull `AllCertificateRecordsCSVFormatV5` — metadata for every
///    CCADB-tracked CA. Filter rows where
///    `Microsoft Status == "Included"` AND
///    `TLS Capable == "True"`. Record each row's SHA-256.
/// 2. Pull `AllCertificatePEMsCSVFormat?NotBeforeDecade=<D>` for
///    D ∈ {1990, 2000, 2010, 2020}. Each gives
///    `(SHA-256, PEM)` rows.
/// 3. Intersect: for every Microsoft-included SHA-256, pull its
///    PEM from the decade dumps. Missing PEMs are logged but
///    don't fail the refresh — the bundle simply lacks those
///    anchors this refresh.
///
/// Concatenate into a PEM file. Upstream version: none —
/// Microsoft doesn't publish a versioned snapshot identifier via
/// this path.
pub async fn fetch_microsoft() -> Result<(Vec<u8>, BundleMetadata), String> {
    let client = build_client()?;
    let v5 = fetch_text(
        &client,
        "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatV5",
    )
    .await?;

    // Filter V5 CSV → Microsoft-included TLS SHA-256 set.
    let mut wanted = std::collections::BTreeSet::new();
    let mut reader = csv::Reader::from_reader(v5.as_bytes());
    let headers: Vec<String> = reader
        .headers()
        .map_err(|e| format!("v5 csv header: {e}"))?
        .iter()
        .map(|s| s.to_string())
        .collect();
    let col = |name: &str| headers.iter().position(|h| h == name);
    let msft_col = col("Microsoft Status")
        .ok_or_else(|| "v5 csv missing 'Microsoft Status' column".to_string())?;
    let tls_col =
        col("TLS Capable").ok_or_else(|| "v5 csv missing 'TLS Capable' column".to_string())?;
    let fp_col = col("SHA-256 Fingerprint")
        .ok_or_else(|| "v5 csv missing 'SHA-256 Fingerprint' column".to_string())?;
    for row in reader.records() {
        let row = row.map_err(|e| format!("v5 csv row: {e}"))?;
        if row.get(msft_col).map(str::trim) != Some("Included") {
            continue;
        }
        if row.get(tls_col).map(str::trim) != Some("True") {
            continue;
        }
        if let Some(fp) = row.get(fp_col) {
            let normalized: String = fp
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .map(|c| c.to_ascii_uppercase())
                .collect();
            if !normalized.is_empty() {
                wanted.insert(normalized);
            }
        }
    }
    debug!(count = wanted.len(), "microsoft V5 filter → wanted count");

    // Decade pulls → PEM map.
    let mut pems: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for decade in [1990, 2000, 2010, 2020] {
        let url = format!(
            "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificatePEMsCSVFormat?NotBeforeDecade={decade}"
        );
        let body = fetch_text(&client, &url).await?;
        let mut r = csv::Reader::from_reader(body.as_bytes());
        let hs: Vec<String> = r
            .headers()
            .map_err(|e| format!("pems csv header decade {decade}: {e}"))?
            .iter()
            .map(|s| s.to_string())
            .collect();
        let fp_i = hs
            .iter()
            .position(|h| h == "SHA-256 Fingerprint")
            .ok_or_else(|| {
                format!("pems csv decade {decade} missing SHA-256 Fingerprint column")
            })?;
        let pem_i = hs
            .iter()
            .position(|h| h == "X.509 Certificate (PEM)")
            .ok_or_else(|| {
                format!("pems csv decade {decade} missing X.509 Certificate (PEM) column")
            })?;
        for row in r.records() {
            let row = row.map_err(|e| format!("pems decade {decade} row: {e}"))?;
            let fp: String = row
                .get(fp_i)
                .unwrap_or("")
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .map(|c| c.to_ascii_uppercase())
                .collect();
            let pem = row.get(pem_i).unwrap_or("").trim().to_string();
            if !fp.is_empty() && !pem.is_empty() {
                pems.insert(fp, pem);
            }
        }
    }
    debug!(count = pems.len(), "microsoft PEM map size across decades");

    // Intersect + write bundle.
    let mut matched = 0usize;
    let mut missing = 0usize;
    let mut out = String::new();
    out.push_str("# Microsoft CCADB TLS trust store.\n");
    out.push_str("# Source: CCADB V5 (Microsoft Status filter) × AllCertificatePEMs by decade.\n");
    out.push_str(&format!(
        "# Fetched: {}\n",
        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    ));
    out.push_str(&format!(
        "# Wanted: {}, matched: TBD (count recorded in manifest).\n\n",
        wanted.len()
    ));
    let mut ordered: Vec<_> = wanted.iter().collect();
    ordered.sort();
    for fp in ordered {
        if let Some(pem) = pems.get(fp) {
            out.push_str(pem.trim().trim_matches(['"', '\''].as_ref()));
            out.push('\n');
            matched += 1;
        } else {
            missing += 1;
        }
    }
    debug!(matched, missing, "microsoft bundle assembly");
    let bytes = out.into_bytes();
    Ok((
        bytes,
        BundleMetadata {
            source: "ccadb V5 × AllCertificatePEMs by decade".to_string(),
            fetched_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            sha256: String::new(), // caller fills in after write
            entry_count: matched,
            upstream_version: None,
        },
    ))
}

/// Fetch the US Federal Common Policy CA G2 root + its SIA-chained
/// agency intermediates. SIA URL is discovered from the root cert
/// itself (not hardcoded) so a root-key rollover + SIA update
/// naturally flows through to the refreshed bundle.
pub async fn fetch_us_fpki_common() -> Result<(Vec<u8>, BundleMetadata), String> {
    let client = build_client()?;
    let root_der = fetch_bytes(&client, "https://http.fpki.gov/fcpca/fcpcag2.crt").await?;

    // Extract SIA URL from the root's X.509 extensions.
    let sia_url = extract_fpki_sia_url(&root_der)?;

    let p7c_bytes = fetch_bytes(&client, &sia_url).await?;

    // Convert p7c (DER-encoded PKCS#7) to PEM certs. Concatenate:
    // root first, then intermediates.
    let p7 = openssl::pkcs7::Pkcs7::from_der(&p7c_bytes).map_err(|e| format!("p7c parse: {e}"))?;
    let root_cert =
        openssl::x509::X509::from_der(&root_der).map_err(|e| format!("root cert parse: {e}"))?;

    let mut out = String::new();
    out.push_str("# FPKI Common Policy bundle: FCPCA G2 + SIA-discovered intermediates.\n");
    out.push_str(&format!(
        "# SIA URL (read from root cert, not hardcoded): {sia_url}\n"
    ));
    out.push_str(&format!(
        "# Fetched: {}\n\n",
        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    ));
    out.push_str(
        &String::from_utf8(
            root_cert
                .to_pem()
                .map_err(|e| format!("root to_pem: {e}"))?,
        )
        .map_err(|e| format!("root pem utf8: {e}"))?,
    );
    let mut intermediate_count = 0usize;
    if let Some(signed) = p7.signed() {
        if let Some(stack) = signed.certificates() {
            for cert in stack {
                let pem = cert
                    .to_pem()
                    .map_err(|e| format!("intermediate to_pem: {e}"))?;
                out.push_str(
                    &String::from_utf8(pem).map_err(|e| format!("intermediate pem utf8: {e}"))?,
                );
                intermediate_count += 1;
            }
        }
    }
    let total = 1 + intermediate_count;

    Ok((
        out.into_bytes(),
        BundleMetadata {
            source: format!("https://http.fpki.gov/fcpca/fcpcag2.crt + SIA:{sia_url}"),
            fetched_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            sha256: String::new(),
            entry_count: total,
            upstream_version: None,
        },
    ))
}

/// Walk the FCPCA G2 cert's Subject Information Access extension
/// (RFC 5280 §4.2.2.2) and return the CA-Repository URI. We parse
/// via the openssl crate — avoids lifting another DER walker in.
fn extract_fpki_sia_url(cert_der: &[u8]) -> Result<String, String> {
    let cert =
        openssl::x509::X509::from_der(cert_der).map_err(|e| format!("fpki root parse: {e}"))?;
    // openssl-rs 0.10 doesn't expose SIA via a typed accessor;
    // fall back to the text-form dump and grep. Ugly but stable —
    // the text format is consumer-facing and hasn't changed.
    let text = cert
        .to_text()
        .map_err(|e| format!("fpki root to_text: {e}"))?;
    let s = String::from_utf8_lossy(&text);
    // Match the repository URI in the Subject Information Access
    // section. Multi-line format:
    //   Subject Information Access:
    //       CA Repository - URI:http://...
    let mut in_sia = false;
    for line in s.lines() {
        if line.contains("Subject Information Access") {
            in_sia = true;
            continue;
        }
        if in_sia {
            if let Some(idx) = line.find("URI:http") {
                return Ok(line[idx + 4..].trim().to_string());
            }
            // Any de-indented line means we left the SIA block.
            if !line.starts_with(' ') && !line.starts_with('\t') && !line.is_empty() {
                break;
            }
        }
    }
    Err("fpki root: no CA-Repository URI in SIA extension".to_string())
}

/// Fetch + extract the DoD PKI unclassified bundle. The ZIP lives
/// at `dl.dod.cyber.mil` but the server refuses default reqwest
/// UAs with 403; browser-style UA works. Contents: a versioned
/// directory with PKCS#7 files keyed on each DoD Root CA (3/4/5/6)
/// plus a combined `<root>.pem.p7b` with every cert in one file.
/// We prefer the combined PEM-encoded p7b — one parse call, full
/// trust set.
pub async fn fetch_us_dod() -> Result<(Vec<u8>, BundleMetadata), String> {
    const URL: &str =
        "https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_DoD.zip";
    let client = build_client()?;
    let zip_bytes = fetch_bytes(&client, URL).await?;

    let reader = std::io::Cursor::new(&zip_bytes);
    let mut archive = zip::ZipArchive::new(reader).map_err(|e| format!("dod zip parse: {e}"))?;

    // Find the combined PEM PKCS#7 (filename ends with
    // `.pem.p7b` and lacks a per-root suffix).
    let mut combined_p7b: Option<(String, Vec<u8>)> = None;
    let mut version_tag: Option<String> = None;
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| format!("dod zip entry {i}: {e}"))?;
        let name = entry.name().to_string();
        // Capture the version from the directory prefix,
        // e.g. `Certificates_PKCS7_v5_14_DoD/...`.
        if version_tag.is_none() {
            if let Some(prefix) = name.split('/').next() {
                if let Some(v) = prefix.strip_prefix("Certificates_PKCS7_") {
                    if let Some(vv) = v.strip_suffix("_DoD") {
                        version_tag = Some(vv.to_string());
                    }
                }
            }
        }
        // The combined PEM PKCS#7 has no per-root suffix.
        let is_combined =
            name.ends_with(".pem.p7b") && !name.contains("Root_CA_") && !name.contains("Root_ECA");
        if is_combined {
            let mut buf = Vec::new();
            entry
                .read_to_end(&mut buf)
                .map_err(|e| format!("dod zip read {name}: {e}"))?;
            combined_p7b = Some((name, buf));
            break;
        }
    }
    let (p7b_name, p7b_bytes) =
        combined_p7b.ok_or_else(|| "dod zip: no combined `.pem.p7b` entry found".to_string())?;

    // Parse PEM-PKCS7 via openssl. The stored format is PEM; load
    // via from_pem.
    let p7 = openssl::pkcs7::Pkcs7::from_pem(&p7b_bytes)
        .map_err(|e| format!("dod p7b from_pem: {e}"))?;

    let mut out = String::new();
    out.push_str("# US DoD PKI trust store.\n");
    out.push_str(&format!("# Source: {URL}\n"));
    out.push_str(&format!("# Archive entry: {p7b_name}\n"));
    if let Some(v) = &version_tag {
        out.push_str(&format!("# Upstream version: {v}\n"));
    }
    out.push_str(&format!(
        "# Fetched: {}\n\n",
        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    ));
    let mut cert_count = 0usize;
    if let Some(signed) = p7.signed() {
        if let Some(stack) = signed.certificates() {
            for cert in stack {
                let pem = cert.to_pem().map_err(|e| format!("dod cert to_pem: {e}"))?;
                out.push_str(&String::from_utf8(pem).map_err(|e| format!("dod pem utf8: {e}"))?);
                cert_count += 1;
            }
        }
    }

    Ok((
        out.into_bytes(),
        BundleMetadata {
            source: URL.to_string(),
            fetched_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            sha256: String::new(),
            entry_count: cert_count,
            upstream_version: version_tag,
        },
    ))
}

/// Fetch the Chromium HSTS preload snapshot
/// (`transport_security_state_static.json`). Chromium hosts it on
/// gitiles with `?format=TEXT`, which returns the file
/// base64-encoded over a plain text/plain response. We strip +
/// decode + return the raw JSON with comments.
pub async fn fetch_hsts_preload() -> Result<(Vec<u8>, BundleMetadata), String> {
    const URL: &str =
        "https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/http/transport_security_state_static.json?format=TEXT";
    let client = build_client()?;
    let b64 = fetch_text(&client, URL).await?;

    // Decode base64 (standard alphabet, line-wrapped).
    let decoded = base64_decode(&b64).map_err(|e| format!("gitiles base64 decode: {e}"))?;

    // Count force-https entries so the manifest records a real
    // signal about the bundle's content. Same format detection
    // the build.rs uses.
    let text = std::str::from_utf8(&decoded).map_err(|e| format!("preload utf8: {e}"))?;
    let entry_count = text.matches("\"force-https\"").count();

    Ok((
        decoded,
        BundleMetadata {
            source: URL.to_string(),
            fetched_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            sha256: String::new(),
            entry_count,
            upstream_version: None,
        },
    ))
}

fn build_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .user_agent(UA)
        .timeout(FETCH_TIMEOUT)
        .build()
        .map_err(|e| format!("reqwest client build: {e}"))
}

async fn fetch_bytes(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, String> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("GET {url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GET {url}: HTTP {}", resp.status()));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("GET {url} body: {e}"))?;
    if bytes.len() > MAX_BODY_BYTES {
        return Err(format!(
            "GET {url}: body {} exceeds cap {MAX_BODY_BYTES}",
            bytes.len()
        ));
    }
    Ok(bytes.to_vec())
}

async fn fetch_text(client: &reqwest::Client, url: &str) -> Result<String, String> {
    let bytes = fetch_bytes(client, url).await?;
    String::from_utf8(bytes).map_err(|e| format!("GET {url} non-utf8: {e}"))
}

/// Minimal base64 decoder — used only for the Chromium gitiles
/// response. Tolerates whitespace + optional padding.
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lookup = [255u8; 256];
    for (i, &c) in TABLE.iter().enumerate() {
        lookup[c as usize] = i as u8;
    }
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut group: u32 = 0;
    let mut bits: u32 = 0;
    let mut pad = 0usize;
    for &b in input.as_bytes() {
        if b == b'=' {
            pad += 1;
            continue;
        }
        if (b as char).is_ascii_whitespace() {
            continue;
        }
        if pad > 0 {
            return Err("data after padding".to_string());
        }
        let v = lookup[b as usize];
        if v == 255 {
            return Err(format!("invalid char {}", b as char));
        }
        group = (group << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((group >> bits) as u8);
            group &= (1u32 << bits) - 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decode_matches_stdlib_vectors() {
        assert_eq!(base64_decode("TWFu").unwrap(), b"Man");
        assert_eq!(base64_decode("TWE=").unwrap(), b"Ma");
        assert_eq!(base64_decode("TQ==").unwrap(), b"M");
        // Newline tolerance — gitiles wraps at 76 cols.
        assert_eq!(base64_decode("T\nW\nF\nu").unwrap(), b"Man");
    }
}
