//! Certificate observations.
//!
//! Non-verdict extraction of cert facts that downstream rule engines consume:
//! raw signature OID, resolved algorithm name, PQC OID match flag, embedded
//! SCT count, SAN-vs-SNI name match. Separated from [`crate::model::cert`]
//! (pure data types) so parsing logic stays testable without requiring a
//! full `CertificateInfo`.

use der_parser::oid::Oid;
use std::collections::HashMap;
use std::sync::OnceLock;
use x509_parser::prelude::*;

use crate::model::cert_extensions::CertExtensions;

/// RFC 6962 embedded Signed Certificate Timestamp extension OID.
const SCT_EXTENSION_OID: &str = "1.3.6.1.4.1.11129.2.4.2";

/// Extract X.509 v3 extension fields into [`CertExtensions`].
///
/// Step A1 placeholder: returns [`CertExtensions::default()`] — every
/// sub-field stays `None` / empty so the serialized form is `{}`.
/// Per-extension parsers land in steps A2–A5; this function's
/// signature stays stable across those steps.
pub fn extract_extensions(_cert: &X509Certificate) -> CertExtensions {
    CertExtensions::default()
}

/// Canonical PQC signature OIDs per the kemist spec (NIST + IETF drafts).
/// Downstream consumers look at `is_pqc_signature` first; the resolved name
/// here is a convenience for humans reading the JSON.
///
/// Sources:
/// - ML-DSA: NIST FIPS 204 (CSOR 2.16.840.1.101.3.4.3.17–.19)
/// - SLH-DSA: NIST FIPS 205 (CSOR 2.16.840.1.101.3.4.3.20–.34)
/// - Composite sigs: IETF LAMPS drafts (when they stabilize, add here)
fn pqc_oid_map() -> &'static HashMap<&'static str, &'static str> {
    static MAP: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = HashMap::new();
        // ML-DSA (FIPS 204)
        m.insert("2.16.840.1.101.3.4.3.17", "ML-DSA-44");
        m.insert("2.16.840.1.101.3.4.3.18", "ML-DSA-65");
        m.insert("2.16.840.1.101.3.4.3.19", "ML-DSA-87");
        // SLH-DSA SHA2 family (FIPS 205)
        m.insert("2.16.840.1.101.3.4.3.20", "SLH-DSA-SHA2-128s");
        m.insert("2.16.840.1.101.3.4.3.21", "SLH-DSA-SHA2-128f");
        m.insert("2.16.840.1.101.3.4.3.22", "SLH-DSA-SHA2-192s");
        m.insert("2.16.840.1.101.3.4.3.23", "SLH-DSA-SHA2-192f");
        m.insert("2.16.840.1.101.3.4.3.24", "SLH-DSA-SHA2-256s");
        m.insert("2.16.840.1.101.3.4.3.25", "SLH-DSA-SHA2-256f");
        // SLH-DSA SHAKE family
        m.insert("2.16.840.1.101.3.4.3.26", "SLH-DSA-SHAKE-128s");
        m.insert("2.16.840.1.101.3.4.3.27", "SLH-DSA-SHAKE-128f");
        m.insert("2.16.840.1.101.3.4.3.28", "SLH-DSA-SHAKE-192s");
        m.insert("2.16.840.1.101.3.4.3.29", "SLH-DSA-SHAKE-192f");
        m.insert("2.16.840.1.101.3.4.3.30", "SLH-DSA-SHAKE-256s");
        m.insert("2.16.840.1.101.3.4.3.31", "SLH-DSA-SHAKE-256f");
        m
    })
}

/// Raw OID match — cheap bool for schema's `is_pqc_signature` field.
pub fn is_pqc_oid(oid_str: &str) -> bool {
    pqc_oid_map().contains_key(oid_str)
}

/// Human-readable signature algorithm name. Falls back to the OID string
/// when the OID isn't in our known list — never fails, never None.
pub fn resolve_signature_algorithm(oid: &Oid) -> String {
    let oid_str = oid.to_id_string();
    if let Some(pqc) = pqc_oid_map().get(oid_str.as_str()) {
        return (*pqc).to_string();
    }
    match oid_str.as_str() {
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.113549.1.1.10" => "rsassaPss",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        _ => oid_str.as_str(),
    }
    .to_string()
}

/// Count Signed Certificate Timestamps embedded in the leaf cert (RFC 6962
/// extension, OID 1.3.6.1.4.1.11129.2.4.2). Each SCT occupies one entry in
/// a length-prefixed `SignedCertificateTimestampList`.
///
/// Returns 0 if the extension is absent or malformed. Does NOT validate
/// the signatures — presence/count is the observation.
pub fn count_embedded_scts(cert_der: &[u8]) -> u32 {
    let Ok((_, cert)) = X509Certificate::from_der(cert_der) else {
        return 0;
    };
    for ext in cert.extensions() {
        if ext.oid.to_id_string() == SCT_EXTENSION_OID {
            // The extension value is an OCTET STRING containing a
            // `SignedCertificateTimestampList`. Its outer structure is:
            //   2 bytes: total length of the list (big-endian)
            //   for each SCT: 2 bytes length + SCT body
            // We count entries rather than validate them.
            return count_sct_entries(ext.value);
        }
    }
    0
}

fn count_sct_entries(ext_value: &[u8]) -> u32 {
    // The extension value is itself DER-wrapped OCTET STRING; peel that.
    // der_parser's approach: the top-level is OctetString whose contents
    // are the SCT list. We skip the two ASN.1 tag/length bytes when present.
    let inner: &[u8] = match (ext_value.first(), ext_value.get(1)) {
        // OCTET STRING tag 0x04 followed by short-form length
        (Some(0x04), Some(len)) if *len as usize + 2 == ext_value.len() => &ext_value[2..],
        // OCTET STRING tag 0x04 with long-form length (0x81 = 1-byte length)
        (Some(0x04), Some(0x81)) if ext_value.len() >= 3 => &ext_value[3..],
        // OCTET STRING tag 0x04 with long-form length (0x82 = 2-byte length)
        (Some(0x04), Some(0x82)) if ext_value.len() >= 4 => &ext_value[4..],
        _ => ext_value,
    };

    if inner.len() < 2 {
        return 0;
    }
    let list_len = u16::from_be_bytes([inner[0], inner[1]]) as usize;
    let body = match inner.get(2..2 + list_len) {
        Some(b) => b,
        None => return 0,
    };

    let mut count: u32 = 0;
    let mut i = 0;
    while i + 2 <= body.len() {
        let sct_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
        i += 2;
        if i + sct_len > body.len() {
            break;
        }
        i += sct_len;
        count = count.saturating_add(1);
    }
    count
}

/// Case-insensitive SAN DNS name matching with RFC 6125 wildcard semantics.
/// `*.example.com` matches `foo.example.com` but not `example.com` or
/// `sub.foo.example.com`. Returns `false` if the cert has no usable names
/// (no SANs and no CN).
pub fn name_matches_sni(san_entries: &[String], subject_dn: &str, sni: &str) -> bool {
    let sni_lc = sni.to_lowercase();

    // Collect candidate names from SAN entries. We only match on DNS-style
    // strings — SAN entries surfaced with prefixes like "Email:" or "URI:"
    // come from kemist's existing extract_san_names; skip those.
    let san_dns_names: Vec<String> = san_entries
        .iter()
        .filter(|s| !s.starts_with("Email:") && !s.starts_with("URI:"))
        .map(|s| s.to_lowercase())
        .collect();

    for san in &san_dns_names {
        if matches_dns_pattern(san, &sni_lc) {
            return true;
        }
    }

    // Fallback: subject CN. Only honored when the cert has no SANs (RFC
    // 6125 §6.4.4 — CN MUST be ignored if SAN is present).
    if san_dns_names.is_empty() {
        if let Some(cn) = extract_cn(subject_dn) {
            return matches_dns_pattern(&cn.to_lowercase(), &sni_lc);
        }
    }

    false
}

fn matches_dns_pattern(pattern: &str, name: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Wildcard matches exactly one leftmost label. Bail on corner cases:
        // no dot in name, or pattern equals name (shouldn't match `*` vs "")
        let first_dot = match name.find('.') {
            Some(i) => i,
            None => return false,
        };
        &name[first_dot + 1..] == suffix
    } else {
        pattern == name
    }
}

fn extract_cn(dn: &str) -> Option<String> {
    for rdn in dn.split(',') {
        let rdn = rdn.trim();
        if let Some(v) = rdn.strip_prefix("CN=") {
            return Some(v.to_string());
        }
    }
    None
}

/// All SAN DNS entries (wildcard and literal) as lowercased strings. Used
/// when retrying webpki validation with a known-matching name.
pub fn first_san_dns(san_entries: &[String]) -> Option<String> {
    san_entries
        .iter()
        .find(|s| !s.starts_with("Email:") && !s.starts_with("URI:"))
        .map(|s| s.trim_start_matches("*.").to_string())
        .map(|s| {
            // If the entry was a wildcard, substitute a dummy left label so
            // webpki gets a concrete FQDN.
            if san_entries
                .iter()
                .any(|raw| raw.starts_with("*.") && raw[2..].eq_ignore_ascii_case(&s))
            {
                format!("probe.{s}")
            } else {
                s
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_pqc_oids_detected() {
        assert!(is_pqc_oid("2.16.840.1.101.3.4.3.17")); // ML-DSA-44
        assert!(is_pqc_oid("2.16.840.1.101.3.4.3.20")); // SLH-DSA-SHA2-128s
    }

    #[test]
    fn non_pqc_oids_not_flagged() {
        assert!(!is_pqc_oid("1.2.840.113549.1.1.11")); // sha256WithRSA
        assert!(!is_pqc_oid("1.2.840.10045.4.3.2")); // ecdsa-with-SHA256
        assert!(!is_pqc_oid("")); // empty
    }

    #[test]
    fn san_exact_match() {
        let sans = vec!["example.com".to_string(), "www.example.com".to_string()];
        assert!(name_matches_sni(&sans, "CN=example.com", "example.com"));
        assert!(name_matches_sni(&sans, "CN=example.com", "www.example.com"));
        assert!(!name_matches_sni(
            &sans,
            "CN=example.com",
            "other.example.com"
        ));
    }

    #[test]
    fn san_wildcard_matches_single_label() {
        let sans = vec!["*.example.com".to_string()];
        assert!(name_matches_sni(
            &sans,
            "CN=*.example.com",
            "foo.example.com"
        ));
        assert!(!name_matches_sni(&sans, "CN=*.example.com", "example.com"));
        // Wildcard matches exactly one label — no multi-level.
        assert!(!name_matches_sni(
            &sans,
            "CN=*.example.com",
            "a.b.example.com"
        ));
    }

    #[test]
    fn cn_used_only_when_no_sans_present() {
        let no_sans: Vec<String> = vec![];
        assert!(name_matches_sni(&no_sans, "CN=example.com", "example.com"));

        // With SANs, CN is ignored per RFC 6125.
        let sans_dont_match = vec!["other.example.com".to_string()];
        assert!(!name_matches_sni(
            &sans_dont_match,
            "CN=example.com",
            "example.com"
        ));
    }

    #[test]
    fn name_match_is_case_insensitive() {
        let sans = vec!["Example.COM".to_string()];
        assert!(name_matches_sni(&sans, "CN=Example.COM", "EXAMPLE.com"));
    }

    #[test]
    fn email_and_uri_san_entries_ignored() {
        let sans = vec![
            "Email: admin@example.com".to_string(),
            "URI:https://example.com".to_string(),
            "example.com".to_string(),
        ];
        assert!(name_matches_sni(&sans, "", "example.com"));
        assert!(!name_matches_sni(&sans, "", "admin@example.com"));
    }
}
