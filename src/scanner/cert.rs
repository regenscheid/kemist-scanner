//! Certificate observations.
//!
//! Non-verdict extraction of cert facts that downstream rule engines consume:
//! raw signature OID, resolved algorithm name, PQC OID match flag, embedded
//! SCT count, SAN-vs-SNI name match. Separated from [`crate::model::cert`]
//! (pure data types) so parsing logic stays testable without requiring a
//! full `CertificateInfo`.

use chrono::{DateTime, Utc};
use der_parser::oid::Oid;
use std::collections::HashMap;
use std::sync::OnceLock;
use x509_parser::extensions::{
    DistributionPointName, GeneralName, ParsedExtension, SignedCertificateTimestamp,
};
use x509_parser::prelude::*;

use crate::model::cert_extensions::{
    AuthorityInformationAccess, BasicConstraints, CertExtensions, CertificatePolicies,
    CrlDistributionPoints, ExtendedKeyUsage, KeyUsage, NameConstraints, SctDetail,
};

/// RFC 6962 embedded Signed Certificate Timestamp extension OID.
const SCT_EXTENSION_OID: &str = "1.3.6.1.4.1.11129.2.4.2";

/// AIA accessMethod OIDs.
const AIA_OCSP: &str = "1.3.6.1.5.5.7.48.1";
const AIA_CA_ISSUERS: &str = "1.3.6.1.5.5.7.48.2";

/// Extract X.509 v3 extension fields into [`CertExtensions`].
///
/// Walks the cert's extensions list and dispatches on OID. For
/// extensions x509-parser has a `ParsedExtension` variant for, we
/// use the structured form; for the RFC 7633 TLS Feature extension
/// (no dedicated variant), we parse the raw DER value ourselves.
///
/// Unknown / unparseable extensions are silently skipped — the
/// absence of a field in the output means "not present on this
/// cert," same as "scanner couldn't make sense of it," which is
/// acceptable because rule engines key off presence/value, not
/// existence. If a future compliance rule needs to distinguish
/// unparseable from absent, the helper can grow an error
/// sub-field.
pub fn extract_extensions(cert: &X509Certificate) -> CertExtensions {
    let mut out = CertExtensions::default();

    for ext in cert.extensions() {
        match ext.oid.to_id_string().as_str() {
            // Basic Constraints — RFC 5280 §4.2.1.9
            "2.5.29.19" => {
                if let ParsedExtension::BasicConstraints(bc) = ext.parsed_extension() {
                    out.basic_constraints = Some(BasicConstraints {
                        ca: bc.ca,
                        path_len_constraint: bc.path_len_constraint,
                    });
                }
            }
            // Key Usage — RFC 5280 §4.2.1.3
            "2.5.29.15" => {
                if let ParsedExtension::KeyUsage(ku) = ext.parsed_extension() {
                    let mut bits = Vec::new();
                    if ku.digital_signature() {
                        bits.push("digital_signature".into());
                    }
                    if ku.non_repudiation() {
                        bits.push("content_commitment".into());
                    }
                    if ku.key_encipherment() {
                        bits.push("key_encipherment".into());
                    }
                    if ku.data_encipherment() {
                        bits.push("data_encipherment".into());
                    }
                    if ku.key_agreement() {
                        bits.push("key_agreement".into());
                    }
                    if ku.key_cert_sign() {
                        bits.push("key_cert_sign".into());
                    }
                    if ku.crl_sign() {
                        bits.push("crl_sign".into());
                    }
                    if ku.encipher_only() {
                        bits.push("encipher_only".into());
                    }
                    if ku.decipher_only() {
                        bits.push("decipher_only".into());
                    }
                    out.key_usage = Some(KeyUsage { bits });
                }
            }
            // Extended Key Usage — RFC 5280 §4.2.1.12
            "2.5.29.37" => {
                if let ParsedExtension::ExtendedKeyUsage(eku) = ext.parsed_extension() {
                    let mut oids = Vec::new();
                    if eku.any {
                        oids.push("any".into());
                    }
                    if eku.server_auth {
                        oids.push("server_auth".into());
                    }
                    if eku.client_auth {
                        oids.push("client_auth".into());
                    }
                    if eku.code_signing {
                        oids.push("code_signing".into());
                    }
                    if eku.email_protection {
                        oids.push("email_protection".into());
                    }
                    if eku.time_stamping {
                        oids.push("time_stamping".into());
                    }
                    for o in &eku.other {
                        oids.push(resolve_eku_oid(&o.to_id_string()));
                    }
                    out.extended_key_usage = Some(ExtendedKeyUsage { oids });
                }
            }
            // Authority Key Identifier — RFC 5280 §4.2.1.1
            "2.5.29.35" => {
                if let ParsedExtension::AuthorityKeyIdentifier(aki) = ext.parsed_extension() {
                    if let Some(kid) = &aki.key_identifier {
                        out.authority_key_identifier = Some(hex::encode(kid.0));
                    }
                }
            }
            // Subject Key Identifier — RFC 5280 §4.2.1.2
            "2.5.29.14" => {
                if let ParsedExtension::SubjectKeyIdentifier(kid) = ext.parsed_extension() {
                    out.subject_key_identifier = Some(hex::encode(kid.0));
                }
            }
            // Authority Information Access — RFC 5280 §4.2.2.1
            "1.3.6.1.5.5.7.1.1" => {
                if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
                    let mut ocsp = Vec::new();
                    let mut ca_issuers = Vec::new();
                    for desc in &aia.accessdescs {
                        let url = general_name_to_string(&desc.access_location);
                        match desc.access_method.to_id_string().as_str() {
                            AIA_OCSP => ocsp.push(url),
                            AIA_CA_ISSUERS => ca_issuers.push(url),
                            _ => {}
                        }
                    }
                    out.authority_information_access =
                        Some(AuthorityInformationAccess { ocsp, ca_issuers });
                }
            }
            // CRL Distribution Points — RFC 5280 §4.2.1.13
            "2.5.29.31" => {
                if let ParsedExtension::CRLDistributionPoints(crl) = ext.parsed_extension() {
                    let mut urls = Vec::new();
                    for point in crl.iter() {
                        if let Some(DistributionPointName::FullName(names)) =
                            &point.distribution_point
                        {
                            for n in names {
                                urls.push(general_name_to_string(n));
                            }
                        }
                    }
                    out.crl_distribution_points = Some(CrlDistributionPoints { urls });
                }
            }
            // Name Constraints — RFC 5280 §4.2.1.10
            "2.5.29.30" => {
                if let ParsedExtension::NameConstraints(nc) = ext.parsed_extension() {
                    let permitted_subtrees = nc
                        .permitted_subtrees
                        .as_ref()
                        .map(|v| {
                            v.iter()
                                .map(|s| general_name_to_string(&s.base))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    let excluded_subtrees = nc
                        .excluded_subtrees
                        .as_ref()
                        .map(|v| {
                            v.iter()
                                .map(|s| general_name_to_string(&s.base))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    out.name_constraints = Some(NameConstraints {
                        permitted_subtrees,
                        excluded_subtrees,
                    });
                }
            }
            // Certificate Policies — RFC 5280 §4.2.1.4
            "2.5.29.32" => {
                if let ParsedExtension::CertificatePolicies(cp) = ext.parsed_extension() {
                    let oids = cp.iter().map(|p| p.policy_id.to_id_string()).collect();
                    out.certificate_policies = Some(CertificatePolicies { oids });
                }
            }
            // TLS Feature / Must-Staple — RFC 7633
            // x509-parser has no dedicated variant; parse raw bytes.
            "1.3.6.1.5.5.7.1.24" => {
                out.must_staple = Some(parse_tls_feature_must_staple(ext.value));
            }
            // Embedded SCTs — RFC 6962 §3.3
            SCT_EXTENSION_OID => {
                if let ParsedExtension::SCT(list) = ext.parsed_extension() {
                    out.scts = list.iter().map(sct_to_detail).collect();
                }
            }
            _ => {}
        }
    }

    out
}

/// Render a `GeneralName` to a single human-readable string. Used
/// for CRL DP, AIA accessLocation, and Name Constraints subtree
/// names. Returns a best-effort representation — IP addresses get
/// `ip:<hex>`, registered IDs return the dotted OID, unknown
/// variants return an opaque `"unknown"` marker.
fn general_name_to_string(gn: &GeneralName) -> String {
    match gn {
        GeneralName::DNSName(s) => s.to_string(),
        GeneralName::URI(s) => s.to_string(),
        GeneralName::RFC822Name(s) => s.to_string(),
        GeneralName::IPAddress(ip) => format!("ip:{}", hex::encode(ip)),
        GeneralName::DirectoryName(dn) => format!("dn:{}", dn),
        GeneralName::RegisteredID(oid) => oid.to_id_string(),
        _ => "unknown".to_string(),
    }
}

/// Resolve common Extended Key Usage OIDs not directly exposed by
/// x509-parser's boolean flags. Falls back to the dotted OID string
/// for unknowns.
fn resolve_eku_oid(oid: &str) -> String {
    match oid {
        "1.3.6.1.5.5.7.3.9" => "ocsp_signing".into(),
        "1.3.6.1.5.5.7.3.5" => "ipsec_end_system".into(),
        "1.3.6.1.5.5.7.3.6" => "ipsec_tunnel".into(),
        "1.3.6.1.5.5.7.3.7" => "ipsec_user".into(),
        // Microsoft EKUs seen on some Web PKI certs.
        "1.3.6.1.4.1.311.10.3.3" => "ms_sgc".into(),
        "1.3.6.1.4.1.311.20.2.2" => "ms_smartcard_logon".into(),
        other => other.to_string(),
    }
}

/// Parse the TLS Feature extension value (RFC 7633) and return
/// `true` iff feature integer 5 (status_request) is listed — the
/// Must-Staple marker.
///
/// Structure: `SEQUENCE OF INTEGER`. Parsed at the byte level rather
/// than via a helper crate because (a) the structure is trivially
/// simple and (b) it avoids pulling in another ASN.1 dependency.
/// Tolerant of short-form and long-form length encodings.
fn parse_tls_feature_must_staple(value: &[u8]) -> bool {
    // DER SEQUENCE tag.
    if value.first() != Some(&0x30) {
        return false;
    }
    // Decode the SEQUENCE's contents slice, skipping the tag+length
    // prefix.
    let contents: &[u8] = match value.get(1).copied() {
        Some(l) if l < 0x80 => {
            let end = 2usize.saturating_add(l as usize);
            match value.get(2..end) {
                Some(s) => s,
                None => return false,
            }
        }
        Some(0x81) => {
            let Some(&l) = value.get(2) else { return false };
            let end = 3usize.saturating_add(l as usize);
            match value.get(3..end) {
                Some(s) => s,
                None => return false,
            }
        }
        Some(0x82) => {
            let (Some(&h), Some(&l)) = (value.get(2), value.get(3)) else {
                return false;
            };
            let length = (u16::from(h) << 8 | u16::from(l)) as usize;
            let end = 4usize.saturating_add(length);
            match value.get(4..end) {
                Some(s) => s,
                None => return false,
            }
        }
        _ => return false,
    };

    // Iterate INTEGER entries. Short-form lengths only — feature
    // integers are single bytes in practice.
    let mut i = 0;
    while i + 2 <= contents.len() {
        if contents[i] != 0x02 {
            // Unexpected tag inside SEQUENCE OF INTEGER — bail.
            return false;
        }
        let int_len = contents[i + 1] as usize;
        if i + 2 + int_len > contents.len() {
            return false;
        }
        let int_bytes = &contents[i + 2..i + 2 + int_len];
        // Must-Staple = feature 5 (status_request).
        if int_bytes == [0x05] {
            return true;
        }
        i += 2 + int_len;
    }
    false
}

/// Convert an RFC 6962 SCT to our serializable `SctDetail`. Hash and
/// signature algorithm IDs map to the TLS 1.2 HashAlgorithm /
/// SignatureAlgorithm enums (RFC 5246 §7.4.1.4.1).
fn sct_to_detail(sct: &SignedCertificateTimestamp) -> SctDetail {
    // RFC 6962 §3.2 — timestamp is milliseconds since the Unix epoch.
    let ts_secs = (sct.timestamp / 1000) as i64;
    let ts_nsecs = ((sct.timestamp % 1000) * 1_000_000) as u32;
    let timestamp = DateTime::from_timestamp(ts_secs, ts_nsecs).unwrap_or(DateTime::<Utc>::MIN_UTC);

    let hash_alg = match sct.signature.hash_alg_id {
        0 => "none",
        1 => "md5",
        2 => "sha1",
        3 => "sha224",
        4 => "sha256",
        5 => "sha384",
        6 => "sha512",
        _ => "unknown",
    };
    let sig_alg = match sct.signature.sign_alg_id {
        0 => "anonymous",
        1 => "rsa",
        2 => "dsa",
        3 => "ecdsa",
        _ => "unknown",
    };

    SctDetail {
        log_id: hex::encode(sct.id.key_id),
        timestamp,
        signature_hash_algorithm: hash_alg.to_string(),
        signature_algorithm: sig_alg.to_string(),
        signature_hex: hex::encode(sct.signature.data),
    }
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

/// Classify a PQC signature OID into its FIPS-assigned family.
/// Returns `"ml_dsa"` for FIPS 204 codepoints,
/// `"slh_dsa"` for FIPS 205, `"composite"` for IETF LAMPS composite
/// signature codepoints (when added), and `None` for classical
/// signatures or OIDs not in the PQC table. Lets rule engines
/// distinguish stateless-hash-based sigs (SLH-DSA) from lattice sigs
/// (ML-DSA) without re-implementing an OID table.
pub fn pqc_family_of_oid(oid_str: &str) -> Option<&'static str> {
    // ML-DSA — FIPS 204 (CSOR 2.16.840.1.101.3.4.3.{17,18,19})
    if matches!(
        oid_str,
        "2.16.840.1.101.3.4.3.17" | "2.16.840.1.101.3.4.3.18" | "2.16.840.1.101.3.4.3.19"
    ) {
        return Some("ml_dsa");
    }
    // SLH-DSA — FIPS 205 (CSOR 2.16.840.1.101.3.4.3.{20..=31}; SHA2
    // family 20-25, SHAKE family 26-31).
    if let Some(suffix) = oid_str.strip_prefix("2.16.840.1.101.3.4.3.") {
        if let Ok(n) = suffix.parse::<u32>() {
            if (20..=31).contains(&n) {
                return Some("slh_dsa");
            }
        }
    }
    None
}

/// Canonical hash family name extracted from a signature-algorithm
/// OID, or `None` when the algorithm handles hashing internally
/// (Ed25519, Ed448, ML-DSA, SLH-DSA pure variants). Returns the RFC
/// 6931 hash name for classical sigs and an algorithm-specific
/// hint for SLH-DSA variants (they're named by their hash family,
/// though the hashing is internal to the signature scheme).
fn hash_of_sig_oid(oid_str: &str) -> Option<&'static str> {
    match oid_str {
        // RSA PKCS#1 v1.5
        "1.2.840.113549.1.1.5" => Some("sha1"),
        "1.2.840.113549.1.1.11" => Some("sha256"),
        "1.2.840.113549.1.1.12" => Some("sha384"),
        "1.2.840.113549.1.1.13" => Some("sha512"),
        // ECDSA
        "1.2.840.10045.4.1" => Some("sha1"),
        "1.2.840.10045.4.3.2" => Some("sha256"),
        "1.2.840.10045.4.3.3" => Some("sha384"),
        "1.2.840.10045.4.3.4" => Some("sha512"),
        _ => None,
    }
}

/// Canonical algorithm-family name (lower-case, RFC 5912 / IANA-style)
/// for a signature-algorithm OID. Used by the structured
/// `signature_algorithm_structured.algorithm` field so rule engines
/// can key on a stable short name without reparsing OIDs.
fn algorithm_family_of_sig_oid(oid_str: &str) -> &'static str {
    // PKCS#1 v1.5 + unparameterized RSA
    if matches!(
        oid_str,
        "1.2.840.113549.1.1.5"
            | "1.2.840.113549.1.1.11"
            | "1.2.840.113549.1.1.12"
            | "1.2.840.113549.1.1.13"
    ) {
        return "rsa";
    }
    if oid_str == "1.2.840.113549.1.1.10" {
        return "rsa_pss";
    }
    if matches!(
        oid_str,
        "1.2.840.10045.4.1" | "1.2.840.10045.4.3.2" | "1.2.840.10045.4.3.3" | "1.2.840.10045.4.3.4"
    ) {
        return "ecdsa";
    }
    if oid_str == "1.3.101.112" {
        return "ed25519";
    }
    if oid_str == "1.3.101.113" {
        return "ed448";
    }
    // PQC — return the family-specific FIPS name. Uses the same
    // table as the human-readable resolver so naming stays in sync.
    if let Some(name) = pqc_oid_map().get(oid_str) {
        // Translate the FIPS-style name to a canonical snake-case
        // identifier: "ML-DSA-65" → "ml_dsa_65",
        // "SLH-DSA-SHA2-128s" → "slh_dsa_sha2_128s".
        return match *name {
            "ML-DSA-44" => "ml_dsa_44",
            "ML-DSA-65" => "ml_dsa_65",
            "ML-DSA-87" => "ml_dsa_87",
            "SLH-DSA-SHA2-128s" => "slh_dsa_sha2_128s",
            "SLH-DSA-SHA2-128f" => "slh_dsa_sha2_128f",
            "SLH-DSA-SHA2-192s" => "slh_dsa_sha2_192s",
            "SLH-DSA-SHA2-192f" => "slh_dsa_sha2_192f",
            "SLH-DSA-SHA2-256s" => "slh_dsa_sha2_256s",
            "SLH-DSA-SHA2-256f" => "slh_dsa_sha2_256f",
            "SLH-DSA-SHAKE-128s" => "slh_dsa_shake_128s",
            "SLH-DSA-SHAKE-128f" => "slh_dsa_shake_128f",
            "SLH-DSA-SHAKE-192s" => "slh_dsa_shake_192s",
            "SLH-DSA-SHAKE-192f" => "slh_dsa_shake_192f",
            "SLH-DSA-SHAKE-256s" => "slh_dsa_shake_256s",
            "SLH-DSA-SHAKE-256f" => "slh_dsa_shake_256f",
            _ => "unknown",
        };
    }
    "unknown"
}

/// Structured decomposition of an X.509 signature-algorithm
/// identifier, independent of the human-readable name string and the
/// raw OID. Lets rule engines key on `(hash, algorithm)` pairs
/// without parsing OIDs themselves.
pub fn signature_algorithm_structured(
    oid: &Oid,
    params_der: Option<&[u8]>,
) -> crate::model::scan_result::SignatureAlgorithmStructured {
    let oid_str = oid.to_id_string();
    let algorithm = algorithm_family_of_sig_oid(&oid_str).to_string();

    // RSA-PSS — hash lives inside the parameters SEQUENCE, not in the
    // outer OID. Parse the parameters DER if available; default to
    // SHA-1 per RFC 4055 §3.1 when absent (the spec's default).
    if oid_str == "1.2.840.113549.1.1.10" {
        let (hash_name, params_summary) = parse_rsa_pss_params(params_der);
        return crate::model::scan_result::SignatureAlgorithmStructured {
            hash: Some(hash_name.to_string()),
            algorithm,
            parameters: params_summary,
        };
    }

    let hash = hash_of_sig_oid(&oid_str).map(|s| s.to_string());
    crate::model::scan_result::SignatureAlgorithmStructured {
        hash,
        algorithm,
        parameters: None,
    }
}

/// Best-effort RSA-PSS parameter parser. Walks the outer SEQUENCE
/// looking for the `hashAlgorithm` context-tag `[0]`, extracts the
/// inner OID, and maps to a canonical hash name. Returns
/// `(hash_name, parameter_summary)`. Summary is a short
/// human-readable string rule engines can log; the definitive data
/// is `hash`.
///
/// Not a full parser — if the DER is malformed or a context tag is
/// missing, falls back to the RFC 4055 §3.1 default of SHA-1.
fn parse_rsa_pss_params(params_der: Option<&[u8]>) -> (&'static str, Option<String>) {
    let Some(der) = params_der else {
        return ("sha1", Some("rfc4055_defaults".to_string()));
    };
    // RSASSA-PSS-params ::= SEQUENCE {
    //   hashAlgorithm      [0] HashAlgorithm       DEFAULT sha1,
    //   maskGenAlgorithm   [1] MaskGenAlgorithm    DEFAULT mgf1SHA1,
    //   saltLength         [2] INTEGER             DEFAULT 20,
    //   trailerField       [3] TrailerField        DEFAULT trailerFieldBC
    // }
    // Walk the SEQUENCE body looking for `[0]` (0xA0) and extract the
    // inner AlgorithmIdentifier's OID. Anything more is structured
    // parsing we don't need for the observation surface.
    if der.len() < 2 || der[0] != 0x30 {
        return ("sha1", Some("rfc4055_defaults".to_string()));
    }
    let (body, _) = match der_body(der) {
        Some(b) => b,
        None => return ("sha1", Some("rfc4055_defaults".to_string())),
    };
    // Look for context-tag [0].
    let mut p = 0usize;
    while p + 2 <= body.len() {
        let tag = body[p];
        let (elem_body, total) = match der_body(&body[p..]) {
            Some(b) => b,
            None => break,
        };
        if tag == 0xA0 {
            // Inner AlgorithmIdentifier: SEQUENCE { OID, params? }
            if let Some((inner, _)) = der_body(elem_body) {
                if !inner.is_empty() && inner[0] == 0x06 {
                    if let Some((oid_bytes, _)) = der_body(inner) {
                        if let Ok((_, oid)) = der_parser::der::parse_der_oid(&[
                            &[0x06, oid_bytes.len() as u8][..],
                            oid_bytes,
                        ].concat()) {
                            let oid_str = oid
                                .as_oid()
                                .map(|o| o.to_id_string())
                                .unwrap_or_default();
                            let name = match oid_str.as_str() {
                                "2.16.840.1.101.3.4.2.1" => "sha256",
                                "2.16.840.1.101.3.4.2.2" => "sha384",
                                "2.16.840.1.101.3.4.2.3" => "sha512",
                                "1.3.14.3.2.26" => "sha1",
                                _ => "unknown",
                            };
                            return (name, Some(format!("mgf1-{}", name)));
                        }
                    }
                }
            }
            return ("sha1", Some("rfc4055_defaults".to_string()));
        }
        p += total;
    }
    ("sha1", Some("rfc4055_defaults".to_string()))
}

/// Extract the DER body (value bytes) and total element length (tag+len+value)
/// from a DER-encoded element. Returns `None` on malformed length
/// encodings. Handles short-form and long-form length octets.
fn der_body(data: &[u8]) -> Option<(&[u8], usize)> {
    if data.len() < 2 {
        return None;
    }
    let first_len_byte = data[1];
    if first_len_byte < 0x80 {
        let len = first_len_byte as usize;
        let total = 2 + len;
        if data.len() < total {
            return None;
        }
        Some((&data[2..total], total))
    } else {
        let n = (first_len_byte & 0x7f) as usize;
        if n == 0 || n > 4 || data.len() < 2 + n {
            return None;
        }
        let mut len: usize = 0;
        for i in 0..n {
            len = (len << 8) | (data[2 + i] as usize);
        }
        let total = 2 + n + len;
        if data.len() < total {
            return None;
        }
        Some((&data[2 + n..total], total))
    }
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
    fn pqc_family_splits_ml_dsa_from_slh_dsa() {
        // FIPS 204 codepoints — ML-DSA family
        assert_eq!(pqc_family_of_oid("2.16.840.1.101.3.4.3.17"), Some("ml_dsa"));
        assert_eq!(pqc_family_of_oid("2.16.840.1.101.3.4.3.18"), Some("ml_dsa"));
        assert_eq!(pqc_family_of_oid("2.16.840.1.101.3.4.3.19"), Some("ml_dsa"));
        // FIPS 205 codepoints — SLH-DSA family
        assert_eq!(pqc_family_of_oid("2.16.840.1.101.3.4.3.20"), Some("slh_dsa")); // SHA2-128s
        assert_eq!(pqc_family_of_oid("2.16.840.1.101.3.4.3.25"), Some("slh_dsa")); // SHA2-256f
        assert_eq!(pqc_family_of_oid("2.16.840.1.101.3.4.3.26"), Some("slh_dsa")); // SHAKE-128s
        assert_eq!(pqc_family_of_oid("2.16.840.1.101.3.4.3.31"), Some("slh_dsa")); // SHAKE-256f
    }

    #[test]
    fn pqc_family_none_for_classical_and_out_of_range() {
        assert_eq!(pqc_family_of_oid("1.2.840.113549.1.1.11"), None); // RSA
        assert_eq!(pqc_family_of_oid("1.2.840.10045.4.3.2"), None); // ECDSA
        // Arc with no subidentifier suffix.
        assert_eq!(pqc_family_of_oid("2.16.840.1.101.3.4.3"), None);
        // OID in the same arc but outside the FIPS-assigned range (e.g.
        // KEM OIDs on 2.16.840.1.101.3.4.4.*).
        assert_eq!(pqc_family_of_oid("2.16.840.1.101.3.4.3.16"), None);
        assert_eq!(pqc_family_of_oid("2.16.840.1.101.3.4.3.32"), None);
    }

    #[test]
    fn algorithm_family_of_sig_oid_maps_rsa_ecdsa_ed() {
        assert_eq!(algorithm_family_of_sig_oid("1.2.840.113549.1.1.11"), "rsa"); // sha256WithRSA
        assert_eq!(algorithm_family_of_sig_oid("1.2.840.113549.1.1.10"), "rsa_pss");
        assert_eq!(algorithm_family_of_sig_oid("1.2.840.10045.4.3.2"), "ecdsa");
        assert_eq!(algorithm_family_of_sig_oid("1.3.101.112"), "ed25519");
        assert_eq!(algorithm_family_of_sig_oid("1.3.101.113"), "ed448");
        assert_eq!(algorithm_family_of_sig_oid("2.16.840.1.101.3.4.3.18"), "ml_dsa_65");
        assert_eq!(algorithm_family_of_sig_oid("2.16.840.1.101.3.4.3.20"), "slh_dsa_sha2_128s");
        assert_eq!(algorithm_family_of_sig_oid("1.2.3.4.999"), "unknown");
    }

    #[test]
    fn hash_of_sig_oid_extracts_hash_family() {
        assert_eq!(hash_of_sig_oid("1.2.840.113549.1.1.11"), Some("sha256"));
        assert_eq!(hash_of_sig_oid("1.2.840.10045.4.3.3"), Some("sha384"));
        // Ed25519, ML-DSA, SLH-DSA hash internally — no hash family knowable from OID.
        assert_eq!(hash_of_sig_oid("1.3.101.112"), None);
        assert_eq!(hash_of_sig_oid("2.16.840.1.101.3.4.3.18"), None);
    }

    #[test]
    fn rsa_pss_params_default_to_rfc4055_sha1() {
        // Absent parameters → SHA-1 default per RFC 4055 §3.1.
        let (hash, summary) = parse_rsa_pss_params(None);
        assert_eq!(hash, "sha1");
        assert_eq!(summary.as_deref(), Some("rfc4055_defaults"));
    }

    #[test]
    fn rsa_pss_params_extracts_sha256_hash() {
        // RSASSA-PSS-params ::= SEQUENCE {
        //   hashAlgorithm [0] AlgorithmIdentifier DEFAULT sha1, ... }
        // Structured:
        //   30 0F                                 SEQUENCE (len 15)
        //     A0 0D                               [0] EXPLICIT (len 13)
        //       30 0B                             AlgorithmIdentifier (len 11)
        //         06 09 60 86 48 01 65 03 04 02 01  OID 2.16.840.1.101.3.4.2.1 (sha256)
        let der = [
            0x30, 0x0F, 0xA0, 0x0D, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
            0x04, 0x02, 0x01,
        ];
        let (hash, summary) = parse_rsa_pss_params(Some(&der));
        assert_eq!(hash, "sha256");
        assert_eq!(summary.as_deref(), Some("mgf1-sha256"));
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
