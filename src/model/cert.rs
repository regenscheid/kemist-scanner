use chrono::{DateTime, Utc};
use der_parser::oid::Oid;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use crate::model::cert_extensions::CertExtensions;

/// Convert ASN1Time to chrono::DateTime<Utc>
fn offset_to_chrono(asn1_time: x509_parser::time::ASN1Time) -> DateTime<Utc> {
    let offset_dt = asn1_time.to_datetime();
    match DateTime::from_timestamp(offset_dt.unix_timestamp(), 0) {
        Some(dt) => dt,
        None => Utc::now(), // Fallback to current time if conversion fails
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    /// Human-readable algorithm (e.g. `"sha256WithRSAEncryption"`,
    /// `"ML-DSA-65"`). Falls back to the raw OID string for unknowns.
    pub signature_algorithm: String,
    /// Raw signature algorithm OID string (e.g. `"1.2.840.113549.1.1.11"`).
    /// Downstream rule engines key off this — never a human-friendly name.
    pub signature_algorithm_oid: String,
    /// Structured decomposition of the signature algorithm — hash
    /// family + algorithm family + RSA-PSS parameters. Flows into
    /// `certificates.*.signature_algorithm_structured`.
    pub signature_algorithm_structured:
        crate::model::scan_result::SignatureAlgorithmStructured,
    /// PQC family classification — `"ml_dsa"` (FIPS 204), `"slh_dsa"`
    /// (FIPS 205), `"composite"` (IETF LAMPS drafts), or `None` for
    /// classical signatures.
    pub pqc_signature_family: Option<String>,
    pub public_key_algorithm: String,
    pub public_key_size: usize,
    /// RSA public exponent — populated only for RSA keys. See
    /// [`crate::model::scan_result::PublicKey::rsa_exponent`].
    pub rsa_exponent: Option<u64>,
    pub ecc_curve_name: Option<String>,
    /// RFC 5480 named-curve OID as dotted decimal (e.g.
    /// `"1.2.840.10045.3.1.7"` for secp256r1). Separate from
    /// `ecc_curve_name` so rule engines can key on a raw OID
    /// identifier independent of the human-readable name.
    pub ecc_curve_oid: Option<String>,
    pub ecc_key_strength: Option<u16>,
    pub san: Vec<String>,
    pub is_self_signed: bool,
    pub is_expired: bool,
    pub days_until_expiry: i64,
    pub fingerprint_sha256: String,
    pub fingerprint_sha1: String,
    /// Count of RFC 6962 Signed Certificate Timestamps embedded in the cert
    /// via extension OID 1.3.6.1.4.1.11129.2.4.2. Presence only —
    /// signatures are not validated.
    pub embedded_scts: u32,
    /// Parsed X.509 v3 extension observations. See
    /// [`crate::model::cert_extensions`].
    #[serde(default)]
    pub extensions: CertExtensions,
}

impl CertificateInfo {
    pub fn from_der(der_data: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let (_, cert) = X509Certificate::from_der(der_data)?;

        let subject = cert.subject().to_string();
        let issuer = cert.issuer().to_string();
        let serial = cert.raw_serial_as_string();

        let not_before = offset_to_chrono(cert.validity().not_before);
        let not_after = offset_to_chrono(cert.validity().not_after);

        let sig_oid_str = cert.signature_algorithm.algorithm.to_id_string();
        let sig_alg =
            crate::scanner::cert::resolve_signature_algorithm(&cert.signature_algorithm.algorithm);
        let pqc_signature_family =
            crate::scanner::cert::pqc_family_of_oid(&sig_oid_str).map(|s| s.to_string());
        // Structured decomposition — hash + algorithm family +
        // RSA-PSS parameters. The parameters DER bytes live on the
        // outer AlgorithmIdentifier.
        let sig_params_der = cert
            .signature_algorithm
            .parameters
            .as_ref()
            .map(|p| p.as_bytes());
        let signature_algorithm_structured =
            crate::scanner::cert::signature_algorithm_structured(
                &cert.signature_algorithm.algorithm,
                sig_params_der,
            );
        let is_self_signed = cert.subject() == cert.issuer();

        let now = Utc::now();
        let is_expired = now > not_after;
        let days_until_expiry = (not_after - now).num_days();

        // Extract public key info
        let pki = cert.public_key();
        let alg_name = oid_to_algorithm_name(&pki.algorithm.algorithm);
        let key_size = estimate_key_size(pki);
        let (pub_key_alg, pub_key_size) = (alg_name, key_size);
        let rsa_exponent = extract_rsa_exponent(pki);

        // Extract ECC curve information
        let (ecc_curve_name, ecc_curve_oid, ecc_key_strength) = extract_ecc_info(pki);

        // Extract SANs
        let san = extract_san_names(&cert);

        // Calculate fingerprints
        let mut hasher_sha256 = Sha256::new();
        hasher_sha256.update(der_data);
        let fingerprint_sha256 = hex::encode(hasher_sha256.finalize());

        let mut hasher_sha1 = Sha1::new();
        hasher_sha1.update(der_data);
        let fingerprint_sha1 = hex::encode(hasher_sha1.finalize());

        let embedded_scts = crate::scanner::cert::count_embedded_scts(der_data);
        let extensions = crate::scanner::cert::extract_extensions(&cert);

        Ok(CertificateInfo {
            subject,
            issuer,
            serial_number: serial,
            not_before,
            not_after,
            signature_algorithm: sig_alg,
            signature_algorithm_oid: sig_oid_str,
            signature_algorithm_structured,
            pqc_signature_family,
            public_key_algorithm: pub_key_alg,
            public_key_size: pub_key_size,
            rsa_exponent,
            ecc_curve_name,
            ecc_curve_oid,
            ecc_key_strength,
            san,
            is_self_signed,
            is_expired,
            days_until_expiry,
            fingerprint_sha256,
            fingerprint_sha1,
            embedded_scts,
            extensions,
        })
    }

    pub fn factual_notes(&self) -> Vec<String> {
        let mut notes = Vec::new();

        if self.is_expired {
            notes.push("Certificate past notAfter".to_string());
        } else if self.days_until_expiry < 30 {
            notes.push(format!(
                "Certificate notAfter in {} days",
                self.days_until_expiry
            ));
        }

        if self.is_self_signed {
            notes.push("Self-signed (subject == issuer)".to_string());
        }

        notes
    }
}

fn oid_to_algorithm_name(oid: &Oid) -> String {
    let oid_str = oid.to_id_string();
    match oid_str.as_str() {
        "1.2.840.113549.1.1.5" => "SHA1withRSA",
        "1.2.840.113549.1.1.11" => "SHA256withRSA",
        "1.2.840.113549.1.1.12" => "SHA384withRSA",
        "1.2.840.113549.1.1.13" => "SHA512withRSA",
        "1.2.840.10045.4.3.2" => "SHA256withECDSA",
        "1.2.840.10045.4.3.3" => "SHA384withECDSA",
        "1.3.101.112" => "Ed25519",
        "1.2.840.113549.1.1.1" => "RSA",
        "1.2.840.10045.2.1" => "EC",
        _ => &oid_str,
    }
    .to_string()
}

/// Extract the RSA public exponent `e` from a SubjectPublicKeyInfo.
/// Returns `None` for non-RSA keys or when the exponent overflows
/// `u64` (which would never happen with real-world certificates —
/// `e = 65537` is the universal default; `e = 3` / `e = 17` are the
/// only other values observed).
fn extract_rsa_exponent(pki: &SubjectPublicKeyInfo) -> Option<u64> {
    let Ok(parsed) = pki.parsed() else {
        return None;
    };
    let x509_parser::public_key::PublicKey::RSA(rsa) = parsed else {
        return None;
    };
    // x509-parser exposes `exponent` as a byte slice of the DER
    // INTEGER's magnitude (big-endian, sign-stripped). Convert up to
    // 8 bytes into a u64; anything longer is an exotic case we
    // simply don't capture numerically.
    let bytes = rsa.exponent;
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    let mut out: u64 = 0;
    for &b in bytes {
        out = (out << 8) | b as u64;
    }
    Some(out)
}

fn estimate_key_size(pki: &SubjectPublicKeyInfo) -> usize {
    // Use x509-parser's structured DER decoder — the SubjectPublicKeyInfo
    // BIT STRING contents are an ASN.1 RSAPublicKey / ECPoint / etc.
    // Earlier code bucketed by raw byte length, which was wrong: a
    // 2048-bit RSA key has a SubjectPublicKey `data.len()` of ~270
    // bytes (256-byte modulus + 3-byte exponent + ~10 bytes of DER
    // overhead), which fell into the previous 200-300 band and got
    // reported as 1024.
    if let Ok(key) = pki.parsed() {
        let bits = key.key_size();
        if bits > 0 {
            return bits;
        }
    }
    // Last-resort fallback: length of the raw bit-string contents. Only
    // reached for unrecognized key algorithms — known RSA / EC / DSA all
    // flow through `parsed()` above.
    pki.subject_public_key.data.len() * 8
}

fn extract_san_names(cert: &X509Certificate) -> Vec<String> {
    let mut names = Vec::new();

    // Try to find Subject Alternative Name extension
    for ext in cert.extensions() {
        if ext.oid.to_id_string() == "2.5.29.17" {
            // SAN OID
            // Parse the extension value as SubjectAlternativeName
            use x509_parser::extensions::ParsedExtension;

            if let ParsedExtension::SubjectAlternativeName(san_ext) = ext.parsed_extension() {
                for general_name in &san_ext.general_names {
                    use x509_parser::extensions::GeneralName;
                    match general_name {
                        GeneralName::DNSName(dns) => {
                            names.push(dns.to_string());
                        }
                        GeneralName::IPAddress(ip) => {
                            // Convert IP bytes to string
                            match ip.len() {
                                4 => {
                                    // IPv4
                                    let addr = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
                                    names.push(addr);
                                }
                                16 => {
                                    // IPv6
                                    let mut segments = Vec::new();
                                    for i in (0..16).step_by(2) {
                                        segments.push(format!("{:x}{:x}", ip[i], ip[i + 1]));
                                    }
                                    names.push(segments.join(":"));
                                }
                                _ => {
                                    names.push("Invalid IP address".to_string());
                                }
                            }
                        }
                        GeneralName::RFC822Name(email) => {
                            names.push(format!("Email: {}", email));
                        }
                        GeneralName::URI(uri) => {
                            names.push(format!("URI: {}", uri));
                        }
                        _ => {
                            // Other types not commonly used in web certificates
                            continue;
                        }
                    }
                }
            }
        }
    }

    // If no SANs found, return empty vector (not an error)
    names
}

/// Extract ECC curve information from the SubjectPublicKeyInfo.
///
/// Returns `(curve_name, curve_oid, curve_strength_bits)`.
///
/// The named curve lives in `AlgorithmIdentifier.parameters` per
/// RFC 5480 §2.1.1, not in the key-bytes length. Previous versions
/// of this function bucketed by `subject_public_key.data.len()` —
/// that worked for the three NIST P-curves that ship on ~95% of web
/// certificates today (65 / 97 / 133 bytes for P-256 / 384 / 521)
/// but **false-matched** secp256k1 (65 bytes) and brainpoolP256r1
/// (65 bytes) as P-256. The OID parse fixes that ambiguity.
///
/// Ed25519 and Ed448 use distinct *algorithm* OIDs (`1.3.101.112` /
/// `1.3.101.113`) rather than the EC public-key OID
/// (`1.2.840.10045.2.1`) with curve parameters, so they're matched
/// on the algorithm field, not via `.parameters`.
fn extract_ecc_info(pki: &SubjectPublicKeyInfo) -> (Option<String>, Option<String>, Option<u16>) {
    let alg_oid = pki.algorithm.algorithm.to_id_string();

    // EdDSA first — not "EC" in the RFC 5480 sense; no curve-OID parameters.
    if let Some((name, strength)) = eddsa_curve_from_alg_oid(&alg_oid) {
        return (Some(name.to_string()), Some(alg_oid), Some(strength));
    }

    if alg_oid != "1.2.840.10045.2.1" {
        // Not EC at all (likely RSA, DSA, PQC, etc.).
        return (None, None, None);
    }

    // EC — decode the named-curve OID from algorithm.parameters.
    let curve_oid = pki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok())
        .map(|o| o.to_id_string());

    match curve_oid.as_deref().and_then(ec_curve_from_oid) {
        Some((name, strength)) => (Some(name.to_string()), curve_oid, Some(strength)),
        None => {
            // Unknown / missing curve OID — fall back to byte-length hint
            // for strength but label the curve as unknown so rule engines
            // don't misread it as a known NIST curve. Raw OID (if any)
            // stays queryable via the returned `curve_oid`.
            let len = pki.subject_public_key.data.len();
            let approx = match len {
                65 => 256,
                97 => 384,
                133 => 521,
                _ => (len as u16) * 4,
            };
            (Some("unknown_ec_curve".to_string()), curve_oid, Some(approx))
        }
    }
}

/// Map an EdDSA *algorithm* OID (RFC 8410) to its curve name + security
/// strength. EdDSA doesn't use `AlgorithmIdentifier.parameters` the way
/// ECDSA does; the curve is encoded via the algorithm OID itself.
fn eddsa_curve_from_alg_oid(alg_oid: &str) -> Option<(&'static str, u16)> {
    match alg_oid {
        "1.3.101.112" => Some(("Ed25519", 255)),
        "1.3.101.113" => Some(("Ed448", 448)),
        _ => None,
    }
}

/// Map an RFC 5480 named-curve OID to its canonical curve name + the
/// curve's bit-strength (order of the base point ≈ bits of security ×
/// 2). Covers NIST P-curves, Koblitz secp256k1, brainpool twisted
/// curves, and the legacy prime192v* aliases still seen in the wild.
fn ec_curve_from_oid(oid: &str) -> Option<(&'static str, u16)> {
    Some(match oid {
        "1.2.840.10045.3.1.7" => ("secp256r1", 256),
        "1.3.132.0.34" => ("secp384r1", 384),
        "1.3.132.0.35" => ("secp521r1", 521),
        "1.3.132.0.10" => ("secp256k1", 256),
        "1.3.132.0.33" => ("secp224r1", 224),
        "1.3.132.0.30" => ("secp192r1", 192),
        "1.3.36.3.3.2.8.1.1.7" => ("brainpoolP256r1", 256),
        "1.3.36.3.3.2.8.1.1.11" => ("brainpoolP384r1", 384),
        "1.3.36.3.3.2.8.1.1.13" => ("brainpoolP512r1", 512),
        "1.2.840.10045.3.1.1" => ("secp192r1", 192), // prime192v1 alias
        "1.2.840.10045.3.1.2" => ("prime192v2", 192),
        "1.2.840.10045.3.1.3" => ("prime192v3", 192),
        _ => return None,
    })
}

#[cfg(test)]
mod ecc_tests {
    use super::{ec_curve_from_oid, eddsa_curve_from_alg_oid};

    #[test]
    fn oid_to_curve_covers_nist_p_curves() {
        assert_eq!(
            ec_curve_from_oid("1.2.840.10045.3.1.7"),
            Some(("secp256r1", 256))
        );
        assert_eq!(
            ec_curve_from_oid("1.3.132.0.34"),
            Some(("secp384r1", 384))
        );
        assert_eq!(
            ec_curve_from_oid("1.3.132.0.35"),
            Some(("secp521r1", 521))
        );
    }

    #[test]
    fn oid_to_curve_distinguishes_secp256k1_from_p256() {
        // Both have 65-byte uncompressed points; without OID parsing
        // the old byte-length heuristic mis-labeled secp256k1 as P-256.
        let p256 = ec_curve_from_oid("1.2.840.10045.3.1.7").unwrap();
        let k1 = ec_curve_from_oid("1.3.132.0.10").unwrap();
        assert_eq!(p256.0, "secp256r1");
        assert_eq!(k1.0, "secp256k1");
        assert_ne!(p256.0, k1.0);
    }

    #[test]
    fn oid_to_curve_covers_brainpool() {
        assert_eq!(
            ec_curve_from_oid("1.3.36.3.3.2.8.1.1.7"),
            Some(("brainpoolP256r1", 256))
        );
        assert_eq!(
            ec_curve_from_oid("1.3.36.3.3.2.8.1.1.11"),
            Some(("brainpoolP384r1", 384))
        );
        assert_eq!(
            ec_curve_from_oid("1.3.36.3.3.2.8.1.1.13"),
            Some(("brainpoolP512r1", 512))
        );
    }

    #[test]
    fn oid_to_curve_covers_short_secp_variants() {
        assert_eq!(
            ec_curve_from_oid("1.3.132.0.33"),
            Some(("secp224r1", 224))
        );
        assert_eq!(
            ec_curve_from_oid("1.3.132.0.30"),
            Some(("secp192r1", 192))
        );
    }

    #[test]
    fn unknown_oid_returns_none() {
        assert!(ec_curve_from_oid("1.2.3.4.5").is_none());
        assert!(ec_curve_from_oid("").is_none());
    }

    #[test]
    fn eddsa_alg_oids_map_to_curves() {
        assert_eq!(
            eddsa_curve_from_alg_oid("1.3.101.112"),
            Some(("Ed25519", 255))
        );
        assert_eq!(
            eddsa_curve_from_alg_oid("1.3.101.113"),
            Some(("Ed448", 448))
        );
        assert!(eddsa_curve_from_alg_oid("1.3.101.114").is_none());
    }
}

/// Parse certificate chain from TLS handshake
#[allow(dead_code)]
pub fn parse_certificate_chain(
    chain_data: &[u8],
) -> Result<Vec<CertificateInfo>, Box<dyn std::error::Error>> {
    let mut certificates = Vec::new();
    let mut data = chain_data;

    while !data.is_empty() {
        match X509Certificate::from_der(data) {
            Ok((remaining, _cert)) => {
                if let Ok(cert_info) =
                    CertificateInfo::from_der(&data[..data.len() - remaining.len()])
                {
                    certificates.push(cert_info);
                }
                data = remaining;
            }
            Err(_) => break,
        }
    }

    Ok(certificates)
}
