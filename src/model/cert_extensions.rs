//! X.509 v3 certificate extension observations.
//!
//! Parsed extension fields attached to each cert in the chain under
//! `tls.certificates.chain[].extensions`. All fields optional; absent
//! fields mean either (a) the cert is v1 with no extensions section
//! or (b) this specific extension wasn't present on the cert.
//!
//! Population is driven by
//! [`crate::scanner::cert::extract_extensions`], which reads
//! x509-parser's `ParsedExtension` enum and the raw extension bytes
//! (for extensions x509-parser doesn't have a dedicated variant for,
//! like the TLS Feature / Must-Staple extension).
//!
//! See `OBSERVATION_EXPANSION_REQUIREMENTS.md` §2.1 for the
//! per-field semantic contract.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Aggregate of parsed X.509 v3 extensions for a single certificate.
///
/// Always present on a `CertificateFacts` — serializes to `{}` when
/// every sub-field is absent. A v1 cert or a cert with no
/// recognized extensions lands as `{}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CertExtensions {
    /// RFC 5280 §4.2.1.9 — Basic Constraints (OID 2.5.29.19).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basic_constraints: Option<BasicConstraints>,

    /// RFC 5280 §4.2.1.3 — Key Usage (OID 2.5.29.15).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_usage: Option<KeyUsage>,

    /// RFC 5280 §4.2.1.12 — Extended Key Usage (OID 2.5.29.37).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extended_key_usage: Option<ExtendedKeyUsage>,

    /// RFC 5280 §4.2.1.1 — Authority Key Identifier (OID 2.5.29.35).
    /// Lower-case hex of the `keyIdentifier` bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_key_identifier: Option<String>,

    /// RFC 5280 §4.2.1.2 — Subject Key Identifier (OID 2.5.29.14).
    /// Lower-case hex of the `keyIdentifier` bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_key_identifier: Option<String>,

    /// RFC 5280 §4.2.2.1 — Authority Information Access
    /// (OID 1.3.6.1.5.5.7.1.1). OCSP responder URLs + CA issuer URLs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_information_access: Option<AuthorityInformationAccess>,

    /// RFC 5280 §4.2.1.13 — CRL Distribution Points
    /// (OID 2.5.29.31). Only `fullName` URIs are extracted; RDN-style
    /// distribution-point names are ignored (rare in Web PKI).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crl_distribution_points: Option<CrlDistributionPoints>,

    /// RFC 5280 §4.2.1.10 — Name Constraints (OID 2.5.29.30).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_constraints: Option<NameConstraints>,

    /// RFC 5280 §4.2.1.4 — Certificate Policies (OID 2.5.29.32).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_policies: Option<CertificatePolicies>,

    /// RFC 7633 — TLS Feature / Must-Staple
    /// (OID 1.3.6.1.5.5.7.1.24). `true` iff the extension is present
    /// AND its feature list contains integer 5 (status_request).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub must_staple: Option<bool>,

    /// RFC 6962 — Signed Certificate Timestamps delivered via the
    /// x509 extension OID 1.3.6.1.4.1.11129.2.4.2. Per-SCT detail.
    /// Note: the `CertificateFacts.embedded_scts` count is dual-emitted
    /// for one release cycle so consumers have time to migrate to
    /// `scts.len()`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub scts: Vec<SctDetail>,
}

/// Basic Constraints — CA flag + optional path-length constraint.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BasicConstraints {
    pub ca: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_len_constraint: Option<u32>,
}

/// Key Usage — canonical RFC 5280 §4.2.1.3 names that are set.
///
/// Values are snake_case RFC 5280 names: `digital_signature`,
/// `content_commitment` (a.k.a. non_repudiation), `key_encipherment`,
/// `data_encipherment`, `key_agreement`, `key_cert_sign`, `crl_sign`,
/// `encipher_only`, `decipher_only`. Only set bits appear.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyUsage {
    pub bits: Vec<String>,
}

/// Extended Key Usage — purpose OIDs the cert's key is intended for.
///
/// Commonly-seen purposes are emitted as canonical snake_case names
/// (`server_auth`, `client_auth`, `code_signing`, `email_protection`,
/// `time_stamping`, `ocsp_signing`, `any`). Unknown OIDs are emitted
/// as their dotted-decimal string.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtendedKeyUsage {
    pub oids: Vec<String>,
}

/// Authority Information Access — OCSP + CA Issuer URLs from the
/// `accessDescriptions` sequence. Only `URI`-typed `accessLocation`
/// entries are extracted.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthorityInformationAccess {
    pub ocsp: Vec<String>,
    pub ca_issuers: Vec<String>,
}

/// CRL Distribution Points — `fullName` URI entries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CrlDistributionPoints {
    pub urls: Vec<String>,
}

/// Name Constraints — permitted / excluded subtree names. Each
/// subtree is rendered as a string via the same general-name
/// stringifier used for CRL DP + AIA URLs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NameConstraints {
    pub permitted_subtrees: Vec<String>,
    pub excluded_subtrees: Vec<String>,
}

/// Certificate Policies — policy OIDs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CertificatePolicies {
    pub oids: Vec<String>,
}

/// A single Signed Certificate Timestamp parsed out of the cert's
/// embedded SCT list (RFC 6962 §3.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SctDetail {
    /// SHA-256 of the CT log's public key, lower-case hex (64 chars).
    pub log_id: String,
    /// Timestamp asserted by the log.
    pub timestamp: DateTime<Utc>,
    /// TLS HashAlgorithm name (`"sha256"`, `"sha384"`, etc.).
    pub signature_hash_algorithm: String,
    /// TLS SignatureAlgorithm name (`"rsa"`, `"ecdsa"`, etc.).
    pub signature_algorithm: String,
    /// Raw signature bytes, lower-case hex. Not validated by kemist.
    pub signature_hex: String,
}
