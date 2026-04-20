//! X.509 v3 certificate extension observations.
//!
//! Parsed extension fields attached to each cert in the chain under
//! `tls.certificates.chain[].extensions`. All fields optional; absent
//! fields mean either (a) the cert is v1 with no extensions section,
//! (b) this specific extension wasn't present, or (c) — before the
//! relevant extractor lands — the scanner hadn't started parsing
//! that extension yet.
//!
//! Scope of this file (step A1 of the observation expansion work):
//! **struct definitions only**. The outer [`CertExtensions`] struct
//! always serializes (an empty `{}` when no sub-fields are
//! populated). Inner types are empty stubs here; per-extension
//! parsers and concrete field sets land in steps A2–A5.
//!
//! See `OBSERVATION_EXPANSION_REQUIREMENTS.md` §2.1 for the
//! per-field contract each inner type will carry once populated.

use serde::{Deserialize, Serialize};

/// Aggregate of parsed X.509 v3 extensions for a single certificate.
///
/// Always present on a `CertificateFacts` — serializes to `{}` when
/// no sub-fields are populated. Every sub-field is optional, so a
/// v1 cert (no extensions section at all) serializes as `{}` as
/// well. Consumers treat missing sub-fields as "not present on this
/// certificate," not "scanner failed to parse."
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CertExtensions {
    /// RFC 5280 §4.2.1.9 — Basic Constraints (OID 2.5.29.19).
    /// Identifies CAs and their path-length constraint. Populated
    /// in step A2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basic_constraints: Option<BasicConstraints>,

    /// RFC 5280 §4.2.1.3 — Key Usage (OID 2.5.29.15). Which
    /// cryptographic operations the cert's key is allowed to
    /// perform. Populated in step A2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_usage: Option<KeyUsage>,

    /// RFC 5280 §4.2.1.12 — Extended Key Usage (OID 2.5.29.37).
    /// Purposes (OIDs) the cert's key is intended for, e.g.
    /// server_auth, client_auth. Populated in step A2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extended_key_usage: Option<ExtendedKeyUsage>,

    /// RFC 5280 §4.2.1.1 — Authority Key Identifier (OID 2.5.29.35).
    /// Hex-encoded keyIdentifier that names the issuer's key.
    /// Populated in step A3.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_key_identifier: Option<String>,

    /// RFC 5280 §4.2.1.2 — Subject Key Identifier (OID 2.5.29.14).
    /// Hex-encoded keyIdentifier for this cert's own key.
    /// Populated in step A3.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_key_identifier: Option<String>,

    /// RFC 5280 §4.2.2.1 — Authority Information Access (OID
    /// 1.3.6.1.5.5.7.1.1). OCSP responder URLs + CA issuer URLs.
    /// Populated in step A3.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_information_access: Option<AuthorityInformationAccess>,

    /// RFC 5280 §4.2.1.13 — CRL Distribution Points (OID
    /// 2.5.29.31). Distribution-point URLs. Populated in step A3.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crl_distribution_points: Option<CrlDistributionPoints>,

    /// RFC 5280 §4.2.1.10 — Name Constraints (OID 2.5.29.30).
    /// Permitted / excluded subtree restrictions on subject names.
    /// Populated in step A4.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_constraints: Option<NameConstraints>,

    /// RFC 5280 §4.2.1.4 — Certificate Policies (OID 2.5.29.32).
    /// Policy OIDs the cert was issued under. Populated in step
    /// A4.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_policies: Option<CertificatePolicies>,

    /// RFC 7633 — TLS Feature extension (OID 1.3.6.1.5.5.7.1.24),
    /// a.k.a. Must-Staple. True when the extension is present AND
    /// lists feature 5 (status_request). Populated in step A4.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub must_staple: Option<bool>,

    /// RFC 6962 — Signed Certificate Timestamps delivered via the
    /// x509 extension OID 1.3.6.1.4.1.11129.2.4.2. Per-SCT detail
    /// (log_id, timestamp, signature). Populated in step A5; until
    /// then the existing `embedded_scts` count on
    /// `CertificateFacts` carries the information.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub scts: Vec<SctDetail>,
}

// --- Inner types. A1 keeps every inner type as an empty stub that
// derives Serialize so `Option<Inner>` compiles in CertExtensions.
// Real fields land per the referenced step. `#[allow(dead_code)]`
// is tolerated here because these types are referenced by the
// outer struct but never constructed until their extractor lands.

#[allow(dead_code)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BasicConstraints {}

#[allow(dead_code)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyUsage {}

#[allow(dead_code)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtendedKeyUsage {}

#[allow(dead_code)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthorityInformationAccess {}

#[allow(dead_code)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CrlDistributionPoints {}

#[allow(dead_code)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NameConstraints {}

#[allow(dead_code)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CertificatePolicies {}

#[allow(dead_code)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SctDetail {}
