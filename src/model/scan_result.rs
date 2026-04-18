//! kemist output schema v1.
//!
//! See docs/OUTPUT_SCHEMA.md and schemas/output-v1.json for the formal contract.
//!
//! Envelope rule: probe-derived tri-state observations carry `{value, method, reason?}`.
//! Stable metadata (schema_version, target, fingerprints, IANA codepoints, etc.) is
//! emitted as plain scalars, never wrapped.

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::BTreeMap;

pub const SCHEMA_VERSION: &str = "1.0.0";

/// Top-level scan record. Every emitted JSON document is a `ScanResult`.
#[derive(Serialize, Debug, Clone)]
pub struct ScanResult {
    pub schema_version: String,
    pub scanner: Scanner,
    pub capabilities: Capabilities,
    pub scan: ScanMetadata,
    pub tls: Tls,
    pub certificates: Certificates,
    pub validation: Validation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<Http>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_handshakes: Option<serde_json::Value>,
    pub errors: Vec<ScanError>,
}

/// Identity of the tool that produced this record.
#[derive(Serialize, Debug, Clone)]
pub struct Scanner {
    pub name: String,
    pub version: String,
}

/// Runtime-derived state that lets downstream consumers interpret `not_probed` values.
#[derive(Serialize, Debug, Clone)]
pub struct Capabilities {
    pub enabled_features: Vec<String>,
    pub rustls_version: String,
    pub aws_lc_rs_version: String,
    pub native_tls_version: String,
    pub provider_cipher_suites: Vec<String>,
    pub provider_kx_groups: Vec<String>,
    pub config_paths: Vec<String>,
    pub probe_limitations: Vec<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct ScanMetadata {
    pub target: String,
    pub host: String,
    pub port: u16,
    pub sni_sent: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_ip: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub duration_ms: u64,
}

/// How a given observation was obtained. Stable enum — never add without a schema bump.
#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)] // variants consumed by later PRs (5, 6, 8, 9)
pub enum Method {
    /// Active wire probe was performed and the result reflects the server's response.
    Probe,
    /// Observation was not attempted — provider lacks support, feature disabled, etc.
    NotProbed,
    /// Observation does not apply in the current context (e.g. EMS on TLS 1.3).
    NotApplicable,
    /// Probe was attempted but failed (network, timeout, unexpected alert).
    Error,
    /// Value read directly from a successful rustls connection's state, not a dedicated probe.
    ConnectionState,
}

/// Generic `{value, method, reason?}` envelope for boolean probe-derived observations.
#[derive(Serialize, Debug, Clone)]
pub struct ObservationBool {
    pub value: Option<bool>,
    pub method: Method,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[allow(dead_code)] // some constructors consumed by later PRs
impl ObservationBool {
    pub fn probe(value: bool) -> Self {
        Self {
            value: Some(value),
            method: Method::Probe,
            reason: None,
        }
    }
    pub fn connection_state(value: bool) -> Self {
        Self {
            value: Some(value),
            method: Method::ConnectionState,
            reason: None,
        }
    }
    pub fn not_probed(reason: &str) -> Self {
        Self {
            value: None,
            method: Method::NotProbed,
            reason: Some(reason.into()),
        }
    }
    pub fn not_applicable(reason: &str) -> Self {
        Self {
            value: None,
            method: Method::NotApplicable,
            reason: Some(reason.into()),
        }
    }
    pub fn error(reason: &str) -> Self {
        Self {
            value: None,
            method: Method::Error,
            reason: Some(reason.into()),
        }
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct Tls {
    pub versions_offered: TlsVersionsOffered,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub negotiated: Option<TlsNegotiated>,
    pub cipher_suites: TlsCipherSuites,
    pub groups: BTreeMap<String, GroupObservation>,
    pub extensions: TlsExtensions,
    pub downgrade_signaling: DowngradeSignaling,
    pub sni_behavior: SniBehavior,
}

/// Per-version `{offered, method, reason?}` envelope. Field name differs from `value` per spec.
#[derive(Serialize, Debug, Clone)]
pub struct VersionOffered {
    pub offered: Option<bool>,
    pub method: Method,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[allow(dead_code)] // `error` constructor consumed by PR 3
impl VersionOffered {
    pub fn probe(offered: bool) -> Self {
        Self {
            offered: Some(offered),
            method: Method::Probe,
            reason: None,
        }
    }
    pub fn not_probed(reason: &str) -> Self {
        Self {
            offered: None,
            method: Method::NotProbed,
            reason: Some(reason.into()),
        }
    }
    pub fn error(reason: &str) -> Self {
        Self {
            offered: None,
            method: Method::Error,
            reason: Some(reason.into()),
        }
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct TlsVersionsOffered {
    pub ssl2: VersionOffered,
    pub ssl3: VersionOffered,
    pub tls1_0: VersionOffered,
    pub tls1_1: VersionOffered,
    pub tls1_2: VersionOffered,
    pub tls1_3: VersionOffered,
}

#[derive(Serialize, Debug, Clone)]
pub struct TlsNegotiated {
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_suite: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_scheme: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct CipherSuiteEntry {
    pub name: String,
    pub iana_code: String,
    pub method: Method,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct TlsCipherSuites {
    pub tls1_2: Vec<CipherSuiteEntry>,
    pub tls1_3: Vec<CipherSuiteEntry>,
    pub server_enforces_order: ObservationBool,
}

/// Per-group `{supported, method, reason?}` envelope. Field name differs from `value` per spec.
#[derive(Serialize, Debug, Clone)]
pub struct GroupObservation {
    pub supported: Option<bool>,
    pub method: Method,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[allow(dead_code)] // `probe` consumed by PR 8
impl GroupObservation {
    pub fn probe(supported: bool) -> Self {
        Self {
            supported: Some(supported),
            method: Method::Probe,
            reason: None,
        }
    }
    pub fn not_probed(reason: &str) -> Self {
        Self {
            supported: None,
            method: Method::NotProbed,
            reason: Some(reason.into()),
        }
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct TlsExtensions {
    pub ems: ObservationBool,
    pub secure_renegotiation: ObservationBool,
    pub ocsp_stapling: OcspStapling,
    pub sct: SctObservation,
    pub alpn_offered: Vec<String>,
    pub encrypt_then_mac: ObservationBool,
    pub heartbeat_present: ObservationBool,
    pub heartbeat_echoes_oversized_payload: ObservationBool,
    pub compression_offered: Vec<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct OcspStapling {
    pub stapled: Option<bool>,
    pub method: Method,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub response_length: u64,
}

#[derive(Serialize, Debug, Clone)]
pub struct SctObservation {
    pub delivery_paths: Vec<String>,
    pub count: u32,
}

#[derive(Serialize, Debug, Clone)]
pub struct DowngradeSignaling {
    pub fallback_scsv_accepted: ObservationBool,
}

#[derive(Serialize, Debug, Clone)]
pub struct SniBehavior {
    pub omitted_probe: Option<String>,
    pub method: Method,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct Certificates {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf: Option<CertificateFacts>,
    pub chain: Vec<CertificateFacts>,
    pub chain_length: usize,
}

#[derive(Serialize, Debug, Clone)]
pub struct CertificateFacts {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_cn: Option<String>,
    pub subject_dn: String,
    pub san: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_cn: Option<String>,
    pub issuer_dn: String,
    pub serial: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub validity_days: i64,
    pub signature_algorithm_oid: String,
    pub signature_algorithm_name: String,
    pub is_pqc_signature: bool,
    pub public_key: PublicKey,
    pub embedded_scts: u32,
    pub fingerprint_sha256: String,
    pub fingerprint_sha1: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct PublicKey {
    pub algorithm: String,
    pub size_bits: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub curve: Option<String>,
}

/// Trust-relevant observations, kept separate from X.509 facts so wrong-host and
/// untrusted-root cases produce distinguishable records.
#[derive(Serialize, Debug, Clone)]
pub struct Validation {
    pub chain_valid_to_webpki_roots: ObservationBool,
    pub name_matches_sni: ObservationBool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_error: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct Http {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hsts: Option<Hsts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preload_list_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_txt: Option<SecurityTxt>,
}

#[derive(Serialize, Debug, Clone)]
pub struct Hsts {
    pub header_present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_subdomains: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preload: Option<bool>,
}

#[derive(Serialize, Debug, Clone)]
pub struct SecurityTxt {
    pub present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

/// PR 3 will replace this with a typed `ScannerError` enum, but the serialized
/// shape `{category, context, timestamp}` is fixed at schema v1.
#[derive(Serialize, Debug, Clone)]
pub struct ScanError {
    pub category: String,
    pub context: String,
    pub timestamp: DateTime<Utc>,
}
