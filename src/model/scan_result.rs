//! kemist output schema v1.
//!
//! See docs/OUTPUT_SCHEMA.md and schemas/output-v1.json for the formal contract.
//!
//! Envelope rule: probe-derived tri-state observations carry `{value, method, reason?}`.
//! Stable metadata (schema_version, target, fingerprints, IANA codepoints, etc.) is
//! emitted as plain scalars, never wrapped.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub use crate::model::errors::ScannerError;

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
    pub errors: Vec<ScannerError>,
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
    /// Pinned OpenSSL version from `openssl-src = "=..."` when
    /// `legacy-probes` is compiled in, else `"not_shipped"`.
    pub openssl_version: String,
    /// Cipher suites the scanner probes at least once per scan — union
    /// across every backend present at build time. Per-suite entries in
    /// `tls.cipher_suites.*` carry a `provider` field identifying which
    /// backend actually ran each probe.
    pub probed_cipher_suites: Vec<String>,
    /// Named groups the scanner probes — union across every backend.
    pub probed_kx_groups: Vec<String>,
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
///
/// [`Default`] produces the canonical "not observed yet" shape —
/// `value: None`, `method: NotProbed`, no reason. Useful when
/// deriving `Default` on larger structs that contain `ObservationBool`
/// fields (e.g. [`Tls12Resumption`]).
#[derive(Serialize, Debug, Clone)]
pub struct ObservationBool {
    pub value: Option<bool>,
    pub method: Method,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Default for ObservationBool {
    fn default() -> Self {
        Self {
            value: None,
            method: Method::NotProbed,
            reason: None,
        }
    }
}

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
    /// Cipher-suite probes across TLS 1.0/1.1/1.2/1.3. Each entry is
    /// tagged with the `provider` that probed it (aws-lc-rs or openssl)
    /// so consumers that care about backend attribution can filter.
    pub cipher_suites: TlsCipherSuites,
    /// Key-exchange group probes partitioned by TLS version. FFDHE
    /// groups appear under both `tls1_2` and `tls1_3`; aws-lc-rs modern
    /// groups (X25519, ECDH, ML-KEM, hybrids) appear under `tls1_3`.
    pub groups: TlsGroups,
    pub extensions: TlsExtensions,
    pub downgrade_signaling: DowngradeSignaling,
    pub sni_behavior: SniBehavior,
    /// DH parameters captured from every completed DHE handshake,
    /// classified against RFC 7919 FFDHE primes.
    pub dh_parameters: Vec<DhParametersObservation>,
    /// Signature algorithm the server selected in each completed TLS 1.2
    /// ServerKeyExchange / TLS 1.3 CertificateVerify.
    pub server_key_exchange_signatures: Vec<SkeSigObservation>,
    /// Client-initiated renegotiation verdict.
    pub renegotiation_behavior: RenegotiationBehavior,
    /// Server's `CertificateRequest` contents (`None` when the server
    /// didn't request client auth, or the probe couldn't run).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_auth_request: Option<ClientAuthRequestEntry>,
    /// Session resumption observations — ticket issuance, lifetime
    /// hints, rotation, TLS 1.3 NewSessionTicket count, PSK resumption
    /// acceptance, 0-RTT acceptance. See
    /// [`crate::model::scan_result::SessionResumption`].
    pub session_resumption: SessionResumption,
    /// Active probe: handshake with constrained
    /// `signature_algorithms` offers and record what the server does.
    /// Four independent slots per RFC 8446 §4.2.3 / RFC 8017 sigalg
    /// families. See [`SignatureAlgorithmPolicyProbe`].
    pub signature_algorithm_policy_probe: SignatureAlgorithmPolicyProbe,
    /// Channel-binding material per RFC 9266 (tls-exporter) and
    /// RFC 5929 §4 (tls-server-end-point). Feeds SP 800-63B AAL3
    /// verifier-impersonation-resistance rules.
    pub channel_binding: ChannelBinding,
}

/// Per-constraint outcomes for the sig-alg policy probe.
#[derive(Serialize, Debug, Clone, Default)]
pub struct SignatureAlgorithmPolicyProbe {
    pub sha256_plus_only: ConstrainedProbeResult,
    pub ecdsa_only: ConstrainedProbeResult,
    pub rsa_pss_only: ConstrainedProbeResult,
    pub rsa_pkcs1_only: ConstrainedProbeResult,
    /// EdDSA-only constraint (Ed25519 + Ed448). A
    /// `handshake_complete` here means the server's cert chain is
    /// EdDSA-signed; `handshake_failure` is the common outcome for
    /// RSA/ECDSA-authenticated servers.
    pub eddsa_only: ConstrainedProbeResult,
}

/// Result of one constrained-sigalg handshake attempt.
#[derive(Serialize, Debug, Clone)]
pub struct ConstrainedProbeResult {
    /// Probed outcome. See [`SigalgOutcome`].
    pub outcome: SigalgOutcome,
    /// Signature algorithm the server selected when the handshake
    /// completed — canonical OpenSSL name (`"ecdsa_secp256r1_sha256"`,
    /// `"rsa_pss_rsae_sha256"`, …). `None` on non-completing outcomes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_sigalg: Option<String>,
    /// Alert category string when the server refused
    /// (`"tls_alert_handshake_failure"`, etc.). Same taxonomy as
    /// `errors[].category`. `None` when the handshake completed or
    /// the connection closed without an alert.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert: Option<String>,
    /// Method: `probe` when the attempt ran, `not_probed` when
    /// `--sigalg-probe-skip` opted out, `feature_disabled` under
    /// non-legacy-probes builds, `error` on setup failure.
    pub method: Method,
    /// Human-readable reason for non-probe outcomes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Default for ConstrainedProbeResult {
    fn default() -> Self {
        Self {
            outcome: SigalgOutcome::NotProbed,
            selected_sigalg: None,
            alert: None,
            method: Method::NotProbed,
            reason: None,
        }
    }
}

/// Classifier for a constrained-sigalg handshake attempt.
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SigalgOutcome {
    /// Handshake completed; the server picked a sigalg from our
    /// constrained list.
    HandshakeComplete,
    /// Server returned `handshake_failure` (alert 40) — the canonical
    /// response when it has no compatible cert/sigalg.
    HandshakeFailure,
    /// Peer closed TCP without sending an alert.
    ConnectionClosed,
    /// Server returned some other alert
    /// (`insufficient_security`, `internal_error`, etc.).
    OtherAlert,
    /// Probe didn't run for this constraint (CLI skip or feature
    /// disabled).
    NotProbed,
}

/// TLS 1.2 + TLS 1.3 session resumption observations.
#[derive(Serialize, Debug, Clone, Default)]
pub struct SessionResumption {
    pub tls1_2: Tls12Resumption,
    pub tls1_3: Tls13Resumption,
}

#[derive(Serialize, Debug, Clone, Default)]
pub struct Tls12Resumption {
    /// Did the server send a `NewSessionTicket` handshake message
    /// during the TLS 1.2 handshake?
    pub session_ticket_issued: ObservationBool,
    /// RFC 5077 ticket lifetime hint in seconds, if the server sent a
    /// ticket. Taken from `SSL_SESSION_get_timeout` (OpenSSL's closest
    /// proxy for the server-advertised lifetime).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticket_lifetime_hint_secs: Option<u32>,
    /// Did the server issue a (non-empty) session ID? On ticket-using
    /// servers this can still be true when the server echoes an ID
    /// for compatibility, or false when the server signals ticket-only
    /// resumption.
    pub session_id_issued: ObservationBool,
    /// Did the ticket bytes change between two successive handshakes
    /// with the same target? `true` = ticket rotation (forward
    /// secrecy friendlier); `false` = stable ticket (the server
    /// key that wraps the ticket is a standing secret).
    pub ticket_rotated_across_connections: ObservationBool,
}

#[derive(Serialize, Debug, Clone, Default)]
pub struct Tls13Resumption {
    /// Number of `NewSessionTicket` messages received after the TLS
    /// 1.3 handshake. RFC 8446 §4.6.1 lets servers send multiple;
    /// operators often configure 1 or 2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_session_ticket_count: Option<u32>,
    /// Per-ticket lifetime from `SSL_SESSION_get_timeout`. Empty
    /// when no tickets were observed.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ticket_lifetime_secs: Vec<u32>,
    /// Did a second handshake, using the saved session from the first,
    /// resume via PSK rather than a full handshake?
    /// (`SSL_session_reused` on the resumed connection.)
    pub psk_resumption_accepted: ObservationBool,
    /// Did the server accept 0-RTT / early_data on the resumed
    /// handshake? `NotProbed` until a future workstream wires
    /// `SSL_write_early_data`.
    pub early_data_accepted: ObservationBool,
}

/// Per-version `{offered, method, reason?}` envelope. Field name differs from `value` per spec.
#[derive(Serialize, Debug, Clone)]
pub struct VersionOffered {
    pub offered: Option<bool>,
    pub method: Method,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

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
    /// `Some(true)` = probed and negotiated; `Some(false)` = probed and
    /// rejected; `None` = probe didn't produce a definitive answer (see
    /// `method`/`reason`). Downstream consumers MUST distinguish `Some(false)`
    /// from `None` — absence of probe is not absence of support.
    pub supported: Option<bool>,
    pub method: Method,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// OpenSSL-style short name (e.g. `"AES128-SHA"`). Only present for
    /// probes run via the OpenSSL backend — useful as a reproduction aid
    /// (`openssl s_client -cipher <name>`). aws-lc-rs probes don't use
    /// cipher strings, so this is absent for the modern path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub openssl_name: Option<String>,
    /// Which backend produced this observation: `"aws_lc_rs"` for the
    /// rustls + aws-lc-rs modern path, `"openssl"` for the vendored
    /// OpenSSL legacy/misconfig path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Classification family (kx + privacy posture) per
    /// [`crate::model::cipher_classification::classify`]. Always
    /// present — the classifier is total.
    pub classification: crate::model::cipher_classification::CipherClassification,
}

#[derive(Serialize, Debug, Clone)]
pub struct TlsCipherSuites {
    /// SSLv2 cipher specs the server echoed in its SERVER-HELLO.
    /// Populated only when the SSLv2 probe got a parseable response
    /// (i.e. the server spoke SSLv2 at all). Each entry's `supported`
    /// is `Some(true)` because SSLv2's SERVER-HELLO lists exactly
    /// the ciphers the server accepts from the client's offer set.
    /// Empty on modern servers (the expected case).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssl2: Vec<CipherSuiteEntry>,
    /// SSL 3.0 per-cipher probe results. Populated by the OpenSSL
    /// legacy-probe path; empty on `--no-default-features` builds.
    pub ssl3: Vec<CipherSuiteEntry>,
    pub tls1_0: Vec<CipherSuiteEntry>,
    pub tls1_1: Vec<CipherSuiteEntry>,
    pub tls1_2: Vec<CipherSuiteEntry>,
    pub tls1_3: Vec<CipherSuiteEntry>,
    pub server_enforces_order: ObservationBool,
}

/// Per-TLS-version key-exchange group observations. Keys are group
/// names (e.g. `"X25519"`, `"ffdhe2048"`), values are the per-group
/// observation for that TLS version.
///
/// Not every group appears under both versions:
/// - FFDHE groups can appear under both `tls1_2` and `tls1_3`.
/// - aws-lc-rs modern groups (X25519, ECDH NIST curves, ML-KEM,
///   PQC hybrids) are TLS 1.3-only and appear only under `tls1_3`.
#[derive(Serialize, Debug, Clone, Default)]
pub struct TlsGroups {
    pub tls1_2: BTreeMap<String, GroupObservation>,
    pub tls1_3: BTreeMap<String, GroupObservation>,
}

/// Per-group `{supported, method, reason?}` envelope. Field name differs from `value` per spec.
#[derive(Serialize, Debug, Clone)]
pub struct GroupObservation {
    pub supported: Option<bool>,
    pub method: Method,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// IANA codepoint as `"0xNNNN"`. Populated for OpenSSL-backed FFDHE
    /// observations (where the probe knows the codepoint explicitly);
    /// absent for aws-lc-rs-backed modern groups that emit by debug name
    /// only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iana_code: Option<String>,
    /// Which backend produced this observation. See
    /// [`CipherSuiteEntry::provider`] for the full contract.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
}

impl GroupObservation {
    pub fn probe(supported: bool) -> Self {
        Self {
            supported: Some(supported),
            method: Method::Probe,
            reason: None,
            iana_code: None,
            provider: None,
        }
    }
    pub fn not_probed(reason: &str) -> Self {
        Self {
            supported: None,
            method: Method::NotProbed,
            reason: Some(reason.into()),
            iana_code: None,
            provider: None,
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
    /// RFC 6066 §7 — truncated_hmac extension. Server echo observed
    /// during the byte-level TLS 1.2 ServerHello probe.
    pub truncated_hmac: ObservationBool,
    /// Google NPN (ext 13172) — advertised by the server. Observability
    /// only; kemist never completes NPN negotiation.
    pub npn: ObservationBool,
    /// EC point formats the server echoed back (RFC 4492 §5.1.2).
    /// Canonical names: `"uncompressed"`, `"ansiX962_compressed_prime"`,
    /// `"ansiX962_compressed_char2"`. Empty when the server did not
    /// echo the extension.
    pub supported_point_formats_echoed: Vec<String>,
    /// RFC 6066 §4 — server-echoed max_fragment_length code. Rendered
    /// as `"2^9"` through `"2^12"` for RFC values 1-4, `"0xNN"` for
    /// unknown bytes. Absent when the server did not echo the
    /// extension.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fragment_length: Option<String>,
    /// RFC 8449 — TLS 1.3 `record_size_limit` value observed in
    /// EncryptedExtensions. Populated by the OpenSSL-backed
    /// EncryptedExtensions probe (feature `legacy-probes`); absent
    /// under other build configs or when the server did not send
    /// the extension.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_size_limit: Option<u16>,
    /// RFC 8879 — algorithms listed in the server's
    /// `compress_certificate` extension. Canonical names: `"zlib"`,
    /// `"brotli"`, `"zstd"`; `"0xNNNN"` for unknown codepoints.
    /// Populated by the OpenSSL-backed EncryptedExtensions probe;
    /// empty otherwise.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub compress_certificate_algorithms: Vec<String>,
    /// RFC 8701 GREASE echo-detection. `true` = server echoed an
    /// unknown extension (protocol violation signal). `false` =
    /// server correctly ignored the GREASE extension we injected.
    /// `not_probed` when the byte-level hello probe didn't produce
    /// a ServerHello.
    pub grease_echoed: ObservationBool,
    /// RFC 8446 §4.1.3 HelloRetryRequest observation. `true` = the
    /// dedicated TLS 1.3 ClientHello probe (empty `key_share`) saw a
    /// ServerHello whose random matched the HRR sentinel. `false` =
    /// the server responded with a regular ServerHello (either TLS 1.2
    /// fallback, or it unexpectedly accepted the empty `key_share`).
    /// `not_probed` / `error` — the probe did not reach a parseable
    /// ServerHello; reason carries the failure mode.
    pub hello_retry_request: ObservationBool,
}

#[derive(Serialize, Debug, Clone)]
pub struct OcspStapling {
    pub stapled: Option<bool>,
    pub method: Method,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub response_length: u64,
    /// Parsed OCSP response content — `None` when no staple was
    /// delivered, or when the bytes didn't parse as a well-formed
    /// OCSPResponse. See [`crate::model::ocsp_response`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<crate::model::ocsp_response::OcspResponseContent>,
    /// TLS version the staple was delivered over — `"tls1_2"` (via
    /// CertificateStatus) or `"tls1_3"` (via status_request in
    /// EncryptedExtensions). Absent when no staple or version
    /// indeterminate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_path: Option<String>,
    /// Raw OCSP response bytes, lower-case hex. Gated behind the
    /// `--include-ocsp-raw` CLI flag — most scans don't need the
    /// bytes in output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_hex: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct SctObservation {
    pub delivery_paths: Vec<String>,
    pub count: u32,
}

#[derive(Serialize, Debug, Clone)]
pub struct DowngradeSignaling {
    /// SCSV enforcement observation. `{value: true}` when the
    /// server returned `inappropriate_fallback` on a deliberate
    /// downgrade probe; `{value: false}` when it accepted the
    /// downgraded handshake; `{value: null}` with reason string when
    /// inconclusive.
    pub fallback_scsv_enforced: ObservationBool,
    /// RFC 8446 §4.1.3 — trailing-8-bytes ServerRandom sentinel observed
    /// during the byte-level TLS 1.2 ServerHello probe. Values:
    /// `"tls12"` (server is TLS 1.3-capable but negotiated TLS 1.2),
    /// `"lte_tls11"` (server negotiated TLS 1.1 or lower from a
    /// TLS 1.3 capable stack), `"none"` (no sentinel match — either
    /// a pure TLS 1.2/earlier server or a non-compliant TLS 1.3 stack).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls13_downgrade_sentinel: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct SniBehavior {
    pub omitted_probe: Option<String>,
    pub method: Method,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Channel-binding observations per RFC 9266 (`tls-exporter`) and
/// RFC 5929 §4 (`tls-server-end-point`). Both are derived from the
/// main characterization handshake; no extra network round-trips.
#[derive(Serialize, Debug, Clone, Default)]
pub struct ChannelBinding {
    /// RFC 9266 `tls-exporter` channel binding. `value` is 32 bytes
    /// of exporter output keyed with label
    /// `"EXPORTER-Channel-Binding"` and empty context, rendered as
    /// lower-case hex (64 chars). `method: probe` on TLS 1.3;
    /// `not_applicable` on TLS 1.2 with reason
    /// `not_defined_for_tls12` (RFC 9266 §2: tls-exporter is TLS
    /// 1.3-only). `error` if the exporter call failed.
    pub tls_exporter: ChannelBindingValue,
    /// RFC 5929 §4 `tls-server-end-point` channel binding. `value`
    /// is SHA-256 of the leaf certificate DER, rendered as
    /// lower-case hex (64 chars). `method: probe` whenever a leaf
    /// cert was delivered; `not_probed` if the characterization
    /// handshake didn't complete or no cert arrived.
    pub tls_server_end_point: ChannelBindingValue,
}

/// Single channel-binding value slot — hex string + tri-state method.
#[derive(Serialize, Debug, Clone)]
pub struct ChannelBindingValue {
    /// Lower-case hex encoding of the channel-binding bytes.
    /// `None` whenever `method != probe`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub method: Method,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Default for ChannelBindingValue {
    fn default() -> Self {
        Self {
            value: None,
            method: Method::NotProbed,
            reason: Some("unpopulated".to_string()),
        }
    }
}

// ----------------------------------------------------------------------
// OpenSSL legacy-probe output shapes. Populated by src/output/json.rs
// builders that consume `ScanResults.openssl_observations`. See
// docs/OUTPUT_SCHEMA.md for field semantics.
// ----------------------------------------------------------------------

/// One entry in `tls.dh_parameters`.
#[derive(Serialize, Debug, Clone)]
pub struct DhParametersObservation {
    /// Which completed cipher suite produced this observation — downstream
    /// consumers cross-reference with `legacy_cipher_suites`.
    pub cipher_suite: String,
    pub prime_bits: u32,
    /// `"ffdhe2048"` / `"ffdhe3072"` / `"ffdhe4096"` / `"ffdhe6144"` /
    /// `"ffdhe8192"` / `"custom"`.
    pub classification: String,
    pub generator: u32,
    /// Lowercase hex (64 chars).
    pub prime_sha256: String,
    /// Optional raw prime, lowercase hex. Omitted by default (bandwidth);
    /// populated when the CLI requests `--include-dh-raw` (flag not yet
    /// wired).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prime_raw_hex: Option<String>,
    pub method: Method,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// One entry in `tls.server_key_exchange_signatures`.
#[derive(Serialize, Debug, Clone)]
pub struct SkeSigObservation {
    pub cipher_suite: String,
    pub signature_algorithm: String,
    pub method: Method,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Shape of `tls.renegotiation_behavior`.
#[derive(Serialize, Debug, Clone)]
pub struct RenegotiationBehavior {
    /// `"accepted"` / `"rejected"` / `"not_attempted"` / `"error"` — or
    /// `None` when no probe ran.
    pub client_initiated_verdict: Option<String>,
    pub method: Method,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// One distinguished-name entry in `tls.client_auth_request.ca_distinguished_names`.
#[derive(Serialize, Debug, Clone)]
pub struct ClientAuthCaDn {
    /// Hex-encoded DER (schema field is nominally base64 — see
    /// `client_auth.rs::base64_encode` for the shim, swappable to real
    /// base64 without a schema rename).
    pub raw_der_b64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
}

/// TLS 1.3 `oid_filters` entry.
#[derive(Serialize, Debug, Clone)]
pub struct ClientAuthOidFilter {
    pub oid: String,
    pub values_b64: Vec<String>,
}

/// Shape of `tls.client_auth_request`.
#[derive(Serialize, Debug, Clone)]
pub struct ClientAuthRequestEntry {
    pub requested: bool,
    pub certificate_types: Vec<u8>,
    pub signature_algorithms: Vec<String>,
    pub ca_distinguished_names: Vec<ClientAuthCaDn>,
    pub oid_filters: Vec<ClientAuthOidFilter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert_on_empty_cert: Option<String>,
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
    /// Structured decomposition of the signature-algorithm
    /// identifier. Lets rule engines key on `(hash, algorithm)`
    /// pairs without re-implementing an OID table or parsing the
    /// human-readable `signature_algorithm_name` string.
    pub signature_algorithm_structured: SignatureAlgorithmStructured,
    /// Family classification when the signature OID is PQC. One of
    /// `"ml_dsa"` (FIPS 204), `"slh_dsa"` (FIPS 205), `"composite"`
    /// (IETF LAMPS composite drafts). `None` for classical
    /// signatures (RSA/ECDSA/EdDSA) or OIDs outside the recognized
    /// PQC table. Replaces the earlier `is_pqc_signature: bool` —
    /// rule engines wanting the old semantics can use
    /// `pqc_signature_family.is_some()`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pqc_signature_family: Option<String>,
    pub public_key: PublicKey,
    pub embedded_scts: u32,
    pub fingerprint_sha256: String,
    pub fingerprint_sha1: String,
    /// Parsed X.509 v3 extension observations. Always present;
    /// serializes to `{}` when no sub-fields are populated. See
    /// [`crate::model::cert_extensions::CertExtensions`].
    pub extensions: crate::model::cert_extensions::CertExtensions,
}

#[derive(Serialize, Debug, Clone)]
pub struct PublicKey {
    pub algorithm: String,
    pub size_bits: usize,
    /// Human-readable named-curve label (e.g. `"secp256r1"`,
    /// `"brainpoolP256r1"`, `"Ed25519"`). Derived from
    /// `curve_oid` where available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub curve: Option<String>,
    /// Raw named-curve OID (RFC 5480 §2.1.1), e.g.
    /// `"1.2.840.10045.3.1.7"` for secp256r1. Populated for EC keys
    /// whose SubjectPublicKeyInfo carries a named-curve OID, plus
    /// EdDSA algorithm OIDs. Rule engines keying on a stable OID
    /// (rather than a human name that may shift across upstream
    /// updates) should consume this field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub curve_oid: Option<String>,
    /// RSA public exponent `e` (RFC 8017 §3.1). Populated only for
    /// RSA keys. `u64` covers every exponent observed in practice
    /// (`e = 3`, `e = 17`, `e = 65537`); exotic exponents would
    /// overflow but are vanishingly rare. Lets rule engines flag
    /// small-exponent keys (CVE-2006-4339 / Bleichenbacher-flavored
    /// weaknesses on `e = 3`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rsa_exponent: Option<u64>,
}

/// Structured decomposition of an X.509 signature-algorithm
/// identifier (the `AlgorithmIdentifier` at the end of a
/// TBSCertificate). Emitted alongside
/// `signature_algorithm_oid` / `signature_algorithm_name` so rule
/// engines can key on the family + hash without parsing OIDs.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignatureAlgorithmStructured {
    /// Canonical hash family name keyed on the signature OID: one
    /// of `"sha1"`, `"sha256"`, `"sha384"`, `"sha512"`. `None` when
    /// the signature scheme handles hashing internally (Ed25519,
    /// Ed448) or when the hash family isn't determinable from OID
    /// alone (ML-DSA / SLH-DSA — the scheme name encodes the hash).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    /// Canonical algorithm-family name: `"rsa"`, `"rsa_pss"`,
    /// `"ecdsa"`, `"ed25519"`, `"ed448"`, `"ml_dsa_44"` /
    /// `"ml_dsa_65"` / `"ml_dsa_87"`, `"slh_dsa_sha2_128s"` etc.
    /// `"unknown"` for OIDs outside the recognized set.
    pub algorithm: String,
    /// Algorithm-specific parameter summary. Populated today for
    /// RSA-PSS: `"mgf1-sha256"` / `"mgf1-sha384"` / `"mgf1-sha512"`
    /// / `"rfc4055_defaults"` (when params absent, meaning the RFC
    /// 4055 §3.1 defaults of SHA-1 + MGF1-SHA1 + 20-byte salt).
    /// `None` for algorithms without parameterization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<String>,
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
