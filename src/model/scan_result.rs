//! kemist output schema v2.
//!
//! See docs/OUTPUT_SCHEMA.md and schemas/output-v1.json for the formal contract.
//! (Filename retained at v1 for URL stability across the v1→v2 cut; the
//! `$id` and `title` inside the schema document carry the v2 marker.)
//!
//! Envelope rule: probe-derived tri-state observations carry `{value, method, reason?}`.
//! Stable metadata (schema_version, target, fingerprints, IANA codepoints, etc.) is
//! emitted as plain scalars, never wrapped.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::model::cert::CertificateInfo;
pub use crate::model::errors::ScannerError;

pub const SCHEMA_VERSION: &str = "2.0.0";

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
    /// Non-extension handshake observations: vulnerability probes
    /// (Heartbleed payload echo, ephemeral-key reuse / Raccoon, ROBOT)
    /// plus ClientHello-body / ServerHello-variant signals
    /// (`compression_offered`, `hello_retry_request`, `grease_echoed`).
    /// These were grouped under `extensions` in schema v1.0 because
    /// they're observed in the same handshake window, but none of
    /// them are TLS extensions in the RFC 5246 §7.4.1.4 / RFC 8446
    /// §4.2 sense — schema v2.0 separates them.
    pub behavioral_probes: BehavioralProbes,
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
    /// Per-ALPN-protocol probe matrix. One entry per probed token —
    /// `h2`, `http/1.1`, `http/1.0` today. Each entry records whether
    /// the server accepts that protocol when offered alone.
    /// Complements `negotiated.alpn` (which records the preference
    /// when multiple are offered).
    pub alpn_probe: Vec<AlpnProbeEntry>,
}

/// Per-protocol ALPN probe result.
#[derive(Serialize, Debug, Clone)]
pub struct AlpnProbeEntry {
    /// Protocol token offered (e.g. `"h2"`, `"http/1.1"`).
    pub protocol: String,
    /// `Some(true)` — handshake completed with the server echoing
    /// this protocol. `Some(false)` — rejected (RFC 7301
    /// `no_application_protocol` alert, or handshake completed with
    /// a different / absent ALPN; see `reason`). `None` — probe
    /// errored at the transport or TLS layer.
    pub supported: Option<bool>,
    pub method: Method,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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
    /// SHA-256 fingerprint (lowercase hex) of the leaf certificate
    /// the server returned under this constraint. Populated only
    /// when the handshake completed and the leaf cert was readable.
    /// Two distinct fingerprints across the probe set are the
    /// downstream signal for a dual-cert deployment (e.g. RSA +
    /// ECDSA leaves on the same endpoint). The scanner records the
    /// fingerprints; it does not compute the comparison.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf_fingerprint_sha256: Option<String>,
    /// Subject DN of the leaf (same formatting as
    /// `certificates.leaf.subject_dn`). Convenience for downstream
    /// log correlation; the authoritative identifier is
    /// `leaf_fingerprint_sha256`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf_subject_dn: Option<String>,
    /// Parsed certificate chain observed on this constrained probe.
    /// Internal-only: the JSON emitter deduplicates these into
    /// `certificates.alternates[]` rather than repeating full chains
    /// under every sigalg probe row.
    #[serde(skip_serializing)]
    pub cert_chain: Vec<CertificateInfo>,
}

impl Default for ConstrainedProbeResult {
    fn default() -> Self {
        Self {
            outcome: SigalgOutcome::NotProbed,
            selected_sigalg: None,
            alert: None,
            method: Method::NotProbed,
            reason: None,
            leaf_fingerprint_sha256: None,
            leaf_subject_dn: None,
            cert_chain: Vec::new(),
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
    /// TLS 1.2 NewSessionTicket message.
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
    /// **Functional** RFC 5077 ticket resumption test. The probe
    /// completes a TLS 1.2 handshake, captures the issued session,
    /// then attempts a fresh handshake with `SSL_set_session(prev)`
    /// and reads `SSL_session_reused`. `true` = server accepted the
    /// previously-issued ticket and resumed; `false` = server
    /// declined and ran a full handshake; `not_applicable` when the
    /// first handshake didn't yield a session to present.
    /// Distinct from `session_ticket_issued`, which only tells you
    /// whether the server *handed out* a ticket.
    pub session_ticket_resumption_accepted: ObservationBool,
    /// **Functional** RFC 5246 §F.1.4 session-ID resumption test.
    /// Same shape as `session_ticket_resumption_accepted`, but the
    /// probe builds the SslContext with `SSL_OP_NO_TICKET` so the
    /// server falls back to session-ID-based caching. `true` =
    /// server accepted the previously-issued session ID and resumed;
    /// `false` = server issued an ID but didn't accept it back (the
    /// classic "IDs assigned but not accepted" pattern). Distinct
    /// from `session_id_issued`, which only tells you whether the
    /// server *handed out* an ID.
    pub session_id_resumption_accepted: ObservationBool,
}

#[derive(Serialize, Debug, Clone, Default)]
pub struct Tls13Resumption {
    /// Number of `NewSessionTicket` messages received after the TLS
    /// 1.3 handshake. RFC 8446 §4.6.1 lets servers send multiple;
    /// operators often configure 1 or 2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_session_ticket_count: Option<u32>,
    /// Per-ticket TLS 1.3 lifetime hints when exposed by the backend.
    /// Empty when no lifetimes were observed.
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
    /// FFDHE rows only: classification of the prime the server returned
    /// when its behavior diverged from the codepoint we offered (or when
    /// the host-level cross-codepoint check determined the server isn't
    /// honoring `supported_groups`). Vocabulary matches
    /// `tls.dh_parameters[].classification` — `"ffdhe2048"`,
    /// `"modp3072"`, `"custom"`, etc. Omitted when the row reflects an
    /// honest match or a non-FFDHE codepoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub returned_group: Option<String>,
    /// FFDHE rows only: bit-length of the prime the server actually
    /// returned. Useful primarily when `returned_group == "custom"`,
    /// where the size isn't conveyed by the classification name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub returned_prime_bits: Option<u32>,
}

impl GroupObservation {
    pub fn probe(supported: bool) -> Self {
        Self {
            supported: Some(supported),
            method: Method::Probe,
            reason: None,
            iana_code: None,
            provider: None,
            returned_group: None,
            returned_prime_bits: None,
        }
    }
    pub fn not_probed(reason: &str) -> Self {
        Self {
            supported: None,
            method: Method::NotProbed,
            reason: Some(reason.into()),
            iana_code: None,
            provider: None,
            returned_group: None,
            returned_prime_bits: None,
        }
    }
}

/// True TLS extensions per RFC 5246 §7.4.1.4 / RFC 8446 §4.2 — fields
/// that ride in the `extensions` block of ClientHello / ServerHello /
/// EncryptedExtensions. Non-extension handshake observations
/// (vulnerability probes, ClientHello-body fields, ServerHello
/// variants) live in [`BehavioralProbes`].
#[derive(Serialize, Debug, Clone)]
pub struct TlsExtensions {
    pub ems: ObservationBool,
    pub secure_renegotiation: ObservationBool,
    pub ocsp_stapling: OcspStapling,
    pub sct: SctObservation,
    pub alpn_offered: Vec<String>,
    pub encrypt_then_mac: ObservationBool,
    pub heartbeat_present: ObservationBool,
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
    /// RFC 9345 delegated credentials observation. Offered in the
    /// TLS 1.2 byte-probe ClientHello (ext 0x0022) and in the TLS 1.3
    /// characterization handshake. `value` is `true` when the server
    /// indicated DC support on either path; `delivery_path` identifies
    /// which path observed it. The scanner never verifies the DC
    /// signature over the leaf pubkey and never compares `valid_time`
    /// against the wall clock — observation only.
    pub delegated_credentials: DelegatedCredentialsObservation,
}

/// Handshake-time observations that aren't TLS extensions: active
/// vulnerability probes (Heartbleed payload echo, ephemeral-key reuse,
/// ROBOT) plus ClientHello-body / ServerHello-variant signals
/// (`compression_offered`, `hello_retry_request`, `grease_echoed`).
/// Schema v2.0 split these out of `tls.extensions` to make the
/// distinction explicit; v1.0 grouped them all under `extensions`.
#[derive(Serialize, Debug, Clone)]
pub struct BehavioralProbes {
    /// Heartbleed (CVE-2014-0160) detection. `true` = server echoed
    /// our oversized-payload heartbeat back, leaking adjacent memory
    /// bytes. `false` = server correctly bounds-checked. The
    /// `heartbeat_present` extension is recorded separately under
    /// `extensions`; this field is the *behavioral* signal.
    pub heartbeat_echoes_oversized_payload: ObservationBool,
    /// Compression methods echoed back by the server in the
    /// ServerHello `compression_methods` field (RFC 5246 §7.4.1.3).
    /// Note: the field is in the ClientHello/ServerHello body proper,
    /// not an extension. Non-empty list means CRIME-vulnerable
    /// configuration (RFC 7457 §2.1).
    pub compression_offered: Vec<String>,
    /// RFC 8701 GREASE echo-detection. `true` = server echoed an
    /// unknown extension (protocol violation signal — the server's
    /// ClientHello parser is non-conformant). `false` = server
    /// correctly ignored the GREASE extension we injected.
    /// `not_probed` when the byte-level hello probe didn't produce
    /// a ServerHello.
    pub grease_echoed: ObservationBool,
    /// RFC 8446 §4.1.3 HelloRetryRequest observation — a ServerHello
    /// *variant* (random == sentinel), not an extension. `true` = the
    /// dedicated TLS 1.3 ClientHello probe (empty `key_share`) saw a
    /// ServerHello whose random matched the HRR sentinel. `false` =
    /// the server responded with a regular ServerHello (either TLS 1.2
    /// fallback, or it unexpectedly accepted the empty `key_share`).
    /// `not_applicable` when TLS 1.3 isn't supported on the host.
    pub hello_retry_request: ObservationBool,
    /// Ephemeral DH / ECDH public-value reuse observation. Captured
    /// by running two sequential TLS 1.2 handshakes per family and
    /// comparing the server's ephemeral public value byte-for-byte.
    /// Matching values across fresh handshakes is the observable
    /// signal for Raccoon-class exposure (CVE-2020-1968). Scanner
    /// records; downstream rule engines interpret.
    pub ephemeral_key_reuse: EphemeralKeyReuseObservation,
    /// Bleichenbacher / ROBOT differential probe. Per-variant
    /// alert / timing / close-mode classification under five
    /// malformed PKCS#1 v1.5 `ClientKeyExchange` ciphertexts. Gated
    /// on `TLS_RSA_*` support observed by the cipher probe; when no
    /// RSA-kex suite is supported the `method` is `not_probed` and
    /// `per_variant` is empty. Observation only — the scanner
    /// records the five-entry comparison table; downstream
    /// interprets.
    pub bleichenbacher_oracle_probe: BleichenbacherOracleProbe,
}

/// Per-variant record for the ROBOT differential probe.
/// `alert_category` + `tcp_reset` + `other_outcome` are mutually
/// exclusive — exactly one is populated per variant.
#[derive(Serialize, Debug, Clone)]
pub struct RobotVariantObservation {
    /// Stable variant name — `"correctly_formatted_pkcs1"`,
    /// `"invalid_0x00_02_prefix"`,
    /// `"invalid_version_0x00_02_byte_swap"`,
    /// `"null_separator_missing"`,
    /// `"wrong_tls_version_in_pms"`.
    pub variant: String,
    /// Canonical `tls_alert_*` category string when the server
    /// closed with an alert. Same taxonomy as `errors[].category`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert_category: Option<String>,
    /// `true` when the socket closed with TCP RST
    /// (`ErrorKind::ConnectionReset`). Mutually exclusive with
    /// `alert_category`.
    pub tcp_reset: bool,
    /// Wall-clock elapsed from connect-start to
    /// response-classification. Scanner emits; downstream rule
    /// engines can compare timings across variants.
    pub elapsed_ms: u64,
    /// Non-alert, non-RST outcome classification:
    /// `"timeout"`, `"graceful_close"`,
    /// `"unexpected_plaintext:<detail>"`, or
    /// `"setup_error:<detail>"`. `None` when an alert or RST
    /// populated the other fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other_outcome: Option<String>,
}

/// Outer result of the ROBOT probe. `per_variant` is empty on
/// `method: not_probed`; otherwise it carries exactly five entries
/// in the stable variant order.
#[derive(Serialize, Debug, Clone)]
pub struct BleichenbacherOracleProbe {
    /// IANA name of the RSA-kex suite the probe pinned
    /// (`TLS_RSA_WITH_AES_128_CBC_SHA` today). `None` when the
    /// probe did not run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rsa_kex_suite_probed: Option<String>,
    /// `probe` when the five variants ran; `not_probed` when the
    /// cipher probe observed no `TLS_RSA_*` suite supported (or
    /// the outer environment disabled the probe). Never `error`
    /// at the outer level — per-variant setup failures are
    /// recorded inside `per_variant[].other_outcome`.
    pub method: Method,
    /// Human-readable reason when `method` is `not_probed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Five entries when probed, empty when not.
    pub per_variant: Vec<RobotVariantObservation>,
}

/// Ephemeral DH / ECDH public-value reuse observation. Two sequential
/// handshakes per family; compare the server's ephemeral public
/// value. See module docs at
/// `scanner::backends::openssl::ephemeral_reuse`.
#[derive(Serialize, Debug, Clone)]
pub struct EphemeralKeyReuseObservation {
    /// `true` when two fresh TLS 1.2 DHE handshakes returned
    /// identical DH public values. `not_probed` when no DHE suite
    /// was observed supported by the earlier cipher probe.
    pub dhe_public_reused_across_connections: ObservationBool,
    /// Same signal for ECDHE — `true` when the server's ECDH point
    /// matched byte-for-byte across two fresh handshakes.
    pub ecdhe_public_reused_across_connections: ObservationBool,
    /// IANA name of the DHE suite the probe pinned for its two
    /// handshakes. `None` when no DHE suite was available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhe_suite_probed: Option<String>,
    /// IANA name of the ECDHE suite the probe pinned. `None` when
    /// no ECDHE suite was available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecdhe_suite_probed: Option<String>,
}

/// RFC 9345 delegated-credentials observation. The TLS 1.2 path can
/// only signal presence via the ServerHello extension echo; the
/// TLS 1.3 path parses the leaf CertificateEntry extensions and also
/// surfaces `valid_time` + `expected_cert_verify_algorithm`.
#[derive(Serialize, Debug, Clone)]
pub struct DelegatedCredentialsObservation {
    /// Whether the server indicated delegated-credential support on
    /// either the TLS 1.2 SH or TLS 1.3 CertificateEntry path.
    /// `not_probed` when neither path produced an observation.
    pub value: ObservationBool,
    /// TLS 1.3 only — `valid_time` field from the DelegatedCredential
    /// struct (seconds from the leaf cert's `notBefore`, RFC 9345
    /// §4.1). Absent on TLS 1.2 SH observation (signed-structure
    /// bytes don't reach the probe) and when no DC was observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_time_seconds: Option<u32>,
    /// TLS 1.3 only — canonical IANA SignatureScheme name for the
    /// `expected_cert_verify_algorithm` field of the DelegatedCredential
    /// (`"ecdsa_secp256r1_sha256"`, etc.). `"0xNNNN"` for unrecognized
    /// codepoints. Absent on TLS 1.2 and when no DC was observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_cert_verify_algorithm: Option<String>,
    /// Which observation path populated the fields:
    /// `"tls1_3_certificate_entry"` or `"tls1_2_server_hello"`.
    /// `None` when no DC observation exists (value is not_probed or
    /// probe==false on both paths).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_path: Option<String>,
}

/// Single CRL fetch + revocation-check result.
#[derive(Serialize, Debug, Clone)]
pub struct CrlFetchEntry {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub this_update: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_update: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crl_issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_cert_count: Option<usize>,
    /// `true` — leaf's serial found in this CRL's revoked list
    /// (definitive revocation signal). `false` — CRL fetched,
    /// parsed, searched, and leaf NOT present (definitive "not
    /// revoked" signal). `null` — fetch / parse failed; see
    /// `error`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf_revoked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Single OCSP-over-HTTP fetch result.
#[derive(Serialize, Debug, Clone)]
pub struct OcspHttpFallbackEntry {
    /// URL fetched (from the leaf's AIA `OCSP` extension).
    pub url: String,
    /// HTTP status code from the POST. `None` on transport failure
    /// before an HTTP response arrived.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    /// Parsed OCSP response contents — same shape as
    /// `ocsp_stapling.content` (RFC 6960 BasicOCSPResponse).
    /// `None` when the fetch failed OR the response body wasn't
    /// parseable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<crate::model::ocsp_response::OcspResponseContent>,
    /// Length of the raw response body in bytes. `0` when the fetch
    /// failed before a body arrived.
    pub response_length: usize,
    /// Error category / reason when the probe didn't yield a
    /// parseable response. Canonical values:
    /// `post_failed:<reqwest_error>`, `http_status_<code>`,
    /// `response_exceeds_size_cap:<bytes>`, `body_read:<err>`,
    /// `leaf_parse_failed:<err>`, `issuer_parse_failed:<err>`,
    /// `ocsp_request_build:<err>`, `response_parse_failed:<err>`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
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
    /// Optional raw prime, lowercase hex. Omitted by default
    /// (bandwidth); populated when the CLI requests
    /// `--include-dh-raw`.
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alternates: Vec<CertificateAlternate>,
}

#[derive(Serialize, Debug, Clone)]
pub struct CertificateAlternate {
    /// Probe paths that observed this alternate leaf/chain. Stable
    /// strings such as `signature_algorithm_policy.rsa_pss_only`.
    pub observed_via: Vec<String>,
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
    /// Position of this cert in the wire-order chain delivered by
    /// the server. `0` is the leaf; subsequent integers are
    /// intermediates in the order the server sent them. Duplicates
    /// are preserved (each copy carries its own position);
    /// parse-failures show as gaps in the position sequence across
    /// `Certificates.chain`. Downstream rule engines key on this
    /// field to observe chain ordering directly rather than
    /// inferring it from array index.
    pub wire_position: u32,
    /// Parsed X.509 v3 extension observations. Always present;
    /// serializes to `{}` when no sub-fields are populated. See
    /// [`crate::model::cert_extensions::CertExtensions`].
    pub extensions: crate::model::cert_extensions::CertExtensions,
    /// Out-of-band revocation observations for this cert —
    /// `crl_fetch` results (from `CRLDistributionPoints` URLs) +
    /// `ocsp_http_fallback` results (from AIA `OCSP` URLs).
    /// Populated only when `--enable-revocation-fetch` is set AND
    /// this is the leaf. Other chain entries render as `None`
    /// (intermediate-cert revocation checking is a future
    /// workstream). Distinct from `tls.extensions.ocsp_stapling`,
    /// which captures the server's in-band stapling *behavior* at
    /// the TLS layer regardless of cert scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation: Option<CertRevocation>,
}

/// Out-of-band revocation observations scoped to a single cert.
/// Both fields are opt-in via `--enable-revocation-fetch` and absent
/// when the corresponding URL list on the cert is empty.
#[derive(Serialize, Debug, Clone, Default)]
pub struct CertRevocation {
    /// OCSP-over-HTTP fetches against the leaf's AIA `OCSP` URLs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ocsp_http_fallback: Vec<OcspHttpFallbackEntry>,
    /// CRL downloads against the leaf's `CRLDistributionPoints`
    /// URLs, with a per-URL `leaf_revoked` decision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub crl_fetch: Vec<CrlFetchEntry>,
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
    pub chain_valid_to_microsoft_roots: ObservationBool,
    pub chain_valid_to_apple_roots: ObservationBool,
    pub chain_valid_to_us_fpki_common_roots: ObservationBool,
    pub chain_valid_to_us_dod_roots: ObservationBool,
    /// `--extra-trust-store` entries, keyed on the user-supplied
    /// name. Empty object when no extras were configured. Values
    /// follow the same three-state ObservationBool semantics as the
    /// compiled-in stores.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub chain_valid_to_custom_roots: std::collections::BTreeMap<String, ObservationBool>,
    pub name_matches_sni: ObservationBool,
    /// Error string from the webpki-roots validation attempt (legacy
    /// single-store field). `None` when webpki-roots validated cleanly.
    /// New integrations should consume `per_store_validation_errors`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_error: Option<String>,
    /// Per-store validation error strings, keyed by canonical store
    /// name. Populated only for stores whose chain validation
    /// failed. Empty when every store validated or when no errors
    /// were produced.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub per_store_validation_errors: std::collections::BTreeMap<String, String>,
    /// Provenance breadcrumb per store — `"compiled_in"`,
    /// `"cache_refreshed:<path>"` (loaded from the platform
    /// cache written by `kemist --update-trust-stores`), or
    /// `"runtime_override:<path>"` (loaded from a user-supplied
    /// `--trust-store name:path`). One entry per store attempted.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub trust_store_sources: std::collections::BTreeMap<String, String>,
    /// Per-store bundle metadata — upstream source URL,
    /// fetched_at timestamp, entry count, upstream version. Populated
    /// only for stores whose bundle came from the cache (refreshed
    /// via `--update-trust-stores`); compile-time and runtime-
    /// override bundles have no accompanying manifest metadata.
    /// Lets rule engines pin observations to a specific snapshot.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub trust_store_bundle_metadata: std::collections::BTreeMap<String, TrustStoreBundleMetadata>,
}

/// Output-side projection of [`crate::scanner::bundle_cache::BundleMetadata`].
/// Same shape, but lives in the scan-result tree so schema changes
/// land in one place.
#[derive(Serialize, Debug, Clone)]
pub struct TrustStoreBundleMetadata {
    pub source: String,
    pub fetched_at: String,
    /// SHA-256 of the bundle file on disk (lower-case hex).
    pub sha256: String,
    pub entry_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_version: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct Http {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hsts: Option<Hsts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preload_list_status: Option<String>,
    /// Snapshot provenance — `"compiled_in"` (default) or
    /// `"runtime_override:<path>"` when `--hsts-preload-list-path`
    /// was used. Consumers should never assume the same snapshot
    /// across runs; the breadcrumb makes the source explicit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preload_list_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_txt: Option<SecurityTxt>,
    /// Security-related response headers beyond HSTS — CSP / XFO /
    /// referrer-policy / permissions-policy / cross-origin family /
    /// Set-Cookie flag observations. `None` when HTTP checks didn't
    /// run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_headers: Option<SecurityHeadersOutput>,
    /// Redirect chain observed via `GET /` (up to 10 hops). Each
    /// entry carries the request URL, status, and `Location` target.
    /// `None` when HTTP checks didn't run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_chain: Option<Vec<RedirectHopOutput>>,
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
    /// Structured RFC 9116 parse — fields by directive name.
    /// `None` when the body yielded no recognized directives.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parsed: Option<SecurityTxtParsedOutput>,
}

/// Structured representation of the RFC 9116 security.txt body —
/// each field holds the set of values observed for that directive.
#[derive(Serialize, Debug, Clone, Default)]
pub struct SecurityTxtParsedOutput {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub contact: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub encryption: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub preferred_languages: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub canonical: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub policy: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hiring: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub acknowledgments: Vec<String>,
    pub pgp_signed: bool,
}

/// Security-related HTTP response headers. Raw values for
/// CSP/XFO/etc.; structured for Set-Cookie (name + security flags,
/// cookie values deliberately excluded to avoid capturing session
/// material).
#[derive(Serialize, Debug, Clone, Default)]
pub struct SecurityHeadersOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_security_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_security_policy_report_only: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x_frame_options: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x_content_type_options: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referrer_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cross_origin_opener_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cross_origin_embedder_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cross_origin_resource_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reporting_endpoints: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub set_cookies: Vec<CookieFlagsOutput>,
}

/// Per-cookie security flag observation. Cookie value intentionally
/// absent — see [`crate::scanner::http::CookieObservation`].
#[derive(Serialize, Debug, Clone, Default)]
pub struct CookieFlagsOutput {
    pub name: String,
    pub secure: bool,
    pub http_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub same_site: Option<String>,
}

/// One hop in the observed redirect chain.
#[derive(Serialize, Debug, Clone, Default)]
pub struct RedirectHopOutput {
    pub url: String,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}
