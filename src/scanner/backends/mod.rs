//! Backend abstraction for the TLS probe drivers.
//!
//! Types defined here:
//! - `BackendInventory` — a declaration of which codepoints a given
//!   TLS library can probe.
//! - `HandshakeOutcome` — unified probe-outcome enum across every
//!   probe family (cipher, group, version, sigalg, FALLBACK_SCSV).
//! - `TlsBackend` trait + `HandshakeConstraint` + `HandshakeResult` —
//!   the `handshake()` primitive every codepoint-driven probe
//!   composes, plus the constraint axes the caller can pin.
//! - `BackendRegistry` — owns every backend instance plus the
//!   per-codepoint priority table the orchestrator dispatches through.
//!
//! Concrete backends live in `rustls::RustlsBackend` and
//! `openssl::OpensslBackend`.

use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;

use crate::model::cert::CertificateInfo;
use crate::model::errors::ScannerError;
use crate::model::protocol::TlsVersion;
#[cfg(feature = "legacy-probes")]
use crate::scanner::openssl::dh_params::DhSnapshot;
use crate::scanner::probe::NegotiatedState;

#[cfg(feature = "legacy-probes")]
pub mod openssl;
pub mod registry;
pub mod rustls;

#[cfg(feature = "legacy-probes")]
pub use self::openssl::OpensslBackend;
pub use self::registry::BackendRegistry;
pub use self::rustls::RustlsBackend;

/// Outcome of a single probe handshake. Unifies the per-probe-family
/// outcome enums that used to live alongside each probe (`ProbeOutcome`,
/// `LegacyProbeOutcome`, `GroupProbeOutcome`, `KxGroupOutcome`).
///
/// Not every probe family produces every variant — `NotProbed` is only
/// emitted by group probes (aws-lc-rs doesn't ship some named groups;
/// FFDHE at TLS 1.2 doesn't apply to ECDH codepoints), and
/// `IgnoredGroupReturnedDifferentPrime` is FFDHE-specific. Cipher probes
/// use only `Supported` / `NotSupported` / `Error`.
#[derive(Debug, Clone)]
pub enum HandshakeOutcome {
    /// Handshake completed with the constrained offer.
    Supported,
    /// Server evaluated the single-codepoint offer and rejected it —
    /// handshake alert or post-ClientHello reset.
    NotSupported,
    /// Probe itself failed (transport timeout, unexpected error).
    /// The string carries the scanner error category (and sometimes
    /// context) — format is caller-specific for backwards compatibility
    /// with schema v1 error strings.
    Error(String),
    /// Probe not attempted — e.g. aws-lc-rs doesn't ship this group, or
    /// the probe doesn't apply to this TLS version. Group probes only.
    NotProbed(String),
    /// FFDHE-only: server completed a DHE handshake but returned a
    /// prime that doesn't match the advertised codepoint — i.e. it
    /// ignored our `supported_groups` offer. `returned_group` carries
    /// the classification of the prime the server actually sent
    /// (`"ffdhe2048"`, `"modp3072"`, `"custom"`, etc., per
    /// `DhClassification::as_schema_str`); `returned_prime_bits` is the
    /// modulus size in bits. Meaningless for ECDH / ML-KEM / cipher
    /// probes.
    IgnoredGroupReturnedDifferentPrime {
        returned_group: String,
        returned_prime_bits: u32,
    },
}

/// Heuristic: does this `ScannerError` indicate the server evaluated
/// our offer and rejected it at the wire level? Any `tls_alert_*`
/// category or `connection_refused` is a real observation (server
/// said "no"); everything else is a probe failure we should surface
/// as `Error`.
///
/// Callers produce the `Error` variant themselves because rustls-path
/// and OpenSSL-path probes emit subtly different Error strings (the
/// rustls path includes both category and context; the OpenSSL path
/// emits category only) and schema-v1 output depends on both formats
/// staying as they were.
pub fn is_wire_rejection(e: &ScannerError) -> bool {
    e.category.starts_with("tls_alert_") || e.category == "connection_refused"
}

/// Declares which codepoints a backend can probe.
///
/// `*_codepoints` and `*_names` are aligned by index: the name at
/// position `i` is the canonical identifier for the codepoint at
/// position `i`. Names follow each backend's native convention —
/// rustls Debug formatting for aws-lc-rs, IANA names for OpenSSL.
#[derive(Debug, Clone)]
pub struct BackendInventory {
    /// Short stable identifier used in priority tables and routing.
    pub id: &'static str,
    pub supported_versions: Vec<TlsVersion>,
    pub cipher_codepoints: Vec<u16>,
    pub cipher_names: Vec<String>,
    pub group_codepoints: Vec<u16>,
    pub group_names: Vec<String>,
    /// Short strings describing what this backend cannot do. Reserved
    /// for future propagation into `capabilities.probe_limitations`;
    /// currently populated by backends but not emitted.
    pub limitations: Vec<&'static str>,
}

/// Build the rustls / aws-lc-rs backend inventory from runtime
/// enumeration of `ALL_CIPHER_SUITES` and `ALL_KX_GROUPS`. Cipher and
/// group names use rustls's Debug formatting, matching what the
/// capabilities emitter writes to `probed_cipher_suites`.
pub fn rustls_inventory() -> BackendInventory {
    // Fully-qualified `::rustls::` disambiguates from the sibling
    // `backends::rustls` submodule declared below.
    let mut cipher_codepoints = Vec::new();
    let mut cipher_names = Vec::new();
    for s in ::rustls::crypto::aws_lc_rs::ALL_CIPHER_SUITES {
        cipher_codepoints.push(s.suite().into());
        cipher_names.push(format!("{:?}", s.suite()));
    }
    let mut group_codepoints = Vec::new();
    let mut group_names = Vec::new();
    for g in ::rustls::crypto::aws_lc_rs::ALL_KX_GROUPS {
        group_codepoints.push(g.name().into());
        group_names.push(format!("{:?}", g.name()));
    }
    BackendInventory {
        id: "aws_lc_rs",
        supported_versions: vec![TlsVersion::Tls12, TlsVersion::Tls13],
        cipher_codepoints,
        cipher_names,
        group_codepoints,
        group_names,
        limitations: Vec::new(),
    }
}

/// Build the OpenSSL backend inventory from the hardcoded target
/// tables in `backends::openssl::{ciphers, kx_groups}`. Cipher and
/// group names are IANA-canonical (the spec-standard form), matching
/// what `probed_cipher_suites` emits.
#[cfg(feature = "legacy-probes")]
pub fn openssl_inventory() -> BackendInventory {
    let cipher_entries = crate::scanner::openssl::ciphers::inventory_entries();
    let mut cipher_codepoints = Vec::with_capacity(cipher_entries.len());
    let mut cipher_names = Vec::with_capacity(cipher_entries.len());
    for (code, name, _version) in cipher_entries {
        cipher_codepoints.push(code);
        cipher_names.push(name.to_string());
    }

    let group_entries = crate::scanner::openssl::kx_groups::inventory_entries();
    let mut group_codepoints = Vec::with_capacity(group_entries.len());
    let mut group_names = Vec::with_capacity(group_entries.len());
    for (code, name) in group_entries {
        group_codepoints.push(code);
        group_names.push(name.to_string());
    }

    BackendInventory {
        id: "openssl",
        supported_versions: vec![
            TlsVersion::Ssl3,
            TlsVersion::Tls10,
            TlsVersion::Tls11,
            TlsVersion::Tls12,
            TlsVersion::Tls13,
        ],
        cipher_codepoints,
        cipher_names,
        group_codepoints,
        group_names,
        limitations: Vec::new(),
    }
}

/// All backend inventories available in the current build. Used by the
/// classification-coverage test to iterate every codepoint any backend
/// can probe.
pub fn all_inventories() -> Vec<BackendInventory> {
    #[allow(unused_mut)]
    let mut v = vec![rustls_inventory()];
    #[cfg(feature = "legacy-probes")]
    v.push(openssl_inventory());
    v
}

/// Per-scan context threaded through every `handshake()` call: the
/// target socket + hostname (for SNI) + timeout budgets.
#[derive(Debug, Clone)]
pub struct ProbeContext {
    pub target: SocketAddr,
    pub hostname: String,
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
}

/// Constraints applied to a single probe handshake. Empty defaults mean
/// "no restriction" for each axis — the backend emits whatever its
/// library-default ClientHello negotiates. Callers pin the axes that
/// identify what they're probing (single cipher, single group, single
/// version, etc.).
#[derive(Debug, Clone, Default)]
pub struct HandshakeConstraint {
    /// Inclusive `(min, max)` TLS version range to offer. `None` lets
    /// the backend offer whatever versions its library default allows.
    pub version_range: Option<(TlsVersion, TlsVersion)>,
    /// Restrict the ClientHello cipher list to these IANA codepoints.
    /// `None` lets the backend's library default stand.
    pub cipher_suites: Option<Vec<u16>>,
    /// Restrict `supported_groups` / TLS 1.3 `key_share` to these
    /// IANA codepoints. `None` lets the backend's library default stand.
    pub groups: Option<Vec<u16>>,
    /// Restrict the TLS 1.2 `signature_algorithms` (and TLS 1.3
    /// equivalents) to these IANA codepoints. OpenSSL-only today.
    pub sigalgs: Option<Vec<u16>>,
    /// ALPN identifiers to advertise, in order. `None` offers nothing.
    pub alpn: Option<Vec<Vec<u8>>>,
    /// Add `TLS_FALLBACK_SCSV` (0x5600) to the ClientHello cipher list.
    /// OpenSSL-only.
    pub send_fallback_scsv: bool,
    /// Invoke `SSL_CTX_set_security_level(0)` so legacy primitives
    /// (3DES, RC4, MD5-signed certs) don't get pre-filtered. OpenSSL-only.
    pub seclevel_zero: bool,
}

impl HandshakeConstraint {
    /// Constrain to one TLS version only (min == max).
    pub fn version_only(v: TlsVersion) -> Self {
        Self {
            version_range: Some((v, v)),
            ..Self::default()
        }
    }

    /// Constrain the ClientHello cipher list to a single IANA
    /// codepoint. No version constraint — the backend infers the
    /// applicable TLS version from the suite.
    pub fn single_cipher(code: u16) -> Self {
        Self {
            cipher_suites: Some(vec![code]),
            ..Self::default()
        }
    }

    /// Constrain the ClientHello cipher list to a single codepoint at
    /// a specific TLS version.
    pub fn single_cipher_at(code: u16, v: TlsVersion) -> Self {
        Self {
            version_range: Some((v, v)),
            cipher_suites: Some(vec![code]),
            ..Self::default()
        }
    }

    /// Constrain `supported_groups`/`key_share` to a single IANA
    /// codepoint at a specific TLS version.
    pub fn single_group_at(code: u16, v: TlsVersion) -> Self {
        Self {
            version_range: Some((v, v)),
            groups: Some(vec![code]),
            ..Self::default()
        }
    }
}

/// All observations produced by one probe handshake. Most fields are
/// `Option` because not every backend surfaces every datum — e.g. DH
/// parameter snapshots only come from OpenSSL handshakes involving
/// ephemeral DH, and OCSP bytes only come from a characterization
/// handshake rustls can verify.
#[derive(Debug, Clone)]
pub struct HandshakeResult {
    pub outcome: HandshakeOutcome,
    pub negotiated: Option<NegotiatedState>,
    pub cert_chain_der: Vec<Vec<u8>>,
    /// Parsed certificate chain, when a characterization-style handshake
    /// exposed it. Reuses [`CertificateInfo`] for schema compatibility.
    pub cert_chain: Vec<CertificateInfo>,
    pub alpn_negotiated: Option<Vec<u8>>,
    /// Normalized alert category string when the handshake failed at
    /// the wire level (e.g. `"tls_alert_handshake_failure"`).
    pub alert: Option<String>,
    /// DH parameter snapshot from a completed DHE handshake. OpenSSL
    /// only; rustls does not expose the peer `tmp_key` API.
    #[cfg(feature = "legacy-probes")]
    pub dh_parameters: Option<DhSnapshot>,
    /// TLS 1.2 ServerKeyExchange signature algorithm name, or TLS 1.3
    /// CertificateVerify sigalg. Surfaced by whichever backend ran the
    /// handshake and could read it.
    pub ske_signature_name: Option<String>,
    /// Raw OCSP response bytes delivered in the TLS extension.
    pub ocsp_response_bytes: Option<Vec<u8>>,
    /// Signature scheme observed on the handshake (rustls path captures
    /// this via the verifier callback; OpenSSL exposes it via
    /// `SSL_get_peer_signature_name`).
    pub signature_scheme_observed: Option<String>,
}

impl HandshakeResult {
    /// Construct a minimal result carrying only the handshake outcome.
    /// Used by single-codepoint probes (cipher / group enumeration)
    /// that don't surface observer fields; callers that capture DH
    /// params / SKE sigalg / etc. fill those slots after construction.
    pub fn outcome_only(outcome: HandshakeOutcome) -> Self {
        Self {
            outcome,
            negotiated: None,
            cert_chain_der: Vec::new(),
            cert_chain: Vec::new(),
            alpn_negotiated: None,
            alert: None,
            #[cfg(feature = "legacy-probes")]
            dh_parameters: None,
            ske_signature_name: None,
            ocsp_response_bytes: None,
            signature_scheme_observed: None,
        }
    }
}

/// Returned from `handshake()` when the backend cannot honor the
/// combination of constraints supplied. The orchestrator translates
/// this into a schema `method: not_probed, reason: <reason>` entry —
/// never silently drops the probe.
#[derive(Debug, Clone)]
pub struct UnsatisfiableConstraint {
    pub reason: String,
}

impl UnsatisfiableConstraint {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

/// Which `HandshakeConstraint` axes a backend can honor. Lets the
/// orchestrator check feasibility cheaply without catching errors from
/// every `handshake()` call.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConstraintCapabilities {
    pub version_range: bool,
    pub cipher_suites: bool,
    pub groups: bool,
    pub sigalgs: bool,
    pub alpn: bool,
    pub send_fallback_scsv: bool,
    pub seclevel_zero: bool,
}

/// The abstraction every TLS library plugs into. Backends own their
/// inventory and their handshake primitive; routing between them lives
/// in `BackendRegistry` + the orchestrator.
#[async_trait]
pub trait TlsBackend: Send + Sync {
    /// Short stable identifier — matches `BackendInventory::id`.
    fn id(&self) -> &'static str;

    fn inventory(&self) -> &BackendInventory;

    fn constraint_capabilities(&self) -> ConstraintCapabilities;

    /// Drive exactly one handshake attempt with the supplied constraints
    /// applied to the ClientHello. Returns `Err(UnsatisfiableConstraint)`
    /// when the backend cannot honor the constraint combination (e.g.
    /// rustls asked to set `seclevel_zero`). Does not retry on transient
    /// failures — that's a caller concern.
    async fn handshake(
        &self,
        constraint: HandshakeConstraint,
        ctx: &ProbeContext,
    ) -> Result<HandshakeResult, UnsatisfiableConstraint>;
}
