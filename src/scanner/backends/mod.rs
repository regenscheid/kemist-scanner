//! Backend abstraction scaffolding.
//!
//! Stage 0 of the TLS backend refactor: introduces `BackendInventory`,
//! a declaration of which codepoints a given TLS library can probe.
//! Later stages build the `TlsBackend` trait + `BackendRegistry` on top
//! so the orchestrator routes probes by codepoint instead of by
//! hand-wired branches per call site.
//!
//! An inventory is the single source of truth for "what can this
//! backend see?" — both the capabilities block in schema output
//! (`capabilities.provider_cipher_suites`, `.provider_kx_groups`) and
//! the classification-coverage test under `tests/` consume it.

use crate::model::errors::ScannerError;
use crate::model::protocol::TlsVersion;

/// Outcome of a single probe handshake. Unifies the per-probe-family
/// outcome enums that used to live alongside each probe (`ProbeOutcome`,
/// `LegacyProbeOutcome`, `GroupProbeOutcome`, `KxGroupOutcome`).
///
/// Not every probe family produces every variant — `NotProbed` is only
/// emitted by group probes (aws-lc-rs doesn't ship some named groups;
/// FFDHE at TLS 1.2 doesn't apply to ECDH codepoints), and
/// `IgnoredGroupReturnedCustomPrime` is FFDHE-specific. Cipher probes
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
    /// ignored our `supported_groups` offer. Meaningless for ECDH /
    /// ML-KEM / cipher probes.
    IgnoredGroupReturnedCustomPrime,
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
    /// Short strings describing what this backend cannot do. Flows into
    /// `capabilities.probe_limitations` in later stages; Stage 0 leaves
    /// it empty to preserve byte-identical output.
    pub limitations: Vec<&'static str>,
}

/// Build the rustls / aws-lc-rs backend inventory from runtime
/// enumeration of `ALL_CIPHER_SUITES` and `ALL_KX_GROUPS`. Formatting
/// matches the legacy inline build in `src/output/json.rs` so the
/// capabilities block stays byte-identical through Stage 0.
pub fn rustls_inventory() -> BackendInventory {
    let mut cipher_codepoints = Vec::new();
    let mut cipher_names = Vec::new();
    for s in rustls::crypto::aws_lc_rs::ALL_CIPHER_SUITES {
        cipher_codepoints.push(s.suite().into());
        cipher_names.push(format!("{:?}", s.suite()));
    }
    let mut group_codepoints = Vec::new();
    let mut group_names = Vec::new();
    for g in rustls::crypto::aws_lc_rs::ALL_KX_GROUPS {
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
/// tables in `scanner::openssl::{ciphers, kx_groups}`. Stage 4 will
/// relocate those tables under `backends/openssl/`; until then this
/// function reaches into the existing modules for their canonical data.
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
