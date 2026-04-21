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

use crate::model::protocol::TlsVersion;

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
