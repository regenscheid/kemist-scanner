//! Backend registry + per-codepoint priority routing.
//!
//! Orchestrator-side dispatch: given an IANA cipher / group codepoint,
//! the registry returns the one backend responsible for probing it.
//! Previously this decision was split across two places — aws-lc-rs
//! probed everything it could, then `src/output/json.rs` merged OpenSSL
//! results on top wherever aws-lc-rs reported `not_probed`. The registry
//! replaces that post-hoc merge with an explicit per-codepoint priority
//! table built from the two inventories at construction time.
//!
//! Current backends' codepoint sets don't overlap, so "priority" is
//! effectively "which backend owns this codepoint." Encoded explicitly
//! anyway so adding a third backend (BoringSSL, s2n-tls, liboqs) that
//! overlaps with either requires a deliberate entry in this table rather
//! than a silent first-backend-wins race.

use std::collections::HashMap;

use crate::model::protocol::TlsVersion;
#[cfg(feature = "legacy-probes")]
use crate::scanner::backends::OpensslBackend;
use crate::scanner::backends::{RustlsBackend, TlsBackend};

/// Short stable backend identifier. Matches `BackendInventory::id` and
/// `TlsBackend::id` so routing can be stored as a plain string without
/// needing trait-object references.
type BackendId = &'static str;

const ID_RUSTLS: BackendId = "aws_lc_rs";
#[cfg(feature = "legacy-probes")]
const ID_OPENSSL: BackendId = "openssl";

/// Owns every available backend instance plus the per-codepoint priority
/// tables. Built once per scan and shared across probes.
pub struct BackendRegistry {
    pub rustls: RustlsBackend,
    #[cfg(feature = "legacy-probes")]
    pub openssl: OpensslBackend,
    cipher_priority: HashMap<u16, BackendId>,
    group_priority: HashMap<u16, BackendId>,
    version_priority: HashMap<TlsVersion, BackendId>,
}

impl BackendRegistry {
    /// Build a registry with the backends available in the current
    /// build configuration. Feature-gated: OpenSSL backend is present
    /// only when `legacy-probes` is compiled in.
    pub fn new() -> Self {
        let rustls = RustlsBackend::new();
        #[cfg(feature = "legacy-probes")]
        let openssl = OpensslBackend::new();

        let mut cipher_priority: HashMap<u16, BackendId> = HashMap::new();
        let mut group_priority: HashMap<u16, BackendId> = HashMap::new();
        let mut version_priority: HashMap<TlsVersion, BackendId> = HashMap::new();

        // Rustls claims everything in its inventory first. This captures
        // the modern TLS 1.2/1.3 AEAD suites + classical/PQC curves
        // aws-lc-rs ships.
        for code in &rustls.inventory().cipher_codepoints {
            cipher_priority.insert(*code, ID_RUSTLS);
        }
        for code in &rustls.inventory().group_codepoints {
            group_priority.insert(*code, ID_RUSTLS);
        }
        for v in &rustls.inventory().supported_versions {
            version_priority.insert(*v, ID_RUSTLS);
        }

        // OpenSSL fills in codepoints rustls does not claim: legacy
        // ciphers (RSA-kex, RC4, 3DES, NULL, anon-DH, etc.), FFDHE
        // groups, rustls-unshipped curves (X448, secp521r1, MLKEM512/1024,
        // secp384r1MLKEM1024), and pre-TLS-1.2 protocol versions.
        //
        // Today the codepoint sets don't overlap — rustls claims only
        // what aws-lc-rs ships at build time, OpenSSL claims legacy
        // codepoints aws-lc-rs explicitly doesn't ship. `entry().or_insert`
        // makes the non-overlap explicit: rustls wins any future tie,
        // OpenSSL only fills gaps.
        #[cfg(feature = "legacy-probes")]
        {
            for code in &openssl.inventory().cipher_codepoints {
                cipher_priority.entry(*code).or_insert(ID_OPENSSL);
            }
            for code in &openssl.inventory().group_codepoints {
                group_priority.entry(*code).or_insert(ID_OPENSSL);
            }
            for v in &openssl.inventory().supported_versions {
                version_priority.entry(*v).or_insert(ID_OPENSSL);
            }
        }

        Self {
            rustls,
            #[cfg(feature = "legacy-probes")]
            openssl,
            cipher_priority,
            group_priority,
            version_priority,
        }
    }

    /// Union of cipher codepoints across all present backends, sorted
    /// ascending for deterministic iteration order.
    pub fn merged_cipher_codepoints(&self) -> Vec<u16> {
        let mut v: Vec<u16> = self.cipher_priority.keys().copied().collect();
        v.sort_unstable();
        v
    }

    /// Union of group codepoints across all present backends, sorted
    /// ascending.
    pub fn merged_group_codepoints(&self) -> Vec<u16> {
        let mut v: Vec<u16> = self.group_priority.keys().copied().collect();
        v.sort_unstable();
        v
    }

    /// All TLS versions any backend claims, ordered by `TlsVersion`'s
    /// natural ordering (oldest first). Used by the version-probing
    /// orchestrator loop.
    pub fn merged_versions(&self) -> Vec<TlsVersion> {
        let mut v: Vec<TlsVersion> = self.version_priority.keys().copied().collect();
        v.sort();
        v
    }

    /// Return the backend responsible for probing `code`, or `None`
    /// if no backend claims it.
    pub fn route_cipher(&self, code: u16) -> Option<&dyn TlsBackend> {
        self.cipher_priority
            .get(&code)
            .and_then(|id| self.backend_by_id(id))
    }

    pub fn route_group(&self, code: u16) -> Option<&dyn TlsBackend> {
        self.group_priority
            .get(&code)
            .and_then(|id| self.backend_by_id(id))
    }

    pub fn route_version(&self, v: TlsVersion) -> Option<&dyn TlsBackend> {
        self.version_priority
            .get(&v)
            .and_then(|id| self.backend_by_id(id))
    }

    fn backend_by_id(&self, id: &BackendId) -> Option<&dyn TlsBackend> {
        match *id {
            ID_RUSTLS => Some(&self.rustls),
            #[cfg(feature = "legacy-probes")]
            ID_OPENSSL => Some(&self.openssl),
            _ => None,
        }
    }
}

impl Default for BackendRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modern_aead_cipher_routes_to_rustls() {
        let r = BackendRegistry::new();
        // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 — universally
        // shipped in aws-lc-rs.
        let be = r.route_cipher(0xC02C).expect("cipher routed");
        assert_eq!(be.id(), "aws_lc_rs");
    }

    #[cfg(feature = "legacy-probes")]
    #[test]
    fn legacy_cipher_routes_to_openssl() {
        let r = BackendRegistry::new();
        // TLS_RSA_WITH_RC4_128_SHA — only OpenSSL probes this.
        let be = r.route_cipher(0x0005).expect("cipher routed");
        assert_eq!(be.id(), "openssl");
    }

    #[test]
    fn unknown_cipher_returns_none() {
        let r = BackendRegistry::new();
        assert!(r.route_cipher(0xFFFF).is_none());
    }

    #[test]
    fn shipped_group_routes_to_rustls() {
        let r = BackendRegistry::new();
        // X25519 — universally shipped in aws-lc-rs.
        let be = r.route_group(0x001D).expect("group routed");
        assert_eq!(be.id(), "aws_lc_rs");
    }

    #[cfg(feature = "legacy-probes")]
    #[test]
    fn rustls_unshipped_group_routes_to_openssl() {
        let r = BackendRegistry::new();
        // X448, secp521r1, MLKEM512, MLKEM1024, secp384r1MLKEM1024.
        for code in [0x001E, 0x0019, 0x0200, 0x0202, 0x11ED] {
            let be = r.route_group(code).unwrap_or_else(|| {
                panic!("group 0x{:04X} not routed", code)
            });
            assert_eq!(
                be.id(),
                "openssl",
                "group 0x{:04X} routed to wrong backend",
                code
            );
        }
    }

    #[cfg(feature = "legacy-probes")]
    #[test]
    fn ffdhe_groups_route_to_openssl() {
        let r = BackendRegistry::new();
        for code in [0x0100, 0x0101, 0x0102, 0x0103, 0x0104] {
            let be = r.route_group(code).expect("ffdhe routed");
            assert_eq!(be.id(), "openssl");
        }
    }

    #[test]
    fn tls13_version_routes_to_rustls() {
        let r = BackendRegistry::new();
        let be = r.route_version(TlsVersion::Tls13).expect("version routed");
        assert_eq!(be.id(), "aws_lc_rs");
    }

    #[cfg(feature = "legacy-probes")]
    #[test]
    fn legacy_versions_route_to_openssl() {
        let r = BackendRegistry::new();
        for v in [TlsVersion::Ssl3, TlsVersion::Tls10, TlsVersion::Tls11] {
            let be = r.route_version(v).expect("version routed");
            assert_eq!(be.id(), "openssl");
        }
    }

    #[test]
    fn merged_codepoints_are_sorted_and_deduped() {
        let r = BackendRegistry::new();
        let ciphers = r.merged_cipher_codepoints();
        let mut expected = ciphers.clone();
        expected.sort_unstable();
        expected.dedup();
        assert_eq!(ciphers, expected, "merged cipher list not sorted+deduped");

        let groups = r.merged_group_codepoints();
        let mut expected = groups.clone();
        expected.sort_unstable();
        expected.dedup();
        assert_eq!(groups, expected, "merged group list not sorted+deduped");
    }
}
