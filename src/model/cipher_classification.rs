//! TLS cipher-suite classification enum.
//!
//! Every [`CipherSuiteEntry`] the scanner emits carries a
//! `classification` label computed via [`classify`]. Downstream rule
//! engines use it instead of string-prefix-matching the suite name,
//! so any name-format churn or new suite addition doesn't break
//! their posture rules.
//!
//! The classification is **key-exchange-focused** — it tells you what
//! handshake primitives negotiated the session key. Three variants
//! are exceptions that capture privacy/auth posture directly because
//! those concerns dominate over the kx family:
//!
//! - [`NullCipher`] — the record layer carries plaintext. Matches
//!   `TLS_*_WITH_NULL_*` regardless of kx (RSA, ECDHE, etc.).
//! - [`Anon`] — no server authentication. Matches `TLS_DH_anon_*`
//!   and `TLS_ECDH_anon_*`.
//! - [`Export`] — RFC 3268 deliberately-weakened export-grade suites.
//!
//! For everything else, the classification follows the kx: `RsaKex`,
//! `DheAead`, `DheCbc`, `EcdheAead`, `EcdheCbc`, `StaticDh`,
//! `StaticEcdh`, PSK variants. TLS 1.3 suites (names starting with
//! `TLS13_`) classify as [`EcdheAead`] because their record layer is
//! AEAD-only and the handshake is always ECDHE or PSK+(EC)DHE in the
//! deployments kemist probes.
//!
//! **Stability contract:** values listed here are permanent within
//! schema v1.x. New values may be added; existing names are never
//! renamed or removed. If a new cipher suite doesn't fit any current
//! variant, [`classify`] returns [`Other`] and the exhaustive test
//! at the bottom of this module prints the unmapped name so the
//! enum can grow intentionally.
//!
//! [`CipherSuiteEntry`]: crate::model::scan_result::CipherSuiteEntry
//! [`NullCipher`]: CipherClassification::NullCipher
//! [`Anon`]: CipherClassification::Anon
//! [`Export`]: CipherClassification::Export
//! [`EcdheAead`]: CipherClassification::EcdheAead
//! [`Other`]: CipherClassification::Other

use serde::{Deserialize, Serialize};

/// Classification family for a TLS cipher suite.
///
/// Serializes as the lower-snake-case name (via `serde(rename_all)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CipherClassification {
    /// RSA key exchange — no forward secrecy. Includes RSA+AEAD
    /// suites like `TLS_RSA_WITH_AES_128_GCM_SHA256` (the AEAD is
    /// fine; the kx is the concern).
    RsaKex,
    /// DHE with AEAD record layer (`TLS_DHE_RSA_WITH_*_GCM_*`,
    /// `TLS_DHE_RSA_WITH_CHACHA20_POLY1305_*`). Forward-secret.
    DheAead,
    /// DHE with CBC record layer. Forward-secret but CBC has a
    /// history (BEAST, Lucky13); modern policies often prefer AEAD.
    DheCbc,
    /// ECDHE with AEAD record layer. The modern default. Also covers
    /// TLS 1.3 suites (`TLS13_*`) whose handshake is always ECDHE or
    /// PSK+ECDHE in practice.
    EcdheAead,
    /// ECDHE with CBC record layer.
    EcdheCbc,
    /// `TLS_DH_anon_*` / `TLS_ECDH_anon_*` — no server auth. Always a
    /// posture concern.
    Anon,
    /// RFC 3268 export-grade suites (`TLS_*_EXPORT_*`). Deliberately
    /// weakened for historical US export restrictions; should never
    /// appear on a modern server.
    Export,
    /// Static DH (`TLS_DH_RSA_*`, `TLS_DH_DSS_*`) — the server's
    /// certificate embeds a DH public key. No forward secrecy, rarely
    /// deployed.
    StaticDh,
    /// Static ECDH (`TLS_ECDH_RSA_*`, `TLS_ECDH_ECDSA_*`). Same
    /// no-forward-secrecy concern as static DH.
    StaticEcdh,
    /// Pure PSK (`TLS_PSK_WITH_*`). Pre-shared key, no DH. Used in
    /// closed ecosystems.
    Psk,
    /// PSK plus ephemeral DH (`TLS_DHE_PSK_*`). Forward-secret on
    /// top of PSK.
    DhePsk,
    /// PSK plus ephemeral ECDH (`TLS_ECDHE_PSK_*`).
    EcdhePsk,
    /// RSA plus PSK (`TLS_RSA_PSK_*`). Server auth via RSA cert +
    /// client identification via PSK.
    RsaPsk,
    /// Any suite with `NULL` encryption in the record layer
    /// (`TLS_*_WITH_NULL_*`). Plaintext data.
    NullCipher,
    /// Fallback for suites not in the current probe inventory.
    /// Emitted only when a new IANA codepoint lands that kemist
    /// hasn't been updated for. The exhaustive classification test
    /// fails loudly before this escapes.
    Other,
}

/// Classify a TLS cipher suite by its IANA name.
///
/// Input is the spec-canonical name (e.g. `"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"`
/// or `"TLS13_AES_128_GCM_SHA256"`). The function is total — every
/// input produces a classification, even if it's [`CipherClassification::Other`].
pub fn classify(name: &str) -> CipherClassification {
    // Order matters: catch-alls (NULL, EXPORT, anon) win over the
    // kx-prefix lookup because `TLS_RSA_WITH_NULL_SHA` has an
    // `RSA_WITH_` prefix but the NULL cipher is the dominant concern.
    if name.contains("_WITH_NULL") || name.contains("NULL_MD5") || name.contains("NULL_SHA") {
        return CipherClassification::NullCipher;
    }
    if name.contains("_EXPORT") || name.contains("EXPORT_") {
        return CipherClassification::Export;
    }
    if name.starts_with("TLS_DH_anon_") || name.starts_with("TLS_ECDH_anon_") {
        return CipherClassification::Anon;
    }

    // TLS 1.3 suites use a compact naming scheme (`TLS13_...`) that
    // doesn't encode kx — the handshake negotiates kx separately via
    // named_group. All TLS 1.3 suites are AEAD, and in practice the
    // handshake is ECDHE (or PSK+ECDHE); classify as EcdheAead.
    if name.starts_with("TLS13_") {
        return CipherClassification::EcdheAead;
    }

    // PSK family — check before the kx-family matches below because
    // `TLS_ECDHE_PSK_*` also starts with `TLS_ECDHE_`.
    if name.starts_with("TLS_ECDHE_PSK_") {
        return CipherClassification::EcdhePsk;
    }
    if name.starts_with("TLS_DHE_PSK_") {
        return CipherClassification::DhePsk;
    }
    if name.starts_with("TLS_RSA_PSK_") {
        return CipherClassification::RsaPsk;
    }
    if name.starts_with("TLS_PSK_") {
        return CipherClassification::Psk;
    }

    // Ephemeral (EC)DHE — subdivide by AEAD vs CBC record layer.
    if name.starts_with("TLS_ECDHE_") {
        return if is_aead_suite(name) {
            CipherClassification::EcdheAead
        } else {
            CipherClassification::EcdheCbc
        };
    }
    if name.starts_with("TLS_DHE_") {
        return if is_aead_suite(name) {
            CipherClassification::DheAead
        } else {
            CipherClassification::DheCbc
        };
    }

    // Static (EC)DH — the cert embeds the DH public key.
    if name.starts_with("TLS_DH_RSA_") || name.starts_with("TLS_DH_DSS_") {
        return CipherClassification::StaticDh;
    }
    if name.starts_with("TLS_ECDH_RSA_") || name.starts_with("TLS_ECDH_ECDSA_") {
        return CipherClassification::StaticEcdh;
    }

    // Plain RSA key exchange. Covers both CBC and AEAD record layer
    // variants; the kx is what matters for posture.
    if name.starts_with("TLS_RSA_") {
        return CipherClassification::RsaKex;
    }

    CipherClassification::Other
}

/// Heuristic: does this suite use an AEAD record layer (GCM, CCM,
/// CHACHA20_POLY1305)? Used to split ECDHE and DHE classifications
/// between AEAD and CBC variants.
fn is_aead_suite(name: &str) -> bool {
    name.contains("_GCM_") || name.contains("_CCM_") || name.contains("_CHACHA20_POLY1305")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls13_suites_classify_as_ecdhe_aead() {
        for n in [
            "TLS13_AES_128_GCM_SHA256",
            "TLS13_AES_256_GCM_SHA384",
            "TLS13_CHACHA20_POLY1305_SHA256",
        ] {
            assert_eq!(classify(n), CipherClassification::EcdheAead, "{n}");
        }
    }

    #[test]
    fn ecdhe_rsa_aead_vs_cbc() {
        assert_eq!(
            classify("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
            CipherClassification::EcdheAead
        );
        assert_eq!(
            classify("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
            CipherClassification::EcdheAead
        );
        assert_eq!(
            classify("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
            CipherClassification::EcdheCbc
        );
    }

    #[test]
    fn ecdhe_ecdsa_paths_mirror_rsa_paths() {
        assert_eq!(
            classify("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
            CipherClassification::EcdheAead
        );
        assert_eq!(
            classify("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"),
            CipherClassification::EcdheCbc
        );
    }

    #[test]
    fn dhe_splits_aead_cbc() {
        assert_eq!(
            classify("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"),
            CipherClassification::DheAead
        );
        assert_eq!(
            classify("TLS_DHE_RSA_WITH_AES_128_CBC_SHA"),
            CipherClassification::DheCbc
        );
    }

    #[test]
    fn rsa_kex_ignores_record_layer() {
        assert_eq!(
            classify("TLS_RSA_WITH_AES_128_CBC_SHA"),
            CipherClassification::RsaKex
        );
        assert_eq!(
            classify("TLS_RSA_WITH_AES_128_GCM_SHA256"),
            CipherClassification::RsaKex
        );
        assert_eq!(
            classify("TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
            CipherClassification::RsaKex
        );
        assert_eq!(
            classify("TLS_RSA_WITH_RC4_128_SHA"),
            CipherClassification::RsaKex
        );
    }

    #[test]
    fn null_dominates_kx() {
        // NULL wins even with RSA prefix.
        assert_eq!(
            classify("TLS_RSA_WITH_NULL_SHA"),
            CipherClassification::NullCipher
        );
        assert_eq!(
            classify("TLS_RSA_WITH_NULL_MD5"),
            CipherClassification::NullCipher
        );
        // Hypothetical ECDHE+NULL — still NullCipher, because null
        // encryption is the bigger concern.
        assert_eq!(
            classify("TLS_ECDHE_RSA_WITH_NULL_SHA"),
            CipherClassification::NullCipher
        );
    }

    #[test]
    fn export_dominates_kx() {
        assert_eq!(
            classify("TLS_RSA_EXPORT_WITH_RC4_40_MD5"),
            CipherClassification::Export
        );
    }

    #[test]
    fn anon_suites_classify_as_anon() {
        assert_eq!(
            classify("TLS_DH_anon_WITH_AES_128_CBC_SHA"),
            CipherClassification::Anon
        );
        assert_eq!(
            classify("TLS_ECDH_anon_WITH_AES_128_CBC_SHA"),
            CipherClassification::Anon
        );
    }

    #[test]
    fn static_dh_families() {
        assert_eq!(
            classify("TLS_DH_RSA_WITH_AES_128_CBC_SHA"),
            CipherClassification::StaticDh
        );
        assert_eq!(
            classify("TLS_DH_DSS_WITH_AES_128_CBC_SHA"),
            CipherClassification::StaticDh
        );
        assert_eq!(
            classify("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"),
            CipherClassification::StaticEcdh
        );
        assert_eq!(
            classify("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"),
            CipherClassification::StaticEcdh
        );
    }

    #[test]
    fn psk_family_variants() {
        assert_eq!(
            classify("TLS_PSK_WITH_AES_128_CBC_SHA"),
            CipherClassification::Psk
        );
        assert_eq!(
            classify("TLS_DHE_PSK_WITH_AES_128_GCM_SHA256"),
            CipherClassification::DhePsk
        );
        assert_eq!(
            classify("TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA"),
            CipherClassification::EcdhePsk
        );
        assert_eq!(
            classify("TLS_RSA_PSK_WITH_AES_128_CBC_SHA"),
            CipherClassification::RsaPsk
        );
    }

    #[test]
    fn unknown_name_falls_through_to_other() {
        assert_eq!(
            classify("TLS_FUTURE_HYPOTHETICAL_SUITE"),
            CipherClassification::Other
        );
        assert_eq!(classify(""), CipherClassification::Other);
    }

    /// Exhaustive classification coverage: every cipher suite in the
    /// probe inventory (both aws-lc-rs and OpenSSL backends) must
    /// classify to a non-`Other` variant. If this test fails, the new
    /// codepoint is printed so the enum + classify() can grow
    /// intentionally — never via a silent `Other` entry reaching
    /// production output.
    #[test]
    fn every_probe_suite_classifies_to_known_variant() {
        // Full list maintained by hand — matches what the scanner's
        // cipher-probe drivers advertise. If you add a suite to
        // src/scanner/ciphers.rs or src/scanner/openssl/ciphers.rs,
        // add it here too.
        let suites = &[
            // TLS 1.3 (aws-lc-rs)
            "TLS13_AES_128_GCM_SHA256",
            "TLS13_AES_256_GCM_SHA384",
            "TLS13_CHACHA20_POLY1305_SHA256",
            // TLS 1.2 ECDHE (aws-lc-rs)
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            // TLS 1.0/1.1/1.2 legacy (OpenSSL)
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_RSA_WITH_AES_256_CBC_SHA256",
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            "TLS_RSA_WITH_RC4_128_SHA",
            "TLS_RSA_WITH_RC4_128_MD5",
            "TLS_RSA_WITH_NULL_SHA",
            "TLS_RSA_WITH_NULL_MD5",
            "TLS_DH_anon_WITH_AES_128_CBC_SHA",
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
            // PSK family
            "TLS_PSK_WITH_AES_128_CBC_SHA",
            "TLS_PSK_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
            // Camellia
            "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
            "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
            "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
            // SEED
            "TLS_RSA_WITH_SEED_CBC_SHA",
            "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
            // ARIA
            "TLS_RSA_WITH_ARIA_128_GCM_SHA256",
            "TLS_RSA_WITH_ARIA_256_GCM_SHA384",
            "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
            // Static DH / static ECDH
            "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
            "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
            "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
        ];
        let mut unmapped = Vec::new();
        for s in suites {
            if classify(s) == CipherClassification::Other {
                unmapped.push(*s);
            }
        }
        assert!(
            unmapped.is_empty(),
            "cipher suites classify to Other — extend CipherClassification or classify(): {:?}",
            unmapped
        );
    }
}
