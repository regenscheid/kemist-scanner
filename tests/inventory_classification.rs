//! Inventory-driven classification coverage.
//!
//! The `BackendInventory` instances are the single source of truth for
//! "which cipher codepoints does kemist probe." These tests assert two
//! contracts:
//!
//! 1. Every cipher name in every backend's inventory classifies to a
//!    non-`Other` `CipherClassification` variant. A new codepoint
//!    landing in aws-lc-rs (via an upstream bump) or in an OpenSSL
//!    target list must either classify to a known variant or extend
//!    the enum — never silently emit `Other` through production JSON.
//!
//! 2. Every `CipherClassification` variant in `EXPECTED_REACHED` is hit
//!    by at least one inventoried cipher, so no variant silently goes
//!    permanently unreached as probe coverage evolves.
//!
//! Variants excluded from `EXPECTED_REACHED` are known inventory gaps
//! documented in the list below. Adding a probe that reaches one of
//! those variants should move it into `EXPECTED_REACHED` as a tripwire
//! against regression.

use kemist::model::cipher_classification::{classify, CipherClassification};

// Pulled in from the crate-internal `scanner::backends` module. That
// module is `pub` so the test can reach it; schema-visible API remains
// `kemist::{Scanner, ScanResult, ...}` re-exports in src/lib.rs.
use kemist::scanner::backends::all_inventories;

/// Variants expected to be reachable from the current inventory.
/// Intentionally omits:
/// - `CipherClassification::Export` — no export-grade probe shipped.
///   Separate gap-fix workstream; see docs/CHECKS.md.
/// - `CipherClassification::RsaPsk` — no `TLS_RSA_PSK_*` probe
///   shipped; closed-ecosystem suite.
/// - `CipherClassification::Other` — fallback-only, never expected in
///   probe inventory.
const EXPECTED_REACHED: &[CipherClassification] = &[
    CipherClassification::RsaKex,
    CipherClassification::DheAead,
    CipherClassification::DheCbc,
    CipherClassification::EcdheAead,
    CipherClassification::EcdheCbc,
    CipherClassification::Anon,
    CipherClassification::StaticDh,
    CipherClassification::StaticEcdh,
    CipherClassification::Psk,
    CipherClassification::DhePsk,
    CipherClassification::EcdhePsk,
    CipherClassification::NullCipher,
];

#[test]
fn every_inventoried_cipher_classifies_to_known_variant() {
    let mut unmapped: Vec<(String, String)> = Vec::new();
    for inv in all_inventories() {
        for name in &inv.cipher_names {
            if classify(name) == CipherClassification::Other {
                unmapped.push((inv.id.to_string(), name.clone()));
            }
        }
    }
    assert!(
        unmapped.is_empty(),
        "cipher suites classify to Other — extend CipherClassification or \
         classify(): {:?}",
        unmapped
    );
}

#[test]
fn every_expected_variant_is_reached_by_some_inventory_entry() {
    let mut reached: Vec<CipherClassification> = Vec::new();
    for inv in all_inventories() {
        for name in &inv.cipher_names {
            let c = classify(name);
            if !reached.contains(&c) {
                reached.push(c);
            }
        }
    }

    let missing: Vec<_> = EXPECTED_REACHED
        .iter()
        .filter(|v| !reached.contains(v))
        .collect();

    assert!(
        missing.is_empty(),
        "expected-reached classifications not hit by any inventoried \
         cipher: {:?}. Either add a probe that reaches them or remove \
         them from EXPECTED_REACHED with justification.",
        missing
    );
}
