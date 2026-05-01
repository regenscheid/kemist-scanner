//! Integration tests for the OpenSSL legacy-probe subsystem.
//!
//! These are **ignored by default** (`#[ignore]`) — they require a live
//! fixture listening on `$KEMIST_LEGACY_FIXTURE_ADDR` with SNI
//! `$KEMIST_LEGACY_FIXTURE_HOSTNAME`. The fixture at
//! [tests/fixtures/legacy-server/](./fixtures/legacy-server/) provides
//! such a server; CI boots it in the `legacy_fixture_test` job before
//! running these tests.
//!
//! Run locally with:
//!
//! ```bash
//! cd tests/fixtures/legacy-server && ./generate-certs.sh && \
//!   docker compose up -d
//!
//! KEMIST_LEGACY_FIXTURE_ADDR=127.0.0.1:14443 \
//! KEMIST_LEGACY_FIXTURE_HOSTNAME=legacy-fixture.local \
//!   cargo test --features legacy-probes --test openssl_probe -- \
//!   --ignored --test-threads=1
//! ```
//!
//! `--test-threads=1` avoids port contention if multiple tests connect
//! simultaneously. The probes are cheap but the fixture has finite
//! worker connections.

#![cfg(feature = "legacy-probes")]

use std::net::SocketAddr;
use std::time::Duration;

use kemist::model::protocol::TlsVersion;
use kemist::scanner::backends::HandshakeOutcome;
use kemist::scanner::openssl::{
    ciphers::probe_legacy_suites,
    fallback_scsv,
    kx_groups::probe_kx_groups,
    protocol_versions,
    renegotiation::{self, RenegotiationVerdict},
};

const FIXTURE_ADDR_ENV: &str = "KEMIST_LEGACY_FIXTURE_ADDR";
const FIXTURE_HOSTNAME_ENV: &str = "KEMIST_LEGACY_FIXTURE_HOSTNAME";

/// Resolve fixture target from env. Panics with a helpful message when
/// the variables are missing — these tests only run under `--ignored`
/// so the panic won't fire in the default `cargo test` pass.
fn fixture() -> (SocketAddr, String) {
    let addr_s = std::env::var(FIXTURE_ADDR_ENV).unwrap_or_else(|_| {
        panic!(
            "missing env {FIXTURE_ADDR_ENV}; boot tests/fixtures/legacy-server/ first, see its README"
        )
    });
    let addr: SocketAddr = addr_s
        .parse()
        .unwrap_or_else(|e| panic!("{FIXTURE_ADDR_ENV}={addr_s} is not a valid socket addr: {e}"));
    let hostname =
        std::env::var(FIXTURE_HOSTNAME_ENV).unwrap_or_else(|_| "legacy-fixture.local".to_string());
    (addr, hostname)
}

fn timeout() -> Duration {
    Duration::from_secs(8)
}

#[tokio::test]
#[ignore]
async fn legacy_cipher_probe_observes_weak_suites_on_fixture() {
    let (addr, hostname) = fixture();
    let out = probe_legacy_suites(addr, &hostname, timeout(), timeout(), Duration::ZERO).await;

    assert!(!out.results.is_empty(), "probe produced no results");

    // At least one of the RSA-kex or weak suites should be Supported —
    // that's what makes this fixture a "fixture."
    let any_supported = out
        .results
        .iter()
        .any(|r| matches!(r.outcome, HandshakeOutcome::Supported));
    assert!(
        any_supported,
        "fixture didn't accept any legacy suite (nginx config drift?)"
    );

    // Every probe should be either Supported, NotSupported, WireRejected,
    // Error, or NotProbed — never silently missing.
    // `IgnoredGroupReturnedDifferentPrime` is group-probe-only and should
    // never appear here. Cipher probes emit
    // `NotProbed("openssl_3x_cipher_not_available:*")` for suites OpenSSL
    // 3.x refuses to activate at context build time (static-DH /
    // static-ECDH, occasionally RC4 / 3DES on distros that ship openssl
    // with those disabled) — a legitimate backend-capability signal,
    // not a missing observation. `WireRejected` is emitted by the
    // raw-socket static-DH probes when the server tears the connection
    // down with a TCP RST after our ClientHello.
    for r in &out.results {
        match &r.outcome {
            HandshakeOutcome::Supported
            | HandshakeOutcome::NotSupported
            | HandshakeOutcome::WireRejected { .. }
            | HandshakeOutcome::Error(_)
            | HandshakeOutcome::NotProbed(_) => {}
            HandshakeOutcome::IgnoredGroupReturnedDifferentPrime { .. } => {
                panic!(
                    "cipher probe produced unexpected outcome variant for {}",
                    r.name
                );
            }
        }
    }

    // DHE-RSA probe should populate a DH snapshot with the fixture's
    // deliberately weak 1024-bit custom prime.
    let dhe = out.results.iter().find(|r| {
        r.openssl_name.starts_with("DHE-RSA") && matches!(r.outcome, HandshakeOutcome::Supported)
    });
    if let Some(r) = dhe {
        let snap = r
            .dh_snapshot
            .as_ref()
            .expect("DHE handshake must produce a DH snapshot");
        assert_eq!(snap.prime_bits, 1024, "fixture serves 1024-bit custom DH");
        assert_eq!(
            snap.classification,
            kemist::scanner::openssl::dh_params::DhClassification::Custom,
            "1024-bit prime is not RFC 7919 — must classify as custom"
        );
    }
}

#[tokio::test]
#[ignore]
async fn kx_group_probe_records_per_version_outcomes_on_fixture() {
    let (addr, hostname) = fixture();
    let out = probe_kx_groups(addr, &hostname, timeout(), timeout(), Duration::ZERO).await;

    // Inventory: five FFDHE + five TLS 1.3 non-FFDHE groups aws-lc-rs
    // doesn't ship (X448, secp521r1, MLKEM512/1024, secp384r1MLKEM1024)
    // + three brainpool curves + three deprecated named curves
    // OpenSSL 3.x refuses at handshake-build time (secp192r1, secp224r1,
    // secp256k1). The last six are tripwires: they shrink if a future
    // openssl-src dropped them, expand if new curves land in the probe
    // list.
    assert_eq!(out.results.len(), 16);

    // Every TLS 1.2 / TLS 1.3 cell is populated with some outcome.
    for r in &out.results {
        assert!(matches!(
            r.tls12_outcome,
            HandshakeOutcome::Supported
                | HandshakeOutcome::NotSupported
                | HandshakeOutcome::IgnoredGroupReturnedDifferentPrime { .. }
                | HandshakeOutcome::Error(_)
                | HandshakeOutcome::NotProbed(_)
        ));
        assert!(matches!(
            r.tls13_outcome,
            HandshakeOutcome::Supported
                | HandshakeOutcome::NotSupported
                | HandshakeOutcome::IgnoredGroupReturnedDifferentPrime { .. }
                | HandshakeOutcome::Error(_)
                | HandshakeOutcome::NotProbed(_)
        ));
    }
}

#[tokio::test]
#[ignore]
async fn fallback_scsv_probe_returns_definitive_verdict_on_fixture() {
    let (addr, hostname) = fixture();
    let result = fallback_scsv::probe(addr, &hostname, timeout(), timeout()).await;

    // OpenSSL 1.1.1 nginx enforces RFC 7507. The exact rendering depends
    // on server config, but the probe should land a real verdict
    // (Some(true) or Some(false)) rather than None/inconclusive.
    assert!(
        result.enforced.is_some() || result.reason.contains("no_downgrade_possible"),
        "SCSV probe was inconclusive despite fixture supporting both TLS 1.2 and 1.3: {result:?}"
    );
}

#[tokio::test]
#[ignore]
async fn renegotiation_probe_reports_rejected_on_fixture() {
    let (addr, hostname) = fixture();
    let obs = renegotiation::probe(addr, &hostname, timeout(), timeout()).await;

    // nginx disables client-initiated renegotiation by default. Either
    // a rejected verdict (expected) or NotAttempted (if TLS 1.2 probe
    // failed to complete on a busy runner) is acceptable; Accepted
    // would indicate a fixture regression.
    assert!(
        !matches!(
            obs.client_initiated_verdict,
            RenegotiationVerdict::ClientInitiatedAccepted
        ),
        "fixture unexpectedly accepted client-initiated renegotiation: {obs:?}"
    );
}

#[tokio::test]
#[ignore]
async fn protocol_version_probe_observes_legacy_versions_on_fixture() {
    let (addr, hostname) = fixture();

    // TLS 1.0 and TLS 1.1 are explicitly enabled in nginx.conf.
    for version in [TlsVersion::Tls10, TlsVersion::Tls11] {
        let p =
            protocol_versions::probe_protocol(addr, &hostname, version, timeout(), timeout()).await;
        assert!(
            p.supported,
            "fixture should accept {:?} but reported supported={} (error: {:?})",
            version, p.supported, p.error
        );
    }
}
