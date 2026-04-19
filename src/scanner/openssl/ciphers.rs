//! Phase D1 — Legacy cipher enumeration and RSA-kex probing across
//! TLS 1.0 / TLS 1.1 / TLS 1.2.
//!
//! Covers RSA-kex, RC4, single-DES/3DES, NULL, anon-DH, and a few DHE-RSA
//! suites (the last category drives the Phase D2 DH-parameter observer and
//! Phase D3 SKE signature observer, which are hooked in when those modules
//! land live).
//!
//! Probe discipline: one suite per ClientHello, single TLS version pinned
//! via `set_min/max_proto_version`, `set_security_level(0)` to unblock the
//! weak primitives, `SslVerifyMode::NONE` (we never validate in probes).
//! Outcome classification mirrors the rustls path at
//! `src/scanner/ciphers.rs:182-193` — any `tls_alert_*` or
//! `connection_refused` is `NotSupported`; other errors are `Error`.
//!
//! Execution: synchronous OpenSSL handshake wrapped in `spawn_blocking` so
//! it cooperates with the tokio runtime without pulling in `tokio-openssl`.

use std::net::SocketAddr;
use std::time::Duration;

use openssl::ssl::{HandshakeError, Ssl, SslContext, SslMethod, SslVerifyMode, SslVersion};
use tracing::{debug, info};

use crate::model::errors::ScannerError;
use crate::model::protocol::TlsVersion;
use crate::scanner::openssl::alerts;
use crate::scanner::openssl::dh_params::{self, DhSnapshot};
use crate::scanner::openssl::ske_sig;

/// Per-suite probe outcome. Parallel to
/// `crate::scanner::ciphers::ProbeOutcome` on the rustls side; downstream
/// consumers get the same three-state contract across both probe families.
#[derive(Debug, Clone)]
pub enum LegacyProbeOutcome {
    /// Handshake completed with this suite alone in the ClientHello.
    Supported,
    /// Server rejected the single-suite offer with a handshake alert or a
    /// post-ClientHello reset.
    NotSupported,
    /// Probe itself failed (TCP timeout, unexpected error). Category string
    /// from [`ScannerError`] is preserved.
    Error(String),
}

/// One per-suite probe result.
#[derive(Debug, Clone)]
pub struct LegacyCipherResult {
    /// IANA-style suite name, e.g. `"TLS_RSA_WITH_AES_128_CBC_SHA"`.
    pub name: String,
    /// OpenSSL shorthand name, e.g. `"AES128-SHA"`. Needed to reproduce the
    /// probe by hand during triage.
    pub openssl_name: String,
    /// IANA codepoint (e.g. `0x002F`).
    pub iana_code: u16,
    /// TLS version the probe targeted. Each suite may be probed at multiple
    /// versions; those appear as separate result entries.
    pub version: TlsVersion,
    pub outcome: LegacyProbeOutcome,
    /// Populated by [`crate::scanner::openssl::dh_params::snapshot`] for any
    /// handshake whose server `tmp_key` is DH (i.e. DHE-RSA suites). `None`
    /// for RSA-kex, ECDHE, and failed handshakes.
    pub dh_snapshot: Option<DhSnapshot>,
    /// Populated by Phase D3 (`ske_sig::snapshot`) — TLS 1.2
    /// ServerKeyExchange signature algorithm name.
    pub ske_sig: Option<String>,
}

/// Aggregate output of the D1 probe pass.
#[derive(Debug, Clone, Default)]
pub struct LegacyCipherProbeOutput {
    pub results: Vec<LegacyCipherResult>,
}

/// Static target-list row. Keeps allocations zero for the common case.
struct Target {
    iana_name: &'static str,
    openssl_name: &'static str,
    iana_code: u16,
    version: TlsVersion,
}

/// Hardcoded target list. Each row is one probe; the same suite at multiple
/// TLS versions is split into multiple rows so per-version server behavior
/// is observable. Source of OpenSSL short names: `openssl ciphers -V`.
const TARGETS: &[Target] = &[
    // --- TLS 1.2 ---
    // RSA key-exchange family (Logjam / ROBOT exposure surface)
    Target {
        iana_name: "TLS_RSA_WITH_AES_128_CBC_SHA",
        openssl_name: "AES128-SHA",
        iana_code: 0x002F,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_RSA_WITH_AES_256_CBC_SHA",
        openssl_name: "AES256-SHA",
        iana_code: 0x0035,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_RSA_WITH_AES_128_CBC_SHA256",
        openssl_name: "AES128-SHA256",
        iana_code: 0x003C,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_RSA_WITH_AES_256_CBC_SHA256",
        openssl_name: "AES256-SHA256",
        iana_code: 0x003D,
        version: TlsVersion::Tls12,
    },
    // Obsolete primitives
    Target {
        iana_name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        openssl_name: "DES-CBC3-SHA",
        iana_code: 0x000A,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_RSA_WITH_RC4_128_SHA",
        openssl_name: "RC4-SHA",
        iana_code: 0x0005,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_RSA_WITH_RC4_128_MD5",
        openssl_name: "RC4-MD5",
        iana_code: 0x0004,
        version: TlsVersion::Tls12,
    },
    // NULL ciphers (no encryption — should always be rejected)
    Target {
        iana_name: "TLS_RSA_WITH_NULL_SHA",
        openssl_name: "NULL-SHA",
        iana_code: 0x0002,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_RSA_WITH_NULL_MD5",
        openssl_name: "NULL-MD5",
        iana_code: 0x0001,
        version: TlsVersion::Tls12,
    },
    // Anonymous DH (no server auth)
    Target {
        iana_name: "TLS_DH_anon_WITH_AES_128_CBC_SHA",
        openssl_name: "ADH-AES128-SHA",
        iana_code: 0x0034,
        version: TlsVersion::Tls12,
    },
    // DHE-RSA — gates D2 DH-parameter observer and D3 SKE signature observer
    Target {
        iana_name: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        openssl_name: "DHE-RSA-AES128-SHA",
        iana_code: 0x0033,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        openssl_name: "DHE-RSA-AES256-SHA",
        iana_code: 0x0039,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        openssl_name: "DHE-RSA-AES128-SHA256",
        iana_code: 0x0067,
        version: TlsVersion::Tls12,
    },
    // --- TLS 1.1 ---
    Target {
        iana_name: "TLS_RSA_WITH_AES_128_CBC_SHA",
        openssl_name: "AES128-SHA",
        iana_code: 0x002F,
        version: TlsVersion::Tls11,
    },
    Target {
        iana_name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        openssl_name: "DES-CBC3-SHA",
        iana_code: 0x000A,
        version: TlsVersion::Tls11,
    },
    Target {
        iana_name: "TLS_RSA_WITH_RC4_128_SHA",
        openssl_name: "RC4-SHA",
        iana_code: 0x0005,
        version: TlsVersion::Tls11,
    },
    // --- TLS 1.0 ---
    Target {
        iana_name: "TLS_RSA_WITH_AES_128_CBC_SHA",
        openssl_name: "AES128-SHA",
        iana_code: 0x002F,
        version: TlsVersion::Tls10,
    },
    Target {
        iana_name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        openssl_name: "DES-CBC3-SHA",
        iana_code: 0x000A,
        version: TlsVersion::Tls10,
    },
    Target {
        iana_name: "TLS_RSA_WITH_RC4_128_SHA",
        openssl_name: "RC4-SHA",
        iana_code: 0x0005,
        version: TlsVersion::Tls10,
    },
];

/// Probe every suite in [`TARGETS`]. Each probe runs in `spawn_blocking` so
/// the blocking OpenSSL handshake doesn't park a tokio worker thread.
/// Honors `per_probe_delay` between consecutive probes.
pub async fn probe_legacy_suites(
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    per_probe_delay: Duration,
) -> LegacyCipherProbeOutput {
    info!(
        "OpenSSL legacy cipher probe: {} suites across TLS 1.0/1.1/1.2",
        TARGETS.len()
    );

    let mut results = Vec::with_capacity(TARGETS.len());
    let last = TARGETS.len().saturating_sub(1);

    for (i, t) in TARGETS.iter().enumerate() {
        let hostname_owned = hostname.to_string();
        let openssl_name = t.openssl_name.to_string();
        let version = t.version;
        let target_addr = target;

        let probe_out = tokio::task::spawn_blocking(move || {
            probe_single_suite_blocking(
                target_addr,
                &hostname_owned,
                &openssl_name,
                version,
                connect_timeout,
                handshake_timeout,
            )
        })
        .await
        .unwrap_or_else(|join_err| ProbeRun {
            outcome: LegacyProbeOutcome::Error(format!("spawn_blocking_panic: {join_err}")),
            dh_snapshot: None,
            ske_sig: None,
        });

        debug!(
            suite = %t.openssl_name,
            version = ?t.version,
            outcome = ?probe_out.outcome,
            dh_captured = probe_out.dh_snapshot.is_some(),
            ske_sig = ?probe_out.ske_sig,
            "legacy probe result"
        );

        results.push(LegacyCipherResult {
            name: t.iana_name.to_string(),
            openssl_name: t.openssl_name.to_string(),
            iana_code: t.iana_code,
            version: t.version,
            outcome: probe_out.outcome,
            dh_snapshot: probe_out.dh_snapshot,
            ske_sig: probe_out.ske_sig,
        });

        if i < last && !per_probe_delay.is_zero() {
            tokio::time::sleep(per_probe_delay).await;
        }
    }

    LegacyCipherProbeOutput { results }
}

/// Internal return value of [`probe_single_suite_blocking`] — outcome plus
/// any post-handshake observations (D2 DH snapshot, D3 SKE signature).
struct ProbeRun {
    outcome: LegacyProbeOutcome,
    dh_snapshot: Option<DhSnapshot>,
    ske_sig: Option<String>,
}

/// Synchronous single-suite probe. Called inside `spawn_blocking`. Never
/// panics, never returns Err; failure categories fold into
/// `LegacyProbeOutcome::Error`. On handshake success, also observes DH
/// parameters (D2) if the server's tmp key is DH.
fn probe_single_suite_blocking(
    target: SocketAddr,
    hostname: &str,
    openssl_cipher_name: &str,
    version: TlsVersion,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> ProbeRun {
    let Some(ossl_version) = tls_version_to_ossl(version) else {
        return ProbeRun {
            outcome: LegacyProbeOutcome::Error(format!(
                "unsupported_tls_version_for_openssl:{version:?}"
            )),
            dh_snapshot: None,
            ske_sig: None,
        };
    };

    // TCP connect under connect_timeout. `connect_timeout` enforces
    // the SYN deadline; after that the socket read/write timeouts bound
    // the handshake phase.
    let tcp = match std::net::TcpStream::connect_timeout(&target, connect_timeout) {
        Ok(s) => s,
        Err(e) => {
            let se = ScannerError::from_io("openssl tcp connect", e);
            return ProbeRun {
                outcome: classify_scanner_error(se),
                dh_snapshot: None,
                ske_sig: None,
            };
        }
    };
    let _ = tcp.set_read_timeout(Some(handshake_timeout));
    let _ = tcp.set_write_timeout(Some(handshake_timeout));

    let ctx = match build_legacy_context(ossl_version, openssl_cipher_name) {
        Ok(c) => c,
        Err(stack) => {
            // Usually means the cipher name isn't recognized by the local
            // OpenSSL build. Classify as Error, not NotSupported — this is
            // a kemist-side bug, not a server observation.
            return ProbeRun {
                outcome: LegacyProbeOutcome::Error(format!("openssl_ctx_build: {stack}")),
                dh_snapshot: None,
                ske_sig: None,
            };
        }
    };

    let mut ssl = match Ssl::new(&ctx) {
        Ok(s) => s,
        Err(stack) => {
            return ProbeRun {
                outcome: LegacyProbeOutcome::Error(format!("openssl_ssl_new: {stack}")),
                dh_snapshot: None,
                ske_sig: None,
            }
        }
    };
    // Best-effort SNI; failure here is unlikely and non-fatal.
    let _ = ssl.set_hostname(hostname);

    match ssl.connect(tcp) {
        Ok(stream) => {
            // Handshake completed. Observe DH parameters (D2) and the
            // server's signature algorithm (D3). Both return None for
            // handshakes where the observation doesn't apply (e.g. RSA-kex
            // has no SKE signature; ECDHE has no DH parameters). A
            // snapshot-level ErrorStack from D2 is swallowed — the
            // Supported outcome is the primary signal.
            let dh_snapshot = dh_params::snapshot(stream.ssl()).unwrap_or(None);
            let ske_sig = ske_sig::snapshot(stream.ssl());
            ProbeRun {
                outcome: LegacyProbeOutcome::Supported,
                dh_snapshot,
                ske_sig,
            }
        }
        Err(HandshakeError::Failure(mid)) => {
            let se = alerts::classify_openssl_error("openssl handshake", mid.error());
            ProbeRun {
                outcome: classify_scanner_error(se),
                dh_snapshot: None,
                ske_sig: None,
            }
        }
        Err(HandshakeError::SetupFailure(stack)) => ProbeRun {
            outcome: LegacyProbeOutcome::Error(format!("openssl_setup: {stack}")),
            dh_snapshot: None,
            ske_sig: None,
        },
        Err(HandshakeError::WouldBlock(_)) => {
            // Shouldn't happen with blocking socket + set_*_timeout; if it
            // does, record as Error so the anomaly surfaces rather than
            // masquerading as NotSupported.
            ProbeRun {
                outcome: LegacyProbeOutcome::Error("openssl_would_block".to_string()),
                dh_snapshot: None,
                ske_sig: None,
            }
        }
    }
}

/// Build a single-suite `SslContext` pinned to one TLS version. Mirrors the
/// plan's §5 constraints: seclevel 0, verify NONE, one cipher.
fn build_legacy_context(
    ossl_version: SslVersion,
    cipher_list: &str,
) -> Result<SslContext, openssl::error::ErrorStack> {
    let mut builder = SslContext::builder(SslMethod::tls_client())?;
    builder.set_min_proto_version(Some(ossl_version))?;
    builder.set_max_proto_version(Some(ossl_version))?;
    builder.set_security_level(0);
    builder.set_cipher_list(cipher_list)?;
    builder.set_verify(SslVerifyMode::NONE);
    Ok(builder.build())
}

/// Project our TLS version enum onto OpenSSL's constants. SSLv2 has no
/// OpenSSL 3.x representation (the protocol was dropped entirely); SSLv3
/// resolves but requires the legacy provider and seclevel 0 — D8 handles
/// that pathway explicitly, D1 restricts itself to TLS 1.0+.
fn tls_version_to_ossl(v: TlsVersion) -> Option<SslVersion> {
    match v {
        TlsVersion::Tls10 => Some(SslVersion::TLS1),
        TlsVersion::Tls11 => Some(SslVersion::TLS1_1),
        TlsVersion::Tls12 => Some(SslVersion::TLS1_2),
        TlsVersion::Tls13 => Some(SslVersion::TLS1_3),
        TlsVersion::Ssl3 => Some(SslVersion::SSL3),
        TlsVersion::Ssl2 => None,
    }
}

/// Fold a [`ScannerError`] into the probe-outcome shape.
///
/// Mirrors `crate::scanner::ciphers::classify_probe_error`: any `tls_alert_*`
/// or `connection_refused` is promoted to `NotSupported`. Everything else is
/// `Error` with the category string preserved so rule engines can read it.
fn classify_scanner_error(e: ScannerError) -> LegacyProbeOutcome {
    if e.category.starts_with("tls_alert_") || e.category == "connection_refused" {
        LegacyProbeOutcome::NotSupported
    } else {
        LegacyProbeOutcome::Error(e.category)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_table_iana_codes_are_unique_per_version() {
        // Duplicate (iana_code, version) pairs would double-probe the same
        // cell and produce ambiguous output. Enforce uniqueness.
        use std::collections::HashSet;
        let mut seen: HashSet<(u16, TlsVersion)> = HashSet::new();
        for t in TARGETS {
            let key = (t.iana_code, t.version);
            assert!(
                seen.insert(key),
                "duplicate target ({:#06x}, {:?})",
                t.iana_code,
                t.version
            );
        }
    }

    #[test]
    fn target_table_restricts_versions_to_tls10_through_tls12() {
        // D1 scope is TLS 1.0/1.1/1.2. SSLv3 is D8's surface; TLS 1.3 has
        // no legacy-cipher observables that OpenSSL adds over aws-lc-rs.
        for t in TARGETS {
            assert!(
                matches!(
                    t.version,
                    TlsVersion::Tls10 | TlsVersion::Tls11 | TlsVersion::Tls12
                ),
                "target {} has out-of-scope version {:?}",
                t.iana_name,
                t.version
            );
        }
    }

    #[test]
    fn target_table_names_use_iana_prefix_convention() {
        for t in TARGETS {
            assert!(
                t.iana_name.starts_with("TLS_"),
                "target {} missing TLS_ prefix",
                t.iana_name
            );
            assert!(
                !t.openssl_name.is_empty(),
                "target {} has empty openssl name",
                t.iana_name
            );
        }
    }

    #[test]
    fn tls_version_mapping_covers_every_target() {
        for t in TARGETS {
            assert!(
                tls_version_to_ossl(t.version).is_some(),
                "target {} version {:?} has no OpenSSL mapping",
                t.iana_name,
                t.version
            );
        }
    }

    #[test]
    fn classify_scanner_error_promotes_alerts_and_refused_to_not_supported() {
        // Alerts are server signals — NotSupported.
        let alert = ScannerError::tls_alert("handshake_failure", "ctx");
        assert!(matches!(
            classify_scanner_error(alert),
            LegacyProbeOutcome::NotSupported
        ));

        // connection_refused at TCP level is a real refusal, but some
        // servers reset post-ClientHello without sending an alert — the
        // cipher is effectively NotSupported. Parity with rustls path.
        let refused = ScannerError::connection_refused("ctx");
        assert!(matches!(
            classify_scanner_error(refused),
            LegacyProbeOutcome::NotSupported
        ));
    }

    #[test]
    fn classify_scanner_error_preserves_other_categories_as_error() {
        let timeout = ScannerError::connection_timeout("ctx");
        match classify_scanner_error(timeout) {
            LegacyProbeOutcome::Error(cat) => assert_eq!(cat, "connection_timeout"),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn target_table_includes_every_required_category() {
        let has = |needle: &str| {
            TARGETS
                .iter()
                .any(|t| t.openssl_name.contains(needle) || t.iana_name.contains(needle))
        };
        assert!(has("RC4"), "RC4 family missing from target table");
        assert!(has("3DES") || has("DES-CBC3"), "3DES missing");
        assert!(has("NULL"), "NULL ciphers missing");
        assert!(has("ADH"), "anon-DH missing");
        assert!(has("DHE-RSA"), "DHE-RSA missing (D2 observer won't fire)");
    }
}
