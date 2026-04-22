//! Legacy cipher enumeration and RSA-kex probing across TLS 1.0 / TLS 1.1
//! / TLS 1.2.
//!
//! Covers RSA-kex, RC4, single-DES/3DES, NULL, anon-DH, and a few DHE-RSA
//! suites (the last category drives the [`super::dh_params`] and
//! [`super::ske_sig`] post-handshake observers).
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
use crate::scanner::backends::{is_wire_rejection, HandshakeOutcome};
use crate::scanner::openssl::alerts;
use crate::scanner::openssl::dh_params::{self, DhSnapshot};
use crate::scanner::openssl::ske_sig;

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
    pub outcome: HandshakeOutcome,
    /// Populated by [`crate::scanner::openssl::dh_params::snapshot`] for any
    /// handshake whose server `tmp_key` is DH (i.e. DHE-RSA suites). `None`
    /// for RSA-kex, ECDHE, and failed handshakes.
    pub dh_snapshot: Option<DhSnapshot>,
    /// Populated by [`super::ske_sig::snapshot`] — the server's chosen
    /// TLS 1.2 ServerKeyExchange (or TLS 1.3 CertificateVerify)
    /// signature algorithm name.
    pub ske_sig: Option<String>,
}

/// Aggregate output of the legacy cipher probe pass.
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
    // DHE-RSA — gates the DH-parameter observer + SKE signature observer
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
    // --- PSK family ---
    // Without a pre-shared secret the scanner can't complete a PSK
    // handshake. On most servers these probes alert
    // unknown_psk_identity or handshake_failure, classified as
    // `supported: false`. Real `supported: true` is rare outside
    // closed ecosystems. The observation still has signal: an alert
    // specifically tied to PSK means the server parsed the PSK cipher
    // offer, even if it couldn't authenticate it.
    Target {
        iana_name: "TLS_PSK_WITH_AES_128_CBC_SHA",
        openssl_name: "PSK-AES128-CBC-SHA",
        iana_code: 0x008C,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_PSK_WITH_AES_128_GCM_SHA256",
        openssl_name: "PSK-AES128-GCM-SHA256",
        iana_code: 0x00A8,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
        openssl_name: "DHE-PSK-AES128-GCM-SHA256",
        iana_code: 0x00AA,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
        openssl_name: "ECDHE-PSK-AES128-CBC-SHA",
        iana_code: 0xC035,
        version: TlsVersion::Tls12,
    },
    // --- Camellia ---
    Target {
        iana_name: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
        openssl_name: "CAMELLIA128-SHA",
        iana_code: 0x0041,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
        openssl_name: "CAMELLIA256-SHA",
        iana_code: 0x0084,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
        openssl_name: "DHE-RSA-CAMELLIA128-SHA",
        iana_code: 0x0045,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
        openssl_name: "ECDHE-RSA-CAMELLIA128-SHA256",
        iana_code: 0xC076,
        version: TlsVersion::Tls12,
    },
    // --- SEED ---
    Target {
        iana_name: "TLS_RSA_WITH_SEED_CBC_SHA",
        openssl_name: "SEED-SHA",
        iana_code: 0x0096,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
        openssl_name: "DHE-RSA-SEED-SHA",
        iana_code: 0x009A,
        version: TlsVersion::Tls12,
    },
    // --- ARIA ---
    Target {
        iana_name: "TLS_RSA_WITH_ARIA_128_GCM_SHA256",
        openssl_name: "ARIA128-GCM-SHA256",
        iana_code: 0xC050,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_RSA_WITH_ARIA_256_GCM_SHA384",
        openssl_name: "ARIA256-GCM-SHA384",
        iana_code: 0xC051,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",
        openssl_name: "DHE-RSA-ARIA128-GCM-SHA256",
        iana_code: 0xC052,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
        // OpenSSL 3.x collapsed the RSA-signature qualifier on ARIA
        // ECDHE suites; the accepted name is `ECDHE-ARIA128-GCM-SHA256`
        // without the `-RSA-` segment. IANA codepoint 0xC060 is still
        // the RSA-authenticated variant.
        openssl_name: "ECDHE-ARIA128-GCM-SHA256",
        iana_code: 0xC060,
        version: TlsVersion::Tls12,
    },
    // --- Static DH / static ECDH ---
    // Require the server's CERTIFICATE to embed a DH/ECDH public key
    // (not the common ephemeral-DH + signed-cert pattern). Modern CAs
    // don't issue those certs, so real-world `supported: true` is
    // effectively zero. Probes exist for completeness.
    Target {
        iana_name: "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
        openssl_name: "DH-RSA-AES128-SHA",
        iana_code: 0x0031,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
        openssl_name: "DH-DSS-AES128-SHA",
        iana_code: 0x0030,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
        openssl_name: "ECDH-RSA-AES128-SHA",
        iana_code: 0xC00E,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
        openssl_name: "ECDH-ECDSA-AES128-SHA",
        iana_code: 0xC004,
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

/// Emit this backend's cipher inventory as `(iana_code, iana_name, version)`
/// rows. Used by `scanner::backends::openssl_inventory` so the single
/// source of truth for "what does the OpenSSL backend probe" is
/// this `TARGETS` table rather than a parallel hand-maintained list.
pub fn inventory_entries() -> Vec<(u16, &'static str, TlsVersion)> {
    TARGETS
        .iter()
        .map(|t| (t.iana_code, t.iana_name, t.version))
        .collect()
}

/// Probe a single cipher identified by `(iana_code, version)`. Thin
/// wrapper over `probe_single_suite_blocking` that looks up the
/// matching `TARGETS` row and runs the probe on a `spawn_blocking`
/// thread. Returns a `ProbeRun` with `HandshakeOutcome::Error` when no
/// row matches — a programmer error on the caller's part since
/// `inventory_entries()` and this function read the same table.
///
/// Special-case: the four static-DH/ECDH cipher suites OpenSSL 3.x
/// removed entirely (0x0030, 0x0031, 0xC004, 0xC00E) route to
/// `raw::static_dh` instead. OpenSSL can't drive them at all, but a
/// raw-socket ClientHello can — we just need to send one codepoint
/// and classify the response.
pub(crate) async fn probe_single_by_code(
    target: SocketAddr,
    hostname: &str,
    iana_code: u16,
    version: TlsVersion,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> ProbeRun {
    if matches!(iana_code, 0x0030 | 0x0031 | 0xC004 | 0xC00E) {
        let outcome = crate::scanner::raw::static_dh::probe(
            target,
            hostname,
            iana_code,
            connect_timeout,
            handshake_timeout,
        )
        .await;
        return ProbeRun {
            outcome,
            dh_snapshot: None,
            ske_sig: None,
        };
    }

    let Some(row) = TARGETS
        .iter()
        .find(|t| t.iana_code == iana_code && t.version == version)
    else {
        return ProbeRun {
            outcome: HandshakeOutcome::Error(format!(
                "openssl_unknown_target:0x{:04X}:{:?}",
                iana_code, version
            )),
            dh_snapshot: None,
            ske_sig: None,
        };
    };
    let hostname_owned = hostname.to_string();
    let openssl_name = row.openssl_name.to_string();
    let version_copy = row.version;

    tokio::task::spawn_blocking(move || {
        probe_single_suite_blocking(
            target,
            &hostname_owned,
            &openssl_name,
            version_copy,
            connect_timeout,
            handshake_timeout,
        )
    })
    .await
    .unwrap_or_else(|join_err| ProbeRun {
        outcome: HandshakeOutcome::Error(format!("spawn_blocking_panic: {join_err}")),
        dh_snapshot: None,
        ske_sig: None,
    })
}

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

    // Registry-driven per-suite probing through `OpensslBackend::handshake()`.
    // Every `TARGETS` codepoint routes back to this backend (OpenSSL
    // claims the full legacy cipher inventory today), so the
    // indirection is semantically a no-op — going through the
    // registry keeps all cipher-probe dispatch on one path regardless
    // of which backend ultimately runs the handshake.
    let registry = crate::scanner::backends::BackendRegistry::new();
    let ctx = crate::scanner::backends::ProbeContext {
        target,
        hostname: hostname.to_string(),
        connect_timeout,
        handshake_timeout,
    };

    for (i, t) in TARGETS.iter().enumerate() {
        let constraint = crate::scanner::backends::HandshakeConstraint::single_cipher_at(
            t.iana_code,
            t.version,
        );
        let (outcome, dh_snapshot, ske_sig) = match registry.route_cipher(t.iana_code) {
            Some(backend) => match backend.handshake(constraint, &ctx).await {
                Ok(r) => (r.outcome, r.dh_parameters, r.ske_signature_name),
                Err(u) => (
                    HandshakeOutcome::Error(format!("unsatisfiable_constraint:{}", u.reason)),
                    None,
                    None,
                ),
            },
            None => (
                HandshakeOutcome::Error(format!(
                    "no_backend_routes_cipher:0x{:04X}",
                    t.iana_code
                )),
                None,
                None,
            ),
        };

        debug!(
            suite = %t.openssl_name,
            version = ?t.version,
            outcome = ?outcome,
            dh_captured = dh_snapshot.is_some(),
            ske_sig = ?ske_sig,
            "legacy probe result"
        );

        results.push(LegacyCipherResult {
            name: t.iana_name.to_string(),
            openssl_name: t.openssl_name.to_string(),
            iana_code: t.iana_code,
            version: t.version,
            outcome,
            dh_snapshot,
            ske_sig,
        });

        if i < last && !per_probe_delay.is_zero() {
            tokio::time::sleep(per_probe_delay).await;
        }
    }

    LegacyCipherProbeOutput { results }
}

/// Internal return value of [`probe_single_suite_blocking`] — outcome plus
/// any post-handshake observations (DH parameter snapshot, SKE signature).
/// Exposed pub(crate) so `backends::openssl` can surface the observer
/// fields through `HandshakeResult`.
pub(crate) struct ProbeRun {
    pub(crate) outcome: HandshakeOutcome,
    pub(crate) dh_snapshot: Option<DhSnapshot>,
    pub(crate) ske_sig: Option<String>,
}

/// Synchronous single-suite probe. Called inside `spawn_blocking`. Never
/// panics, never returns Err; failure categories fold into
/// `HandshakeOutcome::Error`. On handshake success, also observes DH
/// parameters if the server's tmp key is DH.
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
            outcome: HandshakeOutcome::Error(format!(
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
            // `no cipher match` from `SSL_CTX_set_cipher_list` means
            // the cipher name isn't in the vendored OpenSSL 3.x build
            // at all — static-DH/ECDH suites (0x0030, 0x0031, 0xC004,
            // 0xC00E) were removed upstream, other suites may need
            // additional openssl-src features. Surface these as
            // `NotProbed` with a deterministic reason rather than an
            // Error, because the scanner cannot generate any
            // server-side signal — it never gets as far as sending a
            // ClientHello. Other build errors (misconfigured SSL_CTX
            // flags, provider load issues) still map to Error.
            let stack_str = stack.to_string();
            let outcome = if stack_str.contains("no cipher match") {
                HandshakeOutcome::NotProbed(format!(
                    "openssl_3x_cipher_not_available:{openssl_cipher_name}"
                ))
            } else {
                HandshakeOutcome::Error(format!("openssl_ctx_build: {stack}"))
            };
            return ProbeRun {
                outcome,
                dh_snapshot: None,
                ske_sig: None,
            };
        }
    };

    let mut ssl = match Ssl::new(&ctx) {
        Ok(s) => s,
        Err(stack) => {
            return ProbeRun {
                outcome: HandshakeOutcome::Error(format!("openssl_ssl_new: {stack}")),
                dh_snapshot: None,
                ske_sig: None,
            }
        }
    };
    // Best-effort SNI; failure here is unlikely and non-fatal.
    let _ = ssl.set_hostname(hostname);

    match ssl.connect(tcp) {
        Ok(stream) => {
            // Handshake completed. Observe DH parameters and the server's
            // signature algorithm. Both return None for handshakes where
            // the observation doesn't apply (e.g. RSA-kex has no SKE
            // signature; ECDHE has no DH parameters). A snapshot-level
            // ErrorStack from the DH observer is swallowed — the
            // Supported outcome is the primary signal.
            let dh_snapshot = dh_params::snapshot(stream.ssl()).unwrap_or(None);
            let ske_sig = ske_sig::snapshot(stream.ssl());
            ProbeRun {
                outcome: HandshakeOutcome::Supported,
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
            outcome: HandshakeOutcome::Error(format!("openssl_setup: {stack}")),
            dh_snapshot: None,
            ske_sig: None,
        },
        Err(HandshakeError::WouldBlock(_)) => {
            // Shouldn't happen with blocking socket + set_*_timeout; if it
            // does, record as Error so the anomaly surfaces rather than
            // masquerading as NotSupported.
            ProbeRun {
                outcome: HandshakeOutcome::Error("openssl_would_block".to_string()),
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
    // `@SECLEVEL=0` in the cipher STRING is load-bearing in addition to
    // `set_security_level(0)` on the SSL_CTX. The cipher-list parser
    // applies its own seclevel filter based on the string; without the
    // `@SECLEVEL=0` prefix, OpenSSL 3.x uses the default SECLEVEL (2),
    // which excludes RC4, single-DES, and other <80-bit-security
    // primitives even with the legacy provider loaded — causing
    // `set_cipher_list` to return "no cipher match" before any handshake
    // is attempted.
    builder.set_cipher_list(&format!("{}:@SECLEVEL=0", cipher_list))?;
    builder.set_verify(SslVerifyMode::NONE);
    // Dummy PSK client callback. Without this, OpenSSL refuses to
    // construct a ClientHello for PSK-family cipher suites because it
    // has no identity/key to put in the `pre_shared_key` extension —
    // the handshake fails client-side before any bytes leave the
    // socket, surfacing as `internal_scanner_error` with no context.
    // Installing a bogus identity/key lets the ClientHello go out;
    // real servers reply with `unknown_psk_identity` (alert 115) or
    // `handshake_failure` (alert 40), which the classifier maps to
    // `NotSupported` — the observation we actually want from a PSK
    // probe against an unknown-secret target.
    //
    // The callback runs only when a PSK-family suite is selected; it
    // never fires for non-PSK probes.
    builder.set_psk_client_callback(|_ssl, _hint, identity_out, psk_out| {
        let identity = b"kemist-probe";
        let psk = [0u8; 32];
        if identity_out.len() < identity.len() + 1 || psk_out.len() < psk.len() {
            // Buffer too small — return a zero-length PSK, OpenSSL
            // then aborts with SSL_R_PSK_IDENTITY_NOT_FOUND. Handshake
            // still fails cleanly.
            return Ok(0);
        }
        identity_out[..identity.len()].copy_from_slice(identity);
        identity_out[identity.len()] = 0;
        psk_out[..psk.len()].copy_from_slice(&psk);
        Ok(psk.len())
    });
    Ok(builder.build())
}

/// Project our TLS version enum onto OpenSSL's constants. SSLv2 has no
/// OpenSSL 3.x representation (the protocol was dropped entirely); SSLv3
/// resolves but requires the legacy provider and seclevel 0 —
/// `protocol_versions.rs` handles the SSLv3 pathway explicitly, this
/// probe restricts itself to TLS 1.0+.
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
/// Uses the shared `is_wire_rejection` predicate. This (OpenSSL) path
/// emits the `category` only in Error; the rustls-path `classify_probe_error`
/// includes both category and context — schema v1 depends on that asymmetry.
fn classify_scanner_error(e: ScannerError) -> HandshakeOutcome {
    if is_wire_rejection(&e) {
        HandshakeOutcome::NotSupported
    } else {
        HandshakeOutcome::Error(e.category)
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
        // This probe's scope is TLS 1.0/1.1/1.2. SSLv3 is handled by
        // `protocol_versions.rs`; TLS 1.3 has no legacy-cipher
        // observables that OpenSSL adds over aws-lc-rs.
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
            HandshakeOutcome::NotSupported
        ));

        // connection_refused at TCP level is a real refusal, but some
        // servers reset post-ClientHello without sending an alert — the
        // cipher is effectively NotSupported. Parity with rustls path.
        let refused = ScannerError::connection_refused("ctx");
        assert!(matches!(
            classify_scanner_error(refused),
            HandshakeOutcome::NotSupported
        ));
    }

    #[test]
    fn classify_scanner_error_preserves_other_categories_as_error() {
        let timeout = ScannerError::connection_timeout("ctx");
        match classify_scanner_error(timeout) {
            HandshakeOutcome::Error(cat) => assert_eq!(cat, "connection_timeout"),
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
        assert!(
            has("DHE-RSA"),
            "DHE-RSA missing — DH parameter observer won't fire"
        );
    }
}
