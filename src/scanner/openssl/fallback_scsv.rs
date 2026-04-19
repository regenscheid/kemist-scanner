//! `TLS_FALLBACK_SCSV` (RFC 7507) enforcement probe.
//!
//! Algorithm:
//! 1. Quick characterization handshake: let OpenSSL pick the highest
//!    protocol version the server will negotiate.
//! 2. If the server's max is < TLS 1.2, there's no meaningful downgrade
//!    to test — emit `enforced: None, reason: no_downgrade_possible`.
//! 3. Build a probe context pinning `max_proto_version` one step below
//!    the server's max, plus `SslMode::SEND_FALLBACK_SCSV` on the SSL_CTX.
//!    Attempt the handshake.
//! 4. Classify:
//!    - `inappropriate_fallback` alert (RFC 5246 alert 86) →
//!      `enforced: Some(true)`. Server correctly rejected the downgrade.
//!    - Handshake success → `enforced: Some(false)`. Server accepted a
//!      downgrade signal — it doesn't enforce RFC 7507.
//!    - Any other outcome → `enforced: None` with reason string so
//!      the consumer can see why the probe was inconclusive (common
//!      case: server disabled the downgrade target entirely and
//!      emitted `protocol_version` alert instead).
//!
//! Supersedes the heuristic stub at
//! `src/scanner/mod.rs::test_fallback_scsv` which always returned
//! `Some(true)` as a proxy for "supports TLS 1.3."

use std::net::SocketAddr;
use std::time::Duration;

use openssl::ssl::{HandshakeError, Ssl, SslContext, SslMethod, SslMode, SslVerifyMode, SslVersion};
use tracing::{debug, info};

use crate::model::errors::ScannerError;
use crate::scanner::openssl::alerts;

/// Per-target SCSV enforcement observation.
#[derive(Debug, Clone)]
pub struct FallbackScsvResult {
    /// Tri-state. `Some(true)` = enforced, `Some(false)` = not enforced,
    /// `None` = inconclusive (see `reason`).
    pub enforced: Option<bool>,
    /// Human-readable diagnosis. Populated in every case so rule engines
    /// always have context.
    pub reason: String,
}

/// Run the SCSV enforcement probe against a single target. Uses two
/// blocking handshakes (one characterization + one probe), each wrapped
/// in `spawn_blocking`.
pub async fn probe(
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> FallbackScsvResult {
    info!("OpenSSL TLS_FALLBACK_SCSV probe");

    // Characterize: what's the server's maximum protocol version?
    let hostname_owned = hostname.to_string();
    let server_max = tokio::task::spawn_blocking(move || {
        characterize_max_version_blocking(target, &hostname_owned, connect_timeout, handshake_timeout)
    })
    .await
    .unwrap_or(None);

    let server_max = match server_max {
        Some(v) => v,
        None => {
            return FallbackScsvResult {
                enforced: None,
                reason: "characterization_handshake_failed".to_string(),
            };
        }
    };

    let Some(downgrade_target) = one_version_below(server_max) else {
        return FallbackScsvResult {
            enforced: None,
            reason: "no_downgrade_possible".to_string(),
        };
    };

    debug!(
        server_max = ?version_label(server_max),
        downgrade_target = ?version_label(downgrade_target),
        "ffdhe_scsv probe"
    );

    let hostname_owned2 = hostname.to_string();
    let probe_outcome = tokio::task::spawn_blocking(move || {
        probe_scsv_blocking(
            target,
            &hostname_owned2,
            downgrade_target,
            connect_timeout,
            handshake_timeout,
        )
    })
    .await
    .unwrap_or_else(|e| ProbeOutcome::Error(format!("spawn_blocking_panic: {e}")));

    classify_probe_outcome(probe_outcome, server_max, downgrade_target)
}

/// Raw outcome of the inner downgrade probe, pre-interpretation.
enum ProbeOutcome {
    /// Handshake completed at the downgraded version.
    HandshakeAccepted,
    /// Server returned a specific TLS alert category.
    Alert(String),
    /// Probe itself failed (transport, timeout).
    Error(String),
}

fn classify_probe_outcome(
    outcome: ProbeOutcome,
    server_max: SslVersion,
    downgrade_target: SslVersion,
) -> FallbackScsvResult {
    match outcome {
        ProbeOutcome::Alert(cat) if cat == "tls_alert_inappropriate_fallback" => {
            FallbackScsvResult {
                enforced: Some(true),
                reason: format!(
                    "inappropriate_fallback_alert_at_{}_with_server_max_{}",
                    version_label(downgrade_target),
                    version_label(server_max)
                ),
            }
        }
        ProbeOutcome::HandshakeAccepted => FallbackScsvResult {
            enforced: Some(false),
            reason: format!(
                "handshake_succeeded_at_{}_despite_scsv",
                version_label(downgrade_target)
            ),
        },
        ProbeOutcome::Alert(cat) => FallbackScsvResult {
            enforced: None,
            reason: format!("unexpected_alert:{cat}"),
        },
        ProbeOutcome::Error(cat) => FallbackScsvResult {
            enforced: None,
            reason: format!("probe_error:{cat}"),
        },
    }
}

/// Quick characterization handshake. Returns the negotiated protocol
/// version or `None` if the handshake failed for any reason. Not a
/// full-featured probe — purely a max-version sniff.
fn characterize_max_version_blocking(
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> Option<SslVersion> {
    let tcp = std::net::TcpStream::connect_timeout(&target, connect_timeout).ok()?;
    let _ = tcp.set_read_timeout(Some(handshake_timeout));
    let _ = tcp.set_write_timeout(Some(handshake_timeout));

    let mut builder = SslContext::builder(SslMethod::tls_client()).ok()?;
    // Let the server pick: we accept everything 1.0 through 1.3.
    builder.set_min_proto_version(Some(SslVersion::TLS1)).ok()?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3)).ok()?;
    builder.set_security_level(0);
    builder.set_verify(SslVerifyMode::NONE);
    let ctx = builder.build();

    let mut ssl = Ssl::new(&ctx).ok()?;
    let _ = ssl.set_hostname(hostname);

    let stream = ssl.connect(tcp).ok()?;
    stream.ssl().version2()
}

fn probe_scsv_blocking(
    target: SocketAddr,
    hostname: &str,
    downgrade_target: SslVersion,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> ProbeOutcome {
    let tcp = match std::net::TcpStream::connect_timeout(&target, connect_timeout) {
        Ok(s) => s,
        Err(e) => {
            return ProbeOutcome::Error(ScannerError::from_io("scsv tcp connect", e).category);
        }
    };
    let _ = tcp.set_read_timeout(Some(handshake_timeout));
    let _ = tcp.set_write_timeout(Some(handshake_timeout));

    let ctx = match build_scsv_context(downgrade_target) {
        Ok(c) => c,
        Err(stack) => return ProbeOutcome::Error(format!("openssl_ctx_build:{stack}")),
    };

    let mut ssl = match Ssl::new(&ctx) {
        Ok(s) => s,
        Err(stack) => return ProbeOutcome::Error(format!("openssl_ssl_new:{stack}")),
    };
    let _ = ssl.set_hostname(hostname);

    match ssl.connect(tcp) {
        Ok(_stream) => ProbeOutcome::HandshakeAccepted,
        Err(HandshakeError::Failure(mid)) => {
            let se = alerts::classify_openssl_error("scsv handshake", mid.error());
            if se.category.starts_with("tls_alert_") {
                ProbeOutcome::Alert(se.category)
            } else {
                ProbeOutcome::Error(se.category)
            }
        }
        Err(HandshakeError::SetupFailure(stack)) => {
            ProbeOutcome::Error(format!("openssl_setup:{stack}"))
        }
        Err(HandshakeError::WouldBlock(_)) => ProbeOutcome::Error("openssl_would_block".to_string()),
    }
}

fn build_scsv_context(
    downgrade_target: SslVersion,
) -> Result<SslContext, openssl::error::ErrorStack> {
    let mut builder = SslContext::builder(SslMethod::tls_client())?;
    builder.set_min_proto_version(Some(SslVersion::TLS1))?;
    builder.set_max_proto_version(Some(downgrade_target))?;
    builder.set_security_level(0);
    builder.set_verify(SslVerifyMode::NONE);
    // The mode bit: signal "this is a retry after a prior handshake
    // failure" so the server can detect a MITM-induced downgrade.
    builder.set_mode(SslMode::SEND_FALLBACK_SCSV);
    Ok(builder.build())
}

/// Version immediately below the server's max. `TLS1.3 → TLS1.2`,
/// `TLS1.2 → TLS1.1`. Returns `None` if no meaningful downgrade exists
/// (server max is already TLS 1.1 or lower).
fn one_version_below(server_max: SslVersion) -> Option<SslVersion> {
    match server_max {
        v if v == SslVersion::TLS1_3 => Some(SslVersion::TLS1_2),
        v if v == SslVersion::TLS1_2 => Some(SslVersion::TLS1_1),
        _ => None,
    }
}

/// Short label for SslVersion — used only in result strings, not on
/// the hot path.
fn version_label(v: SslVersion) -> &'static str {
    if v == SslVersion::TLS1_3 {
        "tls1_3"
    } else if v == SslVersion::TLS1_2 {
        "tls1_2"
    } else if v == SslVersion::TLS1_1 {
        "tls1_1"
    } else if v == SslVersion::TLS1 {
        "tls1_0"
    } else if v == SslVersion::SSL3 {
        "ssl3"
    } else {
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_version_below_maps_expected_pairs() {
        assert_eq!(one_version_below(SslVersion::TLS1_3), Some(SslVersion::TLS1_2));
        assert_eq!(one_version_below(SslVersion::TLS1_2), Some(SslVersion::TLS1_1));
        // TLS 1.1 and lower have no meaningful downgrade target.
        assert_eq!(one_version_below(SslVersion::TLS1_1), None);
        assert_eq!(one_version_below(SslVersion::TLS1), None);
        assert_eq!(one_version_below(SslVersion::SSL3), None);
    }

    #[test]
    fn classification_recognizes_inappropriate_fallback_as_enforced() {
        let r = classify_probe_outcome(
            ProbeOutcome::Alert("tls_alert_inappropriate_fallback".to_string()),
            SslVersion::TLS1_3,
            SslVersion::TLS1_2,
        );
        assert_eq!(r.enforced, Some(true));
        assert!(r.reason.contains("inappropriate_fallback"));
    }

    #[test]
    fn classification_treats_handshake_success_as_not_enforced() {
        let r = classify_probe_outcome(
            ProbeOutcome::HandshakeAccepted,
            SslVersion::TLS1_3,
            SslVersion::TLS1_2,
        );
        assert_eq!(r.enforced, Some(false));
        assert!(r.reason.contains("handshake_succeeded"));
    }

    #[test]
    fn classification_treats_other_alerts_as_inconclusive() {
        let r = classify_probe_outcome(
            ProbeOutcome::Alert("tls_alert_protocol_version".to_string()),
            SslVersion::TLS1_2,
            SslVersion::TLS1_1,
        );
        assert_eq!(r.enforced, None);
        assert!(r.reason.starts_with("unexpected_alert:"));
    }

    #[test]
    fn classification_treats_transport_errors_as_inconclusive() {
        let r = classify_probe_outcome(
            ProbeOutcome::Error("connection_timeout".to_string()),
            SslVersion::TLS1_3,
            SslVersion::TLS1_2,
        );
        assert_eq!(r.enforced, None);
        assert!(r.reason.starts_with("probe_error:"));
    }

    #[test]
    fn version_label_covers_common_cases() {
        assert_eq!(version_label(SslVersion::TLS1_3), "tls1_3");
        assert_eq!(version_label(SslVersion::TLS1_2), "tls1_2");
        assert_eq!(version_label(SslVersion::TLS1_1), "tls1_1");
        assert_eq!(version_label(SslVersion::TLS1), "tls1_0");
        assert_eq!(version_label(SslVersion::SSL3), "ssl3");
    }
}
