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

use openssl::ssl::{
    HandshakeError, Ssl, SslContext, SslMethod, SslMode, SslVerifyMode, SslVersion,
};
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

/// Run the SCSV enforcement probe against a single target. Composes
/// two `OpensslBackend::handshake()` calls — one characterization
/// (wide version range, no pins) followed by one SCSV-flagged downgrade
/// probe. Interpretation (`classify_probe_outcome`) stays in this module
/// because it's policy about what RFC 7507 compliance looks like, not
/// backend-specific handshake plumbing.
pub async fn probe(
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> FallbackScsvResult {
    info!("OpenSSL TLS_FALLBACK_SCSV probe");

    use crate::model::protocol::TlsVersion;
    use crate::scanner::backends::{
        BackendRegistry, HandshakeConstraint, HandshakeOutcome, ProbeContext, TlsBackend,
    };
    let registry = BackendRegistry::new();
    let ctx = ProbeContext {
        target,
        hostname: hostname.to_string(),
        connect_timeout,
        handshake_timeout,
    };

    // Step 1: characterize — let the server pick its max version.
    let characterize = HandshakeConstraint {
        version_range: Some((TlsVersion::Tls10, TlsVersion::Tls13)),
        seclevel_zero: true,
        ..HandshakeConstraint::default()
    };
    let chr = match registry.openssl.handshake(characterize, &ctx).await {
        Ok(r) => r,
        Err(u) => {
            return FallbackScsvResult {
                enforced: None,
                reason: format!("characterization_unsatisfiable:{}", u.reason),
            };
        }
    };
    let Some(server_max_tls) = chr.negotiated.as_ref().and_then(|n| n.version) else {
        return FallbackScsvResult {
            enforced: None,
            reason: "characterization_handshake_failed".to_string(),
        };
    };
    use crate::scanner::backends::openssl::{ssl_to_tls_version, tls_to_ssl_version};
    let Some(server_max) = tls_to_ssl_version(server_max_tls) else {
        return FallbackScsvResult {
            enforced: None,
            reason: format!("characterization_version_out_of_scope:{:?}", server_max_tls),
        };
    };

    let Some(downgrade_target) = one_version_below(server_max) else {
        return FallbackScsvResult {
            enforced: None,
            reason: "no_downgrade_possible".to_string(),
        };
    };
    let Some(downgrade_target_tls) = ssl_to_tls_version(downgrade_target) else {
        return FallbackScsvResult {
            enforced: None,
            reason: format!(
                "downgrade_target_version_out_of_scope:{:?}",
                downgrade_target
            ),
        };
    };

    debug!(
        server_max = ?version_label(server_max),
        downgrade_target = ?version_label(downgrade_target),
        "ffdhe_scsv probe"
    );

    // Step 2: downgrade probe with SCSV bit set.
    let scsv_constraint = HandshakeConstraint {
        version_range: Some((TlsVersion::Tls10, downgrade_target_tls)),
        send_fallback_scsv: true,
        seclevel_zero: true,
        ..HandshakeConstraint::default()
    };
    let probe_outcome = match registry.openssl.handshake(scsv_constraint, &ctx).await {
        Ok(r) => match r.outcome {
            HandshakeOutcome::Supported => ProbeOutcome::HandshakeAccepted,
            HandshakeOutcome::NotSupported => match r.alert {
                Some(cat) => ProbeOutcome::Alert(cat),
                None => ProbeOutcome::Error("rejected_without_alert_category".to_string()),
            },
            HandshakeOutcome::Error(msg) => ProbeOutcome::Error(msg),
            other => ProbeOutcome::Error(format!("unexpected_scsv_outcome:{:?}", other)),
        },
        Err(u) => ProbeOutcome::Error(format!("scsv_unsatisfiable:{}", u.reason)),
    };

    classify_probe_outcome(probe_outcome, server_max, downgrade_target)
}

/// Raw outcome of the inner downgrade probe, pre-interpretation.
/// `pub(crate)` so `backends::openssl` can surface these through
/// `HandshakeResult` when the orchestrator drives the probe via
/// `handshake(send_fallback_scsv: true)`.
#[derive(Debug, Clone)]
pub(crate) enum ProbeOutcome {
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
        // RFC 7507-compliant enforcement: server detected the SCSV in a
        // downgraded handshake and sent the mandated alert.
        // Reason leads with the outcome, not the alert name: this is the
        // clean pass, and `inappropriate_fallback` is the RFC's name for
        // alert 86 — as the leading token it reads like a complaint about
        // the server. Mirrors the `rejected_via_non_mandated_alert:` arm
        // below so the two enforcement paths are greppable as a pair.
        ProbeOutcome::Alert(cat) if cat == "tls_alert_inappropriate_fallback" => {
            FallbackScsvResult {
                enforced: Some(true),
                reason: format!(
                    "rejected_via_mandated_alert:inappropriate_fallback_at_{}_with_server_max_{}",
                    version_label(downgrade_target),
                    version_label(server_max)
                ),
            }
        }
        // Pragmatic enforcement: server rejected the downgraded
        // handshake but used `handshake_failure` (alert 40) instead of
        // the RFC-mandated `inappropriate_fallback` (alert 86). Common
        // in older nginx and certain F5 configs — effective protection
        // against downgrade attacks, just not strictly RFC-compliant.
        // We emit `Some(true)` with an explicit reason flag so:
        // - rule engines checking "is the server protected?" get `true`
        // - rule engines checking "is the server RFC 7507 compliant?"
        //   key on the reason substring and can downgrade the finding
        ProbeOutcome::Alert(cat) if cat == "tls_alert_handshake_failure" => FallbackScsvResult {
            enforced: Some(true),
            reason: format!(
                "rejected_via_non_mandated_alert:handshake_failure_at_{}_with_server_max_{}",
                version_label(downgrade_target),
                version_label(server_max)
            ),
        },
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
/// full-featured probe — purely a max-version sniff. `pub(crate)` so
/// `backends::openssl::handshake()` can wrap it for the characterization
/// constraint shape.
pub(crate) fn characterize_max_version_blocking(
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
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .ok()?;
    builder.set_security_level(0);
    builder.set_verify(SslVerifyMode::NONE);
    let ctx = builder.build();

    let mut ssl = Ssl::new(&ctx).ok()?;
    let _ = ssl.set_hostname(hostname);

    let stream = ssl.connect(tcp).ok()?;
    stream.ssl().version2()
}

/// Synchronous downgrade probe with `SSL_MODE_SEND_FALLBACK_SCSV`.
/// `pub(crate)` so `backends::openssl::handshake()` can wrap it.
pub(crate) fn probe_scsv_blocking(
    target: SocketAddr,
    hostname: &str,
    downgrade_target: SslVersion,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> ProbeOutcome {
    let tcp = match std::net::TcpStream::connect_timeout(&target, connect_timeout) {
        Ok(s) => s,
        Err(e) => {
            let se = ScannerError::from_io("scsv tcp connect", e);
            return ProbeOutcome::Error(format!("{}: {}", se.category, se.context));
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
                // Preserve context: `connection_refused: scsv handshake:
                // connection reset by peer` reads very differently from
                // a bare `connection_refused`, even though both end up
                // as `enforced: None` — a reviewer can tell whether the
                // server closed the TCP socket mid-handshake vs. pre-TCP.
                ProbeOutcome::Error(format!("{}: {}", se.category, se.context))
            }
        }
        Err(HandshakeError::SetupFailure(stack)) => {
            ProbeOutcome::Error(format!("openssl_setup:{stack}"))
        }
        Err(HandshakeError::WouldBlock(_)) => {
            ProbeOutcome::Error("openssl_would_block".to_string())
        }
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
        assert_eq!(
            one_version_below(SslVersion::TLS1_3),
            Some(SslVersion::TLS1_2)
        );
        assert_eq!(
            one_version_below(SslVersion::TLS1_2),
            Some(SslVersion::TLS1_1)
        );
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
    fn classification_treats_handshake_failure_as_pragmatic_enforcement() {
        // Many real servers emit handshake_failure instead of the
        // RFC 7507-mandated inappropriate_fallback when enforcing SCSV.
        // We record that as `enforced: true` but flag the non-compliance
        // in the reason so rule engines keyed on RFC literalism can
        // downgrade the finding.
        let r = classify_probe_outcome(
            ProbeOutcome::Alert("tls_alert_handshake_failure".to_string()),
            SslVersion::TLS1_3,
            SslVersion::TLS1_2,
        );
        assert_eq!(r.enforced, Some(true));
        assert!(r.reason.starts_with("rejected_via_non_mandated_alert:"));
    }

    #[test]
    fn classification_treats_other_alerts_as_inconclusive() {
        // protocol_version (alert 70) is a plausible non-SCSV rejection —
        // server might have TLS 1.1 disabled altogether and would reject
        // the probe even without FALLBACK_SCSV. Stays inconclusive.
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
