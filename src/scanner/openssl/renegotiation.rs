//! Client-initiated renegotiation probe.
//!
//! After a completed TLS 1.2 handshake, issue `SSL_renegotiate` + drive
//! `SSL_do_handshake`. Observe whether the server honors the request:
//!
//! - Handshake completes → `ClientInitiatedAccepted`. Unusual for modern
//!   servers and a mild data-leakage signal even with RFC 5746 secure
//!   renegotiation.
//! - `no_renegotiation` alert (100), `handshake_failure` (40), or
//!   connection reset → `ClientInitiatedRejected`. Expected, compliant
//!   behavior.
//! - Anything else → `Error(...)` with category preserved so triage has
//!   signal.
//!
//! TLS 1.3 has no renegotiation — this module pins TLS 1.2 on the probe
//! context. Servers that don't support TLS 1.2 land as `NotAttempted`
//! with a version-mismatch reason.
//!
//! Supersedes the heuristic stub at
//! `src/scanner/mod.rs::test_secure_renegotiation` (which returned
//! `Some(true)` whenever TLS 1.2 or 1.3 was available, without doing
//! a real probe).

use std::net::SocketAddr;
use std::os::raw::c_int;
use std::time::Duration;

use foreign_types::ForeignTypeRef;
use openssl::ssl::{HandshakeError, Ssl, SslContext, SslMethod, SslVerifyMode, SslVersion};
use tracing::info;

use crate::model::errors::ScannerError;
use crate::scanner::openssl::alerts;

extern "C" {
    /// Raw FFI — the `openssl` crate at 0.10.73 does not expose
    /// `SSL_renegotiate`. Returns 1 on success, 0 on failure (e.g. the
    /// session is already mid-handshake, or the server disabled reneg).
    fn SSL_renegotiate(ssl: *mut openssl_sys::SSL) -> c_int;
}

/// Verdict of a client-initiated renegotiation attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenegotiationVerdict {
    /// Server completed a second handshake on the existing connection.
    /// Uncommon on modern deployments and a posture concern.
    ClientInitiatedAccepted,
    /// Server refused — `no_renegotiation` alert, `handshake_failure`,
    /// or connection close without alert. The compliant outcome.
    ClientInitiatedRejected,
    /// Probe was not attempted — usually because the initial handshake
    /// didn't negotiate TLS 1.2 (TLS 1.3 has no renegotiation), or
    /// the initial handshake itself failed.
    NotAttempted,
    /// Probe itself failed in a way that doesn't match either an
    /// accept or reject signal.
    Error(String),
}

/// Per-target renegotiation observation.
#[derive(Debug, Clone)]
pub struct RenegotiationObservation {
    /// Mirror of the RFC 5746 renegotiation_info extension advertisement
    /// that [`crate::scanner::hello`] already captures. We emit `None`
    /// here because the probe doesn't re-observe it; the authoritative
    /// value lives under `tls.extensions.secure_renegotiation` in the
    /// output JSON. Kept as a struct slot for probe self-containedness
    /// and future expansion.
    pub secure_renegotiation_advertised: Option<bool>,
    pub client_initiated_verdict: RenegotiationVerdict,
    pub reason: Option<String>,
}

/// Run the probe. Full handshake + reneg attempt happens in a single
/// `spawn_blocking` job (the blocking OpenSSL I/O is not cheap to
/// interleave with tokio).
pub async fn probe(
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> RenegotiationObservation {
    info!("OpenSSL client-initiated renegotiation probe");

    let hostname_owned = hostname.to_string();
    tokio::task::spawn_blocking(move || {
        probe_blocking(target, &hostname_owned, connect_timeout, handshake_timeout)
    })
    .await
    .unwrap_or_else(|e| RenegotiationObservation {
        secure_renegotiation_advertised: None,
        client_initiated_verdict: RenegotiationVerdict::Error(format!("spawn_blocking_panic:{e}")),
        reason: Some(format!("spawn_blocking_panic:{e}")),
    })
}

fn probe_blocking(
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> RenegotiationObservation {
    let tcp = match std::net::TcpStream::connect_timeout(&target, connect_timeout) {
        Ok(s) => s,
        Err(e) => {
            let cat = ScannerError::from_io("reneg tcp connect", e).category;
            return error_observation(cat);
        }
    };
    let _ = tcp.set_read_timeout(Some(handshake_timeout));
    let _ = tcp.set_write_timeout(Some(handshake_timeout));

    let ctx = match build_tls12_context() {
        Ok(c) => c,
        Err(stack) => return error_observation(format!("openssl_ctx_build:{stack}")),
    };

    let mut ssl = match Ssl::new(&ctx) {
        Ok(s) => s,
        Err(stack) => return error_observation(format!("openssl_ssl_new:{stack}")),
    };
    let _ = ssl.set_hostname(hostname);

    // Initial handshake — must succeed to have anything to renegotiate.
    let mut stream = match ssl.connect(tcp) {
        Ok(s) => s,
        Err(HandshakeError::Failure(mid)) => {
            let cat =
                alerts::classify_openssl_error("reneg initial handshake", mid.error()).category;
            return RenegotiationObservation {
                secure_renegotiation_advertised: None,
                client_initiated_verdict: RenegotiationVerdict::NotAttempted,
                reason: Some(format!("initial_handshake_failed:{cat}")),
            };
        }
        Err(HandshakeError::SetupFailure(stack)) => {
            return RenegotiationObservation {
                secure_renegotiation_advertised: None,
                client_initiated_verdict: RenegotiationVerdict::NotAttempted,
                reason: Some(format!("initial_handshake_setup:{stack}")),
            };
        }
        Err(HandshakeError::WouldBlock(_)) => {
            return RenegotiationObservation {
                secure_renegotiation_advertised: None,
                client_initiated_verdict: RenegotiationVerdict::NotAttempted,
                reason: Some("initial_handshake_would_block".to_string()),
            };
        }
    };

    // Defensive: confirm TLS 1.2 before requesting renegotiation. The
    // builder already pins this, but a future refactor could drift.
    let negotiated = stream.ssl().version2();
    if negotiated != Some(SslVersion::TLS1_2) {
        return RenegotiationObservation {
            secure_renegotiation_advertised: None,
            client_initiated_verdict: RenegotiationVerdict::NotAttempted,
            reason: Some(format!("negotiated_version_not_tls12:{:?}", negotiated)),
        };
    }

    // Request the renegotiation. OpenSSL flips internal state; the
    // actual ClientHello goes out on the next `do_handshake` call.
    //
    // SAFETY: `ssl_ptr` is a live `*mut SSL` obtained from a live
    // `SslRef` borrow rooted in `stream`.
    let ssl_ptr = stream.ssl().as_ptr();
    let rc = unsafe { SSL_renegotiate(ssl_ptr) };
    if rc != 1 {
        return error_observation(format!("SSL_renegotiate_returned_{rc}"));
    }

    match stream.do_handshake() {
        Ok(()) => RenegotiationObservation {
            secure_renegotiation_advertised: None,
            client_initiated_verdict: RenegotiationVerdict::ClientInitiatedAccepted,
            reason: Some("renegotiation_handshake_completed".to_string()),
        },
        Err(e) => {
            let se = alerts::classify_openssl_error("reneg handshake", &e);
            let verdict = classify_reneg_error(&se.category);
            // Preserve context — the verdict is already definitive, but
            // the reason carries diagnostic detail (e.g. the specific
            // alert bytes or the "connection reset by peer" message).
            RenegotiationObservation {
                secure_renegotiation_advertised: None,
                client_initiated_verdict: verdict,
                reason: Some(format!("{}: {}", se.category, se.context)),
            }
        }
    }
}

fn build_tls12_context() -> Result<SslContext, openssl::error::ErrorStack> {
    let mut builder = SslContext::builder(SslMethod::tls_client())?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_security_level(0);
    builder.set_verify(SslVerifyMode::NONE);
    Ok(builder.build())
}

/// Map a [`ScannerError::category`] from the post-reneg handshake into a
/// [`RenegotiationVerdict`].
///
/// - `tls_alert_no_renegotiation`: RFC 5246 §7.2.1 warning, treated as
///   fatal by RFC 5746 secure-reneg-aware peers. Straightforward reject.
/// - `tls_alert_handshake_failure`: strict server rejection. Reject.
/// - `connection_refused`: TCP reset or abrupt close mid-handshake.
///   Reject. (Bare socket errors during an initiated renegotiation read
///   the same way: the server didn't want to continue.)
/// - Any other alert or error: inconclusive — report as `Error` so the
///   category surfaces for triage.
fn classify_reneg_error(category: &str) -> RenegotiationVerdict {
    match category {
        "tls_alert_no_renegotiation" | "tls_alert_handshake_failure" | "connection_refused" => {
            RenegotiationVerdict::ClientInitiatedRejected
        }
        other => RenegotiationVerdict::Error(other.to_string()),
    }
}

fn error_observation(reason: String) -> RenegotiationObservation {
    RenegotiationObservation {
        secure_renegotiation_advertised: None,
        client_initiated_verdict: RenegotiationVerdict::Error(reason.clone()),
        reason: Some(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_reneg_error_rejects_no_renegotiation_alert() {
        assert_eq!(
            classify_reneg_error("tls_alert_no_renegotiation"),
            RenegotiationVerdict::ClientInitiatedRejected
        );
    }

    #[test]
    fn classify_reneg_error_rejects_handshake_failure_alert() {
        assert_eq!(
            classify_reneg_error("tls_alert_handshake_failure"),
            RenegotiationVerdict::ClientInitiatedRejected
        );
    }

    #[test]
    fn classify_reneg_error_rejects_connection_refused() {
        // Bare socket reset mid-renegotiation — server didn't want to
        // continue, treat same as an alert-based reject.
        assert_eq!(
            classify_reneg_error("connection_refused"),
            RenegotiationVerdict::ClientInitiatedRejected
        );
    }

    #[test]
    fn classify_reneg_error_preserves_other_categories_as_error() {
        let v = classify_reneg_error("connection_timeout");
        match v {
            RenegotiationVerdict::Error(cat) => assert_eq!(cat, "connection_timeout"),
            other => panic!("expected Error, got {other:?}"),
        }

        // Unexpected alerts (e.g. tls_alert_decode_error) also fall through
        // to Error — we'd rather surface the anomaly than over-interpret.
        let v = classify_reneg_error("tls_alert_decode_error");
        match v {
            RenegotiationVerdict::Error(cat) => assert_eq!(cat, "tls_alert_decode_error"),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn error_observation_populates_both_verdict_and_reason() {
        let obs = error_observation("openssl_ssl_new:boom".to_string());
        assert_eq!(obs.reason.as_deref(), Some("openssl_ssl_new:boom"));
        match obs.client_initiated_verdict {
            RenegotiationVerdict::Error(cat) => assert_eq!(cat, "openssl_ssl_new:boom"),
            other => panic!("expected Error, got {other:?}"),
        }
    }
}
