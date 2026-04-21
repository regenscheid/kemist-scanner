//! Signature-algorithm policy probe.
//!
//! Opens up to four TLS handshakes per target, each with the
//! ClientHello's `signature_algorithms` extension restricted to a
//! specific family. Records what the server does in response:
//! handshake_complete (with the server's selected sigalg),
//! handshake_failure, connection_closed, or other_alert.
//!
//! Four constraints:
//!
//! | name | OpenSSL sigalgs list |
//! |---|---|
//! | `sha256_plus_only` | `RSA-PSS+SHA256:...+SHA384:...+SHA512:RSA+SHA256:...:ECDSA+SHA256:...:ECDSA+SHA512` |
//! | `ecdsa_only` | `ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512` |
//! | `rsa_pss_only` | `RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512` |
//! | `rsa_pkcs1_only` | `RSA+SHA256:RSA+SHA384:RSA+SHA512` |
//!
//! Each probe runs at TLS 1.2 or TLS 1.3 (min 1.2, max 1.3). The
//! observation cares about *the server's sigalg selection*, which
//! both versions expose via [`crate::scanner::openssl::ske_sig`].
//!
//! The CLI `--sigalg-probe-skip=<csv>` opts out individual probes.
//! Skipped constraints emit `method: not_probed` with reason
//! `"cli_skipped"` so the output shape stays stable.

use std::net::SocketAddr;
use std::time::Duration;

use openssl::ssl::{HandshakeError, Ssl, SslContext, SslMethod, SslVerifyMode, SslVersion};
use tracing::{debug, info};

use crate::model::scan_result::{
    ConstrainedProbeResult, Method, SigalgOutcome, SignatureAlgorithmPolicyProbe,
};
use crate::scanner::openssl::alerts;
use crate::scanner::openssl::ske_sig;

/// Canonical probe names that a consumer (or `--sigalg-probe-skip`)
/// can reference.
const NAME_SHA256_PLUS_ONLY: &str = "sha256_plus_only";
const NAME_ECDSA_ONLY: &str = "ecdsa_only";
const NAME_RSA_PSS_ONLY: &str = "rsa_pss_only";
const NAME_RSA_PKCS1_ONLY: &str = "rsa_pkcs1_only";

/// Run every non-skipped constraint probe, serially.
pub async fn probe(
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    skip: &[String],
) -> SignatureAlgorithmPolicyProbe {
    info!("OpenSSL sigalg policy probe");

    let sha256_plus_only = run_one(
        NAME_SHA256_PLUS_ONLY,
        sha256_plus_only_sigalgs(),
        target,
        hostname,
        connect_timeout,
        handshake_timeout,
        skip,
    )
    .await;
    let ecdsa_only = run_one(
        NAME_ECDSA_ONLY,
        ecdsa_only_sigalgs(),
        target,
        hostname,
        connect_timeout,
        handshake_timeout,
        skip,
    )
    .await;
    let rsa_pss_only = run_one(
        NAME_RSA_PSS_ONLY,
        rsa_pss_only_sigalgs(),
        target,
        hostname,
        connect_timeout,
        handshake_timeout,
        skip,
    )
    .await;
    let rsa_pkcs1_only = run_one(
        NAME_RSA_PKCS1_ONLY,
        rsa_pkcs1_only_sigalgs(),
        target,
        hostname,
        connect_timeout,
        handshake_timeout,
        skip,
    )
    .await;
    SignatureAlgorithmPolicyProbe {
        sha256_plus_only,
        ecdsa_only,
        rsa_pss_only,
        rsa_pkcs1_only,
    }
}

async fn run_one(
    name: &'static str,
    sigalgs: &'static str,
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    skip: &[String],
) -> ConstrainedProbeResult {
    if skip.iter().any(|s| s == name) {
        return ConstrainedProbeResult {
            outcome: SigalgOutcome::NotProbed,
            method: Method::NotProbed,
            reason: Some("cli_skipped".to_string()),
            ..Default::default()
        };
    }

    let hostname_owned = hostname.to_string();
    let result = tokio::task::spawn_blocking(move || {
        probe_blocking(
            sigalgs,
            target,
            &hostname_owned,
            connect_timeout,
            handshake_timeout,
        )
    })
    .await;

    result.unwrap_or_else(|e| {
        debug!("sigalg policy probe panic ({name}): {e}");
        ConstrainedProbeResult {
            outcome: SigalgOutcome::NotProbed,
            method: Method::Error,
            reason: Some(format!("spawn_blocking_panic:{e}")),
            ..Default::default()
        }
    })
}

fn probe_blocking(
    sigalgs: &str,
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> ConstrainedProbeResult {
    let ctx = match build_context(sigalgs) {
        Ok(c) => c,
        Err(e) => {
            return ConstrainedProbeResult {
                outcome: SigalgOutcome::NotProbed,
                method: Method::Error,
                reason: Some(format!("ctx_build:{e}")),
                ..Default::default()
            };
        }
    };

    let tcp = match std::net::TcpStream::connect_timeout(&target, connect_timeout) {
        Ok(s) => s,
        Err(e) => {
            return ConstrainedProbeResult {
                outcome: SigalgOutcome::ConnectionClosed,
                method: Method::Probe,
                reason: Some(format!("tcp_connect:{e}")),
                ..Default::default()
            };
        }
    };
    let _ = tcp.set_read_timeout(Some(handshake_timeout));
    let _ = tcp.set_write_timeout(Some(handshake_timeout));

    let mut ssl = match Ssl::new(&ctx) {
        Ok(s) => s,
        Err(e) => {
            return ConstrainedProbeResult {
                outcome: SigalgOutcome::NotProbed,
                method: Method::Error,
                reason: Some(format!("ssl_new:{e}")),
                ..Default::default()
            };
        }
    };
    let _ = ssl.set_hostname(hostname);

    match ssl.connect(tcp) {
        Ok(stream) => {
            let selected = ske_sig::snapshot(stream.ssl());
            ConstrainedProbeResult {
                outcome: SigalgOutcome::HandshakeComplete,
                selected_sigalg: selected,
                alert: None,
                method: Method::Probe,
                reason: None,
            }
        }
        Err(HandshakeError::Failure(mid)) => {
            let se = alerts::classify_openssl_error("sigalg_policy handshake", mid.error());
            let (outcome, alert) = classify_failure(&se.category);
            ConstrainedProbeResult {
                outcome,
                selected_sigalg: None,
                alert,
                method: Method::Probe,
                reason: Some(se.category),
            }
        }
        Err(HandshakeError::SetupFailure(e)) => ConstrainedProbeResult {
            outcome: SigalgOutcome::NotProbed,
            method: Method::Error,
            reason: Some(format!("setup_failure:{e}")),
            ..Default::default()
        },
        Err(HandshakeError::WouldBlock(_)) => ConstrainedProbeResult {
            outcome: SigalgOutcome::NotProbed,
            method: Method::Error,
            reason: Some("handshake_would_block".to_string()),
            ..Default::default()
        },
    }
}

/// Map a [`crate::model::errors::ScannerError::category`] from the
/// OpenSSL handshake-error classifier into a [`SigalgOutcome`]
/// variant + alert-category string.
fn classify_failure(category: &str) -> (SigalgOutcome, Option<String>) {
    if category == "tls_alert_handshake_failure" {
        (SigalgOutcome::HandshakeFailure, Some(category.to_string()))
    } else if category.starts_with("tls_alert_") {
        (SigalgOutcome::OtherAlert, Some(category.to_string()))
    } else if category == "connection_refused" || category == "connection_closed_by_peer" {
        (SigalgOutcome::ConnectionClosed, None)
    } else {
        // Timeouts, internal errors, unexpected I/O — we observed
        // the probe ran and didn't complete, but can't cleanly
        // classify. Preserve the category as-is so rule engines
        // can match on the raw string if needed.
        (SigalgOutcome::OtherAlert, Some(category.to_string()))
    }
}

fn build_context(sigalgs: &str) -> Result<SslContext, openssl::error::ErrorStack> {
    let mut builder = SslContext::builder(SslMethod::tls_client())?;
    // Cover both TLS 1.2 (SKE signature) and TLS 1.3
    // (CertificateVerify signature). Both expose the chosen
    // sigalg via SSL_get0_peer_signature_name.
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_security_level(0);
    builder.set_verify(SslVerifyMode::NONE);
    // The load-bearing call: restrict the ClientHello's
    // signature_algorithms extension to our constraint.
    builder.set_sigalgs_list(sigalgs)?;
    Ok(builder.build())
}

/// SHA-256+ only — every sigalg in our offer has SHA-256, SHA-384, or
/// SHA-512. This reveals servers whose cert chain signs with SHA-1
/// (or worse) because they won't find a compatible sigalg.
fn sha256_plus_only_sigalgs() -> &'static str {
    concat!(
        // RSA-PSS (RFC 8446 / RFC 8017)
        "RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:",
        // RSA PKCS#1 v1.5
        "RSA+SHA256:RSA+SHA384:RSA+SHA512:",
        // ECDSA
        "ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512"
    )
}

/// ECDSA-only. Reveals RSA-cert-only deployments.
fn ecdsa_only_sigalgs() -> &'static str {
    "ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512"
}

/// RSA-PSS-only. Reveals servers that can't or won't sign with PSS
/// (i.e. PKCS#1 v1.5-only servers).
fn rsa_pss_only_sigalgs() -> &'static str {
    "RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512"
}

/// RSA-PKCS1v1.5-only. Reveals servers that mandate PSS (modern
/// posture — a response of `handshake_failure` is the "good" signal
/// for this probe).
fn rsa_pkcs1_only_sigalgs() -> &'static str {
    "RSA+SHA256:RSA+SHA384:RSA+SHA512"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_failure_maps_handshake_failure_to_dedicated_variant() {
        let (outcome, alert) = classify_failure("tls_alert_handshake_failure");
        assert_eq!(outcome, SigalgOutcome::HandshakeFailure);
        assert_eq!(alert.as_deref(), Some("tls_alert_handshake_failure"));
    }

    #[test]
    fn classify_failure_maps_other_alerts_to_other_alert() {
        let (outcome, alert) = classify_failure("tls_alert_insufficient_security");
        assert_eq!(outcome, SigalgOutcome::OtherAlert);
        assert_eq!(alert.as_deref(), Some("tls_alert_insufficient_security"));
    }

    #[test]
    fn classify_failure_maps_connection_refused_to_connection_closed() {
        let (outcome, alert) = classify_failure("connection_refused");
        assert_eq!(outcome, SigalgOutcome::ConnectionClosed);
        assert_eq!(alert, None);
    }

    #[test]
    fn sigalgs_strings_are_colon_separated() {
        // Ensure each constraint string at least contains the
        // expected algorithm family name; guards against typos in
        // the hand-built strings.
        assert!(sha256_plus_only_sigalgs().contains("RSA-PSS+SHA256"));
        assert!(sha256_plus_only_sigalgs().contains("ECDSA+SHA256"));
        assert!(ecdsa_only_sigalgs().starts_with("ECDSA+SHA256"));
        assert!(!ecdsa_only_sigalgs().contains("RSA"));
        assert!(rsa_pss_only_sigalgs().starts_with("RSA-PSS+SHA256"));
        assert!(!rsa_pss_only_sigalgs().contains("ECDSA"));
        assert!(rsa_pkcs1_only_sigalgs().starts_with("RSA+SHA256"));
        assert!(!rsa_pkcs1_only_sigalgs().contains("RSA-PSS"));
    }
}
