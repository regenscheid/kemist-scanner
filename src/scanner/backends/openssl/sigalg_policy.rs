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

use openssl::ssl::{HandshakeError, Ssl, SslContext, SslMethod, SslRef, SslVerifyMode, SslVersion};
use sha2::{Digest, Sha256};
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
const NAME_EDDSA_ONLY: &str = "eddsa_only";

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
        SHA256_PLUS_ONLY_CODEPOINTS,
        target,
        hostname,
        connect_timeout,
        handshake_timeout,
        skip,
    )
    .await;
    let ecdsa_only = run_one(
        NAME_ECDSA_ONLY,
        ECDSA_ONLY_CODEPOINTS,
        target,
        hostname,
        connect_timeout,
        handshake_timeout,
        skip,
    )
    .await;
    let rsa_pss_only = run_one(
        NAME_RSA_PSS_ONLY,
        RSA_PSS_ONLY_CODEPOINTS,
        target,
        hostname,
        connect_timeout,
        handshake_timeout,
        skip,
    )
    .await;
    let rsa_pkcs1_only = run_one(
        NAME_RSA_PKCS1_ONLY,
        RSA_PKCS1_ONLY_CODEPOINTS,
        target,
        hostname,
        connect_timeout,
        handshake_timeout,
        skip,
    )
    .await;
    let eddsa_only = run_one(
        NAME_EDDSA_ONLY,
        EDDSA_ONLY_CODEPOINTS,
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
        eddsa_only,
    }
}

async fn run_one(
    name: &'static str,
    codepoints: &'static [u16],
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

    // Compose the probe over `OpensslBackend::handshake(sigalgs: ...)`.
    // The backend drives `probe_blocking` internally and folds its
    // `ConstrainedProbeResult` into a `HandshakeResult`; this composer
    // unfolds it back so schema-visible shape is preserved exactly.
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
    let constraint = HandshakeConstraint {
        sigalgs: Some(codepoints.to_vec()),
        version_range: Some((TlsVersion::Tls12, TlsVersion::Tls13)),
        seclevel_zero: true,
        ..Default::default()
    };

    let hr = match registry.openssl.handshake(constraint, &ctx).await {
        Ok(r) => r,
        Err(u) => {
            debug!("sigalg probe unsatisfiable ({name}): {}", u.reason);
            return ConstrainedProbeResult {
                outcome: SigalgOutcome::NotProbed,
                method: Method::Error,
                reason: Some(format!("unsatisfiable:{}", u.reason)),
                ..Default::default()
            };
        }
    };

    // Reverse-map HandshakeResult → ConstrainedProbeResult. The
    // backend's forward mapping encoded the `method` distinction via
    // an Error-string prefix (`setup:...` for probe-setup failures,
    // raw otherwise for wire-level failures like `tcp_connect:...`).
    match hr.outcome {
        HandshakeOutcome::Supported => ConstrainedProbeResult {
            outcome: SigalgOutcome::HandshakeComplete,
            selected_sigalg: hr.ske_signature_name,
            alert: None,
            method: Method::Probe,
            reason: None,
            ..Default::default()
        },
        HandshakeOutcome::NotSupported => {
            let cat = hr.alert.unwrap_or_default();
            let (outcome, alert) = classify_failure(&cat);
            ConstrainedProbeResult {
                outcome,
                selected_sigalg: None,
                alert,
                method: Method::Probe,
                reason: Some(cat),
                ..Default::default()
            }
        }
        HandshakeOutcome::Error(msg) => {
            if let Some(stripped) = msg.strip_prefix("setup:") {
                ConstrainedProbeResult {
                    outcome: SigalgOutcome::NotProbed,
                    method: Method::Error,
                    reason: Some(stripped.to_string()),
                    ..Default::default()
                }
            } else {
                // Wire-level failure — TCP connect, unexpected close.
                ConstrainedProbeResult {
                    outcome: SigalgOutcome::ConnectionClosed,
                    method: Method::Probe,
                    reason: Some(msg),
                    ..Default::default()
                }
            }
        }
        other => ConstrainedProbeResult {
            outcome: SigalgOutcome::NotProbed,
            method: Method::Error,
            reason: Some(format!("unexpected_handshake_outcome:{:?}", other)),
            ..Default::default()
        },
    }
}

/// Synchronous sigalg-pinned handshake. `pub(crate)` so
/// `backends::openssl::handshake()` can wrap it for the sigalgs
/// constraint shape.
pub(crate) fn probe_blocking(
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
            let (leaf_fingerprint_sha256, leaf_subject_dn) = leaf_observation(stream.ssl());
            ConstrainedProbeResult {
                outcome: SigalgOutcome::HandshakeComplete,
                selected_sigalg: selected,
                alert: None,
                method: Method::Probe,
                reason: None,
                leaf_fingerprint_sha256,
                leaf_subject_dn,
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
                ..Default::default()
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

/// Capture the leaf fingerprint (SHA-256 of DER) and subject DN from
/// a completed handshake. Returns `(None, None)` when the peer cert
/// can't be read or its DER can't be extracted — the constrained
/// probe still completed, so these are observation gaps, not errors.
///
/// Formatting matches `CertificateFacts.subject_dn` (x509-parser
/// `Display`) so downstream correlation against the main cert chain
/// is a byte-equality check.
fn leaf_observation(ssl: &SslRef) -> (Option<String>, Option<String>) {
    let Some(cert) = ssl.peer_certificate() else {
        return (None, None);
    };
    let Ok(der) = cert.to_der() else {
        return (None, None);
    };
    let fingerprint = fingerprint_der(&der);
    let subject_dn = parse_subject_dn(&der);
    (Some(fingerprint), subject_dn)
}

/// Lowercase hex SHA-256 of a DER blob. Matches the fingerprint
/// format used throughout `certificates.*.fingerprint_sha256`.
fn fingerprint_der(der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(der);
    hex::encode(hasher.finalize())
}

/// Parse the DN out of the leaf DER via x509-parser so the emitted
/// string formatting matches `CertificateFacts.subject_dn` exactly.
fn parse_subject_dn(der: &[u8]) -> Option<String> {
    use x509_parser::prelude::FromDer;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der).ok()?;
    Some(cert.subject().to_string())
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

// IANA signature_algorithms codepoints per RFC 8446 §4.2.3. The
// backend's `iana_sigalgs_to_openssl_string` helper recognizes these
// exact sets and translates to OpenSSL's `set_sigalgs_list` format.

/// SHA-256+ only — RSA-PKCS1, ECDSA, and RSA-PSS (rsae) with SHA-256/384/512.
/// Reveals servers whose cert chain signs with SHA-1 (or worse).
const SHA256_PLUS_ONLY_CODEPOINTS: &[u16] = &[
    0x0401, 0x0501, 0x0601, // rsa_pkcs1_sha256/384/512
    0x0403, 0x0503, 0x0603, // ecdsa_secp{256r1,384r1,521r1}_sha{256,384,512}
    0x0804, 0x0805, 0x0806, // rsa_pss_rsae_sha256/384/512
];

/// ECDSA-only. Reveals RSA-cert-only deployments.
const ECDSA_ONLY_CODEPOINTS: &[u16] = &[0x0403, 0x0503, 0x0603];

/// RSA-PSS-only. Reveals servers that can't or won't sign with PSS
/// (i.e. PKCS#1 v1.5-only servers).
const RSA_PSS_ONLY_CODEPOINTS: &[u16] = &[0x0804, 0x0805, 0x0806];

/// RSA-PKCS1v1.5-only. Reveals servers that mandate PSS (modern
/// posture — a response of `handshake_failure` is the "good" signal
/// for this probe).
const RSA_PKCS1_ONLY_CODEPOINTS: &[u16] = &[0x0401, 0x0501, 0x0601];

/// EdDSA-only (Ed25519 + Ed448 per RFC 8446 §4.2.3 / IANA registry).
/// A server that completes this probe runs on an EdDSA-authenticated
/// cert chain; `handshake_failure` means the server doesn't support
/// EdDSA at all (common today outside PQC migration pilots).
const EDDSA_ONLY_CODEPOINTS: &[u16] = &[0x0807, 0x0808];

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
    fn fingerprint_der_emits_64_lowercase_hex_chars() {
        let der: &[u8] = b"\x30\x82\x00\x03\x02\x01\x00";
        let fp = fingerprint_der(der);
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(fp.chars().all(|c| !c.is_ascii_uppercase()));
    }

    #[test]
    fn fingerprint_der_is_deterministic_for_same_input() {
        let der: &[u8] = b"some_fake_der_bytes";
        assert_eq!(fingerprint_der(der), fingerprint_der(der));
    }

    #[test]
    fn parse_subject_dn_returns_none_on_unparseable_bytes() {
        assert!(parse_subject_dn(&[0x00, 0x01, 0x02]).is_none());
    }

    #[test]
    fn codepoint_families_cover_expected_iana_values() {
        // Guard against typos in the hand-coded IANA values.
        // RFC 8446 §4.2.3 codepoint mapping.
        assert!(SHA256_PLUS_ONLY_CODEPOINTS.contains(&0x0804)); // rsa_pss_rsae_sha256
        assert!(SHA256_PLUS_ONLY_CODEPOINTS.contains(&0x0403)); // ecdsa_*_sha256
        assert!(SHA256_PLUS_ONLY_CODEPOINTS.contains(&0x0401)); // rsa_pkcs1_sha256
        assert_eq!(SHA256_PLUS_ONLY_CODEPOINTS.len(), 9);

        assert_eq!(ECDSA_ONLY_CODEPOINTS, &[0x0403, 0x0503, 0x0603]);
        assert!(ECDSA_ONLY_CODEPOINTS.iter().all(|c| (c & 0xFF) == 0x03));

        assert_eq!(RSA_PSS_ONLY_CODEPOINTS, &[0x0804, 0x0805, 0x0806]);
        assert_eq!(RSA_PKCS1_ONLY_CODEPOINTS, &[0x0401, 0x0501, 0x0601]);
        assert_eq!(EDDSA_ONLY_CODEPOINTS, &[0x0807, 0x0808]);
    }
}
