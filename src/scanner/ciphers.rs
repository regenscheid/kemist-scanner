//! Per-cipher-suite probing for TLS 1.2 and TLS 1.3.
//!
//! For each suite in `aws_lc_rs::ALL_CIPHER_SUITES` we build a
//! `CryptoProvider` carrying exactly that suite and attempt a handshake.
//! Three possible outcomes:
//!
//! - Handshake succeeds → `supported: true, method: probe`
//! - Server rejects with a handshake-level alert, or resets/aborts the
//!   connection after ClientHello → `supported: false, method: probe`
//!   (server evaluated our offer and declined)
//! - TCP-level or other error → `supported: null, method: error`
//!
//! ## Absence of probe ≠ absence of support
//! Suites outside aws-lc-rs' implementation set (e.g. RC4, 3DES, export
//! ciphers) are never probed. They emit `supported: null,
//! method: not_probed, reason: provider_no_suite_support` elsewhere in
//! the pipeline (see output/json.rs). Downstream rule engines looking
//! for weak-cipher acceptance must examine both `true` and `not_probed`
//! sets together with `capabilities.provider_cipher_suites`.
//!
//! ## Server ordering detection
//! Two additional handshakes with the full provider suite list — default
//! order and reversed. If the server returned the same cipher both
//! times, `server_enforces_order: true`; if it switched to match the
//! client's top pick, `false`. Either probe erroring leaves the
//! observation `null, error`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme, SupportedCipherSuite};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{rustls, TlsConnector};
use tracing::debug;

use crate::model::errors::ScannerError;
use crate::model::protocol::TlsVersion;
use crate::scanner::backends::{is_wire_rejection, HandshakeOutcome};

/// One per-cipher probe result.
#[derive(Debug, Clone)]
pub struct CipherProbeResult {
    /// Debug-formatted rustls cipher suite name
    /// (e.g. `"TLS13_AES_256_GCM_SHA384"`).
    pub name: String,
    /// IANA codepoint (e.g. `0x1302`).
    pub iana_code: u16,
    pub version: TlsVersion,
    pub outcome: HandshakeOutcome,
}

/// Output of the full cipher-probe pass for one target: per-suite results
/// plus the order-enforcement observation.
#[derive(Debug, Clone, Default)]
pub struct CipherProbeOutput {
    pub results: Vec<CipherProbeResult>,
    pub server_enforces_order: Option<bool>,
    pub order_probe_error: Option<String>,
}

/// Probe every suite aws-lc-rs exposes, then detect server ordering.
/// Respects `per_probe_delay` between consecutive handshakes.
pub async fn probe_cipher_suites(
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    per_probe_delay: Duration,
) -> CipherProbeOutput {
    let all_suites: Vec<SupportedCipherSuite> = aws_lc_rs::ALL_CIPHER_SUITES.to_vec();
    let mut results = Vec::with_capacity(all_suites.len());

    for suite in &all_suites {
        let Some(version) = to_model_version(suite.version()) else {
            debug!("skipping suite {:?} with unknown version", suite.suite());
            continue;
        };
        let name = format!("{:?}", suite.suite());
        let iana_code: u16 = suite.suite().into();

        let outcome =
            probe_single_suite(target, hostname, *suite, connect_timeout, handshake_timeout).await;

        results.push(CipherProbeResult {
            name,
            iana_code,
            version,
            outcome,
        });

        if !per_probe_delay.is_zero() {
            tokio::time::sleep(per_probe_delay).await;
        }
    }

    let (server_enforces_order, order_probe_error) = detect_order_enforcement(
        target,
        hostname,
        &all_suites,
        connect_timeout,
        handshake_timeout,
    )
    .await;

    CipherProbeOutput {
        results,
        server_enforces_order,
        order_probe_error,
    }
}

fn to_model_version(v: &'static rustls::SupportedProtocolVersion) -> Option<TlsVersion> {
    match v.version {
        rustls::ProtocolVersion::TLSv1_2 => Some(TlsVersion::Tls12),
        rustls::ProtocolVersion::TLSv1_3 => Some(TlsVersion::Tls13),
        _ => None,
    }
}

pub(crate) async fn probe_single_suite(
    target: SocketAddr,
    hostname: &str,
    suite: SupportedCipherSuite,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> HandshakeOutcome {
    let mut provider = aws_lc_rs::default_provider();
    provider.cipher_suites = vec![suite];

    let version = suite.version();

    let config = match rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[version])
    {
        Ok(b) => b
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PermissiveVerifier))
            .with_no_client_auth(),
        Err(e) => return HandshakeOutcome::Error(format!("config builder: {e}")),
    };

    let connector = TlsConnector::from(Arc::new(config));

    let tcp = match timeout(connect_timeout, TcpStream::connect(&target)).await {
        Err(_) => return HandshakeOutcome::Error("tcp_connect_timeout".to_string()),
        Ok(Err(e)) => {
            // TCP-level failure — can't classify as "cipher not supported".
            let err = ScannerError::from_io("tcp_connect", e);
            return HandshakeOutcome::Error(err.category);
        }
        Ok(Ok(s)) => s,
    };

    let domain = match ServerName::try_from(hostname.to_string()) {
        Ok(d) => d,
        Err(_) => return HandshakeOutcome::Error(format!("invalid_sni:{hostname}")),
    };

    match timeout(handshake_timeout, connector.connect(domain, tcp)).await {
        Err(_) => HandshakeOutcome::Error("handshake_timeout".to_string()),
        Ok(Ok(_)) => HandshakeOutcome::Supported,
        Ok(Err(e)) => classify_probe_error(e),
    }
}

/// Distinguish "server evaluated our offer and rejected it" (real signal)
/// from "something else went wrong" (probe error). The Error-string
/// format preserves both category and context on this (rustls) path;
/// the OpenSSL-path classifier emits category only. Schema v1 depends
/// on that asymmetry — see `is_wire_rejection`.
fn classify_probe_error(e: std::io::Error) -> HandshakeOutcome {
    let scanner_err = ScannerError::from_io("handshake", e);
    if is_wire_rejection(&scanner_err) {
        HandshakeOutcome::NotSupported
    } else {
        HandshakeOutcome::Error(format!("{}: {}", scanner_err.category, scanner_err.context))
    }
}

async fn detect_order_enforcement(
    target: SocketAddr,
    hostname: &str,
    suites: &[SupportedCipherSuite],
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> (Option<bool>, Option<String>) {
    if suites.len() < 2 {
        // With 0 or 1 suites there's no ordering to observe.
        return (None, Some("insufficient_suites_for_ordering".to_string()));
    }

    let forward =
        negotiate_with_order(target, hostname, suites, connect_timeout, handshake_timeout).await;
    let mut reversed: Vec<SupportedCipherSuite> = suites.to_vec();
    reversed.reverse();
    let reversed_out = negotiate_with_order(
        target,
        hostname,
        &reversed,
        connect_timeout,
        handshake_timeout,
    )
    .await;

    match (forward, reversed_out) {
        (Ok(Some(a)), Ok(Some(b))) => {
            let ai: u16 = a.suite().into();
            let bi: u16 = b.suite().into();
            (Some(ai == bi), None)
        }
        (Err(e), _) | (_, Err(e)) => (None, Some(e)),
        _ => (None, Some("no_suite_negotiated".to_string())),
    }
}

async fn negotiate_with_order(
    target: SocketAddr,
    hostname: &str,
    suites: &[SupportedCipherSuite],
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> Result<Option<SupportedCipherSuite>, String> {
    let mut provider = aws_lc_rs::default_provider();
    provider.cipher_suites = suites.to_vec();

    let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("builder:{e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PermissiveVerifier))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    let tcp = timeout(connect_timeout, TcpStream::connect(&target))
        .await
        .map_err(|_| "tcp_timeout".to_string())?
        .map_err(|e| format!("tcp:{e}"))?;

    let domain = ServerName::try_from(hostname.to_string())
        .map_err(|_| format!("invalid_sni:{hostname}"))?;

    let stream = timeout(handshake_timeout, connector.connect(domain, tcp))
        .await
        .map_err(|_| "handshake_timeout".to_string())?
        .map_err(|e| format!("handshake:{e}"))?;

    let (_, conn) = stream.get_ref();
    Ok(conn.negotiated_cipher_suite())
}

/// Minimal accept-all verifier for probes where we don't care about the cert —
/// we're only observing the server's cipher choice. Duplicated from probe.rs
/// to keep the per-cipher module self-contained.
#[derive(Debug)]
struct PermissiveVerifier;

impl ServerCertVerifier for PermissiveVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}
