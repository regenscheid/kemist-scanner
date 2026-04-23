//! SNI behavior probe.
//!
//! One extra handshake to the target using `ServerName::IpAddress` instead
//! of a DNS name. rustls is RFC 6066 compliant and omits the SNI extension
//! when the `ServerName` is an IP literal — so this probe tells us what
//! the server returns when no SNI is sent. Compare the leaf cert
//! fingerprint to the SNI-set characterization handshake's fingerprint
//! to categorize:
//!
//! - Server returned the same cert → `same_cert` (SNI made no difference)
//! - Server returned a different cert → `different_cert` (name-based vhost)
//! - Server refused the connection → `rejected` (strict SNI enforcement)
//! - Probe itself failed → `error`
//!
//! Downstream rule engines decide what these mean for their policy — the
//! scanner only reports the raw observation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{rustls, TlsConnector};
use tracing::debug;

use crate::model::errors::ScannerError;

/// The wire-shape observation the scanner emits for `tls.sni_behavior`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniBehaviorOutcome {
    /// No-SNI connection succeeded with the same leaf cert as the SNI probe.
    SameCert,
    /// No-SNI connection succeeded with a different leaf cert.
    DifferentCert,
    /// Server refused the no-SNI connection (handshake alert or reset).
    Rejected,
    /// Probe failed in an unexpected way (TCP/timeout/etc).
    Error,
}

impl SniBehaviorOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SameCert => "same_cert",
            Self::DifferentCert => "different_cert",
            Self::Rejected => "rejected",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SniBehaviorResult {
    pub outcome: SniBehaviorOutcome,
    /// Context for Error/Rejected outcomes; None for Same/DifferentCert.
    pub reason: Option<String>,
}

/// Probe the target with SNI deliberately omitted (via `ServerName::IpAddress`)
/// and compare the returned leaf cert's SHA-256 fingerprint to the one from
/// the SNI-set characterization handshake.
///
/// Returns `None` when `sni_cert_fingerprint` is None — with no reference
/// cert we can't distinguish Same from Different, and the SNI-set probe
/// already failed upstream anyway.
pub async fn probe_sni_omitted(
    target: SocketAddr,
    sni_cert_fingerprint: Option<&str>,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> SniBehaviorResult {
    let Some(reference_fp) = sni_cert_fingerprint else {
        return SniBehaviorResult {
            outcome: SniBehaviorOutcome::Error,
            reason: Some("no_reference_cert_from_sni_probe".to_string()),
        };
    };

    let collector = Arc::new(FingerprintCollector::default());

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(collector.clone())
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    let tcp = match timeout(connect_timeout, TcpStream::connect(&target)).await {
        Err(_) => {
            return SniBehaviorResult {
                outcome: SniBehaviorOutcome::Error,
                reason: Some("tcp_connect_timeout".to_string()),
            }
        }
        Ok(Err(e)) => {
            let err = ScannerError::from_io("tcp_connect", e);
            return SniBehaviorResult {
                outcome: SniBehaviorOutcome::Error,
                reason: Some(format!("{}:{}", err.category, err.context)),
            };
        }
        Ok(Ok(s)) => s,
    };

    // ServerName::IpAddress — rustls will not emit the SNI extension.
    let server_name = ServerName::IpAddress(target.ip().into());

    match timeout(handshake_timeout, connector.connect(server_name, tcp)).await {
        Err(_) => SniBehaviorResult {
            outcome: SniBehaviorOutcome::Error,
            reason: Some("handshake_timeout".to_string()),
        },
        Ok(Err(e)) => {
            // A TLS alert / connection reset after ClientHello is the server
            // explicitly rejecting the SNI-less connection.
            let err = ScannerError::from_io("handshake", e);
            let is_rejection =
                err.category.starts_with("tls_alert_") || err.category == "connection_refused";
            if is_rejection {
                SniBehaviorResult {
                    outcome: SniBehaviorOutcome::Rejected,
                    reason: Some(err.category),
                }
            } else {
                SniBehaviorResult {
                    outcome: SniBehaviorOutcome::Error,
                    reason: Some(err.category),
                }
            }
        }
        Ok(Ok(_)) => {
            let observed = collector.leaf_fingerprint();
            match observed {
                Some(fp) if fp.eq_ignore_ascii_case(reference_fp) => SniBehaviorResult {
                    outcome: SniBehaviorOutcome::SameCert,
                    reason: None,
                },
                Some(_) => SniBehaviorResult {
                    outcome: SniBehaviorOutcome::DifferentCert,
                    reason: None,
                },
                None => {
                    debug!("SNI probe handshake OK but verifier captured no leaf cert");
                    SniBehaviorResult {
                        outcome: SniBehaviorOutcome::Error,
                        reason: Some("no_leaf_cert_captured".to_string()),
                    }
                }
            }
        }
    }
}

/// Minimal verifier that captures only the leaf cert's SHA-256 fingerprint.
/// No need for the full `StateCollector` infrastructure — SNI probing just
/// needs "what cert did the server pick this time."
#[derive(Debug, Default)]
struct FingerprintCollector {
    leaf_fp: Mutex<Option<String>>,
}

impl FingerprintCollector {
    fn leaf_fingerprint(&self) -> Option<String> {
        self.leaf_fp.lock().ok().and_then(|g| g.clone())
    }
}

impl ServerCertVerifier for FingerprintCollector {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let fp = hex::encode(hasher.finalize());
        if let Ok(mut guard) = self.leaf_fp.lock() {
            *guard = Some(fp);
        }
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
