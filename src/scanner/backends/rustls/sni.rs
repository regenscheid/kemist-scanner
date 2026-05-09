//! SNI behavior probe.
//!
//! Runs SNI-variant handshakes and compares each returned leaf cert
//! fingerprint to the SNI-set characterization handshake's fingerprint:
//! omitted SNI, bogus DNS SNI, and an IP-literal SNI when the OpenSSL
//! backend is available. rustls is RFC 6066 compliant and only serializes
//! SNI for DNS names; the deliberately non-conformant IP-literal SNI path
//! uses OpenSSL's lower-level `SSL_set_tlsext_host_name`.
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
    /// Probe variant could not be expressed by the TLS backend.
    NotProbed,
}

impl SniBehaviorOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SameCert => "same_cert",
            Self::DifferentCert => "different_cert",
            Self::Rejected => "rejected",
            Self::Error => "error",
            Self::NotProbed => "not_probed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SniBehaviorResult {
    pub outcome: SniBehaviorOutcome,
    pub leaf_fingerprint_sha256: Option<String>,
    /// Context for Error/Rejected outcomes; None for Same/DifferentCert.
    pub reason: Option<String>,
    pub probes: Vec<SniProbeResult>,
}

#[derive(Debug, Clone)]
pub struct SniProbeResult {
    pub variant: SniProbeVariant,
    pub sni_sent: Option<String>,
    pub outcome: SniBehaviorOutcome,
    pub leaf_fingerprint_sha256: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniProbeVariant {
    Omitted,
    BogusDns,
    IpLiteral,
}

impl SniProbeVariant {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Omitted => "omitted",
            Self::BogusDns => "bogus_dns",
            Self::IpLiteral => "ip_literal",
        }
    }
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
            leaf_fingerprint_sha256: None,
            reason: Some("no_reference_cert_from_sni_probe".to_string()),
            probes: Vec::new(),
        };
    };

    let omitted = probe_variant(
        target,
        SniProbeVariant::Omitted,
        None,
        ServerName::IpAddress(target.ip().into()),
        reference_fp,
        connect_timeout,
        handshake_timeout,
    )
    .await;

    let bogus_name = "kemist-invalid-sni.local".to_string();
    let bogus = match ServerName::try_from(bogus_name.clone()) {
        Ok(server_name) => {
            probe_variant(
                target,
                SniProbeVariant::BogusDns,
                Some(bogus_name),
                server_name,
                reference_fp,
                connect_timeout,
                handshake_timeout,
            )
            .await
        }
        Err(e) => SniProbeResult {
            variant: SniProbeVariant::BogusDns,
            sni_sent: Some("kemist-invalid-sni.local".to_string()),
            outcome: SniBehaviorOutcome::NotProbed,
            leaf_fingerprint_sha256: None,
            reason: Some(format!("invalid_probe_sni:{e}")),
        },
    };

    let ip_literal =
        probe_ip_literal_with_openssl(target, reference_fp, connect_timeout, handshake_timeout)
            .await;

    SniBehaviorResult {
        outcome: omitted.outcome,
        leaf_fingerprint_sha256: omitted.leaf_fingerprint_sha256.clone(),
        reason: omitted.reason.clone(),
        probes: vec![omitted, bogus, ip_literal],
    }
}

async fn probe_variant(
    target: SocketAddr,
    variant: SniProbeVariant,
    sni_sent: Option<String>,
    server_name: ServerName<'static>,
    reference_fp: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> SniProbeResult {
    let collector = Arc::new(FingerprintCollector::default());

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(collector.clone())
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    let tcp = match timeout(connect_timeout, TcpStream::connect(&target)).await {
        Err(_) => {
            return SniProbeResult {
                variant,
                sni_sent,
                outcome: SniBehaviorOutcome::Error,
                leaf_fingerprint_sha256: None,
                reason: Some("tcp_connect_timeout".to_string()),
            };
        }
        Ok(Err(e)) => {
            let err = ScannerError::from_io("tcp_connect", e);
            return SniProbeResult {
                variant,
                sni_sent,
                outcome: SniBehaviorOutcome::Error,
                leaf_fingerprint_sha256: None,
                reason: Some(format!("{}:{}", err.category, err.context)),
            };
        }
        Ok(Ok(s)) => s,
    };

    match timeout(handshake_timeout, connector.connect(server_name, tcp)).await {
        Err(_) => SniProbeResult {
            variant,
            sni_sent,
            outcome: SniBehaviorOutcome::Error,
            leaf_fingerprint_sha256: None,
            reason: Some("handshake_timeout".to_string()),
        },
        Ok(Err(e)) => {
            let err = ScannerError::from_io("handshake", e);
            let is_rejection =
                err.category.starts_with("tls_alert_") || err.category == "connection_refused";
            SniProbeResult {
                variant,
                sni_sent,
                outcome: if is_rejection {
                    SniBehaviorOutcome::Rejected
                } else {
                    SniBehaviorOutcome::Error
                },
                leaf_fingerprint_sha256: None,
                reason: Some(err.category),
            }
        }
        Ok(Ok(_)) => {
            let observed = collector.leaf_fingerprint();
            match observed {
                Some(fp) if fp.eq_ignore_ascii_case(reference_fp) => SniProbeResult {
                    variant,
                    sni_sent,
                    outcome: SniBehaviorOutcome::SameCert,
                    leaf_fingerprint_sha256: Some(fp),
                    reason: None,
                },
                Some(fp) => SniProbeResult {
                    variant,
                    sni_sent,
                    outcome: SniBehaviorOutcome::DifferentCert,
                    leaf_fingerprint_sha256: Some(fp),
                    reason: None,
                },
                None => {
                    debug!("SNI probe handshake OK but verifier captured no leaf cert");
                    SniProbeResult {
                        variant,
                        sni_sent,
                        outcome: SniBehaviorOutcome::Error,
                        leaf_fingerprint_sha256: None,
                        reason: Some("no_leaf_cert_captured".to_string()),
                    }
                }
            }
        }
    }
}

#[cfg(feature = "legacy-probes")]
async fn probe_ip_literal_with_openssl(
    target: SocketAddr,
    reference_fp: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> SniProbeResult {
    let ip_literal = target.ip().to_string();
    let reference_fp = reference_fp.to_string();
    let ip_literal_for_task = ip_literal.clone();
    tokio::task::spawn_blocking(move || {
        probe_ip_literal_with_openssl_blocking(
            target,
            &ip_literal_for_task,
            &reference_fp,
            connect_timeout,
            handshake_timeout,
        )
    })
    .await
    .unwrap_or_else(|e| SniProbeResult {
        variant: SniProbeVariant::IpLiteral,
        sni_sent: Some(ip_literal),
        outcome: SniBehaviorOutcome::Error,
        leaf_fingerprint_sha256: None,
        reason: Some(format!("spawn_blocking_panic:{e}")),
    })
}

#[cfg(feature = "legacy-probes")]
fn probe_ip_literal_with_openssl_blocking(
    target: SocketAddr,
    ip_literal: &str,
    reference_fp: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> SniProbeResult {
    use openssl::ssl::{HandshakeError, Ssl};

    let tcp = match std::net::TcpStream::connect_timeout(&target, connect_timeout) {
        Ok(s) => s,
        Err(e) => {
            let err = ScannerError::from_io("openssl_sni_ip_literal tcp_connect", e);
            return SniProbeResult {
                variant: SniProbeVariant::IpLiteral,
                sni_sent: Some(ip_literal.to_string()),
                outcome: SniBehaviorOutcome::Error,
                leaf_fingerprint_sha256: None,
                reason: Some(format!("{}:{}", err.category, err.context)),
            };
        }
    };
    let _ = tcp.set_read_timeout(Some(handshake_timeout));
    let _ = tcp.set_write_timeout(Some(handshake_timeout));

    let ctx = match build_openssl_context_for_sni_probe() {
        Ok(ctx) => ctx,
        Err(e) => {
            return SniProbeResult {
                variant: SniProbeVariant::IpLiteral,
                sni_sent: Some(ip_literal.to_string()),
                outcome: SniBehaviorOutcome::Error,
                leaf_fingerprint_sha256: None,
                reason: Some(format!("openssl_ctx_build:{e}")),
            };
        }
    };

    let mut ssl = match Ssl::new(&ctx) {
        Ok(ssl) => ssl,
        Err(e) => {
            return SniProbeResult {
                variant: SniProbeVariant::IpLiteral,
                sni_sent: Some(ip_literal.to_string()),
                outcome: SniBehaviorOutcome::Error,
                leaf_fingerprint_sha256: None,
                reason: Some(format!("openssl_ssl_new:{e}")),
            };
        }
    };

    if let Err(e) = ssl.set_hostname(ip_literal) {
        return SniProbeResult {
            variant: SniProbeVariant::IpLiteral,
            sni_sent: Some(ip_literal.to_string()),
            outcome: SniBehaviorOutcome::NotProbed,
            leaf_fingerprint_sha256: None,
            reason: Some(format!("openssl_rejected_ip_literal_sni:{e}")),
        };
    }

    match ssl.connect(tcp) {
        Ok(stream) => match leaf_fingerprint_from_openssl(stream.ssl()) {
            Some(fp) if fp.eq_ignore_ascii_case(reference_fp) => SniProbeResult {
                variant: SniProbeVariant::IpLiteral,
                sni_sent: Some(ip_literal.to_string()),
                outcome: SniBehaviorOutcome::SameCert,
                leaf_fingerprint_sha256: Some(fp),
                reason: None,
            },
            Some(fp) => SniProbeResult {
                variant: SniProbeVariant::IpLiteral,
                sni_sent: Some(ip_literal.to_string()),
                outcome: SniBehaviorOutcome::DifferentCert,
                leaf_fingerprint_sha256: Some(fp),
                reason: None,
            },
            None => SniProbeResult {
                variant: SniProbeVariant::IpLiteral,
                sni_sent: Some(ip_literal.to_string()),
                outcome: SniBehaviorOutcome::Error,
                leaf_fingerprint_sha256: None,
                reason: Some("no_leaf_cert_captured".to_string()),
            },
        },
        Err(HandshakeError::Failure(mid)) => {
            let err = crate::scanner::openssl::alerts::classify_openssl_error(
                "openssl_sni_ip_literal handshake",
                mid.error(),
            );
            let is_rejection =
                err.category.starts_with("tls_alert_") || err.category == "connection_refused";
            SniProbeResult {
                variant: SniProbeVariant::IpLiteral,
                sni_sent: Some(ip_literal.to_string()),
                outcome: if is_rejection {
                    SniBehaviorOutcome::Rejected
                } else {
                    SniBehaviorOutcome::Error
                },
                leaf_fingerprint_sha256: None,
                reason: Some(err.category),
            }
        }
        Err(HandshakeError::SetupFailure(e)) => SniProbeResult {
            variant: SniProbeVariant::IpLiteral,
            sni_sent: Some(ip_literal.to_string()),
            outcome: SniBehaviorOutcome::Error,
            leaf_fingerprint_sha256: None,
            reason: Some(format!("openssl_setup:{e}")),
        },
        Err(HandshakeError::WouldBlock(_)) => SniProbeResult {
            variant: SniProbeVariant::IpLiteral,
            sni_sent: Some(ip_literal.to_string()),
            outcome: SniBehaviorOutcome::Error,
            leaf_fingerprint_sha256: None,
            reason: Some("openssl_would_block".to_string()),
        },
    }
}

#[cfg(feature = "legacy-probes")]
fn build_openssl_context_for_sni_probe(
) -> Result<openssl::ssl::SslContext, openssl::error::ErrorStack> {
    use openssl::ssl::{SslContext, SslMethod, SslVerifyMode};

    let mut builder = SslContext::builder(SslMethod::tls_client())?;
    builder.set_verify(SslVerifyMode::NONE);
    Ok(builder.build())
}

#[cfg(feature = "legacy-probes")]
fn leaf_fingerprint_from_openssl(ssl: &openssl::ssl::SslRef) -> Option<String> {
    let der = ssl.peer_certificate()?.to_der().ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&der);
    Some(hex::encode(hasher.finalize()))
}

#[cfg(not(feature = "legacy-probes"))]
async fn probe_ip_literal_with_openssl(
    target: SocketAddr,
    _reference_fp: &str,
    _connect_timeout: Duration,
    _handshake_timeout: Duration,
) -> SniProbeResult {
    SniProbeResult {
        variant: SniProbeVariant::IpLiteral,
        sni_sent: Some(target.ip().to_string()),
        outcome: SniBehaviorOutcome::NotProbed,
        leaf_fingerprint_sha256: None,
        reason: Some("legacy_probes_disabled".to_string()),
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
