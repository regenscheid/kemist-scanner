//! `rustls` + aws-lc-rs backend. Drives every TLS 1.2 / TLS 1.3
//! codepoint the pinned aws-lc-rs build ships.
//!
//! Supported `handshake()` constraint shapes:
//! - `single_cipher(code)` — one IANA cipher codepoint, version
//!   inferred from the suite's TLS 1.2 vs 1.3 family
//! - `single_group_at(code, Tls13)` — one IANA group codepoint at
//!   TLS 1.3 (rustls ties `kx_groups` to both 1.2 and 1.3 at the
//!   provider level, but the probe semantics are TLS-1.3-native)
//! - `version_only(v)` — one pinned TLS version
//!
//! Other constraint combinations return `UnsatisfiableConstraint`;
//! the orchestrator translates that into `method: not_probed,
//! reason: backend_lacks_capability`.

use std::sync::Arc;

use async_trait::async_trait;

pub mod alpn_matrix;
pub mod characterize;
pub mod ciphers;
pub mod groups;
pub mod session_resumption;
pub mod sni;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{rustls, TlsConnector};

use crate::model::errors::ScannerError;
use crate::model::protocol::TlsVersion;
use crate::scanner::backends::{
    is_wire_rejection, rustls_inventory, BackendInventory, ConstraintCapabilities,
    HandshakeConstraint, HandshakeOutcome, HandshakeResult, ProbeContext, TlsBackend,
    UnsatisfiableConstraint,
};

pub struct RustlsBackend {
    inventory: BackendInventory,
}

impl RustlsBackend {
    pub fn new() -> Self {
        Self {
            inventory: rustls_inventory(),
        }
    }
}

impl Default for RustlsBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TlsBackend for RustlsBackend {
    fn id(&self) -> &'static str {
        "aws_lc_rs"
    }

    fn inventory(&self) -> &BackendInventory {
        &self.inventory
    }

    fn constraint_capabilities(&self) -> ConstraintCapabilities {
        ConstraintCapabilities {
            version_range: true,
            cipher_suites: true,
            groups: true,
            sigalgs: false,
            alpn: true,
            send_fallback_scsv: false,
            seclevel_zero: false,
        }
    }

    async fn handshake(
        &self,
        c: HandshakeConstraint,
        ctx: &ProbeContext,
    ) -> Result<HandshakeResult, UnsatisfiableConstraint> {
        // Reject constraint axes this backend doesn't support.
        if c.sigalgs.is_some() {
            return Err(UnsatisfiableConstraint::new(
                "rustls_backend_no_sigalg_pinning",
            ));
        }
        if c.send_fallback_scsv {
            return Err(UnsatisfiableConstraint::new(
                "rustls_backend_no_fallback_scsv",
            ));
        }
        if c.seclevel_zero {
            return Err(UnsatisfiableConstraint::new(
                "rustls_backend_no_seclevel",
            ));
        }

        // Dispatch by constraint shape.
        match (&c.cipher_suites, &c.groups, c.version_range) {
            (Some(suites), None, _) if suites.len() == 1 => {
                probe_single_cipher_shape(suites[0], ctx).await
            }
            (None, Some(groups), Some((v_min, v_max))) if groups.len() == 1 && v_min == v_max => {
                probe_single_group_shape(groups[0], v_min, ctx).await
            }
            (None, None, Some((v_min, v_max))) if v_min == v_max => {
                probe_version_only_shape(v_min, ctx).await
            }
            _ => Err(UnsatisfiableConstraint::new(
                "rustls_backend_constraint_shape_not_implemented_yet",
            )),
        }
    }
}

async fn probe_single_cipher_shape(
    code: u16,
    ctx: &ProbeContext,
) -> Result<HandshakeResult, UnsatisfiableConstraint> {
    let Some(suite) = rustls::crypto::aws_lc_rs::ALL_CIPHER_SUITES
        .iter()
        .find(|s| u16::from(s.suite()) == code)
        .copied()
    else {
        return Err(UnsatisfiableConstraint::new(format!(
            "cipher_codepoint_not_shipped_by_aws_lc_rs:0x{:04X}",
            code
        )));
    };
    let outcome = self::ciphers::probe_single_suite(
        ctx.target,
        &ctx.hostname,
        suite,
        ctx.connect_timeout,
        ctx.handshake_timeout,
    )
    .await;
    Ok(HandshakeResult::outcome_only(outcome))
}

async fn probe_single_group_shape(
    code: u16,
    version: TlsVersion,
    ctx: &ProbeContext,
) -> Result<HandshakeResult, UnsatisfiableConstraint> {
    // Only TLS 1.2 and TLS 1.3 are meaningful targets for the rustls
    // group probe — rustls doesn't speak earlier versions at all.
    if !matches!(version, TlsVersion::Tls12 | TlsVersion::Tls13) {
        return Err(UnsatisfiableConstraint::new(format!(
            "rustls_group_probe_version_out_of_scope:{:?}",
            version
        )));
    }
    let Some(group) = rustls::crypto::aws_lc_rs::ALL_KX_GROUPS
        .iter()
        .find(|g| u16::from(g.name()) == code)
        .copied()
    else {
        return Ok(HandshakeResult::outcome_only(HandshakeOutcome::NotProbed(
            format!("aws_lc_rs_does_not_ship_group:0x{:04X}", code),
        )));
    };
    let outcome = self::groups::probe_single_group(
        ctx.target,
        &ctx.hostname,
        group,
        version,
        ctx.connect_timeout,
        ctx.handshake_timeout,
    )
    .await;
    Ok(HandshakeResult::outcome_only(outcome))
}

async fn probe_version_only_shape(
    version: TlsVersion,
    ctx: &ProbeContext,
) -> Result<HandshakeResult, UnsatisfiableConstraint> {
    let rv = match version {
        TlsVersion::Tls12 => &rustls::version::TLS12,
        TlsVersion::Tls13 => &rustls::version::TLS13,
        _ => {
            return Err(UnsatisfiableConstraint::new(format!(
                "rustls_backend_version_out_of_scope:{:?}",
                version
            )));
        }
    };

    let mut config = rustls::ClientConfig::builder_with_protocol_versions(&[rv])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
        .with_no_client_auth();
    config.alpn_protocols = match version {
        TlsVersion::Tls13 => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        _ => Vec::new(),
    };

    let outcome = rustls_connect_outcome(config, ctx).await;
    Ok(HandshakeResult::outcome_only(outcome))
}

async fn rustls_connect_outcome(
    config: rustls::ClientConfig,
    ctx: &ProbeContext,
) -> HandshakeOutcome {
    let connector = TlsConnector::from(Arc::new(config));

    let tcp = match timeout(ctx.connect_timeout, TcpStream::connect(&ctx.target)).await {
        Err(_) => return HandshakeOutcome::Error("tcp_connect_timeout".to_string()),
        Ok(Err(e)) => {
            let err = ScannerError::from_io("tcp_connect", e);
            return HandshakeOutcome::Error(err.category);
        }
        Ok(Ok(s)) => s,
    };

    let domain = match rustls::pki_types::ServerName::try_from(ctx.hostname.clone()) {
        Ok(d) => d,
        Err(_) => {
            return HandshakeOutcome::Error(format!("invalid_sni:{}", ctx.hostname));
        }
    };

    match timeout(ctx.handshake_timeout, connector.connect(domain, tcp)).await {
        Err(_) => HandshakeOutcome::Error("handshake_timeout".to_string()),
        Ok(Ok(_)) => HandshakeOutcome::Supported,
        Ok(Err(e)) => {
            let scanner_err = ScannerError::from_io("handshake", e);
            if is_wire_rejection(&scanner_err) {
                HandshakeOutcome::NotSupported
            } else {
                HandshakeOutcome::Error(format!(
                    "{}: {}",
                    scanner_err.category, scanner_err.context
                ))
            }
        }
    }
}

/// Minimal accept-all verifier for probe handshakes. Mirrors the
/// equivalents scattered across `ciphers.rs` / `groups.rs` — probes
/// never validate certificates; the characterization path does.
#[derive(Debug)]
pub(crate) struct AcceptAllVerifier;

impl rustls::client::danger::ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_is_stable() {
        assert_eq!(RustlsBackend::new().id(), "aws_lc_rs");
    }

    #[test]
    fn constraint_caps_declare_unsupported_axes() {
        let caps = RustlsBackend::new().constraint_capabilities();
        assert!(caps.cipher_suites);
        assert!(caps.groups);
        assert!(caps.version_range);
        assert!(caps.alpn);
        assert!(!caps.sigalgs);
        assert!(!caps.send_fallback_scsv);
        assert!(!caps.seclevel_zero);
    }

    #[tokio::test]
    async fn handshake_rejects_sigalgs_constraint() {
        let be = RustlsBackend::new();
        let c = HandshakeConstraint {
            sigalgs: Some(vec![0x0403]),
            ..Default::default()
        };
        let ctx = ProbeContext {
            target: "127.0.0.1:1".parse().unwrap(),
            hostname: "example.test".to_string(),
            connect_timeout: std::time::Duration::from_millis(10),
            handshake_timeout: std::time::Duration::from_millis(10),
        };
        let err = be.handshake(c, &ctx).await.unwrap_err();
        assert_eq!(err.reason, "rustls_backend_no_sigalg_pinning");
    }

    #[tokio::test]
    async fn handshake_reports_not_probed_for_unshipped_group() {
        let be = RustlsBackend::new();
        // 0xFFFF is not a real codepoint and will never be shipped.
        let c = HandshakeConstraint::single_group_at(0xFFFF, TlsVersion::Tls13);
        let ctx = ProbeContext {
            target: "127.0.0.1:1".parse().unwrap(),
            hostname: "example.test".to_string(),
            connect_timeout: std::time::Duration::from_millis(10),
            handshake_timeout: std::time::Duration::from_millis(10),
        };
        let r = be.handshake(c, &ctx).await.expect("shape supported");
        match r.outcome {
            HandshakeOutcome::NotProbed(reason) => {
                assert!(reason.starts_with("aws_lc_rs_does_not_ship_group"));
            }
            other => panic!("expected NotProbed, got {:?}", other),
        }
    }
}
