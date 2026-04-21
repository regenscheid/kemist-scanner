//! Per-group key exchange probing.
//!
//! For each group in the target list we build a `CryptoProvider` carrying
//! exactly that `SupportedKxGroup` and attempt a TLS 1.3 handshake. Groups
//! aws-lc-rs does not ship an implementation for emit `not_probed` with a
//! specific reason — never `supported: false` without a real probe.
//!
//! ## Target list
//! Hardcoded below per the kemist spec. A future workstream could move this
//! to a YAML config so new groups can be added without a code release.
//! Until then the defaults cover the groups the spec acceptance criteria
//! exercise:
//!
//! - Classical: X25519, X448, secp256r1/384r1/521r1
//! - PQC hybrids: X25519MLKEM768 (0x11EC), SecP256r1MLKEM768 (0x11EB),
//!   SecP384r1MLKEM1024 (0x11ED)
//! - Standalone ML-KEM: MLKEM512 (0x0200), MLKEM768 (0x0201), MLKEM1024
//!   (0x0202)
//! - Pre-standard: X25519Kyber768Draft00 (0x6399)
//!
//! ## Restricted to TLS 1.3
//! rustls applies `kx_groups` to both TLS 1.2 ECDHE and TLS 1.3 key share,
//! but TLS 1.3 is where named-group enumeration is the load-bearing
//! observation. Probing over TLS 1.3 isolates "server supports this group"
//! from "server supports this TLS version" — handshake failures here
//! classify cleanly as group rejection.
//!
//! ## Future: extending probe coverage for un-shipped groups
//! Groups aws-lc-rs does not expose (`MLKEM512`, `MLKEM1024`, `X448`,
//! `secp521r1`, `secp384r1MLKEM1024`, `X25519Kyber768Draft00`) currently
//! emit `not_probed`. Two paths, not mutually exclusive:
//!
//! **(a) Raw-ClientHello probing.** Hand-craft a TLS 1.3 ClientHello with
//! the target codepoint in `key_share` plus a dummy payload — see
//! `src/scanner/hello.rs` for the raw-socket pattern. Response classifies:
//! ServerHello echoing the group → `supported: true`; `handshake_failure`
//! alert → `supported: false`; `HelloRetryRequest` → `supported: false`.
//! No crypto implementation needed; we probe intent, not completion.
//!
//! **(b) Alternate crypto backend.** Plug a second `CryptoProvider` (e.g.
//! liboqs-sys / oqs-provider via a Rust binding, or a future
//! `rustls-post-quantum` crate with broader coverage) and route groups
//! aws-lc-rs doesn't ship through it. Keeps the probe path uniform with
//! the current `SupportedKxGroup` abstraction — no byte-level code — at
//! the cost of a larger build + another crypto implementation to trust.
//!
//! (a) is cheaper to ship and self-contained in this crate. (b) scales
//! better long-term as new post-quantum parameter sets land. The
//! `not_probed` reason string stays accurate either way.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{aws_lc_rs, SupportedKxGroup};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{rustls, TlsConnector};
use tracing::debug;

use crate::model::errors::ScannerError;

/// One per-group probe result.
#[derive(Debug, Clone)]
pub struct GroupProbeResult {
    /// Human-readable name matching rustls's `NamedGroup` Debug output
    /// (e.g. `"X25519MLKEM768"`).
    pub name: String,
    /// IANA codepoint (e.g. `0x11EC`).
    pub iana_code: u16,
    pub outcome: GroupProbeOutcome,
}

#[derive(Debug, Clone)]
pub enum GroupProbeOutcome {
    /// Handshake succeeded with this group alone.
    Supported,
    /// Server rejected the single-group offer — handshake alert or reset.
    NotSupported,
    /// Probe itself failed (TCP timeout, DNS, unexpected error).
    Error(String),
    /// Probe not attempted — aws-lc-rs doesn't ship this group at build
    /// time. Carries a specific reason for downstream consumers.
    NotProbed(String),
}

#[derive(Debug, Clone, Default)]
pub struct GroupProbeOutput {
    pub results: Vec<GroupProbeResult>,
}

/// The hardcoded target list. Each entry pairs the rustls Debug name with
/// its IANA codepoint. If aws-lc-rs ships this group at build time, the
/// scanner probes it; otherwise the entry emits `not_probed`.
///
/// The Debug names here must match what `SupportedKxGroup::name()` Debug
/// prints — the format is stable because rustls derives Debug via
/// `enum_builder!` from exact identifier names.
/// Public lookup so renderers can reunite a probe-result name with its
/// codepoint. Returns `None` for unknown names — the scanner only ever
/// emits names from this table, so downstream misses are programmer
/// errors, not data errors.
pub fn iana_code_for(name: &str) -> Option<u16> {
    TARGET_GROUPS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, code)| *code)
}

const TARGET_GROUPS: &[(&str, u16)] = &[
    // Classical elliptic curves
    ("X25519", 0x001d),
    ("X448", 0x001e),
    ("secp256r1", 0x0017),
    ("secp384r1", 0x0018),
    ("secp521r1", 0x0019),
    // Standalone ML-KEM (NIST FIPS 203)
    ("MLKEM512", 0x0200),
    ("MLKEM768", 0x0201),
    ("MLKEM1024", 0x0202),
    // PQC hybrids (IETF TLS WG codepoints)
    ("secp256r1MLKEM768", 0x11eb),
    ("X25519MLKEM768", 0x11ec),
    ("secp384r1MLKEM1024", 0x11ed),
    // Pre-standard (Cloudflare research codepoint)
    ("X25519Kyber768Draft00", 0x6399),
];

/// Probe every target group. Respects `per_probe_delay` between
/// handshakes. For groups aws-lc-rs does not ship, emits `NotProbed`
/// with a reason rather than attempting an impossible handshake.
pub async fn probe_kx_groups(
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    per_probe_delay: Duration,
) -> GroupProbeOutput {
    // aws-lc-rs ships a subset of NamedGroups. Build a lookup of what's
    // available at runtime so the probe loop can honestly distinguish
    // "probed and rejected" from "can't be probed by this build".
    let available: Vec<&'static dyn SupportedKxGroup> = aws_lc_rs::ALL_KX_GROUPS.to_vec();

    let mut results = Vec::with_capacity(TARGET_GROUPS.len());

    for (name, iana_code) in TARGET_GROUPS {
        let matched = available
            .iter()
            .find(|g| format!("{:?}", g.name()) == *name)
            .copied();

        let outcome = match matched {
            Some(group) => {
                probe_single_group(target, hostname, group, connect_timeout, handshake_timeout)
                    .await
            }
            None => {
                debug!("group {} not exposed by aws-lc-rs, skipping probe", name);
                GroupProbeOutcome::NotProbed(format!(
                    "aws_lc_rs_no_{}_support",
                    name.to_lowercase()
                ))
            }
        };

        results.push(GroupProbeResult {
            name: (*name).to_string(),
            iana_code: *iana_code,
            outcome,
        });

        if !per_probe_delay.is_zero()
            && !matches!(
                results.last().unwrap().outcome,
                GroupProbeOutcome::NotProbed(_)
            )
        {
            tokio::time::sleep(per_probe_delay).await;
        }
    }

    GroupProbeOutput { results }
}

async fn probe_single_group(
    target: SocketAddr,
    hostname: &str,
    group: &'static dyn SupportedKxGroup,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> GroupProbeOutcome {
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = vec![group];

    let config = match rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
    {
        Ok(b) => b
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PermissiveVerifier))
            .with_no_client_auth(),
        Err(e) => return GroupProbeOutcome::Error(format!("config_builder:{e}")),
    };

    let connector = TlsConnector::from(Arc::new(config));

    let tcp = match timeout(connect_timeout, TcpStream::connect(&target)).await {
        Err(_) => return GroupProbeOutcome::Error("tcp_connect_timeout".to_string()),
        Ok(Err(e)) => {
            let err = ScannerError::from_io("tcp_connect", e);
            return GroupProbeOutcome::Error(err.category);
        }
        Ok(Ok(s)) => s,
    };

    let domain = match ServerName::try_from(hostname.to_string()) {
        Ok(d) => d,
        Err(_) => return GroupProbeOutcome::Error(format!("invalid_sni:{hostname}")),
    };

    match timeout(handshake_timeout, connector.connect(domain, tcp)).await {
        Err(_) => GroupProbeOutcome::Error("handshake_timeout".to_string()),
        Ok(Ok(_)) => GroupProbeOutcome::Supported,
        Ok(Err(e)) => classify_probe_error(e),
    }
}

fn classify_probe_error(e: std::io::Error) -> GroupProbeOutcome {
    let scanner_err = ScannerError::from_io("handshake", e);
    let is_rejection = scanner_err.category.starts_with("tls_alert_")
        || scanner_err.category == "connection_refused";
    if is_rejection {
        GroupProbeOutcome::NotSupported
    } else {
        // Preserve the context for diagnosis; see the matching
        // comment in `ciphers::classify_probe_error`.
        GroupProbeOutcome::Error(format!("{}: {}", scanner_err.category, scanner_err.context))
    }
}

/// Minimal accept-all verifier. Mirrors the one in `ciphers.rs`.
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
