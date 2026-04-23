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
//!
//! ## Restricted to TLS 1.3
//! rustls applies `kx_groups` to both TLS 1.2 ECDHE and TLS 1.3 key share,
//! but TLS 1.3 is where named-group enumeration is the load-bearing
//! observation. Probing over TLS 1.3 isolates "server supports this group"
//! from "server supports this TLS version" — handshake failures here
//! classify cleanly as group rejection.
//!
//! ## Future: extending probe coverage for un-shipped groups
//! Groups aws-lc-rs does not expose are covered by the OpenSSL path in
//! [`crate::scanner::openssl::kx_groups`] where OpenSSL 3.5 ships them
//! (X448, secp521r1, MLKEM512/1024, secp384r1MLKEM1024). For any future
//! codepoints neither backend ships, two paths are available:
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
use crate::scanner::backends::{is_wire_rejection, HandshakeOutcome, TlsBackend};

/// One per-group probe result at a specific TLS version. Same codepoint
/// may appear twice (once for TLS 1.2 ECDHE, once for TLS 1.3
/// key_share) for curves that are valid across versions.
#[derive(Debug, Clone)]
pub struct GroupProbeResult {
    /// Human-readable name matching rustls's `NamedGroup` Debug output
    /// (e.g. `"X25519MLKEM768"`).
    pub name: String,
    /// IANA codepoint (e.g. `0x11EC`).
    pub iana_code: u16,
    /// TLS version this probe targeted.
    pub version: crate::model::protocol::TlsVersion,
    pub outcome: HandshakeOutcome,
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
        .find(|(n, _, _)| *n == name)
        .map(|(_, code, _)| *code)
}

/// `(name, iana_code, tls12_eligible)`. TLS 1.2 eligibility is
/// per-codepoint: classical ECC curves ride TLS 1.2 ECDHE + TLS 1.3
/// key_share; standalone ML-KEM and PQC hybrids are defined only at
/// TLS 1.3, so probing them at 1.2 is a category error.
const TARGET_GROUPS: &[(&str, u16, bool)] = &[
    // Classical elliptic curves — valid at TLS 1.2 (ECDHE) and TLS 1.3.
    ("X25519", 0x001d, true),
    ("X448", 0x001e, true),
    ("secp256r1", 0x0017, true),
    ("secp384r1", 0x0018, true),
    ("secp521r1", 0x0019, true),
    // Standalone ML-KEM (NIST FIPS 203) — TLS 1.3 only.
    ("MLKEM512", 0x0200, false),
    ("MLKEM768", 0x0201, false),
    ("MLKEM1024", 0x0202, false),
    // PQC hybrids (IETF TLS WG codepoints) — TLS 1.3 only.
    ("secp256r1MLKEM768", 0x11eb, false),
    ("X25519MLKEM768", 0x11ec, false),
    ("secp384r1MLKEM1024", 0x11ed, false),
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
    // Registry-driven per-group probing. Every `TARGET_GROUPS` entry
    // still appears in the output — codepoints aws-lc-rs doesn't ship
    // emit `NotProbed` here and are filled in later by the OpenSSL
    // group probe loop via the JSON merge logic. A follow-up could
    // push the merge into `BackendRegistry` so this rustls-path loop
    // skips OpenSSL-routed codepoints instead of emitting NotProbed,
    // but that requires reshaping the downstream output merger.
    let registry = crate::scanner::backends::BackendRegistry::new();
    let ctx = crate::scanner::backends::ProbeContext {
        target,
        hostname: hostname.to_string(),
        connect_timeout,
        handshake_timeout,
    };
    let rustls_cipher_codes: std::collections::HashSet<u16> = registry
        .rustls
        .inventory()
        .group_codepoints
        .iter()
        .copied()
        .collect();

    let mut results = Vec::with_capacity(TARGET_GROUPS.len() * 2);

    for (name, iana_code, tls12_eligible) in TARGET_GROUPS {
        // Every classical ECDHE curve gets probed at both TLS 1.2 and
        // TLS 1.3 — two handshakes per curve, results tagged with the
        // version so the JSON emitter can route them into the right
        // per-version bucket. ML-KEM / PQC hybrids are TLS 1.3 only;
        // their TLS 1.2 slot renders as `not_applicable` in the
        // downstream merge rather than a real probe.
        let mut versions = vec![crate::model::protocol::TlsVersion::Tls13];
        if *tls12_eligible {
            versions.insert(0, crate::model::protocol::TlsVersion::Tls12);
        }

        for version in versions {
            let outcome = if rustls_cipher_codes.contains(iana_code) {
                let constraint = crate::scanner::backends::HandshakeConstraint::single_group_at(
                    *iana_code, version,
                );
                match registry.rustls.handshake(constraint, &ctx).await {
                    Ok(r) => r.outcome,
                    Err(u) => {
                        HandshakeOutcome::Error(format!("unsatisfiable_constraint:{}", u.reason))
                    }
                }
            } else {
                debug!("group {} not exposed by aws-lc-rs, skipping probe", name);
                HandshakeOutcome::NotProbed(format!("aws_lc_rs_no_{}_support", name.to_lowercase()))
            };

            results.push(GroupProbeResult {
                name: (*name).to_string(),
                iana_code: *iana_code,
                version,
                outcome,
            });

            if !per_probe_delay.is_zero()
                && !matches!(
                    results.last().unwrap().outcome,
                    HandshakeOutcome::NotProbed(_)
                )
            {
                tokio::time::sleep(per_probe_delay).await;
            }
        }
    }

    GroupProbeOutput { results }
}

pub(crate) async fn probe_single_group(
    target: SocketAddr,
    hostname: &str,
    group: &'static dyn SupportedKxGroup,
    version: crate::model::protocol::TlsVersion,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> HandshakeOutcome {
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = vec![group];

    let proto = match version {
        crate::model::protocol::TlsVersion::Tls12 => &rustls::version::TLS12,
        crate::model::protocol::TlsVersion::Tls13 => &rustls::version::TLS13,
        other => {
            return HandshakeOutcome::Error(format!(
                "rustls_group_probe_version_out_of_scope:{:?}",
                other
            ));
        }
    };

    let config = match rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[proto])
    {
        Ok(b) => b
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PermissiveVerifier))
            .with_no_client_auth(),
        Err(e) => return HandshakeOutcome::Error(format!("config_builder:{e}")),
    };

    let connector = TlsConnector::from(Arc::new(config));

    let tcp = match timeout(connect_timeout, TcpStream::connect(&target)).await {
        Err(_) => return HandshakeOutcome::Error("tcp_connect_timeout".to_string()),
        Ok(Err(e)) => {
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

fn classify_probe_error(e: std::io::Error) -> HandshakeOutcome {
    let scanner_err = ScannerError::from_io("handshake", e);
    if is_wire_rejection(&scanner_err) {
        HandshakeOutcome::NotSupported
    } else {
        HandshakeOutcome::Error(format!("{}: {}", scanner_err.category, scanner_err.context))
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
