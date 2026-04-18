//! Connection-state characterization.
//!
//! Runs a single successful rustls handshake and captures everything
//! `rustls::ClientConnection` exposes post-handshake: negotiated version,
//! cipher suite, kx group, ALPN, plus verifier-side signals captured during
//! callbacks (OCSP response bytes, signature scheme from CertificateVerify).
//!
//! This is passive — no separate probe per version or per group. It complements
//! (doesn't replace) `test_protocol_support`, which still enumerates every
//! TLS version's offered/not-offered state via its own handshakes.
//!
//! What rustls does NOT expose as of 0.23.x:
//! - Whether EMS (RFC 7627) was negotiated on a TLS 1.2 connection
//! - Whether the server sent the RFC 5746 renegotiation_info extension
//! - SCT delivery via TLS extension (only embedded-in-cert SCTs are
//!   accessible via x509 parsing, which PR 6 covers)
//!
//! Those stay `not_probed` with a reason pointing at PR 9's byte parsing,
//! or `not_applicable` on TLS 1.3 where they don't apply.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{rustls, TlsConnector};
use tracing::debug;

use crate::model::cert::CertificateInfo;
use crate::model::errors::ScannerError;
use crate::model::protocol::TlsVersion;
use crate::scanner::cert as cert_ops;

/// State captured from a successful characterization handshake. Every field
/// is `Option` because rustls may not expose a value for every connection
/// (e.g. some versions report no kx group).
#[derive(Debug, Clone, Default)]
pub struct NegotiatedState {
    pub version: Option<TlsVersion>,
    pub cipher_suite_name: Option<String>,
    /// IANA cipher-suite codepoint.
    pub cipher_suite_id: Option<u16>,
    pub kx_group_name: Option<String>,
    /// IANA kx group codepoint.
    pub kx_group_id: Option<u16>,
    pub alpn_negotiated: Option<String>,
    /// Signature scheme used for the TLS 1.2/1.3 CertificateVerify, captured
    /// via `ServerCertVerifier::verify_tls{12,13}_signature`.
    pub signature_scheme: Option<String>,
    pub ocsp_stapled: bool,
    pub ocsp_response_len: usize,
}

#[derive(Debug, Clone)]
pub struct CharacterizationOutput {
    pub negotiated: Option<NegotiatedState>,
    pub certificates: Vec<CertificateInfo>,
    /// DER bytes of the chain as received on the wire. Used by offline
    /// validation; not emitted directly to the schema.
    pub cert_der: Vec<Vec<u8>>,
    /// The ALPN list the client proposed. Surfaced in the output schema
    /// so downstream consumers can interpret `alpn_negotiated` against
    /// what was actually offered.
    pub alpn_offered: Vec<String>,
    /// Trust observations computed after the handshake completes. Three
    /// independent observations — chain validity, name match, and the
    /// first-failure category string when chain validity is false.
    pub validation: ValidationResult,
}

/// Three independent trust observations. See `validation.*` in the schema.
/// All fields are `Option` because a failed/absent handshake leaves each
/// unevaluated (`not_probed` in the emitted JSON).
#[derive(Debug, Clone, Default)]
pub struct ValidationResult {
    pub chain_valid_to_webpki_roots: Option<bool>,
    pub name_matches_sni: Option<bool>,
    /// Spec-canonical error strings when chain validation fails:
    /// `"expired"`, `"not_valid_yet"`, `"untrusted_root"`, `"revoked"`,
    /// `"bad_signature"`, `"bad_encoding"`, `"unsupported_signature_algorithm"`,
    /// `"name_mismatch"` (only populated when chain is otherwise valid but
    /// name fails — see probe module docs), or `"other:<rustls_error>"` for
    /// unexpected categories. `None` when the chain validated cleanly.
    pub validation_error: Option<String>,
}

const DEFAULT_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];

/// Do one handshake with a permissive verifier, capture state, return.
/// Errors correspond to connection-level failures; downstream callers push
/// them into `scan_errors`.
pub async fn characterize_connection(
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> Result<CharacterizationOutput, ScannerError> {
    let collector = Arc::new(StateCollector::default());

    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(collector.clone())
        .with_no_client_auth();
    config.alpn_protocols = DEFAULT_ALPN.iter().map(|p| p.to_vec()).collect();

    let connector = TlsConnector::from(Arc::new(config));

    let tcp_stream = match timeout(connect_timeout, TcpStream::connect(&target)).await {
        Err(_) => return Err(ScannerError::connection_timeout("characterize tcp connect")),
        Ok(Err(e)) => return Err(ScannerError::from_io("characterize tcp connect", e)),
        Ok(Ok(s)) => s,
    };

    let domain = ServerName::try_from(hostname.to_string())
        .map_err(|_| ScannerError::internal(format!("invalid SNI hostname: {hostname}")))?;

    let stream = match timeout(handshake_timeout, connector.connect(domain, tcp_stream)).await {
        Err(_) => return Err(ScannerError::handshake_timeout("characterize handshake")),
        Ok(Err(e)) => return Err(ScannerError::from_io("characterize handshake", e)),
        Ok(Ok(s)) => s,
    };

    // Post-handshake, pull state from the ClientConnection.
    let (_tcp, conn) = stream.get_ref();

    let version = conn.protocol_version().and_then(to_model_version);
    let (cipher_suite_name, cipher_suite_id) = match conn.negotiated_cipher_suite() {
        Some(s) => {
            let name = format!("{:?}", s.suite());
            let id: u16 = s.suite().into();
            (Some(name), Some(id))
        }
        None => (None, None),
    };
    let (kx_group_name, kx_group_id) = match conn.negotiated_key_exchange_group() {
        Some(g) => {
            let name = format!("{:?}", g.name());
            let id: u16 = g.name().into();
            (Some(name), Some(id))
        }
        None => (None, None),
    };
    let alpn_negotiated = conn
        .alpn_protocol()
        .map(|b| String::from_utf8_lossy(b).into_owned());

    let (sig_scheme, ocsp_len, cert_bytes) = collector.take_state();

    let certificates = decode_certs(&cert_bytes);

    // Offline chain validation + name match, decoupled from the permissive
    // handshake above. See probe module docs for why these are independent.
    let validation = evaluate_validation(&cert_bytes, &certificates, hostname);

    let negotiated = Some(NegotiatedState {
        version,
        cipher_suite_name,
        cipher_suite_id,
        kx_group_name,
        kx_group_id,
        alpn_negotiated,
        signature_scheme: sig_scheme,
        ocsp_stapled: ocsp_len > 0,
        ocsp_response_len: ocsp_len,
    });

    Ok(CharacterizationOutput {
        negotiated,
        certificates,
        cert_der: cert_bytes,
        alpn_offered: DEFAULT_ALPN
            .iter()
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect(),
        validation,
    })
}

/// Offline validation pipeline. Runs after the handshake with the raw
/// DER bytes + already-parsed `CertificateInfo`s. Produces three
/// independent observations:
///
/// 1. **`name_matches_sni`** — parsed purely from the leaf's SAN/CN.
///    Never consults webpki.
/// 2. **`chain_valid_to_webpki_roots`** — uses rustls's `WebPkiServerVerifier`
///    against the Mozilla root store bundled in `webpki-roots`. When the
///    first pass fails with `NotValidForName`, retry with a SAN-derived name
///    to isolate chain validity from name matching.
/// 3. **`validation_error`** — populated only when chain validation fails.
///    Maps rustls `CertificateError` variants to spec-canonical strings.
fn evaluate_validation(
    cert_der: &[Vec<u8>],
    certificates: &[CertificateInfo],
    sni: &str,
) -> ValidationResult {
    if cert_der.is_empty() || certificates.is_empty() {
        return ValidationResult::default();
    }

    // 1. Name match (independent of chain check).
    let leaf = &certificates[0];
    let name_matches = cert_ops::name_matches_sni(&leaf.san, &leaf.subject, sni);

    // 2. Chain validity.
    let end_entity = CertificateDer::from(cert_der[0].clone());
    let intermediates: Vec<CertificateDer<'static>> = cert_der[1..]
        .iter()
        .map(|der| CertificateDer::from(der.clone()))
        .collect();

    let verifier = match build_webpki_verifier() {
        Some(v) => v,
        None => {
            // webpki-roots build failure (rare) — can't probe chain validity.
            return ValidationResult {
                chain_valid_to_webpki_roots: None,
                name_matches_sni: Some(name_matches),
                validation_error: Some("webpki_verifier_unavailable".to_string()),
            };
        }
    };

    let now = UnixTime::now();
    let sni_srv = match ServerName::try_from(sni.to_string()) {
        Ok(s) => s,
        Err(_) => {
            // Can't construct ServerName (e.g. numeric IP without brackets).
            // Fall back to SAN-derived probe name below.
            ServerName::try_from("invalid.kemist-placeholder.invalid".to_string())
                .expect("literal placeholder always valid")
        }
    };

    let first_try = verifier.verify_server_cert(&end_entity, &intermediates, &sni_srv, &[], now);

    // If first-try fails on name only, retry with a SAN-derived name to
    // isolate chain validity from the name match.
    let (chain_valid, error) = match &first_try {
        Ok(_) => (true, None),
        Err(rustls::Error::InvalidCertificate(CertificateError::NotValidForName)) => {
            retry_with_san_name(&verifier, &end_entity, &intermediates, &leaf.san, now)
        }
        Err(rustls::Error::InvalidCertificate(CertificateError::NotValidForNameContext {
            ..
        })) => retry_with_san_name(&verifier, &end_entity, &intermediates, &leaf.san, now),
        Err(e) => (false, Some(classify_cert_error(e))),
    };

    ValidationResult {
        chain_valid_to_webpki_roots: Some(chain_valid),
        name_matches_sni: Some(name_matches),
        // Spec: only populate validation_error when chain invalid.
        validation_error: if chain_valid { None } else { error },
    }
}

fn retry_with_san_name(
    verifier: &WebPkiServerVerifier,
    end_entity: &CertificateDer<'static>,
    intermediates: &[CertificateDer<'static>],
    san: &[String],
    now: UnixTime,
) -> (bool, Option<String>) {
    let Some(probe_name) = cert_ops::first_san_dns(san) else {
        // No usable SAN to retry with — we can tell the chain isn't valid
        // for the SNI we sent, but can't say whether the chain would be
        // valid for any name. Emit `name_mismatch` and leave chain_valid
        // as false so downstream consumers don't over-interpret.
        return (false, Some("name_mismatch".to_string()));
    };
    let Ok(name) = ServerName::try_from(probe_name) else {
        return (false, Some("name_mismatch".to_string()));
    };
    match verifier.verify_server_cert(end_entity, intermediates, &name, &[], now) {
        Ok(_) => (true, None),
        Err(rustls::Error::InvalidCertificate(CertificateError::NotValidForName))
        | Err(rustls::Error::InvalidCertificate(CertificateError::NotValidForNameContext {
            ..
        })) => {
            // Unexpected: even with a SAN-derived name webpki rejects on name.
            // Treat as a name failure with chain undetermined, but emit
            // false for chain_valid so consumers get a signal.
            (false, Some("name_mismatch".to_string()))
        }
        Err(e) => (false, Some(classify_cert_error(&e))),
    }
}

fn classify_cert_error(e: &rustls::Error) -> String {
    use CertificateError as CE;
    match e {
        rustls::Error::InvalidCertificate(inner) => match inner {
            CE::Expired | CE::ExpiredContext { .. } => "expired".to_string(),
            CE::NotValidYet | CE::NotValidYetContext { .. } => "not_valid_yet".to_string(),
            CE::Revoked => "revoked".to_string(),
            CE::UnknownIssuer => "untrusted_root".to_string(),
            CE::BadSignature => "bad_signature".to_string(),
            CE::BadEncoding => "bad_encoding".to_string(),
            CE::UnsupportedSignatureAlgorithm => "unsupported_signature_algorithm".to_string(),
            CE::UnhandledCriticalExtension => "unhandled_critical_extension".to_string(),
            CE::UnknownRevocationStatus => "unknown_revocation_status".to_string(),
            CE::NotValidForName | CE::NotValidForNameContext { .. } => "name_mismatch".to_string(),
            other => format!("other:{other:?}"),
        },
        other => format!("other:{other}"),
    }
}

fn build_webpki_verifier() -> Option<std::sync::Arc<WebPkiServerVerifier>> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    WebPkiServerVerifier::builder(std::sync::Arc::new(roots))
        .build()
        .ok()
}

fn to_model_version(v: rustls::ProtocolVersion) -> Option<TlsVersion> {
    // rustls may surface TLS 1.0/1.1 if anyone ever asks, but current builds
    // only negotiate 1.2/1.3. Map everything we know; else None.
    match v {
        rustls::ProtocolVersion::TLSv1_2 => Some(TlsVersion::Tls12),
        rustls::ProtocolVersion::TLSv1_3 => Some(TlsVersion::Tls13),
        _ => None,
    }
}

fn decode_certs(raw: &[Vec<u8>]) -> Vec<CertificateInfo> {
    raw.iter()
        .filter_map(|der| CertificateInfo::from_der(der).ok())
        .collect()
}

/// Permissive verifier that:
/// 1. Collects the peer certificate chain (leaf + intermediates).
/// 2. Captures the OCSP response bytes rustls hands to `verify_server_cert`.
/// 3. Captures the signature scheme from TLS 1.2/1.3 CertificateVerify.
///
/// Accepts all certs — validation is a separate observation emitted via
/// the `validation.*` schema section (PR 6 wires this properly).
#[derive(Debug, Default)]
struct StateCollector {
    certs: Mutex<Vec<Vec<u8>>>,
    ocsp_response_len: Mutex<usize>,
    signature_scheme: Mutex<Option<String>>,
}

impl StateCollector {
    fn take_state(&self) -> (Option<String>, usize, Vec<Vec<u8>>) {
        let sig = self.signature_scheme.lock().ok().and_then(|g| g.clone());
        let ocsp_len = self.ocsp_response_len.lock().map(|g| *g).unwrap_or(0);
        let certs = self.certs.lock().map(|g| g.clone()).unwrap_or_default();
        (sig, ocsp_len, certs)
    }

    fn record_signature(&self, s: SignatureScheme) {
        if let Ok(mut guard) = self.signature_scheme.lock() {
            *guard = Some(format!("{s:?}"));
        }
    }
}

impl ServerCertVerifier for StateCollector {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Ok(mut guard) = self.certs.lock() {
            guard.push(end_entity.to_vec());
            for i in intermediates {
                guard.push(i.to_vec());
            }
        }
        if let Ok(mut guard) = self.ocsp_response_len.lock() {
            *guard = ocsp_response.len();
        }
        debug!(
            "characterize verifier: captured {} cert(s), OCSP {} bytes",
            intermediates.len() + 1,
            ocsp_response.len()
        );
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.record_signature(dss.scheme);
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.record_signature(dss.scheme);
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
