//! Rustls-backed characterization handshake — one permissive-verifier
//! connection that captures the server's TLS state post-handshake:
//! negotiated version / cipher suite / KX group / ALPN, the OCSP
//! staple delivered in-band, the signature scheme the server used in
//! CertificateVerify, and the cert chain as bytes. That state feeds
//! every other observation in the schema.
//!
//! This module owns the rustls-specific pieces — the custom
//! `StateCollector` verifier and [`characterize_connection`] itself.
//! Backend-neutral validation lives in [`crate::scanner::probe`]
//! (`evaluate_validation`, `ValidationResult`) and is called
//! unchanged from here; [`CharacterizationOutput`] is the shared
//! result type owned by `probe.rs`.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{rustls, TlsConnector};
use tracing::debug;

use crate::model::cert::CertificateInfo;
use crate::model::errors::ScannerError;
use crate::model::protocol::TlsVersion;
use crate::scanner::probe::{CharacterizationOutput, NegotiatedState};

const DEFAULT_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];

/// Do one handshake with a permissive verifier, capture state, return.
/// Errors correspond to connection-level failures; downstream callers
/// push them into `scan_errors`.
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

    // Channel-binding export (RFC 9266 + RFC 5929). Must happen BEFORE
    // `collector.take_state()` drains the cert bytes, because
    // tls-server-end-point hashes the leaf DER directly from the
    // collector's guarded state.
    let channel_binding_tls_exporter = if matches!(version, Some(TlsVersion::Tls13)) {
        let mut out_buf = [0u8; 32];
        match conn.export_keying_material(&mut out_buf[..], b"EXPORTER-Channel-Binding", None) {
            Ok(_) => Some(hex_lower(&out_buf)),
            Err(e) => {
                debug!(%e, "export_keying_material failed");
                None
            }
        }
    } else {
        // RFC 9266 §2: tls-exporter is TLS-1.3-only.
        None
    };

    let (sig_scheme, ocsp_bytes, cert_bytes) = collector.take_state();

    let channel_binding_server_end_point = cert_bytes.first().map(|leaf_der| sha256_hex(leaf_der));

    let certificates = decode_certs(&cert_bytes);

    // Offline chain validation + name match, decoupled from the permissive
    // handshake above. See probe module docs for why these are independent.
    let validation =
        crate::scanner::probe::evaluate_validation(&cert_bytes, &certificates, hostname);

    let ocsp_len = ocsp_bytes.as_ref().map(|v| v.len()).unwrap_or(0);
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
        ocsp_response_bytes: ocsp_bytes,
        channel_binding_tls_exporter,
        channel_binding_server_end_point,
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

fn to_model_version(v: rustls::ProtocolVersion) -> Option<TlsVersion> {
    // rustls may surface TLS 1.0/1.1 if anyone ever asks, but current builds
    // only negotiate 1.2/1.3. Map everything we know; else None.
    match v {
        rustls::ProtocolVersion::TLSv1_2 => Some(TlsVersion::Tls12),
        rustls::ProtocolVersion::TLSv1_3 => Some(TlsVersion::Tls13),
        _ => None,
    }
}

/// Assemble the wire-order DER chain the server delivered into a
/// single `Vec<Vec<u8>>` with `index 0 = leaf` followed by
/// intermediates in delivered order. Preserves duplicates; does not
/// re-sort. Downstream observations (Task 1 leaf-fingerprint capture,
/// revocation probes) rely on this ordering.
fn collect_chain_der(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(1 + intermediates.len());
    out.push(end_entity.to_vec());
    for i in intermediates {
        out.push(i.to_vec());
    }
    out
}

/// Parse each DER blob into a `CertificateInfo` and stamp its
/// `wire_position` from the raw-chain index. Parse failures drop the
/// entry silently (matching prior behavior) — a gap in the emitted
/// position sequence signals "we got bytes at position N but couldn't
/// parse them," which is itself a downstream-observable signal.
fn decode_certs(raw: &[Vec<u8>]) -> Vec<CertificateInfo> {
    raw.iter()
        .enumerate()
        .filter_map(|(i, der)| {
            CertificateInfo::from_der(der).ok().map(|mut c| {
                c.wire_position = i as u32;
                c
            })
        })
        .collect()
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex_lower(&h.finalize())
}

/// Permissive verifier that:
/// 1. Collects the peer certificate chain (leaf + intermediates).
/// 2. Captures the OCSP response bytes rustls hands to `verify_server_cert`.
/// 3. Captures the signature scheme from TLS 1.2/1.3 CertificateVerify.
///
/// Accepts all certs — validation is a separate observation emitted via
/// the `validation.*` schema section, computed offline after the
/// handshake completes.
#[derive(Debug, Default)]
struct StateCollector {
    certs: Mutex<Vec<Vec<u8>>>,
    /// Raw OCSP response bytes rustls hands us in
    /// `verify_server_cert`. `None` when no staple was present.
    /// Length is exposed as `.len()` on the captured bytes.
    ocsp_response: Mutex<Option<Vec<u8>>>,
    signature_scheme: Mutex<Option<String>>,
}

impl StateCollector {
    fn take_state(&self) -> (Option<String>, Option<Vec<u8>>, Vec<Vec<u8>>) {
        let sig = self.signature_scheme.lock().ok().and_then(|g| g.clone());
        let ocsp = self.ocsp_response.lock().ok().and_then(|mut g| g.take());
        let certs = self.certs.lock().map(|g| g.clone()).unwrap_or_default();
        (sig, ocsp, certs)
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
            guard.extend(collect_chain_der(end_entity, intermediates));
        }
        if !ocsp_response.is_empty() {
            if let Ok(mut guard) = self.ocsp_response.lock() {
                *guard = Some(ocsp_response.to_vec());
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_chain_der_preserves_wire_order() {
        let leaf = CertificateDer::from(vec![0x30, 0x82, 0x00, 0x01]);
        let int0 = CertificateDer::from(vec![0x30, 0x82, 0x00, 0x02]);
        let int1 = CertificateDer::from(vec![0x30, 0x82, 0x00, 0x03]);

        let out = collect_chain_der(&leaf, &[int0.clone(), int1.clone()]);

        assert_eq!(out.len(), 3);
        assert_eq!(out[0], leaf.as_ref());
        assert_eq!(out[1], int0.as_ref());
        assert_eq!(out[2], int1.as_ref());
    }

    #[test]
    fn collect_chain_der_preserves_duplicates() {
        // Two identical intermediates — some deployments legitimately
        // send the same cert twice (misconfiguration or bridge cert).
        // Observable shape must not silently dedup.
        let leaf = CertificateDer::from(vec![0xAA, 0xBB]);
        let dup = CertificateDer::from(vec![0xCC, 0xDD]);

        let out = collect_chain_der(&leaf, &[dup.clone(), dup.clone()]);

        assert_eq!(out.len(), 3);
        assert_eq!(out[0], leaf.as_ref());
        assert_eq!(out[1], dup.as_ref());
        assert_eq!(out[2], dup.as_ref());
    }

    #[test]
    fn collect_chain_der_leaf_only() {
        let leaf = CertificateDer::from(vec![0x30, 0x00]);
        let out = collect_chain_der(&leaf, &[]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], leaf.as_ref());
    }
}
