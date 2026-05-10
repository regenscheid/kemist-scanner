//! TLS 1.3 certificate-compression observation via rustls.
//!
//! RFC 8879 certificate compression is not TLS record compression. A
//! client advertises supported certificate decompression algorithms in
//! ClientHello; if the server chooses one, it sends a
//! `CompressedCertificate` handshake message instead of `Certificate`.
//! rustls handles that internally, so this probe installs a recording
//! Brotli decompressor and observes whether it was invoked.

use std::cell::RefCell;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::compress::{CertDecompressor, DecompressionFailed};
use rustls::pki_types::ServerName;
use rustls::{CertificateCompressionAlgorithm, ClientConfig, ClientConnection};
use tracing::{debug, info};

use crate::scanner::backends::rustls::AcceptAllVerifier;

thread_local! {
    static OBSERVED_ALGORITHMS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

#[derive(Debug)]
struct RecordingBrotliDecompressor;

static RECORDING_BROTLI_DECOMPRESSOR: RecordingBrotliDecompressor = RecordingBrotliDecompressor;

impl CertDecompressor for RecordingBrotliDecompressor {
    fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
        let result = rustls::compress::BROTLI_DECOMPRESSOR.decompress(input, output);
        if result.is_ok() {
            OBSERVED_ALGORITHMS.with(|observed| {
                let mut observed = observed.borrow_mut();
                if !observed.iter().any(|alg| alg == "brotli") {
                    observed.push("brotli".to_string());
                }
            });
        }
        result
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        rustls::compress::BROTLI_DECOMPRESSOR.algorithm()
    }
}

/// Probe whether the server uses TLS 1.3 Brotli certificate compression
/// when the client offers RFC 8879 support. Returns an empty list when
/// no compressed certificate was observed or the probe failed.
pub async fn probe(
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> Vec<String> {
    info!("rustls TLS 1.3 certificate compression probe");

    let hostname = hostname.to_string();
    tokio::task::spawn_blocking(move || {
        probe_blocking(target, &hostname, connect_timeout, handshake_timeout)
    })
    .await
    .unwrap_or_else(|e| {
        debug!("certificate compression probe panic: {e}");
        Vec::new()
    })
}

fn probe_blocking(
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> Vec<String> {
    OBSERVED_ALGORITHMS.with(|observed| observed.borrow_mut().clear());

    let mut cfg = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
        .with_no_client_auth();
    cfg.cert_decompressors = vec![&RECORDING_BROTLI_DECOMPRESSOR];
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let mut tcp = match std::net::TcpStream::connect_timeout(&target, connect_timeout) {
        Ok(tcp) => tcp,
        Err(e) => {
            debug!(%e, "certificate compression tcp connect failed");
            return Vec::new();
        }
    };
    let _ = tcp.set_read_timeout(Some(handshake_timeout));
    let _ = tcp.set_write_timeout(Some(handshake_timeout));

    let domain = match ServerName::try_from(hostname.to_string()) {
        Ok(domain) => domain,
        Err(_) => {
            debug!(hostname, "certificate compression invalid SNI");
            return Vec::new();
        }
    };

    let mut conn = match ClientConnection::new(Arc::new(cfg), domain) {
        Ok(conn) => conn,
        Err(e) => {
            debug!(%e, "certificate compression client connection setup failed");
            return Vec::new();
        }
    };

    while conn.is_handshaking() {
        match conn.complete_io(&mut tcp) {
            Ok(_) => {}
            Err(e) => {
                debug!(%e, "certificate compression handshake failed");
                return Vec::new();
            }
        }
    }

    OBSERVED_ALGORITHMS.with(|observed| observed.borrow().clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_brotli_reports_brotli_algorithm() {
        assert_eq!(
            RECORDING_BROTLI_DECOMPRESSOR.algorithm(),
            CertificateCompressionAlgorithm::Brotli
        );
    }
}
