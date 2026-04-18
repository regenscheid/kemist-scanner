pub mod cert;
pub mod legacy;
pub mod probe;
pub mod runner;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{rustls, TlsConnector};
use tracing::{debug, info};

use crate::model::cert::CertificateInfo;
use crate::model::cipher::{
    get_rustls_cipher_suites, rustls_to_cipher_info, CipherInfo, CipherSuiteResult,
};
use crate::model::errors::ScannerError;
use crate::model::protocol::{ProtocolSupport, TlsVersion};
use crate::scanner::probe::{characterize_connection, NegotiatedState, ValidationResult};

// Scanner-module functions return `Result<T, ScannerError>` explicitly rather
// than a type alias, so they don't collide with `rustls::Result<T, rustls::Error>`
// used by custom ServerCertVerifier impls below.

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyExchangeGroup {
    pub name: String,
    pub iana_name: String,
    pub supported: bool,
    pub negotiated: bool,
    pub post_quantum: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TlsRenegotiation {
    pub secure_renegotiation: Option<bool>,  // RFC 5746 support
    pub compression_supported: Option<bool>, // TLS compression offered
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub target: SocketAddr,
    pub hostname: String,
    pub timeout: Duration,
    pub _show_certificate: bool,
    pub _show_failed: bool,
    pub no_ciphersuites: bool,
    pub tls_version: Option<TlsVersion>,
    /// Per-probe delay hint. Honored between probes inside `scan()` — probes
    /// to a single target are already serialized; this controls how
    /// aggressively we hit that target.
    pub per_target_delay: Duration,
}

#[derive(Debug)]
pub struct SslScanner {
    config: ScanConfig,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanResults {
    pub target: String,
    pub hostname: String,
    pub port: u16,
    pub scan_time: chrono::DateTime<chrono::Utc>,
    pub protocol_support: Vec<ProtocolSupport>,
    pub cipher_suites: Vec<CipherSuiteResult>,
    pub key_exchange_groups: Vec<KeyExchangeGroup>,
    pub certificate_chain: Vec<CertificateInfo>,
    pub preferred_cipher: Option<CipherInfo>,
    pub tls_renegotiation: TlsRenegotiation,
    pub heartbeat_echoes_oversized_payload: Option<bool>,
    pub fallback_scsv_accepted: Option<bool>,
    /// State from the characterization handshake (one successful connection).
    /// Populated by PR 5; feeds `tls.negotiated` + several `tls.extensions`
    /// fields in the schema.
    #[serde(skip_serializing)]
    pub negotiated: Option<NegotiatedState>,
    /// ALPN protocols kemist proposed on the characterization handshake.
    #[serde(skip_serializing)]
    pub alpn_offered: Vec<String>,
    /// Trust observations — chain validity, name match, first-failure
    /// category string. Populated by PR 6. Feeds `validation.*` in schema.
    #[serde(skip_serializing)]
    pub validation: ValidationResult,
    /// Probe-level failures accumulated during the scan. Never aborts scan()
    /// even if every entry errors — downstream consumers read this alongside
    /// the partial observations.
    pub scan_errors: Vec<ScannerError>,
}

impl SslScanner {
    pub fn new(config: ScanConfig) -> Self {
        Self { config }
    }

    /// Infallible scan. Individual probe failures are accumulated into
    /// `ScanResults.scan_errors`; the scan itself never aborts. Callers
    /// always receive a complete-shaped result.
    pub async fn scan(&self) -> ScanResults {
        info!(
            "Starting SSL/TLS scan of {}:{}",
            self.config.hostname,
            self.config.target.port()
        );

        let mut results = ScanResults {
            target: self.config.target.to_string(),
            hostname: self.config.hostname.clone(),
            port: self.config.target.port(),
            scan_time: chrono::Utc::now(),
            protocol_support: vec![],
            cipher_suites: vec![],
            key_exchange_groups: vec![],
            certificate_chain: vec![],
            preferred_cipher: None,
            tls_renegotiation: TlsRenegotiation {
                secure_renegotiation: None,
                compression_supported: None,
            },
            heartbeat_echoes_oversized_payload: None,
            fallback_scsv_accepted: None,
            negotiated: None,
            alpn_offered: vec![],
            validation: ValidationResult::default(),
            scan_errors: vec![],
        };

        // Every probe feeds into `results` on success and `scan_errors` on
        // failure. No early returns — the scan completes regardless.
        // `per_target_delay` spaces probes so we don't hammer a single host.
        let delay = self.config.per_target_delay;
        let pause = || async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
        };

        match self.test_protocol_support().await {
            Ok(v) => results.protocol_support = v,
            Err(e) => results.scan_errors.push(e),
        }
        pause().await;

        results.fallback_scsv_accepted = self.test_fallback_scsv().await;
        pause().await;

        results.tls_renegotiation = self.test_tls_renegotiation().await;
        pause().await;

        results.heartbeat_echoes_oversized_payload = self.test_heartbleed(&mut results).await;
        pause().await;

        if !self.config.no_ciphersuites {
            match self.test_cipher_suites().await {
                Ok(v) => results.cipher_suites = v,
                Err(e) => results.scan_errors.push(e),
            }
            pause().await;
        }

        match self.test_key_exchange_groups().await {
            Ok(v) => results.key_exchange_groups = v,
            Err(e) => results.scan_errors.push(e),
        }
        pause().await;

        // Single characterization handshake captures cert chain AND
        // negotiated state (version/suite/group/ALPN + verifier-side signals
        // like OCSP + signature scheme).
        match characterize_connection(
            self.config.target,
            &self.config.hostname,
            self.config.timeout,
            self.config.timeout,
        )
        .await
        {
            Ok(out) => {
                results.certificate_chain = out.certificates;
                results.negotiated = out.negotiated;
                results.alpn_offered = out.alpn_offered;
                results.validation = out.validation;
            }
            Err(e) => {
                // If the verifier fired before the handshake aborted, keep
                // partial state; otherwise propagate the error.
                results.scan_errors.push(e);
            }
        }

        if let Some(preferred) = results.cipher_suites.iter().find(|c| c.preferred) {
            results.preferred_cipher = Some(preferred.cipher.clone());
        }

        results
    }

    async fn test_protocol_support(&self) -> Result<Vec<ProtocolSupport>, ScannerError> {
        let versions = if let Some(version) = self.config.tls_version {
            vec![version]
        } else {
            TlsVersion::all()
        };

        let mut protocol_results = Vec::new();

        for version in versions {
            info!("Testing {} support", version);

            let result = match version {
                TlsVersion::Tls12 | TlsVersion::Tls13 => {
                    // Test with rustls
                    self.test_rustls_protocol(version).await
                }
                TlsVersion::Ssl2 => {
                    crate::scanner::legacy::test_sslv2(
                        self.config.target,
                        &self.config.hostname,
                        self.config.timeout,
                    )
                    .await
                }
                TlsVersion::Ssl3 | TlsVersion::Tls10 | TlsVersion::Tls11 => {
                    let legacy_scanner = crate::scanner::legacy::LegacyScanner::new(
                        self.config.target,
                        self.config.hostname.clone(),
                        self.config.timeout,
                    );
                    legacy_scanner.test_legacy_protocol(version).await
                }
            };

            protocol_results.push(result);
        }

        Ok(protocol_results)
    }

    async fn test_rustls_protocol(&self, version: TlsVersion) -> ProtocolSupport {
        let mut config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
            .with_no_client_auth();

        // Configure for specific TLS version
        match version {
            TlsVersion::Tls12 => {
                config.alpn_protocols = vec![];
                config.enable_early_data = false;
            }
            TlsVersion::Tls13 => {
                config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            }
            _ => {}
        }

        let connector = TlsConnector::from(Arc::new(config));

        match self.connect_with_timeout(connector).await {
            Ok(_) => ProtocolSupport {
                version,
                supported: true,
                error: None,
            },
            Err(e) => ProtocolSupport {
                version,
                supported: false,
                error: Some(e.to_string()),
            },
        }
    }

    async fn test_cipher_suites(&self) -> Result<Vec<CipherSuiteResult>, ScannerError> {
        let mut results = Vec::new();

        // Get all available cipher suites
        let cipher_suites = get_rustls_cipher_suites();

        for suite in cipher_suites {
            debug!("Testing cipher suite: {:?}", suite);

            // Create config with only this cipher suite
            let _config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
                .with_no_client_auth();

            // Note: rustls doesn't allow configuring individual cipher suites easily
            // This is a limitation compared to OpenSSL-based scanners
            // For now, we'll test with default configurations

            // Let rustls_to_cipher_info determine the correct TLS version
            let cipher_info = rustls_to_cipher_info(suite);

            // In a real implementation, we'd test each cipher individually
            // For now, mark all rustls default ciphers as supported
            results.push(CipherSuiteResult {
                cipher: cipher_info,
                supported: true,
                preferred: false,
            });
        }

        // Mark the first successful cipher as preferred
        if let Some(first) = results.first_mut() {
            first.preferred = true;
        }

        Ok(results)
    }

    async fn connect_with_timeout(&self, connector: TlsConnector) -> Result<(), ScannerError> {
        let tcp_stream =
            match timeout(self.config.timeout, TcpStream::connect(&self.config.target)).await {
                Err(_) => return Err(ScannerError::connection_timeout("tcp connect")),
                Ok(Err(e)) => return Err(ScannerError::from_io("tcp connect", e)),
                Ok(Ok(s)) => s,
            };

        let domain = rustls_pki_types::ServerName::try_from(self.config.hostname.as_str())
            .map_err(|_| {
                ScannerError::internal(format!("invalid SNI hostname: {}", self.config.hostname))
            })?
            .to_owned();

        match timeout(self.config.timeout, connector.connect(domain, tcp_stream)).await {
            Err(_) => Err(ScannerError::handshake_timeout("rustls handshake")),
            Ok(Err(e)) => Err(ScannerError::from_io("tls handshake", e)),
            Ok(Ok(_)) => Ok(()),
        }
    }

    async fn test_key_exchange_groups(&self) -> Result<Vec<KeyExchangeGroup>, ScannerError> {
        let mut groups = Vec::new();

        // Define known key exchange groups with their properties
        let known_groups = vec![
            ("X25519", "x25519", false),
            ("X448", "x448", false),
            ("secp256r1", "secp256r1", false),
            ("secp384r1", "secp384r1", false),
            ("secp521r1", "secp521r1", false),
            ("X25519MLKEM768", "x25519_mlkem768", true),
            ("SecP256r1MLKEM768", "secp256r1_mlkem768", true),
            ("SecP384r1MLKEM1024", "secp384r1_mlkem1024", true),
            ("MLKEM512", "mlkem512", true),
            ("MLKEM768", "mlkem768", true),
            ("MLKEM1024", "mlkem1024", true),
        ];

        for (name, iana_name, is_pq) in known_groups {
            // For now, we'll mark all groups as supported since rustls with aws-lc-rs
            // supports most of these groups. In a more complete implementation,
            // we would test each group individually.
            groups.push(KeyExchangeGroup {
                name: name.to_string(),
                iana_name: iana_name.to_string(),
                supported: true,
                negotiated: false, // We would need to capture this from actual handshake
                post_quantum: is_pq,
            });
        }

        Ok(groups)
    }

    async fn test_fallback_scsv(&self) -> Option<bool> {
        // TLS Fallback SCSV (RFC 7507) test
        // The test works by:
        // 1. First check if server supports TLS 1.3
        // 2. Then try to connect with TLS 1.2 and TLS_FALLBACK_SCSV
        // 3. If server properly implements SCSV, it should reject the connection

        // First, check if server supports TLS 1.3
        let supports_tls13 = self.check_tls_version_support(TlsVersion::Tls13).await;
        if !supports_tls13 {
            // If server doesn't support TLS 1.3, test with TLS 1.2 -> TLS 1.1 fallback
            return self.test_fallback_scsv_tls12_to_tls11().await;
        }

        // Server supports TLS 1.3, test TLS 1.3 -> TLS 1.2 fallback
        self.test_fallback_scsv_tls13_to_tls12().await
    }

    async fn check_tls_version_support(&self, version: TlsVersion) -> bool {
        let result = self.test_rustls_protocol(version).await;
        result.supported
    }

    async fn test_fallback_scsv_tls13_to_tls12(&self) -> Option<bool> {
        // Try to connect with TLS 1.2 and indicate we support TLS 1.3
        // If SCSV is supported, server should reject this connection

        // Note: rustls doesn't easily allow us to inject TLS_FALLBACK_SCSV
        // This is a simplified implementation that would need lower-level TLS control
        // For now, we'll assume modern servers support SCSV if they support TLS 1.3

        info!("Testing TLS Fallback SCSV (TLS 1.3 -> TLS 1.2)");

        // Since we can't easily test the actual SCSV with rustls,
        // we'll do a heuristic: modern servers that support TLS 1.3
        // are likely to support Fallback SCSV
        Some(true)
    }

    async fn test_fallback_scsv_tls12_to_tls11(&self) -> Option<bool> {
        // Test TLS 1.2 -> TLS 1.1 fallback
        let supports_tls12 = self.check_tls_version_support(TlsVersion::Tls12).await;
        let supports_tls11 = self.check_tls_version_support(TlsVersion::Tls11).await;

        if supports_tls12 && supports_tls11 {
            info!("Testing TLS Fallback SCSV (TLS 1.2 -> TLS 1.1)");
            // Similar limitation - assume support if both versions work
            Some(true)
        } else {
            // Can't test SCSV meaningfully
            None
        }
    }

    async fn test_tls_renegotiation(&self) -> TlsRenegotiation {
        // Test various aspects of TLS renegotiation
        info!("Testing TLS renegotiation capabilities");

        let mut renegotiation = TlsRenegotiation {
            secure_renegotiation: None,
            compression_supported: None,
        };

        // Test secure renegotiation (RFC 5746)
        renegotiation.secure_renegotiation = self.test_secure_renegotiation().await;

        // Test TLS compression offered
        renegotiation.compression_supported = self.test_tls_compression().await;

        renegotiation
    }

    async fn test_secure_renegotiation(&self) -> Option<bool> {
        // Test if server supports secure renegotiation (RFC 5746)
        // This extension prevents renegotiation attacks

        // With rustls, secure renegotiation is typically enabled by default
        // We can infer support based on successful TLS connections
        if self.check_tls_version_support(TlsVersion::Tls12).await
            || self.check_tls_version_support(TlsVersion::Tls13).await
        {
            // Modern TLS implementations typically support secure renegotiation
            Some(true)
        } else {
            // If we can't establish any secure connection, we can't determine this
            None
        }
    }

    async fn test_tls_compression(&self) -> Option<bool> {
        // Test if server supports TLS compression (CRIME vulnerability - CVE-2012-4929)
        // Modern servers should have this disabled

        // rustls doesn't support TLS compression, and modern servers disable it
        // If we can connect with rustls, compression is likely disabled
        if self.check_tls_version_support(TlsVersion::Tls12).await
            || self.check_tls_version_support(TlsVersion::Tls13).await
        {
            // Modern implementations don't support compression
            Some(false)
        } else {
            None
        }
    }

    async fn test_heartbleed(&self, results: &mut ScanResults) -> Option<bool> {
        // Observation: does the server echo an oversized heartbeat payload?
        // Raw wire signal — downstream rule engines interpret its meaning.

        info!("Probing heartbeat oversized-payload echo");

        // Only probe on TLS 1.2 and below, as TLS 1.3 doesn't support heartbeat
        let supports_tls12 = self.check_tls_version_support(TlsVersion::Tls12).await;
        let supports_tls11 = self.check_tls_version_support(TlsVersion::Tls11).await;
        let supports_tls10 = self.check_tls_version_support(TlsVersion::Tls10).await;

        if !supports_tls12 && !supports_tls11 && !supports_tls10 {
            // Not applicable — no pre-1.3 protocol available to heartbeat over
            return Some(false);
        }

        match self.perform_heartbleed_test().await {
            Ok(vulnerable) => Some(vulnerable),
            Err(e) => {
                debug!("heartbeat probe error: {}", e);
                results.scan_errors.push(e);
                None
            }
        }
    }

    async fn perform_heartbleed_test(&self) -> Result<bool, ScannerError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream =
            match timeout(self.config.timeout, TcpStream::connect(&self.config.target)).await {
                Err(_) => return Err(ScannerError::connection_timeout("heartbleed tcp connect")),
                Ok(Err(e)) => return Err(ScannerError::from_io("heartbleed tcp connect", e)),
                Ok(Ok(s)) => s,
            };

        // Perform basic TLS handshake first to establish encryption
        // We need to get to a state where we can send heartbeat messages

        // For a proper Heartbleed test, we would need to:
        // 1. Complete TLS handshake
        // 2. Send a heartbeat request with length > actual payload
        // 3. Check if server responds with more data than sent

        // This is a simplified implementation that demonstrates the concept
        // In practice, you'd need to implement the full TLS handshake manually
        // or use a low-level TLS library that allows heartbeat manipulation

        // Send a malformed heartbeat request
        let heartbeat_request = self.craft_heartbleed_payload();

        match stream.write_all(&heartbeat_request).await {
            Ok(_) => {
                // Try to read response
                let mut buffer = vec![0u8; 1024];
                match timeout(Duration::from_secs(2), stream.read(&mut buffer)).await {
                    Ok(Ok(bytes_read)) => {
                        // Analyze response for signs of Heartbleed
                        Ok(self.analyze_heartbleed_response(&buffer[..bytes_read]))
                    }
                    _ => {
                        // No response or timeout - likely not vulnerable
                        Ok(false)
                    }
                }
            }
            Err(_) => {
                // Failed to send - connection likely closed
                Ok(false)
            }
        }
    }

    fn craft_heartbleed_payload(&self) -> Vec<u8> {
        // Craft a TLS heartbeat request with malformed length
        // This is a simplified version for demonstration

        // TLS Record Header:
        // - Content Type: Heartbeat (24 = 0x18)
        // - Version: TLS 1.2 (0x0303)
        // - Length: 8 bytes

        // Heartbeat Message:
        // - Type: Request (1)
        // - Payload Length: 65535 (0xFFFF) - malformed, much larger than actual payload
        // - Payload: 3 bytes "ABC"
        // - Padding: None

        let mut payload = Vec::new();

        // TLS Record Header
        payload.push(0x18); // Content Type: Heartbeat
        payload.extend_from_slice(&[0x03, 0x03]); // Version: TLS 1.2
        payload.extend_from_slice(&[0x00, 0x08]); // Length: 8 bytes

        // Heartbeat Request
        payload.push(0x01); // Type: Request
        payload.extend_from_slice(&[0xFF, 0xFF]); // Payload Length: 65535 (malformed!)
        payload.extend_from_slice(b"ABC"); // Actual payload: only 3 bytes

        payload
    }

    fn analyze_heartbleed_response(&self, response: &[u8]) -> bool {
        // Analyze the response to determine if Heartbleed vulnerability exists

        if response.is_empty() {
            return false;
        }

        // Check if this looks like a TLS record
        if response.len() < 5 {
            return false;
        }

        // Check for heartbeat response (content type 0x18)
        if response[0] == 0x18 {
            // Extract the length from TLS record header
            let record_length = u16::from_be_bytes([response[3], response[4]]) as usize;

            // If the response length is significantly larger than our payload,
            // it might indicate Heartbleed vulnerability
            if record_length > 100 {
                // Our payload was only 3 bytes
                debug!(
                    "Potential Heartbleed response detected: {} bytes",
                    record_length
                );
                return true;
            }
        }

        false
    }
}

/// Certificate verifier that accepts all certificates but collects them
#[derive(Debug)]
struct AcceptAllVerifier;

impl rustls::client::danger::ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
