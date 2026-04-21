pub mod backends;
pub mod cert;
pub mod ciphers;
pub mod groups;
pub mod hello;
pub mod http;
pub mod legacy;
#[cfg(feature = "legacy-probes")]
pub mod openssl;
pub mod probe;
pub mod runner;
pub mod sni;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{rustls, TlsConnector};
use tracing::{debug, info};

use crate::model::cert::CertificateInfo;
use crate::model::errors::ScannerError;
use crate::model::protocol::{ProtocolSupport, TlsVersion};
use crate::scanner::ciphers::{probe_cipher_suites, CipherProbeOutput};
use crate::scanner::groups::{probe_kx_groups, GroupProbeOutput};
use crate::scanner::hello::{probe_hello_extensions, HelloExtensionsObserved};
use crate::scanner::http::{probe_http, HttpObservations};
use crate::scanner::probe::{characterize_connection, NegotiatedState, ValidationResult};
use crate::scanner::sni::{probe_sni_omitted, SniBehaviorResult};

// Scanner-module functions return `Result<T, ScannerError>` explicitly rather
// than a type alias, so they don't collide with `rustls::Result<T, rustls::Error>`
// used by custom ServerCertVerifier impls below.

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
    /// Fire HTTP observations (HSTS / security.txt / preload list)
    /// after TLS probes complete.
    pub enable_http_checks: bool,
    /// Appended to User-Agent when HTTP checks fire: `kemist/<ver> (+<url>)`.
    pub user_agent_info_url: String,
    /// Canonical names of signature-algorithm policy probes to skip
    /// (from `--sigalg-probe-skip`). Empty = run all four.
    pub sigalg_probe_skip: Vec<String>,
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
    pub certificate_chain: Vec<CertificateInfo>,
    pub tls_renegotiation: TlsRenegotiation,
    pub heartbeat_echoes_oversized_payload: Option<bool>,
    /// State from the characterization handshake (one successful connection).
    /// Feeds `tls.negotiated` + several `tls.extensions` fields in the
    /// schema.
    #[serde(skip_serializing)]
    pub negotiated: Option<NegotiatedState>,
    /// ALPN protocols kemist proposed on the characterization handshake.
    #[serde(skip_serializing)]
    pub alpn_offered: Vec<String>,
    /// Trust observations — chain validity, name match, first-failure
    /// category string. Feeds `validation.*` in schema.
    #[serde(skip_serializing)]
    pub validation: ValidationResult,
    /// Real per-cipher probe results + server ordering observation.
    /// Feeds `tls.cipher_suites.*` in schema.
    #[serde(skip_serializing)]
    pub cipher_probes: Option<CipherProbeOutput>,
    /// Real per-group probe results (classical + PQC hybrid + standalone
    /// ML-KEM). Feeds `tls.groups.*` in schema.
    #[serde(skip_serializing)]
    pub group_probes: Option<GroupProbeOutput>,
    /// SNI-omitted comparison probe. Feeds
    /// `tls.sni_behavior.omitted_probe` in schema.
    #[serde(skip_serializing)]
    pub sni_behavior: Option<SniBehaviorResult>,
    /// Byte-level ServerHello observations from a dedicated TLS 1.2 probe
    /// — EMS, EtM, heartbeat, renegotiation_info, compression method, SCT
    /// via extension 18, truncated_hmac, NPN, supported_point_formats,
    /// max_fragment_length, TLS 1.3 downgrade sentinel.
    #[serde(skip_serializing)]
    pub hello_observed: Option<HelloExtensionsObserved>,
    /// HTTP-layer observations (HSTS / security.txt / preload list).
    /// Feeds the top-level `http` field in schema.
    #[serde(skip_serializing)]
    pub http_observations: Option<HttpObservations>,
    /// OpenSSL-backed legacy-probe subsystem output — legacy ciphers, DH
    /// parameters, FFDHE groups, SCSV, renegotiation, client-auth request.
    /// Gated on the `legacy-probes` cargo feature. Feeds the new `tls.*`
    /// sections per docs/OUTPUT_SCHEMA.md additions.
    #[cfg(feature = "legacy-probes")]
    #[serde(skip_serializing)]
    pub openssl_observations: Option<openssl::OpensslObservations>,
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
            certificate_chain: vec![],
            tls_renegotiation: TlsRenegotiation {
                secure_renegotiation: None,
                compression_supported: None,
            },
            heartbeat_echoes_oversized_payload: None,
            negotiated: None,
            alpn_offered: vec![],
            validation: ValidationResult::default(),
            cipher_probes: None,
            group_probes: None,
            sni_behavior: None,
            hello_observed: None,
            http_observations: None,
            #[cfg(feature = "legacy-probes")]
            openssl_observations: None,
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

        // `tls_renegotiation` was a pair of heuristics whose signal is
        // now produced by `openssl_observations.renegotiation` and the
        // byte-level `hello_observed.secure_renegotiation` extension
        // detection.

        results.heartbeat_echoes_oversized_payload = self.test_heartbleed(&mut results).await;
        pause().await;

        if !self.config.no_ciphersuites {
            // Real per-cipher probing: one handshake per aws-lc-rs suite,
            // plus two for order-enforcement detection. Respects the
            // per_target_delay between handshakes inside this function.
            let probe_out = probe_cipher_suites(
                self.config.target,
                &self.config.hostname,
                self.config.timeout,
                self.config.timeout,
                self.config.per_target_delay,
            )
            .await;
            results.cipher_probes = Some(probe_out);
            pause().await;
        }

        // Real per-group probing: one TLS 1.3 handshake per target group
        // from the hardcoded list (classical + PQC hybrids + standalone
        // ML-KEM + Kyber768Draft00). Groups not exposed by aws-lc-rs at
        // build time emit `not_probed` with a specific reason.
        let group_out = probe_kx_groups(
            self.config.target,
            &self.config.hostname,
            self.config.timeout,
            self.config.timeout,
            self.config.per_target_delay,
        )
        .await;
        results.group_probes = Some(group_out);
        pause().await;

        // OpenSSL legacy/misconfig probe subsystem: legacy ciphers, DH
        // parameters, FFDHE groups, SCSV, renegotiation, CertificateRequest,
        // plus SSLv3/TLS1.0/1.1 when routed through the OpenSSL path at
        // `test_protocol_support`. Gated by the `legacy-probes` feature.
        // A fatal setup error (providers won't load) lands in `scan_errors`
        // and skips the subsystem; individual probe-level failures land
        // inside `OpensslObservations.probe_errors` so the scan completes.
        #[cfg(feature = "legacy-probes")]
        {
            match crate::scanner::openssl::run_all_probes(&self.config).await {
                Ok(obs) => results.openssl_observations = Some(obs),
                Err(e) => results.scan_errors.push(e),
            }
            pause().await;
        }

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
        pause().await;

        // SNI-omitted comparison probe — one extra handshake with
        // ServerName::IpAddress (rustls omits SNI for IP literals per
        // RFC 6066). Compare leaf cert fingerprint against the SNI probe.
        let reference_fp = results
            .certificate_chain
            .first()
            .map(|c| c.fingerprint_sha256.clone());
        results.sni_behavior = Some(
            probe_sni_omitted(
                self.config.target,
                reference_fp.as_deref(),
                self.config.timeout,
                self.config.timeout,
            )
            .await,
        );
        pause().await;

        // Byte-level ServerHello probe — hand-crafted TLS 1.2 ClientHello
        // to extract extensions rustls does not expose (EMS, EtM,
        // heartbeat, renegotiation_info, compression, ext-path SCTs).
        results.hello_observed = Some(
            probe_hello_extensions(
                self.config.target,
                &self.config.hostname,
                self.config.timeout,
                self.config.timeout,
            )
            .await,
        );
        pause().await;

        // HTTP-layer observations (HSTS, security.txt, preload list).
        // Gated by `enable_http_checks` — even when the cargo feature
        // is compiled in, HTTP only fires when the CLI opts in.
        results.http_observations = Some(
            probe_http(
                &self.config.hostname,
                self.config.target.port(),
                self.config.enable_http_checks,
                &self.config.user_agent_info_url,
                self.config.timeout,
            )
            .await,
        );

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
                    // Backend priority: OpenSSL (legacy-probes) > native-tls
                    // (native-legacy) > "not probed" placeholder. The two
                    // backend cfg branches are mutually exclusive so the
                    // else-branch only kicks in when neither feature is on.
                    #[cfg(feature = "legacy-probes")]
                    {
                        crate::scanner::openssl::protocol_versions::probe_protocol(
                            self.config.target,
                            &self.config.hostname,
                            version,
                            self.config.timeout,
                            self.config.timeout,
                        )
                        .await
                    }
                    #[cfg(all(feature = "native-legacy", not(feature = "legacy-probes")))]
                    {
                        let legacy_scanner = crate::scanner::legacy::LegacyScanner::new(
                            self.config.target,
                            self.config.hostname.clone(),
                            self.config.timeout,
                        );
                        legacy_scanner.test_legacy_protocol(version).await
                    }
                    #[cfg(not(any(feature = "legacy-probes", feature = "native-legacy")))]
                    {
                        ProtocolSupport {
                            version,
                            supported: false,
                            error: Some(
                                "legacy_feature_disabled: rebuild with \
                                 --features legacy-probes or native-legacy to probe \
                                 SSLv3/TLS1.0/TLS1.1"
                                    .to_string(),
                            ),
                        }
                    }
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

    async fn check_tls_version_support(&self, version: TlsVersion) -> bool {
        let result = self.test_rustls_protocol(version).await;
        result.supported
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
