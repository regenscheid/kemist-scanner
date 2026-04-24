pub mod backends;
pub mod bundle_cache;
#[cfg(all(feature = "http-checks", feature = "legacy-probes"))]
pub mod bundle_fetcher;
#[cfg(all(feature = "http-checks", feature = "legacy-probes"))]
pub mod bundle_updater;
pub mod cert;
#[cfg(feature = "http-checks")]
pub mod crl_fetch;
pub mod hello;
pub mod http;
#[cfg(all(feature = "http-checks", feature = "legacy-probes"))]
pub mod ocsp_http;
pub mod probe;
pub mod raw;
pub mod runner;
pub mod trust_stores;

// Back-compat re-exports for the rustls-backed probe modules that
// migrated from `src/scanner/*.rs` to `src/scanner/backends/rustls/*.rs`.
// External callers that still reference `crate::scanner::{ciphers,
// groups, alpn_matrix, sni}` continue to resolve. Mirrors the
// `crate::scanner::openssl` alias below.
pub use crate::scanner::backends::rustls::alpn_matrix;
pub use crate::scanner::backends::rustls::ciphers;
pub use crate::scanner::backends::rustls::groups;
pub use crate::scanner::backends::rustls::sni;

// Backwards-compatible alias. The entire OpenSSL subsystem lives
// under `backends::openssl`; this re-export keeps
// `crate::scanner::openssl::X` working for callers / tests that
// haven't migrated to the new path.
#[cfg(feature = "legacy-probes")]
pub use self::backends::openssl;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{rustls, TlsConnector};
use tracing::info;

use crate::model::cert::CertificateInfo;
use crate::model::errors::ScannerError;
use crate::model::protocol::{ProtocolSupport, TlsVersion};
use crate::scanner::backends::rustls::ciphers::{probe_cipher_suites, CipherProbeOutput};
use crate::scanner::backends::rustls::groups::{probe_kx_groups, GroupProbeOutput};
use crate::scanner::backends::rustls::sni::{probe_sni_omitted, SniBehaviorResult};
use crate::scanner::hello::{
    probe_hello_extensions, probe_hello_retry_request, HelloExtensionsObserved,
    HelloRetryRequestObservation,
};
use crate::scanner::http::{probe_http, HttpObservations};
use crate::scanner::probe::{characterize_connection, NegotiatedState, ValidationResult};

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
    /// Fire active revocation fetches — CRL + OCSP-over-HTTP. When
    /// `false`, the scanner only observes whatever revocation data
    /// comes in-band during the TLS handshake (stapled OCSP).
    pub enable_revocation_fetch: bool,
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
    /// TLS 1.3 HelloRetryRequest observation from a dedicated TLS 1.3
    /// ClientHello-with-empty-key_share probe. Feeds
    /// `tls.extensions.hello_retry_request` in schema.
    #[serde(skip_serializing)]
    pub hrr_observed: Option<HelloRetryRequestObservation>,
    /// SSLv2 SERVER-HELLO observation. When the server answered
    /// SSLv2, the observation carries the cipher_specs list echoed
    /// in its response; feeds `tls.cipher_suites.ssl2` in the JSON
    /// emitter. `None` when the SSLv2 probe didn't run (e.g.
    /// `--tls-version` pinned to a higher version).
    #[serde(skip_serializing)]
    pub sslv2_observation: Option<crate::scanner::raw::sslv2::SslV2Observation>,
    /// Per-ALPN-protocol probe matrix — one handshake per target
    /// ALPN token. Feeds `tls.alpn_probe` in schema. `None` when the
    /// probe didn't run.
    #[serde(skip_serializing)]
    pub alpn_matrix: Option<crate::scanner::backends::rustls::alpn_matrix::AlpnMatrixOutput>,
    /// OCSP-over-HTTP fallback results — one fetch per AIA OCSP URL
    /// the leaf cert advertises. Populated only when
    /// `--enable-revocation-fetch` is set AND the characterization
    /// handshake captured both a leaf and an issuer cert. `None`
    /// otherwise. Feeds `tls.extensions.ocsp_http_fallback` in
    /// schema.
    #[cfg(all(feature = "http-checks", feature = "legacy-probes"))]
    #[serde(skip_serializing)]
    pub ocsp_http_fetch: Option<crate::scanner::ocsp_http::OcspHttpFetchOutput>,
    /// CRL fetch + revocation-check results — one entry per CRL DP
    /// URL on the leaf. Populated only when
    /// `--enable-revocation-fetch` is set. Feeds
    /// `tls.extensions.crl_fetch` in schema. `None` otherwise.
    #[cfg(feature = "http-checks")]
    #[serde(skip_serializing)]
    pub crl_fetch: Option<crate::scanner::crl_fetch::CrlFetchOutput>,
    /// Raw DER bytes of every cert in the chain the server delivered
    /// during the characterization handshake. Retained on the
    /// results so post-handshake probes (OCSP-over-HTTP, CRL fetch)
    /// can rebuild `X509` handles without re-running the handshake.
    /// Index 0 is the leaf; subsequent entries are intermediates in
    /// chain order. Not serialized to JSON (the parsed form under
    /// `certificate_chain` already carries everything consumers key on).
    #[serde(skip_serializing)]
    pub cert_chain_der: Vec<Vec<u8>>,
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
            hrr_observed: None,
            sslv2_observation: None,
            alpn_matrix: None,
            #[cfg(all(feature = "http-checks", feature = "legacy-probes"))]
            ocsp_http_fetch: None,
            #[cfg(feature = "http-checks")]
            crl_fetch: None,
            cert_chain_der: Vec::new(),
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
            Ok((v, sslv2)) => {
                results.protocol_support = v;
                results.sslv2_observation = sslv2;
            }
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
                results.cert_chain_der = out.cert_der;
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

        // TLS 1.3 HelloRetryRequest probe — separate handshake that
        // sends a TLS 1.3 ClientHello with an empty `key_share`,
        // forcing a spec-compliant server into HRR. Classifies the
        // ServerHello random against the RFC 8446 §4.1.3 sentinel.
        results.hrr_observed = Some(
            probe_hello_retry_request(
                self.config.target,
                &self.config.hostname,
                self.config.timeout,
                self.config.timeout,
            )
            .await,
        );
        pause().await;

        // Per-ALPN-protocol probe matrix. One handshake per target
        // token (h2 / http/1.1 / http/1.0) — records which ALPNs the
        // server would accept independently, not just what it picks
        // when both are offered.
        results.alpn_matrix = Some(
            crate::scanner::backends::rustls::alpn_matrix::probe_alpn_matrix(
                self.config.target,
                &self.config.hostname,
                self.config.timeout,
                self.config.timeout,
            )
            .await,
        );
        pause().await;

        // OCSP-over-HTTP fallback. Only fires when the operator
        // opted into revocation fetches (`--enable-revocation-fetch`)
        // AND the characterization handshake captured both a leaf +
        // issuer cert AND the leaf's AIA advertises OCSP URLs. Runs
        // regardless of whether the server already stapled — the two
        // responses (stapled vs HTTP-fetched) can legitimately
        // differ on timing, and both are useful observations.
        #[cfg(all(feature = "http-checks", feature = "legacy-probes"))]
        if self.config.enable_revocation_fetch {
            if let Some(leaf_info) = results.certificate_chain.first() {
                let urls: Vec<String> = leaf_info
                    .extensions
                    .authority_information_access
                    .as_ref()
                    .map(|aia| aia.ocsp.clone())
                    .unwrap_or_default();
                if !urls.is_empty() {
                    if let (Some(leaf_der), Some(issuer_der)) = (
                        results.cert_chain_der.first(),
                        results.cert_chain_der.get(1),
                    ) {
                        results.ocsp_http_fetch = Some(
                            crate::scanner::ocsp_http::probe_ocsp_http(
                                leaf_der,
                                issuer_der,
                                &urls,
                                self.config.timeout,
                            )
                            .await,
                        );
                    }
                }
            }
            pause().await;
        }

        // CRL fetch + revocation check. Shares the
        // `--enable-revocation-fetch` gate with OCSP-over-HTTP.
        // Unlike OCSP-HTTP, this only needs the leaf cert + its DP
        // URLs — the issuer cert is used by the CA that signed the
        // CRL, not by the scanner. Leaf serial comes from the
        // captured chain DER so it matches the exact bytes the CA
        // stored in `revokedCertificates`.
        #[cfg(feature = "http-checks")]
        if self.config.enable_revocation_fetch {
            if let Some(leaf_info) = results.certificate_chain.first() {
                let urls: Vec<String> = leaf_info
                    .extensions
                    .crl_distribution_points
                    .as_ref()
                    .map(|crl| crl.urls.clone())
                    .unwrap_or_default();
                if !urls.is_empty() {
                    // Re-parse the leaf DER to pull the raw serial —
                    // the CertificateInfo view stringifies it, which
                    // is lossy for CRL matching (no leading zero
                    // preservation, no sign bit). Raw bytes match
                    // the CRL's `user_certificate` INTEGER exactly.
                    if let Some(leaf_der) = results.cert_chain_der.first() {
                        use x509_parser::prelude::FromDer;
                        if let Ok((_, cert)) =
                            x509_parser::certificate::X509Certificate::from_der(leaf_der)
                        {
                            let serial_bytes = cert.raw_serial().to_vec();
                            results.crl_fetch = Some(
                                crate::scanner::crl_fetch::probe_crl(
                                    &urls,
                                    &serial_bytes,
                                    self.config.timeout,
                                )
                                .await,
                            );
                        }
                    }
                }
            }
            pause().await;
        }

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

    async fn test_protocol_support(
        &self,
    ) -> Result<
        (
            Vec<ProtocolSupport>,
            Option<crate::scanner::raw::sslv2::SslV2Observation>,
        ),
        ScannerError,
    > {
        let versions = if let Some(version) = self.config.tls_version {
            vec![version]
        } else {
            TlsVersion::all()
        };

        let mut protocol_results = Vec::new();
        let mut captured_sslv2: Option<crate::scanner::raw::sslv2::SslV2Observation> = None;

        for version in versions {
            info!("Testing {} support", version);

            let result = match version {
                TlsVersion::Tls12 | TlsVersion::Tls13 => {
                    // Test with rustls
                    self.test_rustls_protocol(version).await
                }
                TlsVersion::Ssl2 => {
                    // Rich observation — carries both the version
                    // probe's supported/error AND the SERVER-HELLO
                    // cipher_specs echo. Stash the full value on the
                    // accumulator so the JSON emitter can populate
                    // `tls.cipher_suites.ssl2` separately from the
                    // `versions_offered` entry.
                    let obs = crate::scanner::raw::sslv2::probe(
                        self.config.target,
                        &self.config.hostname,
                        self.config.timeout,
                    )
                    .await;
                    let ps = obs.to_protocol_support();
                    captured_sslv2 = Some(obs);
                    ps
                }
                TlsVersion::Ssl3 | TlsVersion::Tls10 | TlsVersion::Tls11 => {
                    // SSLv3/TLS1.0/TLS1.1 route exclusively through the
                    // vendored OpenSSL backend; `--no-default-features`
                    // builds surface a `legacy_feature_disabled`
                    // placeholder so consumers can tell the difference
                    // from "probed and rejected".
                    #[cfg(feature = "legacy-probes")]
                    {
                        use crate::scanner::backends::{
                            BackendRegistry, HandshakeConstraint, HandshakeOutcome, ProbeContext,
                        };
                        let registry = BackendRegistry::new();
                        let ctx = ProbeContext {
                            target: self.config.target,
                            hostname: self.config.hostname.clone(),
                            connect_timeout: self.config.timeout,
                            handshake_timeout: self.config.timeout,
                        };
                        // Registry routes SSLv3/TLS1.0/1.1 to the OpenSSL
                        // backend; `handshake()` wraps the existing
                        // `protocol_versions::probe_protocol` helper. The
                        // error-string detail that HandshakeResult drops
                        // is unused downstream — `build_versions_offered`
                        // in the JSON emitter only reads `supported: bool`.
                        let supported = match registry.route_version(version) {
                            Some(backend) => match backend
                                .handshake(HandshakeConstraint::version_only(version), &ctx)
                                .await
                            {
                                Ok(r) => matches!(r.outcome, HandshakeOutcome::Supported),
                                Err(_) => false,
                            },
                            None => false,
                        };
                        ProtocolSupport {
                            version,
                            supported,
                            error: None,
                        }
                    }
                    #[cfg(not(feature = "legacy-probes"))]
                    {
                        ProtocolSupport {
                            version,
                            supported: false,
                            error: Some(
                                "legacy_feature_disabled: rebuild with \
                                 --features legacy-probes to probe \
                                 SSLv3/TLS1.0/TLS1.1"
                                    .to_string(),
                            ),
                        }
                    }
                }
            };

            protocol_results.push(result);
        }

        Ok((protocol_results, captured_sslv2))
    }

    async fn test_rustls_protocol(&self, version: TlsVersion) -> ProtocolSupport {
        // Pin rustls to exactly the version under test. Without this
        // pin the builder defaults to {TLS 1.2, TLS 1.3} and the
        // handshake silently falls back to whichever the server
        // accepts — so "TLS 1.3 support" against a 1.2-only server
        // would complete via 1.2 and falsely report 1.3 offered.
        let rv = match version {
            TlsVersion::Tls12 => &rustls::version::TLS12,
            TlsVersion::Tls13 => &rustls::version::TLS13,
            _ => {
                return ProtocolSupport {
                    version,
                    supported: false,
                    error: Some(format!(
                        "rustls_backend_version_out_of_scope:{version:?}"
                    )),
                };
            }
        };
        let mut config = rustls::ClientConfig::builder_with_protocol_versions(&[rv])
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
            .with_no_client_auth();

        // ALPN per-version. TLS 1.3 clients commonly carry ALPN;
        // TLS 1.2 probing leaves it empty to keep the hello minimal.
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

    async fn test_heartbleed(&self, _results: &mut ScanResults) -> Option<bool> {
        // Delegate to the raw-socket probe. Technique per testssl.sh:
        // vulnerable OpenSSL processes heartbeat records before
        // encryption is established, so the probe exploits the flaw
        // over plaintext with no session-key derivation required.
        info!("Probing heartbeat oversized-payload echo");
        crate::scanner::raw::heartbleed::probe(
            self.config.target,
            &self.config.hostname,
            self.config.timeout,
        )
        .await
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
