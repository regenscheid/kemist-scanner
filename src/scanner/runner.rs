//! Public scanning API.
//!
//! `Scanner` wraps the internal probe orchestrator with DNS resolution,
//! timing, retry logic, and schema-v1 conversion. It is the stable surface
//! downstream consumers depend on — probe internals will churn over time,
//! but `Scanner::scan(Target) -> ScanResult` and
//! `Scanner::scan_many(Vec<Target>) -> Vec<ScanResult>` do not.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use futures::stream::{self, StreamExt};
use hickory_resolver::TokioAsyncResolver;
use tokio::sync::Semaphore;
use tracing::{info, warn};

use crate::model::errors::ScannerError;
use crate::model::protocol::TlsVersion;
use crate::model::scan_result::ScanResult;
use crate::model::target::Target;
use crate::output::json::{build_scan_result, JsonEmitContext};
use crate::scanner::{ScanConfig, SslScanner};

/// Configuration for a scanner session. Applies to every target scanned
/// through this `Scanner` instance.
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    /// Maximum concurrent targets. Probes to a single target are always
    /// sequential — this limits parallelism across distinct targets.
    pub concurrency: usize,
    /// Minimum delay between probes to the same target. Honored between
    /// probes inside the OpenSSL subsystem; rustls-path probes currently
    /// run back-to-back.
    pub per_target_delay: Duration,
    /// TCP connect timeout (per attempt, per target).
    pub connect_timeout: Duration,
    /// TLS handshake timeout (per attempt, per target).
    pub handshake_timeout: Duration,
    /// Hard ceiling for time spent on a single target including retries.
    pub total_timeout: Duration,
    /// Number of retry attempts on transient network errors. Set to 0 to
    /// disable. Non-transient failures (TLS alerts, cert parse errors) are
    /// never retried — those are real signal about the server.
    pub retries: u32,
    /// Restrict probes to a single TLS version. `None` probes all versions.
    pub tls_version_filter: Option<TlsVersion>,
    /// `--ipv4` flag — when set, DNS resolution returns IPv4 only.
    pub ipv4_only: bool,
    /// `--ipv6` flag — when set, DNS resolution returns IPv6 only.
    pub ipv6_only: bool,
    /// Cargo features enabled in this binary. Passed through to the
    /// `capabilities.enabled_features` field on every emitted record.
    pub enabled_features: Vec<String>,
    /// Config file paths used by the scanner. Echoed into capabilities.
    pub config_paths: Vec<String>,
    /// Fire HTTP-layer observations (HSTS / security.txt / preload list).
    /// Runtime opt-in: requires the `http-checks` cargo feature AND this
    /// flag set to `true` at the CLI.
    pub enable_http_checks: bool,
    /// Identifier URL appended to the User-Agent when HTTP checks fire:
    /// `kemist/<ver> (+<url>)`. Let server operators trace requests
    /// back to a kemist scan.
    pub user_agent_info_url: String,
    /// Emit `tls.extensions.ocsp_stapling.raw_hex` (hex of the raw
    /// OCSP response bytes) alongside the parsed `content`. Off by
    /// default — rule engines rarely need the raw bytes, and
    /// including them inflates per-scan JSON size noticeably.
    pub include_ocsp_raw: bool,
    /// Canonical names of signature-algorithm policy probes the
    /// operator explicitly skipped (`--sigalg-probe-skip=...`).
    /// Recognized: `"sha256_plus_only"`, `"ecdsa_only"`,
    /// `"rsa_pss_only"`, `"rsa_pkcs1_only"`. Unknown entries are
    /// ignored.
    pub sigalg_probe_skip: Vec<String>,
    /// Fire active revocation fetches — CRL downloads and
    /// OCSP-over-HTTP fallback. Default `false`; when `true`, the
    /// scanner issues HTTP GETs to `crl_distribution_points.urls`
    /// and HTTP POSTs to `authority_information_access.ocsp`.
    /// Even when this flag is on, individual fetches respect
    /// per-URL timeouts (10s) and body-size caps.
    pub enable_revocation_fetch: bool,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            concurrency: 10,
            per_target_delay: Duration::from_millis(100),
            connect_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(15),
            total_timeout: Duration::from_secs(60),
            retries: 2,
            tls_version_filter: None,
            ipv4_only: false,
            ipv6_only: false,
            enabled_features: Vec::new(),
            config_paths: Vec::new(),
            enable_http_checks: false,
            user_agent_info_url: "https://www.kemist-tls.net".to_string(),
            include_ocsp_raw: false,
            sigalg_probe_skip: Vec::new(),
            enable_revocation_fetch: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Scanner {
    config: Arc<ScannerConfig>,
}

impl Scanner {
    pub fn new(config: ScannerConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    pub fn config(&self) -> &ScannerConfig {
        &self.config
    }

    /// Scan a single target. Always returns a schema-v1 `ScanResult`, even
    /// when every probe failed — partial data lives alongside
    /// accumulated errors in the `errors` array.
    pub async fn scan(&self, target: Target) -> ScanResult {
        let started_at = Utc::now();

        // Resolve DNS up front. On failure, emit an otherwise-empty record
        // with a `dns_resolution_failed` error so consumers see which target
        // couldn't be probed.
        let (resolved_ip, socket_addr) = match self.resolve(&target).await {
            Ok(v) => (Some(v.0.to_string()), Some(v.1)),
            Err(e) => {
                let completed_at = Utc::now();
                return self.build_dns_failure_record(&target, started_at, completed_at, e);
            }
        };

        // Internal scan with retry loop.
        let probe_results = self.run_with_retries(&target, socket_addr.unwrap()).await;
        let completed_at = Utc::now();

        let ctx = JsonEmitContext {
            host: target.host.clone(),
            port: target.port,
            sni_sent: target.sni().to_string(),
            resolved_ip,
            started_at,
            completed_at,
            enabled_features: self.config.enabled_features.clone(),
            config_paths: self.config.config_paths.clone(),
            include_ocsp_raw: self.config.include_ocsp_raw,
        };
        build_scan_result(&probe_results, &ctx)
    }

    /// Scan many targets concurrently, bounded by `config.concurrency`.
    /// Output order matches iteration order of the unordered stream —
    /// callers that need deterministic ordering should sort by
    /// `scan.target` or `scan.started_at` downstream.
    pub async fn scan_many(&self, targets: Vec<Target>) -> Vec<ScanResult> {
        let sem = Arc::new(Semaphore::new(self.config.concurrency.max(1)));
        let this = self.clone();

        stream::iter(targets)
            .map(move |target| {
                let sem = sem.clone();
                let this = this.clone();
                async move {
                    let _permit = sem.acquire_owned().await.expect("semaphore closed");
                    this.scan(target).await
                }
            })
            .buffer_unordered(self.config.concurrency.max(1))
            .collect()
            .await
    }

    async fn resolve(&self, target: &Target) -> Result<(IpAddr, SocketAddr), ScannerError> {
        // Parse as IP literal first — common enough to shortcut DNS.
        if let Ok(ip) = target.host.parse::<IpAddr>() {
            return Ok((ip, SocketAddr::new(ip, target.port)));
        }

        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .map_err(|e| ScannerError::dns_resolution_failed(format!("resolver init: {e}")))?;

        let response = resolver
            .lookup_ip(target.host.as_str())
            .await
            .map_err(|e| {
                ScannerError::dns_resolution_failed(format!("lookup {}: {e}", target.host))
            })?;

        let ips: Vec<IpAddr> = response.iter().collect();

        let ip = if self.config.ipv4_only {
            ips.into_iter().find(|ip| ip.is_ipv4()).ok_or_else(|| {
                ScannerError::dns_resolution_failed(format!("no IPv4 for {}", target.host))
            })?
        } else if self.config.ipv6_only {
            ips.into_iter().find(|ip| ip.is_ipv6()).ok_or_else(|| {
                ScannerError::dns_resolution_failed(format!("no IPv6 for {}", target.host))
            })?
        } else {
            ips.into_iter().next().ok_or_else(|| {
                ScannerError::dns_resolution_failed(format!("no A/AAAA for {}", target.host))
            })?
        };

        Ok((ip, SocketAddr::new(ip, target.port)))
    }

    async fn run_with_retries(
        &self,
        target: &Target,
        addr: SocketAddr,
    ) -> crate::scanner::ScanResults {
        let max_attempts = self.config.retries.saturating_add(1);
        let mut last_result: Option<crate::scanner::ScanResults> = None;

        let scan_fut = async {
            for attempt in 1..=max_attempts {
                let cfg = ScanConfig {
                    target: addr,
                    hostname: target.sni().to_string(),
                    timeout: self.config.handshake_timeout,
                    _show_certificate: false,
                    _show_failed: false,
                    no_ciphersuites: false,
                    tls_version: self.config.tls_version_filter,
                    per_target_delay: self.config.per_target_delay,
                    enable_http_checks: self.config.enable_http_checks,
                    user_agent_info_url: self.config.user_agent_info_url.clone(),
                    sigalg_probe_skip: self.config.sigalg_probe_skip.clone(),
                    enable_revocation_fetch: self.config.enable_revocation_fetch,
                };

                info!(
                    "scan attempt {}/{} for {}",
                    attempt,
                    max_attempts,
                    target.display()
                );

                let results = SslScanner::new(cfg).scan().await;

                // If this pass had zero useful data AND only transient
                // errors, it's worth retrying. Otherwise accept and return.
                let only_transient = !results.scan_errors.is_empty()
                    && results.scan_errors.iter().all(|e| e.is_transient());
                let no_data = results.protocol_support.is_empty()
                    && results.certificate_chain.is_empty()
                    && results.cipher_probes.is_none();

                if attempt < max_attempts && only_transient && no_data {
                    let backoff =
                        Duration::from_secs(2u64.saturating_pow(attempt.saturating_sub(1)));
                    warn!(
                        "transient failure on attempt {}/{}, retrying after {:?}",
                        attempt, max_attempts, backoff
                    );
                    last_result = Some(results);
                    tokio::time::sleep(backoff).await;
                    continue;
                }

                return results;
            }
            last_result.expect("loop guarantees at least one result or return")
        };

        // Hard cap on per-target wall-clock time, including retries.
        match tokio::time::timeout(self.config.total_timeout, scan_fut).await {
            Ok(results) => results,
            Err(_) => {
                // Return a shell ScanResults with a total_timeout error so
                // the output record stays schema-valid.
                let mut shell = empty_scan_results(target, addr);
                shell
                    .scan_errors
                    .push(ScannerError::handshake_timeout(format!(
                        "total_timeout {:?} elapsed for {}",
                        self.config.total_timeout,
                        target.display()
                    )));
                shell
            }
        }
    }

    fn build_dns_failure_record(
        &self,
        target: &Target,
        started_at: chrono::DateTime<Utc>,
        completed_at: chrono::DateTime<Utc>,
        err: ScannerError,
    ) -> ScanResult {
        let mut probe_results = empty_scan_results(
            target,
            // Sentinel address — DNS failed, no real socket to report.
            SocketAddr::from(([0, 0, 0, 0], target.port)),
        );
        probe_results.scan_errors.push(err);

        let ctx = JsonEmitContext {
            host: target.host.clone(),
            port: target.port,
            sni_sent: target.sni().to_string(),
            resolved_ip: None,
            started_at,
            completed_at,
            enabled_features: self.config.enabled_features.clone(),
            config_paths: self.config.config_paths.clone(),
            include_ocsp_raw: self.config.include_ocsp_raw,
        };
        build_scan_result(&probe_results, &ctx)
    }
}

fn empty_scan_results(target: &Target, addr: SocketAddr) -> crate::scanner::ScanResults {
    crate::scanner::ScanResults {
        target: addr.to_string(),
        hostname: target.sni().to_string(),
        port: target.port,
        scan_time: Utc::now(),
        protocol_support: vec![],
        certificate_chain: vec![],
        tls_renegotiation: crate::scanner::TlsRenegotiation {
            secure_renegotiation: None,
            compression_supported: None,
        },
        heartbeat_echoes_oversized_payload: None,
        negotiated: None,
        alpn_offered: vec![],
        validation: crate::scanner::probe::ValidationResult::default(),
        cipher_probes: None,
        group_probes: None,
        sni_behavior: None,
        hello_observed: None,
        hrr_observed: None,
        sslv2_observation: None,
        alpn_matrix: None,
        #[cfg(all(feature = "http-checks", feature = "legacy-probes"))]
        ocsp_http_fetch: None,
        cert_chain_der: Vec::new(),
        http_observations: None,
        #[cfg(feature = "legacy-probes")]
        openssl_observations: None,
        scan_errors: vec![],
    }
}
