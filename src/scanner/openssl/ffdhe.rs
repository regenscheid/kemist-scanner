//! Phase D4 — RFC 7919 FFDHE named-group probing for TLS 1.2 and TLS 1.3.
//!
//! aws-lc-rs does not implement FFDHE key-exchange arithmetic, so
//! [`crate::scanner::groups`] cannot probe these codepoints — this module
//! owns them. OpenSSL 3.x ships FFDHE natively; `set_groups_list("ffdhe2048")`
//! drives the probe.
//!
//! Two axes per group:
//! - TLS 1.2 — advertise the codepoint in `supported_groups` + a
//!   DHE-only cipher list, so the server can only succeed by using the
//!   requested group.
//! - TLS 1.3 — advertise the codepoint in both `supported_groups` and
//!   `key_share`, with the protocol pinned to TLS 1.3.
//!
//! Cross-check with Phase D2 (`dh_params`): after a successful TLS 1.2
//! handshake, the observed prime's SHA-256 must match the advertised
//! codepoint. Servers that complete a DHE handshake but return a
//! *custom* prime have ignored `supported_groups` — a misconfiguration
//! finding that we surface via the [`FfdheOutcome::IgnoredGroupReturnedCustomPrime`]
//! variant. Size-alone checks on the prime can pass while this finding
//! still holds.

use std::net::SocketAddr;
use std::time::Duration;

use openssl::ssl::{HandshakeError, Ssl, SslContext, SslMethod, SslVerifyMode, SslVersion};
use tracing::{debug, info};

use crate::model::errors::ScannerError;
use crate::scanner::openssl::alerts;
use crate::scanner::openssl::dh_params::{self, DhClassification};

/// Outcome of a single FFDHE probe at one protocol version.
///
/// Richer than [`crate::scanner::groups::GroupProbeOutcome`] — adds the
/// `IgnoredGroupReturnedCustomPrime` variant for the case where the server
/// completes a DHE handshake but with a prime that doesn't match the
/// advertised FFDHE codepoint.
#[derive(Debug, Clone)]
pub enum FfdheOutcome {
    /// Server honored the group offer — handshake completed with this
    /// FFDHE group, verified via the D2 cross-check.
    Supported,
    /// Server rejected the single-group offer (handshake alert or reset).
    NotSupported,
    /// Server completed a DHE handshake but returned a prime that doesn't
    /// match the advertised codepoint. The server ignored
    /// `supported_groups` — a misconfiguration finding that size checks
    /// alone miss.
    IgnoredGroupReturnedCustomPrime,
    /// Probe itself failed (TCP timeout, unexpected error).
    Error(String),
    /// Probe not attempted — usually a build-time or provider limitation.
    NotProbed(String),
}

/// Per-group probe result across TLS 1.2 and TLS 1.3.
#[derive(Debug, Clone)]
pub struct FfdheProbeResult {
    pub group_name: String,
    pub iana_code: u16,
    pub tls12_outcome: FfdheOutcome,
    pub tls13_outcome: FfdheOutcome,
}

/// Aggregate output of the D4 probe pass.
#[derive(Debug, Clone, Default)]
pub struct FfdheProbeOutput {
    pub results: Vec<FfdheProbeResult>,
}

/// Static target-list row. Each FFDHE group appears once; probed at both
/// TLS 1.2 and TLS 1.3.
struct FfdheTarget {
    name: &'static str,
    iana_code: u16,
    expected_classification: DhClassification,
}

const TARGETS: &[FfdheTarget] = &[
    FfdheTarget {
        name: "ffdhe2048",
        iana_code: 0x0100,
        expected_classification: DhClassification::Ffdhe2048,
    },
    FfdheTarget {
        name: "ffdhe3072",
        iana_code: 0x0101,
        expected_classification: DhClassification::Ffdhe3072,
    },
    FfdheTarget {
        name: "ffdhe4096",
        iana_code: 0x0102,
        expected_classification: DhClassification::Ffdhe4096,
    },
    FfdheTarget {
        name: "ffdhe6144",
        iana_code: 0x0103,
        expected_classification: DhClassification::Ffdhe6144,
    },
    FfdheTarget {
        name: "ffdhe8192",
        iana_code: 0x0104,
        expected_classification: DhClassification::Ffdhe8192,
    },
];

/// Probe every FFDHE group at both TLS 1.2 and TLS 1.3. Each attempt runs
/// in `spawn_blocking` so the blocking OpenSSL handshake cooperates with
/// the tokio runtime. Honors `per_probe_delay` between attempts.
pub async fn probe_ffdhe_groups(
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    per_probe_delay: Duration,
) -> FfdheProbeOutput {
    info!(
        "OpenSSL FFDHE group probe: {} groups across TLS 1.2 and TLS 1.3",
        TARGETS.len()
    );

    let mut results = Vec::with_capacity(TARGETS.len());
    // 2 attempts per group (TLS 1.2, TLS 1.3); delay applies between all
    // of them (except the last one).
    let total_attempts = TARGETS.len() * 2;
    let mut attempt_idx: usize = 0;

    for t in TARGETS {
        let tls12_outcome = run_attempt(
            target,
            hostname,
            t,
            SslVersion::TLS1_2,
            connect_timeout,
            handshake_timeout,
        )
        .await;
        attempt_idx += 1;
        if attempt_idx < total_attempts && !per_probe_delay.is_zero() {
            tokio::time::sleep(per_probe_delay).await;
        }

        let tls13_outcome = run_attempt(
            target,
            hostname,
            t,
            SslVersion::TLS1_3,
            connect_timeout,
            handshake_timeout,
        )
        .await;
        attempt_idx += 1;
        if attempt_idx < total_attempts && !per_probe_delay.is_zero() {
            tokio::time::sleep(per_probe_delay).await;
        }

        debug!(
            group = t.name,
            tls12 = ?tls12_outcome,
            tls13 = ?tls13_outcome,
            "ffdhe probe result"
        );

        results.push(FfdheProbeResult {
            group_name: t.name.to_string(),
            iana_code: t.iana_code,
            tls12_outcome,
            tls13_outcome,
        });
    }

    FfdheProbeOutput { results }
}

async fn run_attempt(
    target: SocketAddr,
    hostname: &str,
    t: &'static FfdheTarget,
    version: SslVersion,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> FfdheOutcome {
    let hostname_owned = hostname.to_string();
    tokio::task::spawn_blocking(move || {
        probe_blocking(
            target,
            &hostname_owned,
            t,
            version,
            connect_timeout,
            handshake_timeout,
        )
    })
    .await
    .unwrap_or_else(|join_err| FfdheOutcome::Error(format!("spawn_blocking_panic: {join_err}")))
}

fn probe_blocking(
    target: SocketAddr,
    hostname: &str,
    t: &FfdheTarget,
    version: SslVersion,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> FfdheOutcome {
    let tcp = match std::net::TcpStream::connect_timeout(&target, connect_timeout) {
        Ok(s) => s,
        Err(e) => {
            let se = ScannerError::from_io("ffdhe tcp connect", e);
            return classify_scanner_error(se);
        }
    };
    let _ = tcp.set_read_timeout(Some(handshake_timeout));
    let _ = tcp.set_write_timeout(Some(handshake_timeout));

    let ctx = match build_ffdhe_context(version, t.name) {
        Ok(c) => c,
        Err(stack) => {
            return FfdheOutcome::Error(format!("openssl_ctx_build: {stack}"));
        }
    };

    let mut ssl = match Ssl::new(&ctx) {
        Ok(s) => s,
        Err(stack) => return FfdheOutcome::Error(format!("openssl_ssl_new: {stack}")),
    };
    let _ = ssl.set_hostname(hostname);

    match ssl.connect(tcp) {
        Ok(stream) => {
            // Cross-check: was the prime we got actually the FFDHE we
            // asked for? If not, the server ignored supported_groups.
            match dh_params::snapshot(stream.ssl()) {
                Ok(Some(snap)) if snap.classification == t.expected_classification => {
                    FfdheOutcome::Supported
                }
                Ok(Some(_)) => FfdheOutcome::IgnoredGroupReturnedCustomPrime,
                Ok(None) => {
                    // Success without a DH tmp key is weird — the cipher
                    // list filter should have forced DHE (TLS 1.2) or the
                    // groups list should have driven key_share (TLS 1.3).
                    // Surface as Error so the anomaly is visible.
                    FfdheOutcome::Error("handshake_success_but_no_dh_tmp_key".to_string())
                }
                Err(stack) => FfdheOutcome::Error(format!("dh_snapshot_error: {stack}")),
            }
        }
        Err(HandshakeError::Failure(mid)) => {
            let se = alerts::classify_openssl_error("ffdhe handshake", mid.error());
            classify_scanner_error(se)
        }
        Err(HandshakeError::SetupFailure(stack)) => {
            FfdheOutcome::Error(format!("openssl_setup: {stack}"))
        }
        Err(HandshakeError::WouldBlock(_)) => {
            FfdheOutcome::Error("openssl_would_block".to_string())
        }
    }
}

fn build_ffdhe_context(
    version: SslVersion,
    group_name: &str,
) -> Result<SslContext, openssl::error::ErrorStack> {
    let mut builder = SslContext::builder(SslMethod::tls_client())?;
    builder.set_min_proto_version(Some(version))?;
    builder.set_max_proto_version(Some(version))?;
    builder.set_security_level(0);
    builder.set_verify(SslVerifyMode::NONE);
    // `supported_groups` + (for TLS 1.3) `key_share` advertisement.
    builder.set_groups_list(group_name)?;
    // TLS 1.2 needs the cipher list constrained to DHE so the server
    // can only succeed by using the offered FFDHE group. TLS 1.3 uses
    // separate ciphersuites so the default list is fine.
    if version == SslVersion::TLS1_2 {
        builder.set_cipher_list("DHE:@SECLEVEL=0")?;
    }
    Ok(builder.build())
}

fn classify_scanner_error(e: ScannerError) -> FfdheOutcome {
    if e.category.starts_with("tls_alert_") || e.category == "connection_refused" {
        FfdheOutcome::NotSupported
    } else {
        FfdheOutcome::Error(e.category)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_table_covers_all_five_rfc7919_codepoints() {
        let codepoints: Vec<u16> = TARGETS.iter().map(|t| t.iana_code).collect();
        assert_eq!(codepoints, vec![0x0100, 0x0101, 0x0102, 0x0103, 0x0104]);
    }

    #[test]
    fn target_names_match_schema_strings() {
        for t in TARGETS {
            assert_eq!(t.name, t.expected_classification.as_schema_str());
        }
    }

    #[test]
    fn target_classifications_are_distinct() {
        // Guard against copy-paste accidents where two rows share the
        // same expected classification.
        use std::collections::HashSet;
        let set: HashSet<&'static str> = TARGETS
            .iter()
            .map(|t| t.expected_classification.as_schema_str())
            .collect();
        assert_eq!(set.len(), TARGETS.len());
    }

    #[test]
    fn classify_scanner_error_promotes_alerts_to_not_supported() {
        // Alerts from server → NotSupported, same discipline as D1.
        let alert = ScannerError::tls_alert("handshake_failure", "ctx");
        assert!(matches!(
            classify_scanner_error(alert),
            FfdheOutcome::NotSupported
        ));

        let refused = ScannerError::connection_refused("ctx");
        assert!(matches!(
            classify_scanner_error(refused),
            FfdheOutcome::NotSupported
        ));
    }

    #[test]
    fn classify_scanner_error_preserves_other_categories_as_error() {
        let timeout = ScannerError::connection_timeout("ctx");
        match classify_scanner_error(timeout) {
            FfdheOutcome::Error(cat) => assert_eq!(cat, "connection_timeout"),
            other => panic!("expected Error, got {other:?}"),
        }
    }
}
