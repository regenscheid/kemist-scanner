//! OpenSSL-backed per-group key-exchange probing.
//!
//! Drives `SSL_CTX_set1_groups_list` against a vendored OpenSSL 3.5.5
//! LTS so kemist can probe named groups aws-lc-rs does not ship
//! (`X448`, `secp521r1`, standalone ML-KEM 512/1024,
//! `secp384r1MLKEM1024`) plus the five RFC 7919 FFDHE codepoints
//! aws-lc-rs has no implementation for at all.
//!
//! Two axes per group:
//! - TLS 1.2 — advertise the codepoint in `supported_groups` + a
//!   DHE-only cipher list, so the server can only succeed by using
//!   the requested group. Only meaningful for FFDHE; ECDH / ML-KEM
//!   rows record `NotProbed("tls12_not_applicable")`.
//! - TLS 1.3 — advertise the codepoint in both `supported_groups` and
//!   `key_share`, protocol pinned to TLS 1.3.
//!
//! FFDHE rows cross-check against [`super::dh_params`]: after a
//! successful TLS 1.2 handshake, the observed prime's SHA-256 must
//! match the advertised codepoint. Servers that complete a DHE
//! handshake with a *custom* prime ignored `supported_groups` — a
//! misconfiguration finding surfaced via the
//! [`KxGroupOutcome::IgnoredGroupReturnedCustomPrime`] variant. ECDH
//! and ML-KEM rows skip this cross-check (their key exchange
//! produces no modular prime).

use std::net::SocketAddr;
use std::time::Duration;

use openssl::ssl::{HandshakeError, Ssl, SslContext, SslMethod, SslVerifyMode, SslVersion};
use tracing::{debug, info};

use crate::model::errors::ScannerError;
use crate::scanner::openssl::alerts;
use crate::scanner::openssl::dh_params::{self, DhClassification};

/// Outcome of a single named-group probe at one protocol version.
#[derive(Debug, Clone)]
pub enum KxGroupOutcome {
    /// Server honored the group offer — handshake completed with this
    /// group. For FFDHE rows, also verified against the observed DH prime.
    Supported,
    /// Server rejected the single-group offer (handshake alert or reset).
    NotSupported,
    /// FFDHE-only: server completed a DHE handshake but returned a prime
    /// that doesn't match the advertised codepoint. Meaningless for
    /// ECDH / ML-KEM rows.
    IgnoredGroupReturnedCustomPrime,
    /// Probe itself failed (TCP timeout, unexpected error).
    Error(String),
    /// Probe not attempted — e.g. TLS 1.2 cell for a TLS-1.3-only group.
    NotProbed(String),
}

/// Per-group probe result across TLS 1.2 and TLS 1.3.
#[derive(Debug, Clone)]
pub struct KxGroupProbeResult {
    pub group_name: String,
    pub iana_code: u16,
    pub tls12_outcome: KxGroupOutcome,
    pub tls13_outcome: KxGroupOutcome,
}

/// Aggregate output of the named-group probe pass.
#[derive(Debug, Clone, Default)]
pub struct KxGroupProbeOutput {
    pub results: Vec<KxGroupProbeResult>,
}

/// Static target-list row.
struct KxGroupTarget {
    /// Name passed to `SSL_CTX_set1_groups_list`. Must be accepted by
    /// OpenSSL 3.5.
    openssl_name: &'static str,
    /// Spec-canonical name emitted into the schema. For most rows this
    /// equals `openssl_name`; for `secp521r1` we prefer the IANA name
    /// over OpenSSL's `"P-521"` alias.
    display_name: &'static str,
    /// IANA codepoint for the `iana_code` output field.
    iana_code: u16,
    /// True only for FFDHE rows (the only groups that ride on TLS 1.2
    /// DHE cipher suites). ECDH and ML-KEM probes run TLS 1.3 only.
    tls12_applicable: bool,
    /// `Some(classification)` only for FFDHE rows — drives the
    /// post-handshake DH-prime cross-check. `None` skips the check.
    ffdhe_cross_check: Option<DhClassification>,
}

const TARGETS: &[KxGroupTarget] = &[
    // RFC 7919 FFDHE — aws-lc-rs ships no implementation.
    KxGroupTarget {
        openssl_name: "ffdhe2048",
        display_name: "ffdhe2048",
        iana_code: 0x0100,
        tls12_applicable: true,
        ffdhe_cross_check: Some(DhClassification::Ffdhe2048),
    },
    KxGroupTarget {
        openssl_name: "ffdhe3072",
        display_name: "ffdhe3072",
        iana_code: 0x0101,
        tls12_applicable: true,
        ffdhe_cross_check: Some(DhClassification::Ffdhe3072),
    },
    KxGroupTarget {
        openssl_name: "ffdhe4096",
        display_name: "ffdhe4096",
        iana_code: 0x0102,
        tls12_applicable: true,
        ffdhe_cross_check: Some(DhClassification::Ffdhe4096),
    },
    KxGroupTarget {
        openssl_name: "ffdhe6144",
        display_name: "ffdhe6144",
        iana_code: 0x0103,
        tls12_applicable: true,
        ffdhe_cross_check: Some(DhClassification::Ffdhe6144),
    },
    KxGroupTarget {
        openssl_name: "ffdhe8192",
        display_name: "ffdhe8192",
        iana_code: 0x0104,
        tls12_applicable: true,
        ffdhe_cross_check: Some(DhClassification::Ffdhe8192),
    },
    // Groups OpenSSL 3.5 ships but aws-lc-rs does not.
    KxGroupTarget {
        openssl_name: "X448",
        display_name: "X448",
        iana_code: 0x001E,
        tls12_applicable: false,
        ffdhe_cross_check: None,
    },
    KxGroupTarget {
        openssl_name: "P-521",
        display_name: "secp521r1",
        iana_code: 0x0019,
        tls12_applicable: false,
        ffdhe_cross_check: None,
    },
    KxGroupTarget {
        openssl_name: "MLKEM512",
        display_name: "MLKEM512",
        iana_code: 0x0200,
        tls12_applicable: false,
        ffdhe_cross_check: None,
    },
    KxGroupTarget {
        openssl_name: "MLKEM1024",
        display_name: "MLKEM1024",
        iana_code: 0x0202,
        tls12_applicable: false,
        ffdhe_cross_check: None,
    },
    KxGroupTarget {
        openssl_name: "SecP384r1MLKEM1024",
        display_name: "secp384r1MLKEM1024",
        iana_code: 0x11ED,
        tls12_applicable: false,
        ffdhe_cross_check: None,
    },
];

/// Emit this backend's group inventory as `(iana_code, display_name)`
/// rows. Used by `scanner::backends::openssl_inventory` so the single
/// source of truth for "what named groups does the OpenSSL backend
/// probe" is this `TARGETS` table rather than a parallel list.
pub fn inventory_entries() -> Vec<(u16, &'static str)> {
    TARGETS
        .iter()
        .map(|t| (t.iana_code, t.display_name))
        .collect()
}

/// Probe every target group at TLS 1.2 (FFDHE only) and TLS 1.3. Each
/// attempt runs in `spawn_blocking` so the blocking OpenSSL handshake
/// cooperates with the tokio runtime. Honors `per_probe_delay` between
/// attempts.
pub async fn probe_kx_groups(
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    per_probe_delay: Duration,
) -> KxGroupProbeOutput {
    let total_attempts: usize = TARGETS
        .iter()
        .map(|t| if t.tls12_applicable { 2 } else { 1 })
        .sum();
    info!(
        "OpenSSL named-group probe: {} groups, {} total attempts",
        TARGETS.len(),
        total_attempts
    );

    let mut results = Vec::with_capacity(TARGETS.len());
    let mut attempt_idx: usize = 0;

    for t in TARGETS {
        let tls12_outcome = if t.tls12_applicable {
            let o = run_attempt(
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
            o
        } else {
            KxGroupOutcome::NotProbed("tls12_not_applicable".to_string())
        };

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
            group = t.display_name,
            tls12 = ?tls12_outcome,
            tls13 = ?tls13_outcome,
            "kx group probe result"
        );

        results.push(KxGroupProbeResult {
            group_name: t.display_name.to_string(),
            iana_code: t.iana_code,
            tls12_outcome,
            tls13_outcome,
        });
    }

    KxGroupProbeOutput { results }
}

async fn run_attempt(
    target: SocketAddr,
    hostname: &str,
    t: &'static KxGroupTarget,
    version: SslVersion,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> KxGroupOutcome {
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
    .unwrap_or_else(|join_err| KxGroupOutcome::Error(format!("spawn_blocking_panic: {join_err}")))
}

fn probe_blocking(
    target: SocketAddr,
    hostname: &str,
    t: &KxGroupTarget,
    version: SslVersion,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> KxGroupOutcome {
    let tcp = match std::net::TcpStream::connect_timeout(&target, connect_timeout) {
        Ok(s) => s,
        Err(e) => {
            let se = ScannerError::from_io("kx group tcp connect", e);
            return classify_scanner_error(se);
        }
    };
    let _ = tcp.set_read_timeout(Some(handshake_timeout));
    let _ = tcp.set_write_timeout(Some(handshake_timeout));

    let ctx = match build_context(version, t.openssl_name) {
        Ok(c) => c,
        Err(stack) => {
            return KxGroupOutcome::Error(format!("openssl_ctx_build: {stack}"));
        }
    };

    let mut ssl = match Ssl::new(&ctx) {
        Ok(s) => s,
        Err(stack) => return KxGroupOutcome::Error(format!("openssl_ssl_new: {stack}")),
    };
    let _ = ssl.set_hostname(hostname);

    match ssl.connect(tcp) {
        Ok(stream) => match t.ffdhe_cross_check {
            Some(expected) => match dh_params::snapshot(stream.ssl()) {
                Ok(Some(snap)) if snap.classification == expected => KxGroupOutcome::Supported,
                Ok(Some(_)) => KxGroupOutcome::IgnoredGroupReturnedCustomPrime,
                Ok(None) => {
                    KxGroupOutcome::Error("handshake_success_but_no_dh_tmp_key".to_string())
                }
                Err(stack) => KxGroupOutcome::Error(format!("dh_snapshot_error: {stack}")),
            },
            None => KxGroupOutcome::Supported,
        },
        Err(HandshakeError::Failure(mid)) => {
            let se = alerts::classify_openssl_error("kx group handshake", mid.error());
            classify_scanner_error(se)
        }
        Err(HandshakeError::SetupFailure(stack)) => {
            KxGroupOutcome::Error(format!("openssl_setup: {stack}"))
        }
        Err(HandshakeError::WouldBlock(_)) => {
            KxGroupOutcome::Error("openssl_would_block".to_string())
        }
    }
}

fn build_context(
    version: SslVersion,
    group_name: &str,
) -> Result<SslContext, openssl::error::ErrorStack> {
    let mut builder = SslContext::builder(SslMethod::tls_client())?;
    builder.set_min_proto_version(Some(version))?;
    builder.set_max_proto_version(Some(version))?;
    builder.set_security_level(0);
    builder.set_verify(SslVerifyMode::NONE);
    builder.set_groups_list(group_name)?;
    if version == SslVersion::TLS1_2 {
        builder.set_cipher_list("DHE:@SECLEVEL=0")?;
    }
    Ok(builder.build())
}

fn classify_scanner_error(e: ScannerError) -> KxGroupOutcome {
    if e.category.starts_with("tls_alert_") || e.category == "connection_refused" {
        KxGroupOutcome::NotSupported
    } else {
        KxGroupOutcome::Error(e.category)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_table_contains_all_ffdhe_codepoints() {
        let ffdhe: Vec<u16> = TARGETS
            .iter()
            .filter(|t| t.ffdhe_cross_check.is_some())
            .map(|t| t.iana_code)
            .collect();
        assert_eq!(ffdhe, vec![0x0100, 0x0101, 0x0102, 0x0103, 0x0104]);
    }

    #[test]
    fn ffdhe_targets_classification_matches_display_name() {
        for t in TARGETS {
            if let Some(cls) = t.ffdhe_cross_check {
                assert_eq!(t.display_name, cls.as_schema_str());
            }
        }
    }

    #[test]
    fn target_display_names_are_distinct() {
        use std::collections::HashSet;
        let set: HashSet<&'static str> = TARGETS.iter().map(|t| t.display_name).collect();
        assert_eq!(set.len(), TARGETS.len());
    }

    #[test]
    fn non_ffdhe_targets_are_tls13_only() {
        for t in TARGETS {
            if t.ffdhe_cross_check.is_none() {
                assert!(
                    !t.tls12_applicable,
                    "{} must not be TLS 1.2 applicable",
                    t.display_name
                );
            }
        }
    }

    #[test]
    fn classify_scanner_error_promotes_alerts_to_not_supported() {
        let alert = ScannerError::tls_alert("handshake_failure", "ctx");
        assert!(matches!(
            classify_scanner_error(alert),
            KxGroupOutcome::NotSupported
        ));

        let refused = ScannerError::connection_refused("ctx");
        assert!(matches!(
            classify_scanner_error(refused),
            KxGroupOutcome::NotSupported
        ));
    }

    #[test]
    fn classify_scanner_error_preserves_other_categories_as_error() {
        let timeout = ScannerError::connection_timeout("ctx");
        match classify_scanner_error(timeout) {
            KxGroupOutcome::Error(cat) => assert_eq!(cat, "connection_timeout"),
            other => panic!("expected Error, got {other:?}"),
        }
    }
}
