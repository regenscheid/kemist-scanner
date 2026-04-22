//! OpenSSL 3.5 backend.
//!
//! Houses the `OpensslBackend` implementation of `TlsBackend`, alert
//! classification, DH parameter / SKE signature observers, and the
//! post-handshake action modules (renegotiation, session resumption,
//! CertificateRequest capture, TLS 1.3 EncryptedExtensions capture).
//!
//! Stage 4c consolidated these under one tree; the remaining
//! entry-point probe drivers (cipher / group / version / FALLBACK_SCSV /
//! sigalg_policy) still live in `src/scanner/openssl/` pending Stage 4d
//! inlining into the orchestrator.
//!
//! Supported `handshake()` constraint shapes:
//! - `single_cipher_at(code, version)` — pinned suite + pinned version
//! - `single_group_at(code, version)` — pinned named group + pinned version
//! - `version_only(v)` — one pinned TLS version
//! - `sigalgs: Some(codepoints)` + `version_range` — sigalg-pinned handshake
//! - `send_fallback_scsv: true` + `version_range` — SCSV downgrade probe
//! - Wide `version_range` with no cipher/group pin — characterization

pub mod alerts;
pub mod client_auth;
pub mod dh_params;
pub mod renegotiation;
pub mod ske_sig;
pub mod tickets;
pub mod tls13_extensions;

use async_trait::async_trait;

use crate::model::protocol::{ProtocolSupport, TlsVersion};
use crate::scanner::backends::{
    openssl_inventory, BackendInventory, ConstraintCapabilities, HandshakeConstraint,
    HandshakeOutcome, HandshakeResult, ProbeContext, TlsBackend, UnsatisfiableConstraint,
};
use crate::scanner::probe::NegotiatedState;

pub struct OpensslBackend {
    inventory: BackendInventory,
}

impl OpensslBackend {
    pub fn new() -> Self {
        Self {
            inventory: openssl_inventory(),
        }
    }
}

impl Default for OpensslBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TlsBackend for OpensslBackend {
    fn id(&self) -> &'static str {
        "openssl"
    }

    fn inventory(&self) -> &BackendInventory {
        &self.inventory
    }

    fn constraint_capabilities(&self) -> ConstraintCapabilities {
        // `sigalgs` and `send_fallback_scsv` are advertised as supported
        // because the OpenSSL library plumbing is there; Stage 2's
        // `handshake()` dispatch returns `UnsatisfiableConstraint` for
        // those shapes until Stage 3 wires them up, but callers can
        // still check capabilities to pick the right backend.
        ConstraintCapabilities {
            version_range: true,
            cipher_suites: true,
            groups: true,
            sigalgs: true,
            alpn: false,
            send_fallback_scsv: true,
            seclevel_zero: true,
        }
    }

    async fn handshake(
        &self,
        c: HandshakeConstraint,
        ctx: &ProbeContext,
    ) -> Result<HandshakeResult, UnsatisfiableConstraint> {
        if c.alpn.is_some() {
            return Err(UnsatisfiableConstraint::new(
                "openssl_backend_alpn_not_implemented",
            ));
        }

        // Sigalgs-pinned handshake. The sigalg_policy probes drive four
        // known codepoint sets; this branch maps them to the canonical
        // OpenSSL sigalgs strings and wraps `sigalg_policy::probe_blocking`.
        if let Some(codepoints) = &c.sigalgs {
            let Some(openssl_string) = iana_sigalgs_to_openssl_string(codepoints) else {
                return Err(UnsatisfiableConstraint::new(
                    "openssl_backend_sigalgs_codepoint_set_unknown",
                ));
            };
            let hostname_owned = ctx.hostname.clone();
            let target = ctx.target;
            let connect_timeout = ctx.connect_timeout;
            let handshake_timeout = ctx.handshake_timeout;
            let probe = tokio::task::spawn_blocking(move || {
                crate::scanner::openssl::sigalg_policy::probe_blocking(
                    openssl_string,
                    target,
                    &hostname_owned,
                    connect_timeout,
                    handshake_timeout,
                )
            })
            .await
            .unwrap_or_else(|e| {
                use crate::model::scan_result::{ConstrainedProbeResult, Method, SigalgOutcome};
                ConstrainedProbeResult {
                    outcome: SigalgOutcome::NotProbed,
                    method: Method::Error,
                    reason: Some(format!("spawn_blocking_panic:{e}")),
                    ..Default::default()
                }
            });
            return Ok(sigalg_constrained_to_handshake_result(probe));
        }
        // `seclevel_zero` is always applied to the OpenSSL probes
        // already (`set_security_level(0)` is baked into the context
        // builders). Accepting the flag explicitly is fine — ignoring
        // it matches current behavior.

        // FALLBACK_SCSV downgrade probe. Expects `version_range` pinned
        // to the downgrade target in `max`. Wraps the existing
        // `fallback_scsv::probe_scsv_blocking` helper.
        if c.send_fallback_scsv {
            let Some((_, v_max)) = c.version_range else {
                return Err(UnsatisfiableConstraint::new(
                    "openssl_backend_scsv_requires_version_range",
                ));
            };
            let Some(downgrade_target) = tls_to_ssl_version(v_max) else {
                return Err(UnsatisfiableConstraint::new(format!(
                    "openssl_backend_scsv_version_out_of_scope:{:?}",
                    v_max
                )));
            };
            let hostname_owned = ctx.hostname.clone();
            let target = ctx.target;
            let connect_timeout = ctx.connect_timeout;
            let handshake_timeout = ctx.handshake_timeout;
            let probe = tokio::task::spawn_blocking(move || {
                crate::scanner::openssl::fallback_scsv::probe_scsv_blocking(
                    target,
                    &hostname_owned,
                    downgrade_target,
                    connect_timeout,
                    handshake_timeout,
                )
            })
            .await
            .unwrap_or_else(|e| {
                crate::scanner::openssl::fallback_scsv::ProbeOutcome::Error(format!(
                    "spawn_blocking_panic: {e}"
                ))
            });
            return Ok(scsv_outcome_to_handshake_result(probe));
        }

        // Characterization: wide version range, no cipher/group pin —
        // let the server pick its max supported protocol. Wraps the
        // existing `fallback_scsv::characterize_max_version_blocking`
        // so the returned `HandshakeResult.negotiated.version` carries
        // the server's choice.
        if c.cipher_suites.is_none()
            && c.groups.is_none()
            && matches!(c.version_range, Some((v_min, v_max)) if v_min != v_max)
        {
            let hostname_owned = ctx.hostname.clone();
            let target = ctx.target;
            let connect_timeout = ctx.connect_timeout;
            let handshake_timeout = ctx.handshake_timeout;
            let negotiated_ssl = tokio::task::spawn_blocking(move || {
                crate::scanner::openssl::fallback_scsv::characterize_max_version_blocking(
                    target,
                    &hostname_owned,
                    connect_timeout,
                    handshake_timeout,
                )
            })
            .await
            .unwrap_or(None);
            let result = match negotiated_ssl {
                Some(v) => {
                    let mut r = HandshakeResult::outcome_only(HandshakeOutcome::Supported);
                    r.negotiated = Some(NegotiatedState {
                        version: ssl_to_tls_version(v),
                        ..Default::default()
                    });
                    r
                }
                None => HandshakeResult::outcome_only(HandshakeOutcome::Error(
                    "characterization_handshake_failed".to_string(),
                )),
            };
            return Ok(result);
        }

        match (&c.cipher_suites, &c.groups, c.version_range) {
            (Some(suites), None, Some((v_min, v_max)))
                if suites.len() == 1 && v_min == v_max =>
            {
                let run = crate::scanner::openssl::ciphers::probe_single_by_code(
                    ctx.target,
                    &ctx.hostname,
                    suites[0],
                    v_min,
                    ctx.connect_timeout,
                    ctx.handshake_timeout,
                )
                .await;
                let mut result = HandshakeResult::outcome_only(run.outcome);
                result.dh_parameters = run.dh_snapshot;
                result.ske_signature_name = run.ske_sig;
                Ok(result)
            }
            (None, Some(groups), Some((v_min, v_max)))
                if groups.len() == 1 && v_min == v_max =>
            {
                let outcome = crate::scanner::openssl::kx_groups::probe_single_group_by_code(
                    ctx.target,
                    &ctx.hostname,
                    groups[0],
                    v_min,
                    ctx.connect_timeout,
                    ctx.handshake_timeout,
                )
                .await;
                Ok(HandshakeResult::outcome_only(outcome))
            }
            (None, None, Some((v_min, v_max))) if v_min == v_max => {
                let ps = crate::scanner::openssl::protocol_versions::probe_protocol(
                    ctx.target,
                    &ctx.hostname,
                    v_min,
                    ctx.connect_timeout,
                    ctx.handshake_timeout,
                )
                .await;
                Ok(HandshakeResult::outcome_only(protocol_support_to_outcome(ps)))
            }
            _ => Err(UnsatisfiableConstraint::new(
                "openssl_backend_constraint_shape_not_implemented_yet",
            )),
        }
    }
}

/// Convert a `TlsVersion` to the OpenSSL `SslVersion` enum. Covers
/// the versions probe_scsv and the characterization helper accept;
/// returns `None` for SSLv2 (not representable in OpenSSL 3.x).
pub(crate) fn tls_to_ssl_version(v: TlsVersion) -> Option<openssl::ssl::SslVersion> {
    use openssl::ssl::SslVersion;
    match v {
        TlsVersion::Ssl3 => Some(SslVersion::SSL3),
        TlsVersion::Tls10 => Some(SslVersion::TLS1),
        TlsVersion::Tls11 => Some(SslVersion::TLS1_1),
        TlsVersion::Tls12 => Some(SslVersion::TLS1_2),
        TlsVersion::Tls13 => Some(SslVersion::TLS1_3),
        TlsVersion::Ssl2 => None,
    }
}

/// Reverse mapping: OpenSSL's `SslVersion::version2()` result back into
/// the scanner's `TlsVersion`. `None` for values OpenSSL exposes but
/// the scanner doesn't model (e.g. DTLS versions).
pub(crate) fn ssl_to_tls_version(v: openssl::ssl::SslVersion) -> Option<TlsVersion> {
    use openssl::ssl::SslVersion;
    if v == SslVersion::TLS1_3 {
        Some(TlsVersion::Tls13)
    } else if v == SslVersion::TLS1_2 {
        Some(TlsVersion::Tls12)
    } else if v == SslVersion::TLS1_1 {
        Some(TlsVersion::Tls11)
    } else if v == SslVersion::TLS1 {
        Some(TlsVersion::Tls10)
    } else if v == SslVersion::SSL3 {
        Some(TlsVersion::Ssl3)
    } else {
        None
    }
}

/// Map the four sigalg-policy IANA codepoint sets to the canonical
/// OpenSSL sigalgs-list strings. OpenSSL's `SSL_CTX_set1_sigalgs_list`
/// uses a custom string format (e.g. `"RSA-PSS+SHA256:ECDSA+SHA256"`)
/// that doesn't accept raw IANA codepoints, so this helper recognizes
/// the four sets `sigalg_policy` drives and translates. Unknown sets
/// surface as `UnsatisfiableConstraint` — adding new sigalg families
/// is a deliberate update rather than a silent mismatch.
fn iana_sigalgs_to_openssl_string(codepoints: &[u16]) -> Option<&'static str> {
    use std::collections::HashSet;
    let set: HashSet<u16> = codepoints.iter().copied().collect();

    // sha256_plus_only — RSA-PSS, RSA-PKCS1, ECDSA, all with SHA-256+.
    let sha256_plus: HashSet<u16> = [0x0401, 0x0501, 0x0601, 0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806]
        .into_iter()
        .collect();
    let ecdsa_only: HashSet<u16> = [0x0403, 0x0503, 0x0603].into_iter().collect();
    let rsa_pss_only: HashSet<u16> = [0x0804, 0x0805, 0x0806].into_iter().collect();
    let rsa_pkcs1_only: HashSet<u16> = [0x0401, 0x0501, 0x0601].into_iter().collect();

    if set == sha256_plus {
        Some(concat!(
            "RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:",
            "RSA+SHA256:RSA+SHA384:RSA+SHA512:",
            "ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512"
        ))
    } else if set == ecdsa_only {
        Some("ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512")
    } else if set == rsa_pss_only {
        Some("RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512")
    } else if set == rsa_pkcs1_only {
        Some("RSA+SHA256:RSA+SHA384:RSA+SHA512")
    } else {
        None
    }
}

/// Fold the rich `ConstrainedProbeResult` produced by
/// `sigalg_policy::probe_blocking` into a `HandshakeResult`. The
/// `outcome` axis maps straightforwardly; the method-vs-probe
/// distinction the old code carried in `method` / `reason` is
/// preserved through specific Error-string prefixes that the composer
/// pattern-matches to recover the original method. Schema-visible
/// fields (`selected_sigalg`, `alert`) round-trip losslessly.
fn sigalg_constrained_to_handshake_result(
    r: crate::model::scan_result::ConstrainedProbeResult,
) -> HandshakeResult {
    use crate::model::scan_result::{Method, SigalgOutcome};
    let outcome = match (&r.outcome, &r.method) {
        (SigalgOutcome::HandshakeComplete, _) => HandshakeOutcome::Supported,
        (SigalgOutcome::HandshakeFailure, _) | (SigalgOutcome::OtherAlert, _) => {
            HandshakeOutcome::NotSupported
        }
        // Wire-level failures (tcp_connect etc.) and probe-setup failures
        // both fold into Error here. The composer uses `method` + the
        // reason string's prefix to recover which kind it was.
        (SigalgOutcome::ConnectionClosed, _) | (SigalgOutcome::NotProbed, Method::Probe) => {
            HandshakeOutcome::Error(r.reason.clone().unwrap_or_default())
        }
        (SigalgOutcome::NotProbed, _) => {
            // Setup failures marked as NotProbed + Error. Tag the Error
            // message with a `setup:` prefix so the composer can
            // distinguish from wire-level failures.
            HandshakeOutcome::Error(format!(
                "setup:{}",
                r.reason.clone().unwrap_or_default()
            ))
        }
    };
    let mut hr = HandshakeResult::outcome_only(outcome);
    hr.alert = r.alert;
    hr.ske_signature_name = r.selected_sigalg;
    hr
}

/// Fold an SCSV `ProbeOutcome` into a `HandshakeResult`. The composer
/// on the orchestrator side reads `outcome` + `alert` to classify
/// SCSV enforcement — `HandshakeAccepted` means the server honored a
/// downgrade offer, each alert variant carries the server's rejection
/// category in `alert`.
fn scsv_outcome_to_handshake_result(
    outcome: crate::scanner::openssl::fallback_scsv::ProbeOutcome,
) -> HandshakeResult {
    use crate::scanner::openssl::fallback_scsv::ProbeOutcome;
    let mut result = HandshakeResult::outcome_only(match &outcome {
        ProbeOutcome::HandshakeAccepted => HandshakeOutcome::Supported,
        ProbeOutcome::Alert(_) => HandshakeOutcome::NotSupported,
        ProbeOutcome::Error(msg) => HandshakeOutcome::Error(msg.clone()),
    });
    if let ProbeOutcome::Alert(cat) = outcome {
        result.alert = Some(cat);
    }
    result
}

/// Map the `ProtocolSupport` shape used by existing version probes to
/// `HandshakeOutcome`. Supports the three-state outcome today:
/// `supported=true` → Supported, `supported=false` with a wire-level
/// alert error → NotSupported, anything else (transport, invalid SNI,
/// provider load failures) → Error.
fn protocol_support_to_outcome(ps: ProtocolSupport) -> HandshakeOutcome {
    if ps.supported {
        return HandshakeOutcome::Supported;
    }
    match ps.error {
        None => HandshakeOutcome::NotSupported,
        Some(err) => {
            // The OpenSSL version probe emits `tls_alert_*` /
            // `connection_refused` category strings directly in the
            // error field. Treat them as wire-level rejections to stay
            // consistent with the cipher/group probe classifiers.
            if err.starts_with("tls_alert_") || err == "connection_refused" {
                HandshakeOutcome::NotSupported
            } else {
                HandshakeOutcome::Error(err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::protocol::TlsVersion;

    #[test]
    fn id_is_stable() {
        assert_eq!(OpensslBackend::new().id(), "openssl");
    }

    #[test]
    fn constraint_caps_cover_axes_openssl_supports() {
        let caps = OpensslBackend::new().constraint_capabilities();
        assert!(caps.cipher_suites);
        assert!(caps.groups);
        assert!(caps.version_range);
        assert!(caps.sigalgs);
        assert!(caps.send_fallback_scsv);
        assert!(caps.seclevel_zero);
        // ALPN isn't currently plumbed through the OpenSSL probes.
        assert!(!caps.alpn);
    }

    #[test]
    fn protocol_support_to_outcome_maps_three_states() {
        let s = protocol_support_to_outcome(ProtocolSupport {
            version: TlsVersion::Tls12,
            supported: true,
            error: None,
        });
        assert!(matches!(s, HandshakeOutcome::Supported));

        let s = protocol_support_to_outcome(ProtocolSupport {
            version: TlsVersion::Tls10,
            supported: false,
            error: Some("tls_alert_protocol_version".to_string()),
        });
        assert!(matches!(s, HandshakeOutcome::NotSupported));

        let s = protocol_support_to_outcome(ProtocolSupport {
            version: TlsVersion::Tls12,
            supported: false,
            error: Some("handshake_timeout".to_string()),
        });
        assert!(matches!(s, HandshakeOutcome::Error(_)));
    }

    #[tokio::test]
    async fn handshake_rejects_alpn_constraint() {
        let be = OpensslBackend::new();
        let c = HandshakeConstraint {
            alpn: Some(vec![b"h2".to_vec()]),
            ..Default::default()
        };
        let ctx = ProbeContext {
            target: "127.0.0.1:1".parse().unwrap(),
            hostname: "example.test".to_string(),
            connect_timeout: std::time::Duration::from_millis(10),
            handshake_timeout: std::time::Duration::from_millis(10),
        };
        let err = be.handshake(c, &ctx).await.unwrap_err();
        assert_eq!(err.reason, "openssl_backend_alpn_not_implemented");
    }
}
