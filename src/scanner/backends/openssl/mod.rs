//! OpenSSL 3.5 backend. Wraps the existing per-module probe code in
//! `src/scanner/openssl/` until Stage 4 relocates it here.
//!
//! Supported constraint shapes (Stage 2):
//! - `single_cipher_at(code, version)` — pinned suite + pinned version
//! - `single_group_at(code, version)` — pinned named group + pinned version
//! - `version_only(v)` — one pinned TLS version
//!
//! Not yet implemented (Stage 3 will add):
//! - `sigalgs` pinning for the sigalg-policy rewrite
//! - `send_fallback_scsv` for the FALLBACK_SCSV rewrite

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
        // `sigalgs` pinning still deferred — the sigalg_policy rewrite
        // needs an IANA-codepoint↔OpenSSL-string mapping that Stage 4b
        // scopes out.
        if c.sigalgs.is_some() {
            return Err(UnsatisfiableConstraint::new(
                "openssl_backend_sigalgs_pending",
            ));
        }
        if c.alpn.is_some() {
            return Err(UnsatisfiableConstraint::new(
                "openssl_backend_alpn_not_implemented",
            ));
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
fn tls_to_ssl_version(v: TlsVersion) -> Option<openssl::ssl::SslVersion> {
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
fn ssl_to_tls_version(v: openssl::ssl::SslVersion) -> Option<TlsVersion> {
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
