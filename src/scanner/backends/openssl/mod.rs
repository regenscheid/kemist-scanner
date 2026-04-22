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

use crate::model::protocol::ProtocolSupport;
use crate::scanner::backends::{
    openssl_inventory, BackendInventory, ConstraintCapabilities, HandshakeConstraint,
    HandshakeOutcome, HandshakeResult, ProbeContext, TlsBackend, UnsatisfiableConstraint,
};

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
        // Shapes not wired to existing probe functions yet — Stage 3
        // will migrate fallback_scsv / sigalg_policy rewrites onto them.
        if c.sigalgs.is_some() {
            return Err(UnsatisfiableConstraint::new(
                "openssl_backend_sigalgs_pending_stage_3",
            ));
        }
        if c.send_fallback_scsv {
            return Err(UnsatisfiableConstraint::new(
                "openssl_backend_send_fallback_scsv_pending_stage_3",
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
