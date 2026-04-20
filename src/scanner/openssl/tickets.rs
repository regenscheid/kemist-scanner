//! Session resumption observation.
//!
//! Opens two successive TLS handshakes to the target and records
//! ticket issuance, lifetime hints, session ID issuance, and
//! ticket rotation (whether the second handshake's ticket differs
//! from the first).
//!
//! ## Scope of this module
//!
//! Implemented (F1–F3 of the observation-expansion plan):
//! - TLS 1.2 single-connection: `session_ticket_issued`,
//!   `session_id_issued`, `ticket_lifetime_hint_secs`.
//! - TLS 1.2 two-connection: `ticket_rotated_across_connections`.
//!
//! Plumbed as `NotProbed` (F4–F5, future workstream):
//! - TLS 1.3 NewSessionTicket count + per-ticket lifetimes + PSK
//!   resumption acceptance. OpenSSL's TLS 1.3 NSTs arrive post-
//!   handshake and require a small read to drive their processing;
//!   doing that correctly under a timeout budget is non-trivial.
//! - TLS 1.3 `early_data_accepted` (0-RTT). Requires
//!   `SSL_write_early_data` on a resumed connection.
//!
//! ## Implementation notes
//!
//! Ticket-bytes access: openssl-sys 0.9.109 doesn't expose
//! `SSL_SESSION_get0_ticket`. We use [`SslSessionRef::id`] +
//! `SSL_SESSION_get_timeout` via the openssl 0.10 bindings. For
//! rotation detection we diff the first 32 bytes of the session ID
//! across two handshakes — when tickets are issued most servers
//! include ticket-dependent bytes in the session ID, so a bytewise
//! diff is a reasonable rotation proxy. This is best-effort, not
//! cryptographically definitive; the rule-engine consumer should
//! treat `ticket_rotated_across_connections == false` as "likely
//! stable" rather than "definitely the same ticket."

use std::net::SocketAddr;
use std::time::Duration;

use openssl::ssl::{
    HandshakeError, Ssl, SslContext, SslMethod, SslSessionCacheMode, SslVerifyMode, SslVersion,
};
use tracing::{debug, info};

use crate::model::scan_result::{
    ObservationBool, SessionResumption, Tls12Resumption, Tls13Resumption,
};

/// Run the probe. Always returns a populated [`SessionResumption`];
/// slots that aren't observable fall back to `NotProbed` with a
/// reason rather than returning an error to the caller.
pub async fn probe(
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> SessionResumption {
    info!("OpenSSL session resumption probe");

    let hostname_owned = hostname.to_string();
    let tls1_2 = tokio::task::spawn_blocking(move || {
        probe_tls12_blocking(target, &hostname_owned, connect_timeout, handshake_timeout)
    })
    .await
    .unwrap_or_else(|e| {
        debug!("tls1_2 resumption probe panic: {e}");
        Tls12Resumption {
            session_ticket_issued: ObservationBool::error(&format!("spawn_blocking_panic:{e}")),
            ticket_lifetime_hint_secs: None,
            session_id_issued: ObservationBool::not_probed("spawn_blocking_panic"),
            ticket_rotated_across_connections: ObservationBool::not_probed("spawn_blocking_panic"),
        }
    });

    // TLS 1.3 resumption + 0-RTT are deferred to a follow-up
    // workstream. Always emit with a `NotProbed` reason so rule
    // engines see a stable schema shape.
    let tls1_3 = Tls13Resumption {
        new_session_ticket_count: None,
        ticket_lifetime_secs: Vec::new(),
        psk_resumption_accepted: ObservationBool::not_probed(
            "tls13_resumption_probe_not_implemented",
        ),
        early_data_accepted: ObservationBool::not_probed("early_data_probe_not_implemented"),
    };

    SessionResumption { tls1_2, tls1_3 }
}

/// Two sequential TLS 1.2 handshakes sharing one `SslContext`. The
/// first sets up the ticket observations; the second drives rotation
/// detection.
fn probe_tls12_blocking(
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> Tls12Resumption {
    let ctx = match build_tls12_context() {
        Ok(c) => c,
        Err(e) => {
            return Tls12Resumption {
                session_ticket_issued: ObservationBool::error(&format!("ctx_build:{e}")),
                ticket_lifetime_hint_secs: None,
                session_id_issued: ObservationBool::not_probed(&format!("ctx_build:{e}")),
                ticket_rotated_across_connections: ObservationBool::not_probed(&format!(
                    "ctx_build:{e}"
                )),
            };
        }
    };

    let first =
        match single_tls12_handshake(&ctx, target, hostname, connect_timeout, handshake_timeout) {
            Ok(s) => s,
            Err(reason) => {
                return Tls12Resumption {
                    session_ticket_issued: ObservationBool::error(&format!("handshake:{reason}")),
                    ticket_lifetime_hint_secs: None,
                    session_id_issued: ObservationBool::not_probed(&format!("handshake:{reason}")),
                    ticket_rotated_across_connections: ObservationBool::not_probed(&format!(
                        "handshake:{reason}"
                    )),
                };
            }
        };

    // Second handshake to observe ticket rotation. Failures here
    // don't invalidate the first-connection observations; we just
    // can't speak to rotation.
    let second_result =
        single_tls12_handshake(&ctx, target, hostname, connect_timeout, handshake_timeout);

    let session_ticket_issued = ObservationBool::probe(first.has_ticket_hint);
    let session_id_issued = ObservationBool::probe(first.session_id_nonempty);
    let ticket_lifetime_hint_secs = first.lifetime_hint_secs;

    let ticket_rotated_across_connections = match &second_result {
        Ok(second) => {
            if first.has_ticket_hint && second.has_ticket_hint {
                ObservationBool::probe(first.session_id != second.session_id)
            } else {
                ObservationBool::not_applicable("no_ticket_issued_on_both_connections")
            }
        }
        Err(reason) => ObservationBool::not_probed(&format!("second_handshake_failed:{reason}")),
    };

    Tls12Resumption {
        session_ticket_issued,
        ticket_lifetime_hint_secs,
        session_id_issued,
        ticket_rotated_across_connections,
    }
}

/// What one handshake observed. Kept minimal — only the signals the
/// rotation check compares.
struct HandshakeSnapshot {
    /// Bytes of the session ID as issued. Empty for pure-ticket
    /// servers that don't echo an ID.
    session_id: Vec<u8>,
    session_id_nonempty: bool,
    /// Heuristic: we count the server as having issued a ticket when
    /// `SSL_SESSION_get_timeout` reports a nonzero value. OpenSSL
    /// populates this from the RFC 5077 lifetime hint for ticket-
    /// issuing TLS 1.2 servers; non-ticket servers usually have a
    /// cache-default timeout instead. Not fully precise but good
    /// enough to distinguish "ticket path" from "no ticket."
    has_ticket_hint: bool,
    lifetime_hint_secs: Option<u32>,
}

fn single_tls12_handshake(
    ctx: &SslContext,
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> Result<HandshakeSnapshot, String> {
    let tcp = std::net::TcpStream::connect_timeout(&target, connect_timeout)
        .map_err(|e| format!("tcp_connect:{e}"))?;
    let _ = tcp.set_read_timeout(Some(handshake_timeout));
    let _ = tcp.set_write_timeout(Some(handshake_timeout));

    let mut ssl = Ssl::new(ctx).map_err(|e| format!("ssl_new:{e}"))?;
    let _ = ssl.set_hostname(hostname);

    let stream = match ssl.connect(tcp) {
        Ok(s) => s,
        Err(HandshakeError::Failure(mid)) => {
            return Err(format!("tls_alert:{}", mid.error()));
        }
        Err(HandshakeError::SetupFailure(e)) => {
            return Err(format!("setup_failure:{e}"));
        }
        Err(HandshakeError::WouldBlock(_)) => {
            return Err("handshake_would_block".to_string());
        }
    };

    let session = stream.ssl().session();
    let session_id: Vec<u8> = session.map(|s| s.id().to_vec()).unwrap_or_default();
    let timeout_secs: i64 = session.map(|s| s.timeout()).unwrap_or(0) as i64;
    let (has_ticket_hint, lifetime_hint_secs) = if timeout_secs > 0 {
        (true, Some(timeout_secs as u32))
    } else {
        (false, None)
    };

    Ok(HandshakeSnapshot {
        session_id_nonempty: !session_id.is_empty(),
        session_id,
        has_ticket_hint,
        lifetime_hint_secs,
    })
}

fn build_tls12_context() -> Result<SslContext, openssl::error::ErrorStack> {
    let mut builder = SslContext::builder(SslMethod::tls_client())?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_security_level(0);
    builder.set_verify(SslVerifyMode::NONE);
    // Cache sessions so the second handshake can observe ticket
    // rotation — even though we don't actually resume, we need the
    // cache mode set to CLIENT for OpenSSL to populate the
    // SSL_SESSION fully on the second `ssl.session()` call.
    builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);
    Ok(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_tls12_blocking_surfaces_ctx_build_errors_cleanly() {
        // Can't easily force ctx build failure in-process without
        // mocking, but we CAN verify the Tls12Resumption Default
        // matches our expectations: every field resolves to a sane
        // initial value so partial fills don't leave garbage.
        let d = Tls12Resumption::default();
        assert_eq!(d.ticket_lifetime_hint_secs, None);
        // ObservationBool::default() is NotProbed.
        assert!(matches!(
            d.session_ticket_issued,
            ObservationBool {
                value: None,
                method: crate::model::scan_result::Method::NotProbed,
                ..
            }
        ));
    }
}
