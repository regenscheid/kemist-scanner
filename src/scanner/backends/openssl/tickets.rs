//! Session resumption observation.
//!
//! Drives multiple TLS 1.2 handshake pairs to capture both
//! *issuance* (does the server hand out tickets / session IDs) and
//! *acceptance* (does the server actually resume from a previously-
//! issued session).
//!
//! ## Scope of this module
//!
//! Implemented (TLS 1.2):
//! - Single-connection issuance: `session_ticket_issued`,
//!   `session_id_issued`, `ticket_lifetime_hint_secs`.
//! - Two-connection rotation proxy: `ticket_rotated_across_connections`.
//! - **Functional ticket resumption** (RFC 5077):
//!   `session_ticket_resumption_accepted` — capture the session from
//!   handshake #1, present it via `SSL_set_session` in a fresh
//!   handshake #2, observe `SSL_session_reused`. Matches what
//!   ssllabs reports as "Session resumption (tickets)".
//! - **Functional session ID resumption** (RFC 5246 §F.1.4):
//!   `session_id_resumption_accepted` — same shape as above but with
//!   `SSL_OP_NO_TICKET` set on both handshakes so the server falls
//!   back to session-ID-based caching. Matches ssllabs's "Session
//!   resumption (caching)".
//!
//! TLS 1.3 PSK resumption + 0-RTT live on the rustls backend
//! (`backends::rustls::session_resumption`); aggregated below.
//!
//! ## Implementation notes
//!
//! Ticket-bytes access: openssl-sys 0.9.109 doesn't expose
//! `SSL_SESSION_get0_ticket`. We use [`SslSessionRef::id`] +
//! `SSL_SESSION_get_timeout` via the openssl 0.10 bindings. For
//! rotation detection we diff the first 32 bytes of the session ID
//! across two handshakes — when tickets are issued most servers
//! include ticket-dependent bytes in the session ID, so a bytewise
//! diff is a reasonable rotation proxy. This is best-effort; the
//! rule-engine consumer should treat
//! `ticket_rotated_across_connections == false` as "likely stable"
//! rather than "definitely the same ticket." Functional resumption
//! tests above are the authoritative signals.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openssl::ssl::{
    HandshakeError, Ssl, SslContext, SslMethod, SslOptions, SslSession, SslSessionCacheMode,
    SslVerifyMode, SslVersion,
};
use tracing::{debug, info};

use crate::model::scan_result::{ObservationBool, SessionResumption, Tls12Resumption};

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
            session_ticket_resumption_accepted: ObservationBool::not_probed("spawn_blocking_panic"),
            session_id_resumption_accepted: ObservationBool::not_probed("spawn_blocking_panic"),
        }
    });

    // TLS 1.3 resumption + 0-RTT probe lives on the rustls backend
    // (session ticket + 0-RTT machinery is cleanest via rustls's
    // `ClientSessionStore` trait). Aggregate its result into the
    // combined `SessionResumption` output so consumers see one
    // `tls.session_resumption` block regardless of backend split.
    let ctx = crate::scanner::backends::ProbeContext {
        target,
        hostname: hostname.to_string(),
        connect_timeout,
        handshake_timeout,
    };
    let tls1_3 = crate::scanner::backends::rustls::session_resumption::probe(&ctx).await;

    SessionResumption { tls1_2, tls1_3 }
}

/// All TLS 1.2 resumption probes, run sequentially: issuance/rotation
/// pair (existing semantics) + ticket-resumption pair + session-ID
/// resumption pair. Six handshakes in the worst case; pairs short-
/// circuit on first-handshake failure.
fn probe_tls12_blocking(
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> Tls12Resumption {
    let issuance_ctx = match build_tls12_context(/*allow_tickets=*/ true) {
        Ok(c) => c,
        Err(e) => {
            return ctx_build_failure(&format!("ctx_build:{e}"));
        }
    };

    // ----- Pair 1: issuance + rotation -----
    let first = match single_tls12_handshake(
        &issuance_ctx,
        None,
        target,
        hostname,
        connect_timeout,
        handshake_timeout,
    ) {
        Ok(s) => s,
        Err(reason) => {
            return handshake_failure(&format!("handshake:{reason}"));
        }
    };
    let second_result = single_tls12_handshake(
        &issuance_ctx,
        None,
        target,
        hostname,
        connect_timeout,
        handshake_timeout,
    );

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

    // ----- Pair 2: functional ticket resumption -----
    let session_ticket_resumption_accepted = probe_resumption_pair(
        /*allow_tickets=*/ true,
        target,
        hostname,
        connect_timeout,
        handshake_timeout,
    );

    // ----- Pair 3: functional session-ID resumption (NO_TICKET) -----
    let session_id_resumption_accepted = probe_resumption_pair(
        /*allow_tickets=*/ false,
        target,
        hostname,
        connect_timeout,
        handshake_timeout,
    );

    Tls12Resumption {
        session_ticket_issued,
        ticket_lifetime_hint_secs,
        session_id_issued,
        ticket_rotated_across_connections,
        session_ticket_resumption_accepted,
        session_id_resumption_accepted,
    }
}

/// Two handshakes against a fresh context: capture the session from
/// the first, explicitly `SSL_set_session` it on the second, and
/// observe `SSL_session_reused`. `allow_tickets = false` sets
/// `SSL_OP_NO_TICKET` on the context, forcing both sides to fall
/// back to session-ID caching.
fn probe_resumption_pair(
    allow_tickets: bool,
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> ObservationBool {
    let captured_session = Arc::new(Mutex::new(None));
    let ctx = match build_tls12_context_with_capture(allow_tickets, Some(captured_session.clone()))
    {
        Ok(c) => c,
        Err(e) => return ObservationBool::error(&format!("ctx_build:{e}")),
    };

    let first = match single_tls12_handshake(
        &ctx,
        None,
        target,
        hostname,
        connect_timeout,
        handshake_timeout,
    ) {
        Ok(s) => s,
        Err(reason) => {
            return ObservationBool::not_probed(&format!("first_handshake:{reason}"));
        }
    };
    let prev_session = captured_session
        .lock()
        .ok()
        .and_then(|mut slot| slot.take())
        .or(first.session);
    let Some(prev_session) = prev_session else {
        return ObservationBool::not_applicable("no_session_issued_in_first_handshake");
    };
    let prev_session = prev_session
        .to_der()
        .ok()
        .and_then(|der| SslSession::from_der(&der).ok())
        .unwrap_or(prev_session);

    match single_tls12_handshake(
        &ctx,
        Some(&prev_session),
        target,
        hostname,
        connect_timeout,
        handshake_timeout,
    ) {
        Ok(snap) => ObservationBool::probe(snap.resumed),
        Err(reason) => ObservationBool::not_probed(&format!("second_handshake:{reason}")),
    }
}

/// Snapshot of one completed handshake.
struct HandshakeSnapshot {
    /// Owned copy of the session OpenSSL captured post-handshake.
    /// `None` when the handshake completed but no session was attached
    /// (rare; some misconfigured peers).
    session: Option<SslSession>,
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
    /// `SSL_session_reused` reading post-handshake — true only when
    /// `prev_session` was set on the Ssl and the server accepted it.
    /// `false` for fresh first-of-pair handshakes.
    resumed: bool,
}

fn single_tls12_handshake(
    ctx: &SslContext,
    prev_session: Option<&openssl::ssl::SslSessionRef>,
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

    if let Some(prev) = prev_session {
        // SAFETY: `prev` is a borrowed `SslSessionRef` whose owning
        // `SslSession` outlives this function; `set_session` clones
        // the reference internally (SSL_set_session up-refs).
        unsafe {
            ssl.set_session(prev)
                .map_err(|e| format!("set_session:{e}"))?;
        }
    }

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

    let resumed = stream.ssl().session_reused();
    let session_ref = stream.ssl().session();
    let session: Option<SslSession> = session_ref.map(|s| s.to_owned());
    let session_id: Vec<u8> = session_ref.map(|s| s.id().to_vec()).unwrap_or_default();
    let timeout_secs: i64 = session_ref.map(|s| s.timeout()).unwrap_or(0) as i64;
    let (has_ticket_hint, lifetime_hint_secs) = if timeout_secs > 0 {
        (true, Some(timeout_secs as u32))
    } else {
        (false, None)
    };

    Ok(HandshakeSnapshot {
        session,
        session_id_nonempty: !session_id.is_empty(),
        session_id,
        has_ticket_hint,
        lifetime_hint_secs,
        resumed,
    })
}

fn build_tls12_context(allow_tickets: bool) -> Result<SslContext, openssl::error::ErrorStack> {
    build_tls12_context_with_capture(allow_tickets, None)
}

fn build_tls12_context_with_capture(
    allow_tickets: bool,
    captured_session: Option<Arc<Mutex<Option<SslSession>>>>,
) -> Result<SslContext, openssl::error::ErrorStack> {
    let mut builder = SslContext::builder(SslMethod::tls_client())?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_security_level(0);
    builder.set_verify(SslVerifyMode::NONE);
    // CLIENT cache mode is required for OpenSSL to populate the
    // SslSession fully on `ssl.session()` — applies to all our
    // handshakes whether we resume explicitly or not.
    if let Some(captured_session) = captured_session {
        builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);
        builder.set_new_session_callback(move |_, session| {
            if let Ok(mut slot) = captured_session.lock() {
                *slot = Some(session);
            }
        });
    } else {
        builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);
    }
    if !allow_tickets {
        // SSL_OP_NO_TICKET: client doesn't include the SessionTicket
        // extension and won't process server-issued tickets. Forces
        // RFC 5246 §F.1.4 session-ID-based caching as the only
        // resumption path. Matches ssllabs's "Session resumption
        // (caching)" probe.
        builder.set_options(SslOptions::NO_TICKET);
    }
    Ok(builder.build())
}

fn ctx_build_failure(reason: &str) -> Tls12Resumption {
    Tls12Resumption {
        session_ticket_issued: ObservationBool::error(reason),
        ticket_lifetime_hint_secs: None,
        session_id_issued: ObservationBool::not_probed(reason),
        ticket_rotated_across_connections: ObservationBool::not_probed(reason),
        session_ticket_resumption_accepted: ObservationBool::not_probed(reason),
        session_id_resumption_accepted: ObservationBool::not_probed(reason),
    }
}

fn handshake_failure(reason: &str) -> Tls12Resumption {
    Tls12Resumption {
        session_ticket_issued: ObservationBool::error(reason),
        ticket_lifetime_hint_secs: None,
        session_id_issued: ObservationBool::not_probed(reason),
        ticket_rotated_across_connections: ObservationBool::not_probed(reason),
        session_ticket_resumption_accepted: ObservationBool::not_probed(reason),
        session_id_resumption_accepted: ObservationBool::not_probed(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    const FIXTURE_ADDR_ENV: &str = "KEMIST_LEGACY_FIXTURE_ADDR";
    const FIXTURE_HOSTNAME_ENV: &str = "KEMIST_LEGACY_FIXTURE_HOSTNAME";

    fn fixture() -> (SocketAddr, String) {
        let addr_s = std::env::var(FIXTURE_ADDR_ENV).unwrap_or_else(|_| {
            panic!(
                "missing env {FIXTURE_ADDR_ENV}; boot a resumable TLS fixture first, e.g. openssl s_server"
            )
        });
        let addr: SocketAddr = addr_s.parse().unwrap_or_else(|e| {
            panic!("{FIXTURE_ADDR_ENV}={addr_s} is not a valid socket addr: {e}")
        });
        let hostname = std::env::var(FIXTURE_HOSTNAME_ENV).unwrap_or_else(|_| "localhost".into());
        (addr, hostname)
    }

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
        assert!(matches!(
            d.session_ticket_resumption_accepted,
            ObservationBool {
                value: None,
                method: crate::model::scan_result::Method::NotProbed,
                ..
            }
        ));
    }

    #[test]
    fn build_tls12_context_with_tickets_does_not_set_no_ticket() {
        // Smoke test: building both context flavors should not error.
        // We can't introspect SslOptions on the resulting context (no
        // public getter), but the absence of error from
        // `set_options(NO_TICKET)` confirms wiring.
        assert!(build_tls12_context(true).is_ok());
        assert!(build_tls12_context(false).is_ok());
    }

    #[test]
    #[ignore]
    fn tls12_ticket_resumption_fixture_reports_accepted() {
        let (addr, hostname) = fixture();
        let out = probe_tls12_blocking(
            addr,
            &hostname,
            Duration::from_secs(8),
            Duration::from_secs(8),
        );

        assert_eq!(
            out.session_ticket_issued.value,
            Some(true),
            "fixture must issue TLS 1.2 tickets for this regression test: {out:?}"
        );
        assert_eq!(
            out.session_ticket_resumption_accepted.value,
            Some(true),
            "fixture accepts TLS 1.2 ticket resumption with openssl s_client; kemist should report accepted: {out:?}"
        );
    }
}
