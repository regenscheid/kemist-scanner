//! TLS 1.3 session resumption + 0-RTT (`early_data`) probe via rustls.
//!
//! Two sequential handshakes against the same target, sharing one
//! [`rustls::client::ClientSessionStore`]. Handshake #1 reads enough
//! post-handshake bytes for the server's `NewSessionTicket` records to
//! land in the custom session store, which counts inserts. Handshake #2
//! reuses the cached ticket; rustls auto-offers the PSK in the
//! ClientHello.
//!
//! Observations:
//! - `new_session_ticket_count` — how many `NewSessionTicket` messages
//!   the server issued after handshake #1 (intercepted by a
//!   [`TicketCountingStore`] wrapping [`ClientSessionMemoryCache`]).
//! - `psk_resumption_accepted` — whether handshake #2 reported
//!   [`HandshakeKind::Resumed`] (server accepted the PSK offer).
//! - `early_data_accepted` — whether handshake #2 reported
//!   [`ClientConnection::is_early_data_accepted`]; the ClientHello
//!   advertises `early_data` automatically when `config.enable_early_data`
//!   is set AND the cached ticket's `max_early_data_size > 0`.
//!
//! Both observations fall through to `not_probed` with a specific
//! reason when the preconditions aren't met (TCP failed, no ticket
//! issued, ticket not 0-RTT-capable, etc.) so rule engines always see
//! a stable schema shape.
//!
//! Post-handshake-action style: this is an inherent helper, not part
//! of the `TlsBackend` trait. The orchestrator calls it directly; the
//! OpenSSL-side `tickets::probe` aggregates the result into the
//! combined [`SessionResumption`] output.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::{
    ClientSessionMemoryCache, ClientSessionStore, Resumption, Tls12ClientSessionValue,
    Tls13ClientSessionValue,
};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, NamedGroup};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::{debug, info};

use crate::model::scan_result::{ObservationBool, Tls13Resumption};
use crate::scanner::backends::rustls::AcceptAllVerifier;
use crate::scanner::backends::ProbeContext;

/// Run the rustls-backed TLS 1.3 resumption probe. Always returns a
/// populated `Tls13Resumption`; every unobservable slot falls back to
/// a `NotProbed` reason string.
pub async fn probe(ctx: &ProbeContext) -> Tls13Resumption {
    info!("rustls TLS 1.3 session resumption probe");
    let store = Arc::new(TicketCountingStore::new());
    let config = Arc::new(build_config(store.clone()));

    // Handshake 1: connect, complete handshake, then read briefly so
    // post-handshake NewSessionTicket records arrive and the store
    // records them. If the handshake itself fails we bail early with
    // `NotProbed` across the board.
    let first = timeout(
        ctx.connect_timeout + ctx.handshake_timeout + Duration::from_secs(3),
        do_handshake_and_read_ticket(config.clone(), ctx),
    )
    .await;
    match first {
        Ok(Ok(())) => {}
        Ok(Err(reason)) => return not_probed_with(&reason),
        Err(_) => return not_probed_with("handshake1_timeout"),
    }

    let ticket_count = store.ticket_count.load(Ordering::Relaxed);
    let max_early_data = store.max_early_data.load(Ordering::Relaxed);
    if ticket_count == 0 {
        return Tls13Resumption {
            new_session_ticket_count: Some(0),
            ticket_lifetime_secs: Vec::new(),
            psk_resumption_accepted: ObservationBool::probe(false),
            early_data_accepted: ObservationBool::not_probed(
                "no_new_session_ticket_after_handshake_1",
            ),
        };
    }

    // Handshake 2: reuse the same config + store. rustls offers the
    // cached PSK in the ClientHello automatically.
    let second = timeout(
        ctx.connect_timeout + ctx.handshake_timeout + Duration::from_secs(3),
        do_handshake_and_observe(config, ctx),
    )
    .await;
    match second {
        Ok(Ok((resumed, early_accepted))) => Tls13Resumption {
            new_session_ticket_count: Some(ticket_count),
            ticket_lifetime_secs: Vec::new(),
            psk_resumption_accepted: ObservationBool::probe(resumed),
            early_data_accepted: if max_early_data == 0 {
                ObservationBool::not_probed("ticket_max_early_data_size_zero")
            } else if !resumed {
                ObservationBool::not_probed("psk_not_accepted_so_no_0rtt_to_observe")
            } else {
                ObservationBool::probe(early_accepted)
            },
        },
        Ok(Err(reason)) => Tls13Resumption {
            new_session_ticket_count: Some(ticket_count),
            ticket_lifetime_secs: Vec::new(),
            psk_resumption_accepted: ObservationBool::error(&reason),
            early_data_accepted: ObservationBool::not_probed("resumption_handshake_failed"),
        },
        Err(_) => Tls13Resumption {
            new_session_ticket_count: Some(ticket_count),
            ticket_lifetime_secs: Vec::new(),
            psk_resumption_accepted: ObservationBool::error("handshake2_timeout"),
            early_data_accepted: ObservationBool::not_probed("handshake2_timeout"),
        },
    }
}

fn not_probed_with(reason: &str) -> Tls13Resumption {
    Tls13Resumption {
        new_session_ticket_count: None,
        ticket_lifetime_secs: Vec::new(),
        psk_resumption_accepted: ObservationBool::not_probed(reason),
        early_data_accepted: ObservationBool::not_probed(reason),
    }
}

async fn do_handshake_and_read_ticket(
    config: Arc<ClientConfig>,
    ctx: &ProbeContext,
) -> Result<(), String> {
    let tcp = match timeout(ctx.connect_timeout, TcpStream::connect(&ctx.target)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(format!("tcp_connect:{e}")),
        Err(_) => return Err("tcp_connect_timeout".to_string()),
    };

    let domain = match ServerName::try_from(ctx.hostname.clone()) {
        Ok(d) => d,
        Err(_) => return Err(format!("invalid_sni:{}", ctx.hostname)),
    };

    let connector = TlsConnector::from(config);
    let mut tls = match timeout(ctx.handshake_timeout, connector.connect(domain, tcp)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(format!("handshake1:{e}")),
        Err(_) => return Err("handshake1_timeout".to_string()),
    };

    // Send a minimal HTTP request so the server writes *something*
    // (usually followed immediately by NewSessionTicket records on
    // modern deployments). Most servers send tickets right after their
    // Finished message regardless, but some (nginx with session_ticket
    // off, openssl s_server without `-www`) only emit them once the
    // client writes, so we do both.
    let req = format!(
        "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        ctx.hostname
    );
    let _ = tls.write_all(req.as_bytes()).await;
    let _ = tls.flush().await;

    let mut buf = [0u8; 4096];
    let _ = timeout(Duration::from_secs(2), tls.read(&mut buf)).await;

    // Clean shutdown so the server has a chance to push any
    // late-arriving tickets on some stacks.
    let _ = tls.shutdown().await;
    Ok(())
}

async fn do_handshake_and_observe(
    config: Arc<ClientConfig>,
    ctx: &ProbeContext,
) -> Result<(bool, bool), String> {
    let tcp = match timeout(ctx.connect_timeout, TcpStream::connect(&ctx.target)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(format!("tcp_connect:{e}")),
        Err(_) => return Err("tcp_connect_timeout".to_string()),
    };

    let domain = match ServerName::try_from(ctx.hostname.clone()) {
        Ok(d) => d,
        Err(_) => return Err(format!("invalid_sni:{}", ctx.hostname)),
    };

    let connector = TlsConnector::from(config);
    let tls = match timeout(ctx.handshake_timeout, connector.connect(domain, tcp)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(format!("handshake2:{e}")),
        Err(_) => return Err("handshake2_timeout".to_string()),
    };

    let (_tcp_ref, conn) = tls.get_ref();
    let resumed = matches!(conn.handshake_kind(), Some(rustls::HandshakeKind::Resumed));
    let early_accepted = conn.is_early_data_accepted();
    debug!(resumed, early_accepted, "tls1.3 resumption observation");
    Ok((resumed, early_accepted))
}

fn build_config(store: Arc<dyn ClientSessionStore>) -> ClientConfig {
    let mut cfg = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
        .with_no_client_auth();
    cfg.resumption = Resumption::store(store);
    cfg.enable_early_data = true;
    // ALPN: offer common values so servers that gate session tickets
    // on a specific ALPN (rare but seen) still negotiate.
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    cfg
}

/// Wraps [`ClientSessionMemoryCache`] to count `insert_tls13_ticket`
/// calls and record the max `max_early_data_size` across tickets. All
/// other trait methods delegate to the inner cache unchanged.
#[derive(Debug)]
struct TicketCountingStore {
    inner: ClientSessionMemoryCache,
    ticket_count: AtomicU32,
    max_early_data: AtomicU32,
    #[allow(dead_code)]
    lifetimes: Mutex<Vec<u32>>,
}

impl TicketCountingStore {
    fn new() -> Self {
        Self {
            inner: ClientSessionMemoryCache::new(4),
            ticket_count: AtomicU32::new(0),
            max_early_data: AtomicU32::new(0),
            lifetimes: Mutex::new(Vec::new()),
        }
    }
}

impl ClientSessionStore for TicketCountingStore {
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup) {
        self.inner.set_kx_hint(server_name, group);
    }

    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup> {
        self.inner.kx_hint(server_name)
    }

    fn set_tls12_session(&self, server_name: ServerName<'static>, value: Tls12ClientSessionValue) {
        self.inner.set_tls12_session(server_name, value);
    }

    fn tls12_session(&self, server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        self.inner.tls12_session(server_name)
    }

    fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
        self.inner.remove_tls12_session(server_name);
    }

    fn insert_tls13_ticket(
        &self,
        server_name: ServerName<'static>,
        value: Tls13ClientSessionValue,
    ) {
        self.ticket_count.fetch_add(1, Ordering::Relaxed);
        let mx = value.max_early_data_size();
        let prev = self.max_early_data.load(Ordering::Relaxed);
        if mx > prev {
            self.max_early_data.store(mx, Ordering::Relaxed);
        }
        self.inner.insert_tls13_ticket(server_name, value);
    }

    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<Tls13ClientSessionValue> {
        self.inner.take_tls13_ticket(server_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_counts_insertions() {
        let store = TicketCountingStore::new();
        assert_eq!(store.ticket_count.load(Ordering::Relaxed), 0);
        // Direct construction of Tls13ClientSessionValue isn't public in
        // rustls, so we can only assert the counter starts at zero and
        // increments in integration through the crate. The `new` default
        // is guarded here to catch accidental changes.
    }

    #[test]
    fn not_probed_fields_propagate_reason() {
        let out = not_probed_with("custom_reason");
        assert_eq!(out.new_session_ticket_count, None);
        assert!(out.ticket_lifetime_secs.is_empty());
        // Round-trip the reason string through serde_json to verify it
        // appears as expected in the output shape.
        let j = serde_json::to_value(&out.psk_resumption_accepted).unwrap();
        assert_eq!(j["reason"], "custom_reason");
        assert_eq!(j["method"], "not_probed");
    }
}
