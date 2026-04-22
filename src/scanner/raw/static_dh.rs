//! Static-DH / static-ECDH cipher-suite probes via raw-socket
//! ClientHello.
//!
//! OpenSSL 3.x removed the static-DH/ECDH cipher suites entirely
//! (openssl/openssl#11359) — `SSL_CTX_set_cipher_list` can't parse
//! their names. rustls never shipped them. To probe them we build a
//! minimal TLS 1.2 ClientHello with just the target IANA codepoint in
//! the `cipher_suites` list, send it over raw TCP, and classify the
//! response byte-level. Same wire-probe pattern as `raw::heartbleed`.
//!
//! The four codepoints this covers:
//! - `0x0030` TLS_DH_DSS_WITH_AES_128_CBC_SHA
//! - `0x0031` TLS_DH_RSA_WITH_AES_128_CBC_SHA
//! - `0xC004` TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
//! - `0xC00E` TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
//!
//! Real-world `supported: true` is effectively zero — modern CAs
//! don't issue the static-DH/ECDH certificates these suites require.
//! The probe exists for completeness and so downstream consumers can
//! rule out "kemist silently doesn't look" when they need to confirm
//! absence on audited hosts.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

use crate::scanner::backends::HandshakeOutcome;

const CT_HANDSHAKE: u8 = 0x16;
const CT_ALERT: u8 = 0x15;

/// Drive one static-DH/ECDH cipher probe.
///
/// Builds a TLS 1.2 ClientHello with only `iana_code` in the cipher
/// suites list (plus `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` 0x00FF as a
/// compatibility fallback). Sends it and classifies the response:
///
/// | Response                                                     | Outcome       |
/// |---|---|
/// | ServerHello echoing `iana_code`                              | `Supported`   |
/// | ServerHello with a different cipher_suite                    | `NotSupported` (server ignored us) |
/// | Alert (content type 0x15)                                    | `NotSupported` |
/// | TCP close / timeout / parse failure before decision possible | `Error(reason)` |
pub async fn probe(
    target: SocketAddr,
    hostname: &str,
    iana_code: u16,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> HandshakeOutcome {
    let is_ecdh = matches!(iana_code, 0xC004 | 0xC00E);

    let hello = build_client_hello(hostname, iana_code, is_ecdh);

    let mut stream = match timeout(connect_timeout, TcpStream::connect(&target)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return HandshakeOutcome::Error(format!("tcp_connect:{e}")),
        Err(_) => return HandshakeOutcome::Error("tcp_connect_timeout".to_string()),
    };

    if let Err(e) = stream.write_all(&hello).await {
        return HandshakeOutcome::Error(format!("clienthello_send:{e}"));
    }

    let mut buf = vec![0u8; 4096];
    let n = match timeout(handshake_timeout, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        Ok(Ok(_)) => {
            // Clean EOF after ClientHello — server rejected without
            // even sending an alert. Treat as a wire-level rejection.
            return HandshakeOutcome::NotSupported;
        }
        Ok(Err(e)) => return HandshakeOutcome::Error(format!("read_reply:{e}")),
        Err(_) => return HandshakeOutcome::Error("reply_timeout".to_string()),
    };

    classify_server_reply(&buf[..n], iana_code)
}

/// Parse the opening bytes of the server's reply and decide.
fn classify_server_reply(buf: &[u8], offered: u16) -> HandshakeOutcome {
    // TLS record header: content_type(1) + version(2) + length(2).
    if buf.len() < 5 {
        return HandshakeOutcome::Error("truncated_reply".to_string());
    }

    // Alert → not supported (`handshake_failure`, `insufficient_security`,
    // etc.). We don't parse the alert description; its presence alone
    // is signal enough for a probe-level "no."
    if buf[0] == CT_ALERT {
        return HandshakeOutcome::NotSupported;
    }
    if buf[0] != CT_HANDSHAKE {
        // ServerHello should arrive as content type 0x16. Anything
        // else (ChangeCipherSpec? ApplicationData from a confused
        // server?) — classify as error.
        return HandshakeOutcome::Error(format!("unexpected_content_type:{:#04x}", buf[0]));
    }

    // Skip the record header. The handshake message layout is
    // type(1) + length(3) + body.
    let record_end = 5usize.saturating_add(
        u16::from_be_bytes([buf[3], buf[4]]) as usize,
    );
    let record = match buf.get(5..record_end.min(buf.len())) {
        Some(r) if !r.is_empty() => r,
        _ => return HandshakeOutcome::Error("empty_handshake_record".to_string()),
    };
    if record.len() < 4 || record[0] != 0x02 {
        // Not a ServerHello (type 0x02). HelloRetryRequest is 0x02 in
        // TLS 1.3 only; we're offering TLS 1.2 so not a concern.
        return HandshakeOutcome::Error(format!("unexpected_handshake_type:{:#04x}", record[0]));
    }

    // ServerHello body: version(2) + random(32) + session_id_len(1)
    // + session_id + cipher_suite(2) + compression(1) + extensions...
    let body = match record.get(4..) {
        Some(b) if b.len() >= 2 + 32 + 1 + 2 + 1 => b,
        _ => return HandshakeOutcome::Error("truncated_server_hello".to_string()),
    };

    // version(2) + random(32)
    let mut cur = 2 + 32;
    let sid_len = body[cur] as usize;
    cur += 1;
    if body.len() < cur + sid_len + 2 {
        return HandshakeOutcome::Error("truncated_server_hello_session_id".to_string());
    }
    cur += sid_len;
    let negotiated =
        u16::from_be_bytes([body[cur], body[cur + 1]]);
    debug!(
        offered = format!("{:#06X}", offered),
        negotiated = format!("{:#06X}", negotiated),
        "static_dh probe response"
    );
    if negotiated == offered {
        HandshakeOutcome::Supported
    } else {
        // Server picked something other than our single-suite offer.
        // Per RFC 5246 §7.4.1.2 this is a protocol violation (server
        // MUST echo a codepoint from the client's list), so in
        // practice we only ever see this if the server's cipher
        // preference ignores our offer entirely. Treat as NotSupported
        // rather than error — the observation is "server rejected our
        // intent," which is the signal we want.
        HandshakeOutcome::NotSupported
    }
}

/// Build a TLS 1.2 ClientHello with a single cipher suite codepoint.
/// Includes the compatibility extensions real browsers emit — CDNs
/// drop stripped-down ClientHellos as bot traffic.
fn build_client_hello(hostname: &str, cipher_suite: u16, include_ec_extensions: bool) -> Vec<u8> {
    let mut exts: Vec<u8> = Vec::new();

    // SNI
    let host = hostname.as_bytes();
    let mut sni_body = Vec::with_capacity(host.len() + 5);
    sni_body.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
    sni_body.push(0x00); // name_type = host_name
    sni_body.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni_body.extend_from_slice(host);
    exts.extend_from_slice(&0x0000u16.to_be_bytes());
    exts.extend_from_slice(&(sni_body.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sni_body);

    // supported_groups (ext 10) + ec_point_formats (ext 11). Needed
    // for any ECDH-variant probe; harmless for plain DH variants.
    if include_ec_extensions {
        let groups: [u8; 8] = [0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18];
        exts.extend_from_slice(&0x000au16.to_be_bytes());
        exts.extend_from_slice(&(groups.len() as u16).to_be_bytes());
        exts.extend_from_slice(&groups);

        exts.extend_from_slice(&0x000bu16.to_be_bytes());
        exts.extend_from_slice(&2u16.to_be_bytes());
        exts.push(0x01);
        exts.push(0x00);
    }

    // signature_algorithms (ext 13). RSA/ECDSA with SHA-256/384/512.
    let sigalgs: [u8; 20] = [
        0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08,
        0x06, 0x06, 0x01, 0x02, 0x01,
    ];
    exts.extend_from_slice(&0x000du16.to_be_bytes());
    exts.extend_from_slice(&(sigalgs.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sigalgs);

    // supported_versions (ext 43) pinned to TLS 1.2 — we don't want
    // TLS 1.3 negotiated since these cipher codepoints don't exist
    // there.
    exts.extend_from_slice(&0x002bu16.to_be_bytes());
    exts.extend_from_slice(&3u16.to_be_bytes());
    exts.push(0x02);
    exts.push(0x03);
    exts.push(0x03);

    // Cipher suites — target codepoint + SCSV(0x00FF) so servers that
    // reject bare single-suite ClientHellos still engage.
    let cipher_suites: [u8; 4] = [
        (cipher_suite >> 8) as u8,
        (cipher_suite & 0xff) as u8,
        0x00,
        0xff,
    ];

    // ClientHello body.
    let mut hello = Vec::new();
    hello.extend_from_slice(&[0x03, 0x03]); // version = TLS 1.2
    hello.extend_from_slice(&[
        0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
        0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
        0xbb, 0xbb,
    ]); // 32-byte random — fixed bytes so the probe is deterministic
    hello.push(0x00); // session_id length = 0
    hello.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
    hello.extend_from_slice(&cipher_suites);
    hello.push(0x01); // compression_methods length
    hello.push(0x00); // null compression
    hello.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    hello.extend_from_slice(&exts);

    // Handshake header
    let mut handshake = Vec::with_capacity(hello.len() + 4);
    handshake.push(0x01); // ClientHello
    let len = hello.len();
    handshake.push((len >> 16) as u8);
    handshake.push((len >> 8) as u8);
    handshake.push(len as u8);
    handshake.extend_from_slice(&hello);

    // TLS record header
    let mut record = Vec::with_capacity(handshake.len() + 5);
    record.push(CT_HANDSHAKE);
    record.extend_from_slice(&[0x03, 0x01]); // record-layer version 1.0 for max legacy compatibility
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_alert_as_not_supported() {
        // 5-byte record header: Alert(0x15), TLS 1.2 version, length=2.
        // Body: level=2 (fatal), description=40 (handshake_failure).
        let alert = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
        assert!(matches!(
            classify_server_reply(&alert, 0x0031),
            HandshakeOutcome::NotSupported
        ));
    }

    #[test]
    fn classifies_unexpected_content_type_as_error() {
        // Content type 0x14 (ChangeCipherSpec) is valid TLS but
        // unexpected as the first record.
        let ccs = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
        assert!(matches!(
            classify_server_reply(&ccs, 0x0031),
            HandshakeOutcome::Error(_)
        ));
    }

    #[test]
    fn classifies_short_reply_as_error() {
        let truncated = [0x16, 0x03, 0x03];
        assert!(matches!(
            classify_server_reply(&truncated, 0x0031),
            HandshakeOutcome::Error(_)
        ));
    }

    #[test]
    fn server_hello_echoing_offered_cipher_is_supported() {
        // Fabricate a minimal ServerHello with cipher_suite = 0x0031.
        // record(5): 0x16, 0x03 0x03, len
        // body: 0x02(type) + 24-bit len + TLS1.2 + 32 random + sid_len(0) + cipher(0x0031) + comp(0)
        let mut h = Vec::new();
        h.push(0x02); // ServerHello
        h.extend_from_slice(&[0x00, 0x00, 38]); // len = 38
        h.extend_from_slice(&[0x03, 0x03]);
        h.extend_from_slice(&[0u8; 32]);
        h.push(0x00); // session_id length
        h.extend_from_slice(&[0x00, 0x31]); // cipher_suite
        h.push(0x00); // compression
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(h.len() as u16).to_be_bytes());
        record.extend_from_slice(&h);
        assert!(matches!(
            classify_server_reply(&record, 0x0031),
            HandshakeOutcome::Supported
        ));
    }

    #[test]
    fn server_hello_with_different_cipher_is_not_supported() {
        let mut h = Vec::new();
        h.push(0x02);
        h.extend_from_slice(&[0x00, 0x00, 38]);
        h.extend_from_slice(&[0x03, 0x03]);
        h.extend_from_slice(&[0u8; 32]);
        h.push(0x00);
        h.extend_from_slice(&[0xC0, 0x2F]); // negotiated != offered
        h.push(0x00);
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(h.len() as u16).to_be_bytes());
        record.extend_from_slice(&h);
        assert!(matches!(
            classify_server_reply(&record, 0x0031),
            HandshakeOutcome::NotSupported
        ));
    }

    #[test]
    fn build_client_hello_has_target_codepoint_in_cipher_list() {
        let hello = build_client_hello("example.test", 0xC004, true);
        // The codepoint bytes 0xC0 0x04 should appear somewhere.
        assert!(
            hello.windows(2).any(|w| w == [0xC0, 0x04]),
            "target codepoint missing from ClientHello"
        );
    }
}
