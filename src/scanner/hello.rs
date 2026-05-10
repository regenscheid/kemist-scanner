//! Byte-level ServerHello observation probe (TLS 1.2).
//!
//! rustls 0.23 doesn't expose several TLS 1.2 extension observations to
//! userland code — EMS, Encrypt-then-MAC, heartbeat advertising,
//! renegotiation_info, the server-selected compression method, and SCT
//! delivery via extension 18. This module fills the gap by running a
//! dedicated raw-socket handshake independent of rustls:
//!
//! 1. Open a plain TCP connection to the target.
//! 2. Send a hand-crafted TLS 1.2 ClientHello advertising the extensions
//!    we want the server to echo back.
//! 3. Read the first ~8 KB of response.
//! 4. Parse ServerHello (if present) and record which of our target
//!    extensions it returned.
//!
//! We never complete the handshake — we bail out right after ServerHello.
//! The server sees this as a client that went away; no actual data is
//! exchanged, no certs validated, no application bytes sent.
//!
//! ## Extensions observed
//!
//! | Ext # | Name                           | Observation |
//! |-------|--------------------------------|-------------|
//! | 15    | heartbeat                      | `heartbeat_present` |
//! | 18    | signed_certificate_timestamp   | adds `tls_extension` to sct.delivery_paths |
//! | 22    | encrypt_then_mac               | `encrypt_then_mac.value` |
//! | 23    | extended_master_secret         | `ems.value` |
//! | 0xff01| renegotiation_info             | `secure_renegotiation.value` |
//!
//! Plus the record-layer compression_method byte inside ServerHello
//! → `compression_selected` / `crime_vulnerable` (not RFC 8879
//! certificate compression).
//!
//! ## Failure modes
//!
//! - Server negotiates TLS 1.3 (ignores our legacy_version and picks up
//!   some TLS 1.3 feature) → we can't extract TLS 1.2 observations;
//!   upstream `build_extensions` still emits them as `not_applicable`.
//! - Server sends a TLS alert → observations stay `not_probed`; we
//!   record the alert as the reason.
//! - TCP/timeout → `not_probed` with the failure reason.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

use crate::model::errors::ScannerError;
use crate::model::protocol::TlsVersion;

/// Extensions we look for in ServerHello. Not all servers echo every one.
const EXT_MAX_FRAGMENT_LENGTH: u16 = 1; // RFC 6066 §4.
const EXT_TRUNCATED_HMAC: u16 = 4; // RFC 6066 §7 — deprecated but still observed.
const EXT_SUPPORTED_POINT_FORMATS: u16 = 11; // RFC 4492 / 8422 §5.1.2.
const EXT_HEARTBEAT: u16 = 15;
const EXT_SIGNED_CERT_TIMESTAMP: u16 = 18;
const EXT_ENCRYPT_THEN_MAC: u16 = 22;
const EXT_EXTENDED_MASTER_SECRET: u16 = 23;
/// RFC 9345 — delegated credentials. TLS 1.2 path: server echoes an
/// empty extension in ServerHello; TLS 1.3 path moves the signed DC
/// structure into the leaf CertificateEntry extensions (handled in
/// `openssl/tls13_extensions.rs`, not here).
const EXT_DELEGATED_CREDENTIAL: u16 = 0x0022;
const EXT_NPN: u16 = 13172; // Google's pre-ALPN protocol negotiation.
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

/// GREASE codepoint we inject as an extension_type (RFC 8701).
/// Any codepoint of the form `0xXA, 0xXA` (both bytes equal with low
/// nibble A) is a GREASE value servers must ignore. We pick one
/// specific value and check whether the ServerHello echoes it —
/// echoing is a protocol violation ("server returned an extension
/// not offered by client" per RFC 8446 §4.2).
const GREASE_EXT_TYPE: u16 = 0x0A0A;

/// `max_fragment_length` code we advertise — 4 == 2^12 (4096 bytes), the
/// largest legal value. We don't actually negotiate a smaller record; we
/// bail after ServerHello. Offering this lets us record whether the
/// server will accept it.
const MAX_FRAGMENT_LENGTH_OFFER: u8 = 4;

/// RFC 8446 §4.1.3 downgrade-protection sentinel bytes. Placed in the
/// last 8 bytes of ServerRandom by a TLS 1.3-capable server that
/// negotiated a lower version.
const SENTINEL_TLS12: &[u8; 8] = b"DOWNGRD\x01"; // 44 4F 57 4E 47 52 44 01
const SENTINEL_LTE_TLS11: &[u8; 8] = b"DOWNGRD\x00"; // 44 4F 57 4E 47 52 44 00

/// Result of the byte-level ServerHello probe.
#[derive(Debug, Clone, Default)]
pub struct HelloExtensionsObserved {
    /// Whether we got a parseable ServerHello back. If `false`, every
    /// other field is meaningless and should be treated as `not_probed`
    /// upstream with the reason in `error`.
    pub server_hello_parsed: bool,
    /// Negotiated version as echoed in the plaintext ServerHello. For
    /// TLS 1.3 servers that support downgrade negotiation this is 0x0303.
    pub server_negotiated_version: Option<u16>,
    /// Server negotiated the Extended Master Secret extension (RFC 7627).
    pub ems: Option<bool>,
    /// Server negotiated Encrypt-then-MAC (RFC 7366).
    pub encrypt_then_mac: Option<bool>,
    /// Server advertised the heartbeat extension (RFC 6520).
    pub heartbeat_present: Option<bool>,
    /// Server sent the renegotiation_info extension (RFC 5746).
    pub secure_renegotiation: Option<bool>,
    /// Compression method the server selected from our offer. Spec-canonical
    /// names: "null" (0), "deflate" (1). Other byte values render as `0xNN`.
    pub compression_selected: Option<String>,
    /// Whether the server sent SCTs via TLS extension 18 (RFC 6962 §3.3).
    pub sct_via_tls_extension: bool,
    /// Server echoed the truncated_hmac extension (RFC 6066 §7). Rare on
    /// modern deployments; presence signals an older / less-hardened stack.
    pub truncated_hmac: Option<bool>,
    /// Server advertised Next Protocol Negotiation (Google pre-standard,
    /// superseded by ALPN). Observed via presence only.
    pub npn: Option<bool>,
    /// Canonical names of EC point formats echoed by the server (RFC 4492
    /// §5.1.2 / RFC 8422). Typical values: `"uncompressed"`,
    /// `"ansiX962_compressed_prime"`, `"ansiX962_compressed_char2"`.
    /// Empty when the server didn't echo the extension.
    pub supported_point_formats_echoed: Vec<String>,
    /// RFC 6066 §4 — server-echoed max_fragment_length value. `Some("2^9")`
    /// through `Some("2^12")` (RFC values 1-4); `Some("0xNN")` for
    /// unknown bytes. `None` when the server did not echo the extension.
    pub max_fragment_length: Option<String>,
    /// Raw ServerHello extension codepoints observed by this byte-level
    /// probe. Specific fields above keep their dedicated typed values;
    /// this preserves generic coverage for all extensions the server
    /// echoed.
    pub observed_server_extensions: Vec<u16>,
    /// RFC 8446 §4.1.3 downgrade-protection sentinel observed in the last
    /// 8 bytes of ServerRandom. One of `"tls12"` (server is TLS
    /// 1.3-capable but negotiated TLS 1.2), `"lte_tls11"` (server
    /// negotiated TLS 1.1 or lower), or `"none"` (no sentinel match).
    /// `None` when we never got a parseable ServerHello.
    pub tls13_downgrade_sentinel: Option<String>,
    /// Whether the server echoed the `delegated_credential` extension
    /// (RFC 9345, ext 0x0022) in ServerHello. Observation-only signal
    /// of DC support on the TLS 1.2 path. The signed DC structure
    /// itself isn't observable from this probe (lives in a later
    /// handshake message this probe never reaches); the TLS 1.3 path
    /// in `openssl/tls13_extensions.rs` parses the CertificateEntry
    /// for the full DC payload.
    pub delegated_credential_advertised_in_sh: Option<bool>,
    /// Whether the server echoed the GREASE extension we injected
    /// (RFC 8701). A conforming server silently ignores unknown
    /// extensions (`false`); a misbehaving middlebox or buggy server
    /// echoes it back (`true`). `None` when no ServerHello parsed.
    pub grease_echoed: Option<bool>,
    /// Human-readable failure reason when `server_hello_parsed` is false.
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RecordCompressionProbeResult {
    /// ClientHello maximum protocol version used by this probe.
    pub version: TlsVersion,
    /// Whether we got a parseable ServerHello back.
    pub server_hello_parsed: bool,
    /// Record-layer compression method selected by the server.
    pub compression_selected: Option<String>,
    /// Human-readable failure reason when parsing failed.
    pub error: Option<String>,
}

/// RFC 8446 §4.1.3 HelloRetryRequest sentinel. A TLS 1.3 server that
/// emits a HelloRetryRequest does so by sending a ServerHello whose
/// `random` field carries this fixed 32-byte value (SHA-256 hash of
/// the ASCII string `"HelloRetryRequest"`). Lets us distinguish HRR
/// from a real ServerHello without decoding TLS 1.3-specific
/// extensions.
const HRR_SENTINEL: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// Result of the TLS 1.3 HelloRetryRequest probe. Separate from
/// [`HelloExtensionsObserved`] — this probe sends a TLS 1.3
/// ClientHello (legacy_version 0x0303 + `supported_versions` 0x0304)
/// with an empty `key_share`, which a spec-compliant TLS 1.3 server
/// MUST answer with HelloRetryRequest (RFC 8446 §4.2.8). A TLS 1.2-
/// only server picks 1.2, so `hrr_observed` will be `Some(false)`.
#[derive(Debug, Clone, Default)]
pub struct HelloRetryRequestObservation {
    /// `Some(true)` — server emitted a TLS 1.3 HelloRetryRequest
    /// (ServerRandom matched the RFC 8446 §4.1.3 sentinel).
    /// `Some(false)` — server responded with a regular ServerHello
    /// (either TLS 1.2 fallback, or a TLS 1.3 server that unexpectedly
    /// accepted the empty key_share and didn't retry).
    /// `None` — probe never reached a parseable ServerHello; check
    /// `error` for the reason.
    pub hrr_observed: Option<bool>,
    /// Human-readable failure reason when `hrr_observed` is `None`.
    pub error: Option<String>,
}

/// Run the probe. `sni` is the hostname to put in the server_name extension.
pub async fn probe_hello_extensions(
    target: SocketAddr,
    sni: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> HelloExtensionsObserved {
    let client_hello = build_tls12_client_hello(sni);
    observe_server_hello_with_client_hello(target, client_hello, connect_timeout, handshake_timeout)
        .await
}

pub async fn probe_record_compression_versions(
    target: SocketAddr,
    sni: &str,
    versions: &[TlsVersion],
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> Vec<RecordCompressionProbeResult> {
    let mut observations = Vec::new();
    for &version in versions {
        let client_hello = build_record_compression_client_hello(sni, version);
        let observed = observe_server_hello_with_client_hello(
            target,
            client_hello,
            connect_timeout,
            handshake_timeout,
        )
        .await;
        observations.push(RecordCompressionProbeResult {
            version,
            server_hello_parsed: observed.server_hello_parsed,
            compression_selected: observed.compression_selected,
            error: observed.error,
        });
    }
    observations
}

async fn observe_server_hello_with_client_hello(
    target: SocketAddr,
    client_hello: Vec<u8>,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> HelloExtensionsObserved {
    let mut out = HelloExtensionsObserved::default();
    let mut stream = match timeout(connect_timeout, TcpStream::connect(&target)).await {
        Err(_) => {
            out.error = Some("tcp_connect_timeout".to_string());
            return out;
        }
        Ok(Err(e)) => {
            let err = ScannerError::from_io("tcp_connect", e);
            out.error = Some(err.category);
            return out;
        }
        Ok(Ok(s)) => s,
    };

    if let Err(e) = timeout(handshake_timeout, stream.write_all(&client_hello)).await {
        let _ = e;
        out.error = Some("write_client_hello_timeout".to_string());
        return out;
    } else if let Err(e) = stream.flush().await {
        out.error = Some(format!("write_flush: {e}"));
        return out;
    }

    // Read up to 8 KB. ServerHello fits well under 1 KB; larger records
    // (Certificate) follow but we're only interested in the first record.
    let mut buf = vec![0u8; 8 * 1024];
    let mut read = 0usize;
    let deadline = handshake_timeout;
    loop {
        match timeout(deadline, stream.read(&mut buf[read..])).await {
            Err(_) => {
                if read == 0 {
                    out.error = Some("read_timeout_no_bytes".to_string());
                    return out;
                }
                break; // we have some bytes, try to parse
            }
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n)) => {
                read += n;
                if read >= buf.len() {
                    break;
                }
                // ServerHello-sized read is typically 500-1500 bytes in one
                // chunk. Parse check each iteration so we can bail early.
                if record_contains_server_hello(&buf[..read]) {
                    break;
                }
            }
            Ok(Err(e)) => {
                out.error = Some(format!("read_io: {e}"));
                return out;
            }
        }
    }

    if read == 0 {
        out.error = Some("no_response_bytes".to_string());
        return out;
    }

    parse_server_hello(&buf[..read], &mut out);
    out
}

fn record_contains_server_hello(bytes: &[u8]) -> bool {
    // Needs at least 5 bytes record header + 4 bytes handshake header.
    if bytes.len() < 9 {
        return false;
    }
    if bytes[0] != 0x16 || bytes[5] != 0x02 {
        return false;
    }
    // Only break out of the read loop once the ENTIRE first record has
    // arrived. TCP routinely delivers the ServerHello header in a
    // separate short segment before the body; stopping early trips the
    // parser's bounds check (record_length_exceeds_buffer). Compare the
    // record length in bytes 3-4 to how much we've actually read.
    let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
    bytes.len() >= 5 + record_len
}

/// Parse a TLS record stream. If the first handshake record is a
/// ServerHello, extract what we can into `out`. If it's an alert, record
/// the alert description as the error.
fn parse_server_hello(bytes: &[u8], out: &mut HelloExtensionsObserved) {
    if bytes.len() < 5 {
        out.error = Some("response_too_short".to_string());
        return;
    }
    let content_type = bytes[0];

    if content_type == 0x15 {
        // Alert — map to a reason string.
        if bytes.len() >= 7 {
            let level = bytes[5];
            let desc = bytes[6];
            out.error = Some(format!("alert_level_{level}_desc_{desc}"));
        } else {
            out.error = Some("alert_truncated".to_string());
        }
        return;
    }

    if content_type != 0x16 {
        out.error = Some(format!("unexpected_content_type_{content_type}"));
        return;
    }

    // Record header: content_type(1) | legacy_version(2) | length(2)
    let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
    let record_body = match bytes.get(5..5 + record_len) {
        Some(b) => b,
        None => {
            out.error = Some("record_length_exceeds_buffer".to_string());
            return;
        }
    };

    // Handshake header: msg_type(1) | length(3)
    if record_body.len() < 4 {
        out.error = Some("handshake_header_truncated".to_string());
        return;
    }
    if record_body[0] != 0x02 {
        out.error = Some(format!(
            "handshake_type_not_server_hello_{}",
            record_body[0]
        ));
        return;
    }
    let hs_len = ((record_body[1] as usize) << 16)
        | ((record_body[2] as usize) << 8)
        | (record_body[3] as usize);
    let hs_body = match record_body.get(4..4 + hs_len) {
        Some(b) => b,
        None => {
            out.error = Some("handshake_length_exceeds_record".to_string());
            return;
        }
    };

    // ServerHello body layout:
    //   version (2) | random (32) | session_id_len (1) | session_id (len) |
    //   cipher_suite (2) | compression_method (1) | extensions_len (2) |
    //   extensions (var)
    let mut p = 0usize;
    if hs_body.len() < 2 + 32 + 1 {
        out.error = Some("server_hello_truncated_early".to_string());
        return;
    }
    let version = u16::from_be_bytes([hs_body[p], hs_body[p + 1]]);
    out.server_negotiated_version = Some(version);
    // Capture the downgrade-protection sentinel (RFC 8446 §4.1.3) from
    // the trailing 8 bytes of ServerRandom BEFORE advancing past it.
    out.tls13_downgrade_sentinel = Some(classify_downgrade_sentinel(&hs_body[2 + 24..2 + 32]));
    p += 2 + 32; // version + random

    let sid_len = hs_body[p] as usize;
    p += 1;
    if hs_body.len() < p + sid_len + 3 {
        out.error = Some("server_hello_truncated_session_id".to_string());
        return;
    }
    p += sid_len;

    // cipher_suite (2)
    p += 2;

    // compression_method (1)
    let compression = hs_body[p];
    p += 1;
    out.compression_selected = Some(compression_name(compression));

    out.server_hello_parsed = true;

    // Extensions may be absent for older TLS servers. If the body ends here,
    // `extensions_len` is effectively zero.
    if p + 2 > hs_body.len() {
        // No extensions block — set negative observations for ext-only fields.
        out.ems = Some(false);
        out.encrypt_then_mac = Some(false);
        out.heartbeat_present = Some(false);
        out.secure_renegotiation = Some(false);
        out.truncated_hmac = Some(false);
        out.npn = Some(false);
        out.grease_echoed = Some(false);
        return;
    }

    let ext_total = u16::from_be_bytes([hs_body[p], hs_body[p + 1]]) as usize;
    p += 2;
    let ext_bytes = match hs_body.get(p..p + ext_total) {
        Some(b) => b,
        None => {
            out.error = Some("extensions_length_exceeds_body".to_string());
            // Still publish what we got.
            return;
        }
    };

    let seen = walk_extensions(ext_bytes);
    out.observed_server_extensions = sorted_extension_ids(&seen);

    out.ems = Some(seen.contains_key(&EXT_EXTENDED_MASTER_SECRET));
    out.encrypt_then_mac = Some(seen.contains_key(&EXT_ENCRYPT_THEN_MAC));
    out.heartbeat_present = Some(seen.contains_key(&EXT_HEARTBEAT));
    out.secure_renegotiation = Some(seen.contains_key(&EXT_RENEGOTIATION_INFO));
    out.sct_via_tls_extension = seen.contains_key(&EXT_SIGNED_CERT_TIMESTAMP);
    out.truncated_hmac = Some(seen.contains_key(&EXT_TRUNCATED_HMAC));
    out.npn = Some(seen.contains_key(&EXT_NPN));
    out.delegated_credential_advertised_in_sh = Some(seen.contains_key(&EXT_DELEGATED_CREDENTIAL));
    // GREASE echo-detection: true iff the server echoed ANY codepoint
    // in the `0x?A0?A` family (both bytes `0x?A`), not just the one
    // we injected. Catches both the literal echo and broader buggy
    // behavior that reflects unknown extensions back.
    out.grease_echoed = Some(seen.keys().any(|&ty| is_grease_codepoint(ty)));

    if let Some(body) = seen.get(&EXT_SUPPORTED_POINT_FORMATS) {
        out.supported_point_formats_echoed = parse_point_formats(body);
    }
    if let Some(body) = seen.get(&EXT_MAX_FRAGMENT_LENGTH) {
        if let Some(&code) = body.first() {
            out.max_fragment_length = Some(max_fragment_length_name(code));
        }
    }
}

/// RFC 8701 GREASE codepoint predicate. GREASE reserves values of
/// the form `{0xXA, 0xXA}` where both bytes are equal and the low
/// nibble is `A` — e.g. `0x0A0A`, `0x1A1A`, `0x2A2A`, ... `0xFA FA`.
/// A correctly-behaving server treats these as unknown and ignores
/// them; echoing ANY such codepoint in ServerHello extensions is a
/// protocol violation.
fn is_grease_codepoint(v: u16) -> bool {
    let hi = (v >> 8) as u8;
    let lo = (v & 0xff) as u8;
    hi == lo && (lo & 0x0f) == 0x0a
}

/// Map the `max_fragment_length` single-byte value to its RFC 6066 §4
/// meaning. Returns `"2^9"`..`"2^12"` for values 1-4, `"0xNN"` for
/// any other byte so unexpected values survive into the output.
fn max_fragment_length_name(code: u8) -> String {
    match code {
        1 => "2^9".to_string(),
        2 => "2^10".to_string(),
        3 => "2^11".to_string(),
        4 => "2^12".to_string(),
        other => format!("0x{:02X}", other),
    }
}

/// Walk a flat TLS extensions block into `{type → body bytes}`.
///
/// Replaces an older `HashSet<u16>` presence-only variant — the parser
/// needs access to extension contents (supported_point_formats,
/// max_fragment_length) for a few observations, and storing the bodies
/// is cheap since the ServerHello extension block is at most a few
/// hundred bytes.
fn walk_extensions(bytes: &[u8]) -> HashMap<u16, &[u8]> {
    let mut seen = HashMap::new();
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let ty = u16::from_be_bytes([bytes[i], bytes[i + 1]]);
        let len = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]) as usize;
        let body_end = i + 4 + len;
        if body_end > bytes.len() {
            debug!("extension {} claims length overruns buffer", ty);
            break;
        }
        seen.insert(ty, &bytes[i + 4..body_end]);
        i = body_end;
    }
    seen
}

fn sorted_extension_ids(seen: &HashMap<u16, &[u8]>) -> Vec<u16> {
    let mut ids: Vec<u16> = seen.keys().copied().collect();
    ids.sort_unstable();
    ids
}

/// Parse a `supported_point_formats` extension body (RFC 4492 §5.1.2).
///
/// Structure: `length(1) | point_format(1) *`. We render canonical
/// names for the IANA-allocated values; unknown bytes render as
/// `0xNN` for downstream visibility.
fn parse_point_formats(body: &[u8]) -> Vec<String> {
    let Some((&len, rest)) = body.split_first() else {
        return Vec::new();
    };
    let len = len as usize;
    let entries = rest.get(..len).unwrap_or(rest);
    entries
        .iter()
        .map(|b| match b {
            0 => "uncompressed".to_string(),
            1 => "ansiX962_compressed_prime".to_string(),
            2 => "ansiX962_compressed_char2".to_string(),
            other => format!("0x{:02X}", other),
        })
        .collect()
}

/// Classify the trailing 8 bytes of ServerRandom against the RFC 8446
/// §4.1.3 downgrade-protection sentinels.
///
/// A TLS 1.3-capable server that negotiates a lower version MUST set
/// these bytes so a fully-TLS-1.3 client can detect the downgrade.
/// Because kemist's byte probe always offers TLS 1.2, the sentinel
/// doubles as a signal that "this server has TLS 1.3 support even
/// though we landed on 1.2."
fn classify_downgrade_sentinel(last_eight: &[u8]) -> String {
    if last_eight == SENTINEL_TLS12 {
        "tls12".to_string()
    } else if last_eight == SENTINEL_LTE_TLS11 {
        "lte_tls11".to_string()
    } else {
        "none".to_string()
    }
}

fn compression_name(id: u8) -> String {
    match id {
        0 => "null".to_string(),
        1 => "deflate".to_string(),
        other => format!("0x{other:02X}"),
    }
}

fn protocol_version_bytes(version: TlsVersion) -> [u8; 2] {
    match version {
        TlsVersion::Ssl3 => [0x03, 0x00],
        TlsVersion::Tls10 => [0x03, 0x01],
        TlsVersion::Tls11 => [0x03, 0x02],
        TlsVersion::Tls12 => [0x03, 0x03],
        _ => [0x03, 0x03],
    }
}

fn build_record_compression_client_hello(sni: &str, version: TlsVersion) -> Vec<u8> {
    let client_version = protocol_version_bytes(version);
    let record_version = if matches!(version, TlsVersion::Ssl3) {
        [0x03, 0x00]
    } else {
        [0x03, 0x01]
    };
    build_legacy_client_hello(sni, client_version, record_version)
}

/// Build a TLS 1.2 ClientHello that advertises all extensions we want to
/// observe. Cipher suite list deliberately includes CBC suites (to keep
/// Encrypt-then-MAC applicable) plus modern AEAD suites (so the server
/// isn't forced to pick something ancient).
fn build_tls12_client_hello(sni: &str) -> Vec<u8> {
    build_legacy_client_hello(sni, [0x03, 0x03], [0x03, 0x01])
}

fn build_legacy_client_hello(
    sni: &str,
    client_version: [u8; 2],
    record_version: [u8; 2],
) -> Vec<u8> {
    let mut ch = Vec::with_capacity(512);

    // ── ClientHello body ──────────────────────────────────────────────
    let body_start = 0;

    ch.extend_from_slice(&client_version);

    // random = 32 bytes of a known-uninteresting pattern. Doesn't need to
    // be cryptographically random — we're not completing the handshake.
    ch.extend_from_slice(&[0xAB; 32]);

    // session_id length = 0
    ch.push(0x00);

    // cipher_suites
    let cipher_suites: &[u16] = &[
        0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        0xc009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA — TLS 1.0/1.1 ECDSA path
        0xc00a, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
        0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA — CBC enables EtM
        0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        0xc008, // TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA — legacy fallback
        0xc012, // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
        0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
        0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
        0x000a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        0x00ff, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV (RFC 5746)
    ];
    let cs_bytes: Vec<u8> = cipher_suites.iter().flat_map(|c| c.to_be_bytes()).collect();
    ch.extend_from_slice(&(cs_bytes.len() as u16).to_be_bytes());
    ch.extend_from_slice(&cs_bytes);

    // compression_methods: null + deflate (so server can choose either)
    ch.push(0x02);
    ch.extend_from_slice(&[0x00, 0x01]);

    // Extensions block
    let mut exts: Vec<u8> = Vec::new();
    append_sni_extension(&mut exts, sni);
    append_extension(&mut exts, 0x000d, &signature_algorithms_ext());
    append_extension(&mut exts, 0x000a, &supported_groups_ext());
    append_extension(&mut exts, 0x000b, &ec_point_formats_ext());
    append_extension(&mut exts, 0x0005, &status_request_ext());
    append_extension(&mut exts, EXT_HEARTBEAT, &[0x01]); // peer_allowed_to_send
    append_extension(&mut exts, EXT_ENCRYPT_THEN_MAC, &[]);
    append_extension(&mut exts, EXT_EXTENDED_MASTER_SECRET, &[]);
    append_extension(&mut exts, EXT_SIGNED_CERT_TIMESTAMP, &[]);
    append_extension(&mut exts, EXT_RENEGOTIATION_INFO, &[0x00]); // empty
                                                                  // Observability-only offers — we don't negotiate truncated_hmac
                                                                  // (deprecated, RFC 6066 §7) or NPN (deprecated by ALPN), but
                                                                  // offering lets us record whether the server still implements
                                                                  // them. Servers that ignore unknown extensions silently drop these.
    append_extension(&mut exts, EXT_TRUNCATED_HMAC, &[]);
    append_extension(&mut exts, EXT_NPN, &[]);
    // RFC 9345 §4.1 — offer delegated credentials with a
    // SignatureSchemeList of the signature schemes we'd accept from a
    // DC. The list is `length(2) | scheme(2)+`. Conforming servers
    // that support DC echo an empty extension in ServerHello;
    // servers that don't silently drop the extension. Both
    // outcomes feed the presence observation.
    append_extension(
        &mut exts,
        EXT_DELEGATED_CREDENTIAL,
        &delegated_credential_ext(),
    );
    // RFC 6066 §4 — offer max_fragment_length = 2^12. We advertise the
    // largest legal value so servers that support smaller limits still
    // echo. We never actually honor the negotiated limit (probe bails
    // after ServerHello).
    append_extension(
        &mut exts,
        EXT_MAX_FRAGMENT_LENGTH,
        &[MAX_FRAGMENT_LENGTH_OFFER],
    );
    // GREASE probe (RFC 8701). Inject a known GREASE extension type;
    // conforming servers MUST ignore unknown extensions. If the
    // ServerHello echoes this extension back, the server is violating
    // the TLS spec — a rule engine signal that the target sits behind
    // a broken middlebox or has a nonconforming stack.
    append_extension(&mut exts, GREASE_EXT_TYPE, &[]);

    ch.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    ch.extend_from_slice(&exts);

    let body_len = ch.len() - body_start;

    // ── Handshake header ──────────────────────────────────────────────
    // Prepend msg_type(1) + length(3)
    let mut hs = Vec::with_capacity(4 + ch.len());
    hs.push(0x01); // ClientHello
    hs.push(((body_len >> 16) & 0xff) as u8);
    hs.push(((body_len >> 8) & 0xff) as u8);
    hs.push((body_len & 0xff) as u8);
    hs.extend_from_slice(&ch);

    // ── Record header ─────────────────────────────────────────────────
    let mut record = Vec::with_capacity(5 + hs.len());
    record.push(0x16); // handshake
    record.extend_from_slice(&record_version);
    record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    record.extend_from_slice(&hs);

    record
}

fn append_extension(out: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

fn append_sni_extension(out: &mut Vec<u8>, sni: &str) {
    // server_name extension contents: list length(2) | name_type(1) |
    // host_name length(2) | host_name bytes
    let sni_bytes = sni.as_bytes();
    let mut data = Vec::with_capacity(5 + sni_bytes.len());
    let entry_len = 3 + sni_bytes.len();
    data.extend_from_slice(&(entry_len as u16).to_be_bytes()); // list length
    data.push(0x00); // name_type: host_name
    data.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    data.extend_from_slice(sni_bytes);
    append_extension(out, 0x0000, &data);
}

fn signature_algorithms_ext() -> Vec<u8> {
    // Common modern signature schemes. The precise list doesn't affect
    // our observations — we just need to offer something the server
    // accepts so the handshake reaches ServerHello.
    let schemes: &[u16] = &[
        0x0403, // ecdsa_secp256r1_sha256
        0x0503, // ecdsa_secp384r1_sha384
        0x0804, // rsa_pss_rsae_sha256
        0x0805, // rsa_pss_rsae_sha384
        0x0401, // rsa_pkcs1_sha256
        0x0501, // rsa_pkcs1_sha384
        0x0807, // ed25519
    ];
    let s_bytes: Vec<u8> = schemes.iter().flat_map(|s| s.to_be_bytes()).collect();
    let mut v = Vec::with_capacity(2 + s_bytes.len());
    v.extend_from_slice(&(s_bytes.len() as u16).to_be_bytes());
    v.extend_from_slice(&s_bytes);
    v
}

fn supported_groups_ext() -> Vec<u8> {
    // Modern curves so ECDHE-* suites don't get rejected for missing
    // groups. No PQC groups here — byte probe is explicitly about TLS 1.2.
    let groups: &[u16] = &[0x001d, 0x0017, 0x0018, 0x0019]; // X25519, P-256, P-384, P-521
    let g_bytes: Vec<u8> = groups.iter().flat_map(|g| g.to_be_bytes()).collect();
    let mut v = Vec::with_capacity(2 + g_bytes.len());
    v.extend_from_slice(&(g_bytes.len() as u16).to_be_bytes());
    v.extend_from_slice(&g_bytes);
    v
}

fn ec_point_formats_ext() -> Vec<u8> {
    vec![0x01, 0x00] // length=1, uncompressed
}

fn status_request_ext() -> Vec<u8> {
    // status_type=ocsp(1), responder_id_list len=0, request_extensions len=0
    vec![0x01, 0x00, 0x00, 0x00, 0x00]
}

/// RFC 9345 §4.1 — body of the `delegated_credential` extension
/// (type 0x0022). Offered as a SignatureSchemeList the client would
/// accept as the DC's signature scheme. Shape: `length(2) | scheme(2)+`.
/// Servers that support DC typically echo an empty ext body back in
/// ServerHello; servers that don't drop the extension silently.
fn delegated_credential_ext() -> Vec<u8> {
    // Schemes a DC might sign with. Kept aligned with the schemes we
    // accept elsewhere in the probe — ECDSA, RSA-PSS, Ed25519.
    let schemes: &[u16] = &[
        0x0403, // ecdsa_secp256r1_sha256
        0x0503, // ecdsa_secp384r1_sha384
        0x0804, // rsa_pss_rsae_sha256
        0x0807, // ed25519
    ];
    let s_bytes: Vec<u8> = schemes.iter().flat_map(|s| s.to_be_bytes()).collect();
    let mut v = Vec::with_capacity(2 + s_bytes.len());
    v.extend_from_slice(&(s_bytes.len() as u16).to_be_bytes());
    v.extend_from_slice(&s_bytes);
    v
}

/// Drive the TLS 1.3 HelloRetryRequest probe. Opens a fresh TCP
/// connection, sends a hand-crafted TLS 1.3 ClientHello with an empty
/// `key_share`, reads the response, and classifies whether the
/// ServerHello's random matches the RFC 8446 §4.1.3 HRR sentinel.
///
/// Independent of [`probe_hello_extensions`] — separate handshake,
/// separate output struct. The two probes can run in parallel.
pub async fn probe_hello_retry_request(
    target: SocketAddr,
    sni: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> HelloRetryRequestObservation {
    let mut out = HelloRetryRequestObservation::default();

    let client_hello = build_tls13_client_hello_empty_key_share(sni);

    let mut stream = match timeout(connect_timeout, TcpStream::connect(&target)).await {
        Err(_) => {
            out.error = Some("tcp_connect_timeout".to_string());
            return out;
        }
        Ok(Err(e)) => {
            let err = ScannerError::from_io("tcp_connect", e);
            out.error = Some(err.category);
            return out;
        }
        Ok(Ok(s)) => s,
    };

    if timeout(handshake_timeout, stream.write_all(&client_hello))
        .await
        .is_err()
    {
        out.error = Some("write_client_hello_timeout".to_string());
        return out;
    }
    if let Err(e) = stream.flush().await {
        out.error = Some(format!("write_flush: {e}"));
        return out;
    }

    let mut buf = vec![0u8; 8 * 1024];
    let mut read = 0usize;
    loop {
        match timeout(handshake_timeout, stream.read(&mut buf[read..])).await {
            Err(_) => {
                if read == 0 {
                    out.error = Some("read_timeout_no_bytes".to_string());
                    return out;
                }
                break;
            }
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                read += n;
                if read >= buf.len() || record_contains_server_hello(&buf[..read]) {
                    break;
                }
            }
            Ok(Err(e)) => {
                out.error = Some(format!("read_io: {e}"));
                return out;
            }
        }
    }

    classify_hrr_response(&buf[..read], &mut out);
    out
}

/// Inspect the first TLS record in `bytes` for a ServerHello and set
/// `hrr_observed` according to whether its 32-byte random matches the
/// HRR sentinel. Alert / malformed / non-handshake responses go to
/// `error`.
fn classify_hrr_response(bytes: &[u8], out: &mut HelloRetryRequestObservation) {
    if bytes.len() < 5 {
        out.error = Some("response_too_short".to_string());
        return;
    }
    let content_type = bytes[0];
    if content_type == 0x15 {
        if bytes.len() >= 7 {
            out.error = Some(format!("alert_level_{}_desc_{}", bytes[5], bytes[6]));
        } else {
            out.error = Some("alert_truncated".to_string());
        }
        return;
    }
    if content_type != 0x16 {
        out.error = Some(format!("unexpected_content_type_{content_type}"));
        return;
    }

    let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
    let record_body = match bytes.get(5..5 + record_len) {
        Some(b) => b,
        None => {
            out.error = Some("record_length_exceeds_buffer".to_string());
            return;
        }
    };
    if record_body.len() < 4 || record_body[0] != 0x02 {
        out.error = Some("not_a_server_hello".to_string());
        return;
    }
    // Handshake body starts at +4; ServerRandom at +4+2 (after legacy_version).
    if record_body.len() < 4 + 2 + 32 {
        out.error = Some("server_hello_truncated_random".to_string());
        return;
    }
    let random = &record_body[4 + 2..4 + 2 + 32];
    out.hrr_observed = Some(random == HRR_SENTINEL);
}

/// Build a TLS 1.3 ClientHello that forces a HelloRetryRequest by
/// offering an empty `key_share`. Per RFC 8446 §4.2.8:
///
/// > If the server selects an (EC)DHE group and the client did not
/// > offer a compatible "key_share" extension in the initial
/// > ClientHello, the server MUST respond with a HelloRetryRequest
/// > message.
///
/// An empty `client_shares` vector is explicitly permitted and is
/// the canonical way to trigger HRR from any TLS 1.3 server.
///
/// Also includes `supported_versions` advertising TLS 1.3 only —
/// without it, the server falls back to TLS 1.2 and there's no HRR
/// to observe.
fn build_tls13_client_hello_empty_key_share(sni: &str) -> Vec<u8> {
    let mut ch = Vec::with_capacity(512);

    // client_version = TLS 1.2 (legacy, TLS 1.3 puts real version in
    // the `supported_versions` extension per RFC 8446 §4.1.2).
    ch.extend_from_slice(&[0x03, 0x03]);
    // random — 32 bytes of an uninteresting pattern.
    ch.extend_from_slice(&[0xCD; 32]);
    // session_id = 32 bytes (TLS 1.3 middlebox-compat mode, RFC 8446
    // §4.1.2 — non-empty session_id tricks middleboxes into thinking
    // this is a resumable TLS 1.2 handshake).
    ch.push(0x20);
    ch.extend_from_slice(&[0xAB; 32]);
    // cipher_suites — TLS 1.3 suites only.
    let cipher_suites: &[u16] = &[0x1301, 0x1302, 0x1303, 0x1304, 0x1305];
    let cs_bytes: Vec<u8> = cipher_suites.iter().flat_map(|c| c.to_be_bytes()).collect();
    ch.extend_from_slice(&(cs_bytes.len() as u16).to_be_bytes());
    ch.extend_from_slice(&cs_bytes);
    // compression_methods — null only (TLS 1.3 requires this).
    ch.push(0x01);
    ch.push(0x00);

    let mut exts: Vec<u8> = Vec::new();
    append_sni_extension(&mut exts, sni);
    append_extension(&mut exts, 0x000d, &signature_algorithms_ext());
    append_extension(&mut exts, 0x000a, &supported_groups_ext());
    // supported_versions — TLS 1.3 only (extension 43, RFC 8446 §4.2.1).
    // Body: 1-byte list-length + 2-byte per-version list.
    append_extension(&mut exts, 0x002b, &[0x02, 0x03, 0x04]);
    // key_share — empty vector (extension 51, RFC 8446 §4.2.8).
    // Body: 2-byte client_shares length = 0.
    append_extension(&mut exts, 0x0033, &[0x00, 0x00]);
    // psk_key_exchange_modes — mandatory when offering PSK, but also
    // recommended for compatibility. Body: 1-byte list-length + mode
    // bytes. Offer `psk_dhe_ke` (1).
    append_extension(&mut exts, 0x002d, &[0x01, 0x01]);

    ch.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    ch.extend_from_slice(&exts);

    let body_len = ch.len();
    let mut hs = Vec::with_capacity(4 + ch.len());
    hs.push(0x01); // ClientHello
    hs.push(((body_len >> 16) & 0xff) as u8);
    hs.push(((body_len >> 8) & 0xff) as u8);
    hs.push((body_len & 0xff) as u8);
    hs.extend_from_slice(&ch);

    let mut record = Vec::with_capacity(5 + hs.len());
    record.push(0x16); // handshake
    record.extend_from_slice(&[0x03, 0x01]); // legacy record version
    record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    record.extend_from_slice(&hs);
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_has_valid_record_framing() {
        let ch = build_tls12_client_hello("example.com");
        assert!(ch.len() > 50);
        assert_eq!(ch[0], 0x16); // handshake
        assert_eq!(&ch[1..3], &[0x03, 0x01]); // legacy TLS 1.0 record version
        let rec_len = u16::from_be_bytes([ch[3], ch[4]]) as usize;
        assert_eq!(rec_len, ch.len() - 5);
        assert_eq!(ch[5], 0x01); // ClientHello
    }

    #[test]
    fn grease_codepoints_recognized() {
        // Full RFC 8701 GREASE table.
        for hi in [
            0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
        ] {
            let byte = (hi << 4) | 0x0A;
            let code = u16::from_be_bytes([byte, byte]);
            assert!(is_grease_codepoint(code), "{:#06X} should be GREASE", code);
        }
    }

    #[test]
    fn non_grease_codepoints_rejected() {
        // Common real extension codepoints must never register as GREASE.
        for code in [
            0x0000u16, 0x000a, 0x000d, 0x0017, 0x001d, 0x002b, 0xff01, 0x0A0B, 0x0A1A,
        ] {
            assert!(
                !is_grease_codepoint(code),
                "{:#06X} should NOT be GREASE",
                code
            );
        }
    }

    #[test]
    fn delegated_credential_ext_body_shape_rfc_9345() {
        // length(2) | scheme(2)+ with 4 schemes = 8 bytes of schemes,
        // total body = 10 bytes.
        let body = delegated_credential_ext();
        assert_eq!(body.len(), 10);
        let list_len = u16::from_be_bytes([body[0], body[1]]) as usize;
        assert_eq!(list_len, 8);
        // Each scheme is 2 bytes; verify the four we expect.
        assert_eq!(&body[2..4], &[0x04, 0x03]); // ecdsa_secp256r1_sha256
        assert_eq!(&body[4..6], &[0x05, 0x03]); // ecdsa_secp384r1_sha384
        assert_eq!(&body[6..8], &[0x08, 0x04]); // rsa_pss_rsae_sha256
        assert_eq!(&body[8..10], &[0x08, 0x07]); // ed25519
    }

    #[test]
    fn client_hello_offers_delegated_credential_ext() {
        let ch = build_tls12_client_hello("example.com");
        // Ext type 0x00 0x22 followed by length 0x00 0x0A (10-byte body).
        let mut found = false;
        for window in ch.windows(4) {
            if window[0] == 0x00 && window[1] == 0x22 && window[2] == 0x00 && window[3] == 0x0A {
                found = true;
                break;
            }
        }
        assert!(
            found,
            "ClientHello should include ext 0x0022 body length 10"
        );
    }

    #[test]
    fn extension_walker_recognizes_dc_in_server_hello() {
        // Synthetic extension block: ext_type=0x0022 len=0 (server echo).
        let ext_block: &[u8] = &[0x00, 0x22, 0x00, 0x00];
        let seen = walk_extensions(ext_block);
        assert!(seen.contains_key(&EXT_DELEGATED_CREDENTIAL));
    }

    #[test]
    fn client_hello_includes_grease_extension() {
        let ch = build_tls12_client_hello("example.com");
        // The two GREASE bytes 0x0A 0x0A should appear somewhere in the
        // record — specifically in the extensions block we build.
        let mut found = false;
        for window in ch.windows(4) {
            if window[0] == 0x0A && window[1] == 0x0A && window[2] == 0x00 && window[3] == 0x00 {
                // extension_type=0x0A0A + length=0x0000
                found = true;
                break;
            }
        }
        assert!(
            found,
            "ClientHello missing GREASE extension (0x0A0A, len=0)"
        );
    }

    #[test]
    fn walk_extensions_round_trips() {
        let mut buf = Vec::new();
        append_extension(&mut buf, 22, &[]);
        append_extension(&mut buf, 23, &[]);
        append_extension(&mut buf, 0xff01, &[0x00, 0x11, 0x22]);
        let seen = walk_extensions(&buf);
        assert!(seen.contains_key(&22));
        assert!(seen.contains_key(&23));
        // Body bytes of ext 0xff01 round-trip intact.
        assert_eq!(seen.get(&0xff01), Some(&&[0x00, 0x11, 0x22][..]));
        assert!(!seen.contains_key(&15));
    }

    #[test]
    fn walk_extensions_bails_on_truncation() {
        // Extension claims length 100 but buffer has only 3 bytes of body.
        let buf = vec![0x00, 0x16, 0x00, 0x64, 0xaa, 0xbb, 0xcc];
        let seen = walk_extensions(&buf);
        assert!(seen.is_empty());
    }

    #[test]
    fn compression_name_known_and_unknown() {
        assert_eq!(compression_name(0), "null");
        assert_eq!(compression_name(1), "deflate");
        assert_eq!(compression_name(64), "0x40");
    }

    #[test]
    fn parse_point_formats_decodes_iana_values() {
        // length=3, then uncompressed(0), compressed_prime(1), unknown(0x0A).
        let body = vec![0x03, 0x00, 0x01, 0x0A];
        let names = parse_point_formats(&body);
        assert_eq!(
            names,
            vec!["uncompressed", "ansiX962_compressed_prime", "0x0A"]
        );
    }

    #[test]
    fn tls13_client_hello_has_empty_key_share_and_tls13_only_versions() {
        let ch = build_tls13_client_hello_empty_key_share("example.com");
        // Extensions block must contain `supported_versions` (0x002b) +
        // `key_share` (0x0033) + the empty key_share marker.
        // Search for supported_versions header: 0x00 0x2b LEN_HI LEN_LO ...
        let sv_hdr = [0x00u8, 0x2b, 0x00, 0x03];
        assert!(
            ch.windows(4).any(|w| w == sv_hdr),
            "supported_versions extension missing"
        );
        // key_share ext header = 0x00 0x33 0x00 0x02 followed by empty vec 0x00 0x00.
        let ks_hdr = [0x00u8, 0x33, 0x00, 0x02, 0x00, 0x00];
        assert!(
            ch.windows(6).any(|w| w == ks_hdr),
            "empty key_share extension missing"
        );
    }

    #[test]
    fn classify_hrr_matches_rfc_sentinel() {
        // Fabricate a ServerHello whose 32-byte random equals the RFC
        // 8446 §4.1.3 HRR sentinel. Expect `hrr_observed: Some(true)`.
        let mut record = Vec::new();
        record.push(0x16); // handshake content type
        record.extend_from_slice(&[0x03, 0x03]); // legacy version
                                                 // Handshake body: msg_type(1) + length(3) + legacy_version(2) + random(32)
        let mut hs_body = Vec::new();
        hs_body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        hs_body.extend_from_slice(&HRR_SENTINEL);
        let mut hs = Vec::new();
        hs.push(0x02); // ServerHello
        hs.extend_from_slice(&[0x00, 0x00, hs_body.len() as u8]);
        hs.extend_from_slice(&hs_body);
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);

        let mut out = HelloRetryRequestObservation::default();
        classify_hrr_response(&record, &mut out);
        assert_eq!(out.hrr_observed, Some(true));
        assert!(out.error.is_none());
    }

    #[test]
    fn classify_hrr_rejects_real_server_random() {
        // Random that is NOT the HRR sentinel should give Some(false).
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x03]);
        let mut hs_body = Vec::new();
        hs_body.extend_from_slice(&[0x03, 0x03]);
        hs_body.extend_from_slice(&[0xAAu8; 32]);
        let mut hs = Vec::new();
        hs.push(0x02);
        hs.extend_from_slice(&[0x00, 0x00, hs_body.len() as u8]);
        hs.extend_from_slice(&hs_body);
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);

        let mut out = HelloRetryRequestObservation::default();
        classify_hrr_response(&record, &mut out);
        assert_eq!(out.hrr_observed, Some(false));
    }

    #[test]
    fn classify_hrr_surfaces_alert() {
        // Alert record (content_type 0x15) should populate `error`, not hrr_observed.
        let record = [0x15u8, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
        let mut out = HelloRetryRequestObservation::default();
        classify_hrr_response(&record, &mut out);
        assert!(out.hrr_observed.is_none());
        assert!(out.error.unwrap().starts_with("alert_level_"));
    }

    #[test]
    fn downgrade_sentinel_classifies_tls12_and_lte_tls11() {
        assert_eq!(classify_downgrade_sentinel(b"DOWNGRD\x01"), "tls12");
        assert_eq!(classify_downgrade_sentinel(b"DOWNGRD\x00"), "lte_tls11");
        assert_eq!(classify_downgrade_sentinel(&[0; 8]), "none");
        // Wrong length can't match either sentinel; classifier treats as none.
        assert_eq!(classify_downgrade_sentinel(&[0x44, 0x4F]), "none");
    }
}
