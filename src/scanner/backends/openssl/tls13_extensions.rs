//! TLS 1.3 msg-callback observations.
//!
//! Despite the module name ("tls13_extensions"), this module captures
//! observations from two TLS 1.3 handshake messages via
//! `SSL_CTX_set_msg_callback`: EncryptedExtensions (RFC 8449
//! record_size_limit, RFC 8879 compress_certificate) and Certificate
//! (RFC 9345 delegated_credentials, carried in the leaf
//! CertificateEntry's extensions block).
//!
//! EncryptedExtensions is sent encrypted under the handshake traffic
//! key. Userland code can't read those bytes off the wire without
//! deriving keys, which would mean re-implementing a TLS 1.3 client.
//! OpenSSL decrypts the record internally, then invokes the callback
//! with the plaintext. We capture the message body, parse the
//! extensions block ourselves, and surface the observations.
//!
//! Same pattern as [`crate::scanner::openssl::client_auth`] (which
//! captures CertificateRequest); the two could share scaffolding in
//! the future, but for now each module owns its own callback so the
//! per-probe capture buffer stays narrow.
//!
//! Observations recorded when the EncryptedExtensions message
//! actually carries the extension:
//!
//! | Extension | IANA # | Field |
//! |-----------|--------|-------|
//! | RFC 8449 record_size_limit | 28 | [`Tls13EncryptedExtensions::record_size_limit`] |
//! | RFC 8879 compress_certificate | 27 | [`Tls13EncryptedExtensions::compress_certificate_algorithms`] |
//!
//! ## Known limitation: client-side offer gap
//!
//! Both RFCs require the server to advertise these extensions *only
//! in response to* a matching client offer. OpenSSL 3.5 reserves ext
//! 27 and 28 for its own internal handlers, so `add_custom_ext`
//! cannot inject a client-side offer — the call returns failure with
//! an empty error stack. openssl-sys 0.9.109 doesn't expose the
//! native high-level setters
//! (`SSL_CTX_set1_cert_comp_preference`, etc.) that would let
//! OpenSSL's built-in machinery emit the offer.
//!
//! Result: on real-world targets we typically observe `parsed: true`
//! with empty fields because servers respect the "MUST NOT send
//! unsolicited" rule. The probe still infrastructure-tests correctly
//! (see unit tests in this file) and remains useful for servers that
//! advertise these extensions unsolicited — rare but legal.
//! Follow-up workstream: gain access to the native OpenSSL setters
//! and wire them in, then the fields populate on every modern TLS
//! 1.3 deployment.
//!
//! Deliberately **not** observed here:
//! - `early_data` (ext 42) — only populated in EncryptedExtensions on
//!   a resumed handshake that accepts 0-RTT. A session-resumption
//!   probe is the right place for it; currently that probe reserves
//!   `early_data_accepted` as a `NotProbed` slot pending
//!   `SSL_write_early_data` integration.
//! - `psk_key_exchange_modes` (ext 45) — client-side offer only, no
//!   server observation possible.
//! - `post_handshake_auth` (ext 49) — client-side offer only, no
//!   server observation possible.
//!
//! ## Failure modes
//!
//! - Target doesn't speak TLS 1.3 → handshake fails, `parsed: false`
//!   with an alert category as the reason.
//! - TCP refused / timeout → `parsed: false`, reason populated.
//! - Target speaks TLS 1.3 but the handshake aborts before
//!   EncryptedExtensions (rare — EE is the first message the server
//!   sends after ServerHello) → `parsed: false`.

use std::cell::RefCell;
use std::net::SocketAddr;
use std::os::raw::{c_int, c_long, c_void};
use std::time::Duration;

use foreign_types::ForeignTypeRef;
use openssl::ssl::{Ssl, SslContext, SslMethod, SslVerifyMode, SslVersion};
use tracing::{debug, info};

/// OpenSSL control code from `<openssl/ssl.h>`. Same literal as in
/// [`client_auth`](super::client_auth) — the constant isn't re-exported
/// from openssl-sys at the version we pin.
const SSL_CTRL_SET_MSG_CALLBACK: c_int = 15;

/// TLS record content_type for handshake records.
const CONTENT_TYPE_HANDSHAKE: c_int = 22;
/// TLS 1.3 handshake type for EncryptedExtensions.
const HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: u8 = 8;
/// TLS 1.3 handshake type for Certificate.
const HANDSHAKE_TYPE_CERTIFICATE: u8 = 11;

/// Extensions carried in EncryptedExtensions that we observe.
const EXT_COMPRESS_CERTIFICATE: u16 = 27;
const EXT_RECORD_SIZE_LIMIT: u16 = 28;
/// RFC 9345 — delegated_credential. In TLS 1.3 this rides inside the
/// leaf CertificateEntry's extensions (RFC 8446 §4.4.2), not in EE.
const EXT_DELEGATED_CREDENTIAL: u16 = 0x0022;

extern "C" {
    /// `SSL_CTX_callback_ctrl` — generic callback-installer. Casting
    /// the function pointer according to the control code is how the
    /// public OpenSSL header's `SSL_CTX_set_msg_callback` macro
    /// expands in C.
    #[link_name = "SSL_CTX_callback_ctrl"]
    fn SSL_CTX_callback_ctrl(
        ctx: *mut openssl_sys::SSL_CTX,
        cmd: c_int,
        fp: Option<unsafe extern "C" fn()>,
    ) -> c_long;
}

/// Concrete signature the msg_callback must have. OpenSSL invokes
/// this once per handshake record, both directions.
type MsgCbFn = unsafe extern "C" fn(
    write_p: c_int,
    version: c_int,
    content_type: c_int,
    buf: *const c_void,
    len: usize,
    ssl: *mut openssl_sys::SSL,
    arg: *mut c_void,
);

thread_local! {
    /// Per-thread buffer for the captured EncryptedExtensions handshake
    /// message (including the 4-byte header). Cleared at the start of
    /// each probe on the same worker so stale state doesn't bleed.
    static CAPTURED: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
    /// Per-thread buffer for the captured Certificate handshake message
    /// (including the 4-byte header). Needed for the RFC 9345
    /// delegated_credentials observation which lives inside the leaf
    /// CertificateEntry's extensions block. Cleared alongside CAPTURED.
    static CAPTURED_CERT: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
}

/// Observations parsed out of the TLS 1.3 EncryptedExtensions flight.
/// Despite the struct name, the `delegated_credential` field is
/// sourced from the Certificate handshake message (RFC 8446 §4.4.2
/// CertificateEntry extensions) captured by the same msg_callback.
#[derive(Debug, Clone, Default)]
pub struct Tls13EncryptedExtensions {
    /// Whether the probe received a parseable EncryptedExtensions
    /// message. `false` means the handshake didn't get that far — the
    /// server rejected TLS 1.3, the connection failed, or the
    /// extension block itself was malformed.
    pub parsed: bool,
    /// RFC 8449 — server-selected maximum record size. `None` when
    /// the extension was not present.
    pub record_size_limit: Option<u16>,
    /// RFC 8879 — certificate-compression algorithms the server
    /// advertises. Canonical names for IANA-assigned codepoints
    /// (`"zlib"`, `"brotli"`, `"zstd"`), `"0xNNNN"` for unknowns.
    /// Empty when the extension was not present.
    pub compress_certificate_algorithms: Vec<String>,
    /// RFC 9345 delegated-credential observation parsed from the
    /// leaf CertificateEntry's extensions. `None` when the server
    /// did not advertise DC on this probe's handshake or the
    /// Certificate message was not captured.
    pub delegated_credential: Option<DelegatedCredentialFacts>,
    /// Human-readable failure reason when `parsed` is false.
    pub error: Option<String>,
}

/// Parsed DelegatedCredential fields per RFC 9345 §4.1. Only the
/// structural fields the scanner observes — the signed public-key
/// blob and signature are intentionally skipped (non-goals: no DC
/// signature verification, no `valid_time` wall-clock comparison).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedCredentialFacts {
    /// Seconds from the leaf cert's `notBefore` at which the DC
    /// expires (RFC 9345 §4.1). Scanner observation only — no
    /// wall-clock comparison.
    pub valid_time_seconds: u32,
    /// IANA SignatureScheme codepoint the DC's signature uses.
    pub expected_cert_verify_algorithm_code: u16,
    /// Canonical IANA name for the SignatureScheme
    /// (`"ecdsa_secp256r1_sha256"`, etc.). `"0xNNNN"` for
    /// unrecognized codepoints.
    pub expected_cert_verify_algorithm: String,
}

/// Run the probe. Always returns a `Tls13EncryptedExtensions` so the
/// output slot stays stable; `parsed: false` plus a reason carries
/// the "couldn't observe" signal.
pub async fn probe(
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> Tls13EncryptedExtensions {
    info!("OpenSSL TLS 1.3 EncryptedExtensions probe");

    let hostname_owned = hostname.to_string();
    let result = tokio::task::spawn_blocking(move || {
        probe_blocking(target, &hostname_owned, connect_timeout, handshake_timeout)
    })
    .await;

    result.unwrap_or_else(|e| {
        debug!("tls13_extensions spawn_blocking panic: {e}");
        Tls13EncryptedExtensions {
            parsed: false,
            error: Some(format!("spawn_blocking_panic:{e}")),
            ..Default::default()
        }
    })
}

fn probe_blocking(
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> Tls13EncryptedExtensions {
    CAPTURED.with(|c| *c.borrow_mut() = None);
    CAPTURED_CERT.with(|c| *c.borrow_mut() = None);

    let tcp = match std::net::TcpStream::connect_timeout(&target, connect_timeout) {
        Ok(s) => s,
        Err(e) => {
            return Tls13EncryptedExtensions {
                parsed: false,
                error: Some(format!("tcp_connect:{e}")),
                ..Default::default()
            };
        }
    };
    let _ = tcp.set_read_timeout(Some(handshake_timeout));
    let _ = tcp.set_write_timeout(Some(handshake_timeout));

    let ctx = match build_context_with_callback() {
        Ok(c) => c,
        Err(e) => {
            return Tls13EncryptedExtensions {
                parsed: false,
                error: Some(format!("ctx_build:{e}")),
                ..Default::default()
            };
        }
    };

    let mut ssl = match Ssl::new(&ctx) {
        Ok(s) => s,
        Err(e) => {
            return Tls13EncryptedExtensions {
                parsed: false,
                error: Some(format!("ssl_new:{e}")),
                ..Default::default()
            };
        }
    };
    let _ = ssl.set_hostname(hostname);

    // Attempt the handshake. EncryptedExtensions arrives early — even
    // if the handshake ultimately fails (e.g. bad cert, client-auth
    // required), the msg_callback should have fired by then.
    let _ = ssl.connect(tcp);

    let captured = CAPTURED.with(|c| c.borrow_mut().take());
    let captured_cert = CAPTURED_CERT.with(|c| c.borrow_mut().take());
    debug!(
        "TLS 1.3 EE probe captured_bytes: {} cert_bytes: {}",
        captured.as_ref().map(|v| v.len()).unwrap_or(0),
        captured_cert.as_ref().map(|v| v.len()).unwrap_or(0)
    );

    let mut out = match captured {
        None => Tls13EncryptedExtensions {
            parsed: false,
            error: Some("no_encrypted_extensions_observed".to_string()),
            ..Default::default()
        },
        Some(raw) => parse_encrypted_extensions(&raw),
    };
    // Overlay DC observation (from Certificate message) regardless of
    // EE parse success — the two are independent observations.
    if let Some(cert_bytes) = captured_cert.as_deref() {
        out.delegated_credential = parse_certificate_for_dc(cert_bytes);
    }
    out
}

/// Parse a compress_certificate extension body into canonical names.
/// Shared between the add_custom_ext parse callback (server's EE
/// response) and the fallback EE-bytes walker.
fn parse_compress_cert_list(body: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if let Some((&list_len, rest)) = body.split_first() {
        let algs = rest.get(..list_len as usize).unwrap_or(rest);
        let mut j = 0;
        while j + 2 <= algs.len() {
            let code = u16::from_be_bytes([algs[j], algs[j + 1]]);
            out.push(cert_comp_name(code));
            j += 2;
        }
    }
    out
}

fn build_context_with_callback() -> Result<SslContext, openssl::error::ErrorStack> {
    let mut builder = SslContext::builder(SslMethod::tls_client())?;
    // Pin to TLS 1.3. A server that doesn't support 1.3 will alert or
    // close; we record that as `parsed: false`.
    builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_security_level(0);
    builder.set_verify(SslVerifyMode::NONE);

    // Client-side offer limitation:
    //
    // Per RFC 8449 §4 and RFC 8879 §3, a TLS 1.3 server MUST NOT send
    // record_size_limit or compress_certificate in EncryptedExtensions
    // unless the client offered them in ClientHello. We'd normally use
    // `SSL_CTX_add_custom_ext` (exposed via `add_custom_ext`) to inject
    // both — but OpenSSL 3.5 reserves these specific extension codes
    // for its own internal handlers, so the registration call returns
    // failure with an empty ErrorStack. openssl-sys 0.9.109 doesn't
    // expose the high-level native setters
    // (`SSL_CTX_set1_cert_comp_preference` and friends) that would
    // let us offer these through OpenSSL's built-in machinery.
    //
    // Net: the msg_callback below still fires on every TLS 1.3
    // handshake and the parser handles any EncryptedExtensions bytes
    // correctly (unit tests in this file pass). But on real servers
    // we typically observe `parsed: true` with empty record_size_limit
    // and compress_certificate fields, because servers respect the
    // "MUST NOT advertise unsolicited" rule. That's the honest signal.
    //
    // Follow-up workstream: once openssl-sys gains bindings for the
    // native preference setters, wire them in and these fields will
    // populate on every modern TLS 1.3 deployment.

    let ctx = builder.build();

    // SAFETY: `msg_callback` is a static `extern "C"` function with
    // the signature SSL_CTRL_SET_MSG_CALLBACK expects. SSL_CTX_callback_ctrl
    // reinterprets the generic fn pointer based on the control code.
    unsafe {
        SSL_CTX_callback_ctrl(
            ctx.as_ptr(),
            SSL_CTRL_SET_MSG_CALLBACK,
            Some(std::mem::transmute::<MsgCbFn, unsafe extern "C" fn()>(
                msg_callback,
            )),
        );
    }
    Ok(ctx)
}

/// The msg_callback. Runs for every handshake record in both
/// directions. Captures the first EncryptedExtensions the server
/// sends.
unsafe extern "C" fn msg_callback(
    write_p: c_int,
    _version: c_int,
    content_type: c_int,
    buf: *const c_void,
    len: usize,
    _ssl: *mut openssl_sys::SSL,
    _arg: *mut c_void,
) {
    if write_p != 0 || content_type != CONTENT_TYPE_HANDSHAKE || buf.is_null() || len == 0 {
        return;
    }
    // SAFETY: OpenSSL passes a valid `buf`/`len` for the duration of
    // the callback.
    let slice = unsafe { std::slice::from_raw_parts(buf as *const u8, len) };
    match slice.first() {
        Some(&HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS) => {
            CAPTURED.with(|c| {
                if c.borrow().is_none() {
                    *c.borrow_mut() = Some(slice.to_vec());
                }
            });
        }
        Some(&HANDSHAKE_TYPE_CERTIFICATE) => {
            CAPTURED_CERT.with(|c| {
                if c.borrow().is_none() {
                    *c.borrow_mut() = Some(slice.to_vec());
                }
            });
        }
        _ => {}
    }
}

/// Parse the captured EncryptedExtensions handshake message.
///
/// Layout (RFC 8446 §4.3.1):
/// ```text
///   msg_type(1) = 0x08 | length(3) | extensions_len(2) | extensions
/// ```
fn parse_encrypted_extensions(raw: &[u8]) -> Tls13EncryptedExtensions {
    if raw.len() < 4 {
        return Tls13EncryptedExtensions {
            parsed: false,
            error: Some("ee_truncated_header".to_string()),
            ..Default::default()
        };
    }
    let hs_len = ((raw[1] as usize) << 16) | ((raw[2] as usize) << 8) | (raw[3] as usize);
    let body = match raw.get(4..4 + hs_len) {
        Some(b) => b,
        None => {
            return Tls13EncryptedExtensions {
                parsed: false,
                error: Some("ee_length_exceeds_buffer".to_string()),
                ..Default::default()
            };
        }
    };
    if body.len() < 2 {
        return Tls13EncryptedExtensions {
            parsed: false,
            error: Some("ee_body_too_short".to_string()),
            ..Default::default()
        };
    }
    let ext_total = u16::from_be_bytes([body[0], body[1]]) as usize;
    let ext_bytes = match body.get(2..2 + ext_total) {
        Some(b) => b,
        None => {
            return Tls13EncryptedExtensions {
                parsed: false,
                error: Some("ee_extensions_length_overruns".to_string()),
                ..Default::default()
            };
        }
    };

    let mut out = Tls13EncryptedExtensions {
        parsed: true,
        ..Default::default()
    };

    let mut i = 0;
    while i + 4 <= ext_bytes.len() {
        let ty = u16::from_be_bytes([ext_bytes[i], ext_bytes[i + 1]]);
        let len = u16::from_be_bytes([ext_bytes[i + 2], ext_bytes[i + 3]]) as usize;
        let body_end = i + 4 + len;
        if body_end > ext_bytes.len() {
            break;
        }
        let ext_body = &ext_bytes[i + 4..body_end];

        match ty {
            // RFC 8449 §4 — payload is a single uint16. Any other
            // length is ill-formed, so we skip it silently.
            EXT_RECORD_SIZE_LIMIT if ext_body.len() == 2 => {
                out.record_size_limit = Some(u16::from_be_bytes([ext_body[0], ext_body[1]]));
            }
            EXT_COMPRESS_CERTIFICATE => {
                out.compress_certificate_algorithms = parse_compress_cert_list(ext_body);
            }
            _ => {}
        }
        i = body_end;
    }
    out
}

/// Render an RFC 8879 CertificateCompressionAlgorithm codepoint as
/// its canonical name, falling back to `"0xNNNN"` for unknown codes.
fn cert_comp_name(code: u16) -> String {
    match code {
        1 => "zlib".to_string(),
        2 => "brotli".to_string(),
        3 => "zstd".to_string(),
        other => format!("0x{:04X}", other),
    }
}

/// Render an IANA SignatureScheme codepoint as its canonical name,
/// falling back to `"0xNNNN"` for unknowns. RFC 8446 §4.2.3 table.
fn signature_scheme_name(code: u16) -> String {
    match code {
        0x0201 => "rsa_pkcs1_sha1".to_string(),
        0x0203 => "ecdsa_sha1".to_string(),
        0x0401 => "rsa_pkcs1_sha256".to_string(),
        0x0403 => "ecdsa_secp256r1_sha256".to_string(),
        0x0501 => "rsa_pkcs1_sha384".to_string(),
        0x0503 => "ecdsa_secp384r1_sha384".to_string(),
        0x0601 => "rsa_pkcs1_sha512".to_string(),
        0x0603 => "ecdsa_secp521r1_sha512".to_string(),
        0x0804 => "rsa_pss_rsae_sha256".to_string(),
        0x0805 => "rsa_pss_rsae_sha384".to_string(),
        0x0806 => "rsa_pss_rsae_sha512".to_string(),
        0x0807 => "ed25519".to_string(),
        0x0808 => "ed448".to_string(),
        0x0809 => "rsa_pss_pss_sha256".to_string(),
        0x080A => "rsa_pss_pss_sha384".to_string(),
        0x080B => "rsa_pss_pss_sha512".to_string(),
        other => format!("0x{:04x}", other),
    }
}

/// Parse a captured TLS 1.3 Certificate handshake message, looking
/// for an RFC 9345 delegated_credential extension on the leaf
/// CertificateEntry. Returns `Some` when the DC extension is present
/// and the inner `DelegatedCredential` header fields parse cleanly.
///
/// Layout (RFC 8446 §4.4.2):
/// ```text
///   hs_type(1)=0x0b | hs_len(3) | ctx_len(1) | ctx<ctx_len> |
///   cert_list_len(3) | [ cert_len(3) | cert_data<cert_len> |
///                        ext_len(2) | extensions<ext_len> ]+
/// ```
/// RFC 9345 §4.1 DelegatedCredential payload (inside ext 0x0022):
/// ```text
///   valid_time(4) | expected_cert_verify_algorithm(2) |
///   pk_len(3) | public_key<pk_len> |
///   sig_alg(2) | sig_len(2) | signature<sig_len>
/// ```
/// The scanner reads `valid_time` and `expected_cert_verify_algorithm`;
/// the public-key and signature blobs are skipped.
fn parse_certificate_for_dc(raw: &[u8]) -> Option<DelegatedCredentialFacts> {
    if raw.len() < 4 || raw[0] != HANDSHAKE_TYPE_CERTIFICATE {
        return None;
    }
    let hs_len = ((raw[1] as usize) << 16) | ((raw[2] as usize) << 8) | (raw[3] as usize);
    let body = raw.get(4..4 + hs_len)?;
    // certificate_request_context<0..2^8-1>
    let (&ctx_len, rest) = body.split_first()?;
    let after_ctx = rest.get(ctx_len as usize..)?;
    // certificate_list<0..2^24-1>
    if after_ctx.len() < 3 {
        return None;
    }
    let list_len =
        ((after_ctx[0] as usize) << 16) | ((after_ctx[1] as usize) << 8) | (after_ctx[2] as usize);
    let list_body = after_ctx.get(3..3 + list_len)?;
    // Leaf entry only (first entry).
    if list_body.len() < 3 {
        return None;
    }
    let cert_len =
        ((list_body[0] as usize) << 16) | ((list_body[1] as usize) << 8) | (list_body[2] as usize);
    let after_cert = list_body.get(3 + cert_len..)?;
    if after_cert.len() < 2 {
        return None;
    }
    let ext_len = u16::from_be_bytes([after_cert[0], after_cert[1]]) as usize;
    let ext_block = after_cert.get(2..2 + ext_len)?;
    // Walk CertificateEntry extensions.
    let mut i = 0;
    while i + 4 <= ext_block.len() {
        let ty = u16::from_be_bytes([ext_block[i], ext_block[i + 1]]);
        let body_len = u16::from_be_bytes([ext_block[i + 2], ext_block[i + 3]]) as usize;
        let body_end = i + 4 + body_len;
        if body_end > ext_block.len() {
            break;
        }
        if ty == EXT_DELEGATED_CREDENTIAL {
            return parse_delegated_credential_body(&ext_block[i + 4..body_end]);
        }
        i = body_end;
    }
    None
}

/// Parse the body of the RFC 9345 `delegated_credential` extension.
/// Reads the two header fields the scanner observes and skips the
/// public-key and signature blobs.
fn parse_delegated_credential_body(body: &[u8]) -> Option<DelegatedCredentialFacts> {
    if body.len() < 6 {
        return None;
    }
    let valid_time = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let code = u16::from_be_bytes([body[4], body[5]]);
    Some(DelegatedCredentialFacts {
        valid_time_seconds: valid_time,
        expected_cert_verify_algorithm_code: code,
        expected_cert_verify_algorithm: signature_scheme_name(code),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_ee(ext_bytes: &[u8]) -> Vec<u8> {
        // HS header: type(1) + length(3), then body = ext_len(2) + ext_bytes.
        let body_len = 2 + ext_bytes.len();
        let total_len = body_len;
        let mut v = Vec::with_capacity(4 + body_len);
        v.push(HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS);
        v.push(((total_len >> 16) & 0xff) as u8);
        v.push(((total_len >> 8) & 0xff) as u8);
        v.push((total_len & 0xff) as u8);
        v.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
        v.extend_from_slice(ext_bytes);
        v
    }

    fn make_ext(ty: u16, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&ty.to_be_bytes());
        v.extend_from_slice(&(body.len() as u16).to_be_bytes());
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn parse_record_size_limit_extracts_u16() {
        let exts = make_ext(EXT_RECORD_SIZE_LIMIT, &[0x40, 0x00]); // 16384
        let ee = build_ee(&exts);
        let out = parse_encrypted_extensions(&ee);
        assert!(out.parsed);
        assert_eq!(out.record_size_limit, Some(16384));
    }

    #[test]
    fn parse_compress_certificate_lists_algorithms_by_name() {
        // length=6, then algorithms: zlib(1), brotli(2), zstd(3).
        let body = [0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03];
        let exts = make_ext(EXT_COMPRESS_CERTIFICATE, &body);
        let ee = build_ee(&exts);
        let out = parse_encrypted_extensions(&ee);
        assert!(out.parsed);
        assert_eq!(
            out.compress_certificate_algorithms,
            vec!["zlib", "brotli", "zstd"]
        );
    }

    #[test]
    fn parse_unknown_compression_code_formats_hex() {
        let body = [0x02, 0x12, 0x34];
        let exts = make_ext(EXT_COMPRESS_CERTIFICATE, &body);
        let ee = build_ee(&exts);
        let out = parse_encrypted_extensions(&ee);
        assert!(out.parsed);
        assert_eq!(out.compress_certificate_algorithms, vec!["0x1234"]);
    }

    #[test]
    fn parse_empty_extensions_marks_parsed() {
        let ee = build_ee(&[]);
        let out = parse_encrypted_extensions(&ee);
        assert!(out.parsed);
        assert_eq!(out.record_size_limit, None);
        assert!(out.compress_certificate_algorithms.is_empty());
    }

    #[test]
    fn truncated_ee_returns_error() {
        let out = parse_encrypted_extensions(&[0x08, 0x00]);
        assert!(!out.parsed);
        assert_eq!(out.error.as_deref(), Some("ee_truncated_header"));
    }

    /// Build a synthetic TLS 1.3 Certificate handshake message with a
    /// single CertificateEntry that carries a DC extension. `dc_body`
    /// is the body of ext 0x0022; `cert_der` is an arbitrary leaf DER
    /// (content doesn't matter — the parser skips it).
    fn build_certificate_msg(cert_der: &[u8], dc_body: &[u8]) -> Vec<u8> {
        // CertificateEntry extensions block: ext_type(2) + len(2) + body.
        let mut ext_block = Vec::new();
        ext_block.extend_from_slice(&EXT_DELEGATED_CREDENTIAL.to_be_bytes());
        ext_block.extend_from_slice(&(dc_body.len() as u16).to_be_bytes());
        ext_block.extend_from_slice(dc_body);

        // CertificateEntry: cert_len(3) + cert_der + ext_len(2) + exts.
        let mut entry = Vec::new();
        let cl = cert_der.len();
        entry.push(((cl >> 16) & 0xff) as u8);
        entry.push(((cl >> 8) & 0xff) as u8);
        entry.push((cl & 0xff) as u8);
        entry.extend_from_slice(cert_der);
        entry.extend_from_slice(&(ext_block.len() as u16).to_be_bytes());
        entry.extend_from_slice(&ext_block);

        // certificate_list: 3-byte length prefix + entry bytes.
        let mut list = Vec::new();
        let ll = entry.len();
        list.push(((ll >> 16) & 0xff) as u8);
        list.push(((ll >> 8) & 0xff) as u8);
        list.push((ll & 0xff) as u8);
        list.extend_from_slice(&entry);

        // body: ctx_len(1)=0 + certificate_list.
        let mut body = Vec::new();
        body.push(0x00);
        body.extend_from_slice(&list);

        // Handshake header: type(1)=11 + length(3).
        let mut v = Vec::new();
        v.push(HANDSHAKE_TYPE_CERTIFICATE);
        let bl = body.len();
        v.push(((bl >> 16) & 0xff) as u8);
        v.push(((bl >> 8) & 0xff) as u8);
        v.push((bl & 0xff) as u8);
        v.extend_from_slice(&body);
        v
    }

    #[test]
    fn parse_certificate_extracts_dc_valid_time_and_scheme() {
        // valid_time=604800 (7 days), scheme=ecdsa_secp256r1_sha256 (0x0403).
        // RFC 9345 §4.1 DelegatedCredential: valid_time(4) + scheme(2) +
        // pk_len(3) + pk + sig_alg(2) + sig_len(2) + sig. Padding
        // body with empty pk + empty sig.
        let mut dc = Vec::new();
        dc.extend_from_slice(&604_800u32.to_be_bytes());
        dc.extend_from_slice(&0x0403u16.to_be_bytes());
        dc.extend_from_slice(&[0x00, 0x00, 0x00]); // pk_len=0
        dc.extend_from_slice(&0x0403u16.to_be_bytes()); // sig_alg
        dc.extend_from_slice(&[0x00, 0x00]); // sig_len=0

        let cert_msg = build_certificate_msg(b"fake_leaf_der_bytes", &dc);
        let out = parse_certificate_for_dc(&cert_msg).expect("dc parsed");
        assert_eq!(out.valid_time_seconds, 604_800);
        assert_eq!(out.expected_cert_verify_algorithm_code, 0x0403);
        assert_eq!(out.expected_cert_verify_algorithm, "ecdsa_secp256r1_sha256");
    }

    #[test]
    fn parse_certificate_without_dc_returns_none() {
        // CertificateEntry with no extensions (ext_block empty).
        let cert_der: &[u8] = b"unused_leaf_der";
        let mut entry = Vec::new();
        entry.push(0x00);
        entry.push(0x00);
        entry.push(cert_der.len() as u8);
        entry.extend_from_slice(cert_der);
        entry.extend_from_slice(&[0x00, 0x00]); // ext_len=0

        let mut list = Vec::new();
        list.push(0x00);
        list.push(0x00);
        list.push(entry.len() as u8);
        list.extend_from_slice(&entry);

        let mut body = vec![0x00];
        body.extend_from_slice(&list);

        let mut msg = vec![HANDSHAKE_TYPE_CERTIFICATE];
        msg.push(0x00);
        msg.push(0x00);
        msg.push(body.len() as u8);
        msg.extend_from_slice(&body);

        assert!(parse_certificate_for_dc(&msg).is_none());
    }

    #[test]
    fn parse_certificate_wrong_message_type_returns_none() {
        // Msg type 11 expected; feed type 8 (EE).
        let msg = [HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, 0, 0, 0];
        assert!(parse_certificate_for_dc(&msg).is_none());
    }

    #[test]
    fn parse_delegated_credential_body_short_returns_none() {
        assert!(parse_delegated_credential_body(&[0, 1, 2, 3]).is_none());
    }

    #[test]
    fn signature_scheme_name_maps_known_codes() {
        assert_eq!(signature_scheme_name(0x0403), "ecdsa_secp256r1_sha256");
        assert_eq!(signature_scheme_name(0x0807), "ed25519");
        assert_eq!(signature_scheme_name(0x9999), "0x9999");
    }
}
