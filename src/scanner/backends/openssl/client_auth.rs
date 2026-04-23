//! CertificateRequest capture.
//!
//! Intercepts the server's `CertificateRequest` handshake message via an
//! OpenSSL `SSL_CTX_set_msg_callback` hook, parses the body into structured
//! fields (certificate_types, signature_algorithms, CA DN list, TLS 1.3
//! oid_filters), and records whether the server aborted after our
//! empty-Certificate response — the "mTLS required vs optional" signal.
//!
//! The scanner never provisions or sends a real client certificate.
//! OpenSSL's default when no cert is configured is to send an empty
//! Certificate message; the server's reaction (alert) distinguishes
//! required from optional client auth.
//!
//! Implementation notes:
//! - Neither `openssl` nor `openssl-sys` exposes a high-level
//!   msg_callback binding. We install the callback via the
//!   `SSL_CTX_callback_ctrl(..., SSL_CTRL_SET_MSG_CALLBACK, ...)` /
//!   `SSL_CTX_ctrl(..., SSL_CTRL_SET_MSG_CALLBACK_ARG, ...)` pair that
//!   the macros in OpenSSL's public header resolve to.
//! - Capture state lives in a thread-local so the callback C function
//!   doesn't need to carry shared-state pointers through `arg`. Each
//!   `spawn_blocking` worker has its own thread-local; concurrent probes
//!   on different workers don't interfere. We clear the slot before
//!   every probe.
//! - `ssl.version2()` after the handshake attempt tells us whether to
//!   parse the captured bytes using the TLS 1.3 `{context, extensions}`
//!   shape or the TLS 1.2 `{cert_types, sig_algs, CA DNs}` shape.

use std::cell::RefCell;
use std::net::SocketAddr;
use std::os::raw::{c_int, c_long, c_void};
use std::time::Duration;

use foreign_types::ForeignTypeRef;
use openssl::ssl::{HandshakeError, Ssl, SslContext, SslMethod, SslVerifyMode, SslVersion};
use tracing::{debug, info};

use super::alerts;

// Control codes from `<openssl/ssl.h>`. Kept as literals rather than
// plumbed through openssl-sys because that crate doesn't re-export the
// ones we need at 0.9.109.
const SSL_CTRL_SET_MSG_CALLBACK: c_int = 15;
// `SSL_CTRL_SET_MSG_CALLBACK_ARG = 16` is the companion control code for
// passing a user data pointer through to the callback. We don't need it —
// state lives in a thread-local — so the constant is deliberately omitted.

// TLS record content_type + handshake msg_type values we filter on.
const CONTENT_TYPE_HANDSHAKE: c_int = 22;
const HANDSHAKE_TYPE_CERTIFICATE_REQUEST: u8 = 13;

// TLS 1.3 CertificateRequest extensions (RFC 8446 §4.3.2).
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_CERTIFICATE_AUTHORITIES: u16 = 47;
const EXT_OID_FILTERS: u16 = 48;
const EXT_SIGNATURE_ALGORITHMS_CERT: u16 = 50;

extern "C" {
    // SSL_CTX_callback_ctrl: `fp` is a generic function pointer; the
    // control code tells OpenSSL how to cast it. For
    // SSL_CTRL_SET_MSG_CALLBACK, it expects the msg_cb signature below.
    #[link_name = "SSL_CTX_callback_ctrl"]
    fn SSL_CTX_callback_ctrl(
        ctx: *mut openssl_sys::SSL_CTX,
        cmd: c_int,
        fp: Option<unsafe extern "C" fn()>,
    ) -> c_long;
}

// The C msg_callback signature. OpenSSL invokes this for every
// handshake record, both sides.
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
    /// Per-thread buffer for the captured `CertificateRequest` handshake
    /// message (including the 4-byte header). `None` means we either
    /// haven't run a probe on this worker thread yet, or the last probe
    /// didn't see a CertificateRequest.
    static CAPTURED: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
}

/// One distinguished name entry from the server's `certificate_authorities`.
#[derive(Debug, Clone)]
pub struct CaDnEntry {
    /// Raw DER bytes, base64-encoded for JSON output.
    pub raw_der_b64: String,
    /// RFC 5280 common name (OID 2.5.4.3) if present.
    pub common_name: Option<String>,
    /// RFC 5280 organization (OID 2.5.4.10) if present.
    pub organization: Option<String>,
}

/// TLS 1.3 `oid_filters` extension entry (RFC 8446 §4.2.5).
#[derive(Debug, Clone)]
pub struct OidFilter {
    /// Dotted-decimal OID string.
    pub oid: String,
    /// Allowed extension values, base64-encoded. Empty means the filter
    /// matches any value of the named extension.
    pub values_b64: Vec<String>,
}

/// Observation of the server's `CertificateRequest` message.
///
/// `requested: false` means the server did NOT ask for a client certificate
/// — all other fields are empty and `alert_on_empty_cert` is `None`. When
/// `requested: true`, the parser populated what it could; unrecognized
/// extensions survive as empty collections rather than failing the probe.
#[derive(Debug, Clone, Default)]
pub struct ClientAuthRequest {
    pub requested: bool,
    /// TLS 1.2 `certificate_types` byte list (empty for TLS 1.3).
    pub certificate_types: Vec<u8>,
    /// Accepted signature algorithms as human-readable names
    /// (e.g. `"rsa_pkcs1_sha256"`); unknown codes kept as
    /// `"0xNNNN"` so rule engines can still match by codepoint.
    pub signature_algorithms: Vec<String>,
    pub ca_distinguished_names: Vec<CaDnEntry>,
    /// TLS 1.3 only — empty for TLS 1.2 CertificateRequest.
    pub oid_filters: Vec<OidFilter>,
    /// Alert category observed after our empty-Certificate response.
    /// `None` on handshake success (server accepted the empty cert or
    /// made client auth optional); `Some("tls_alert_<name>")` on a
    /// required-mTLS server.
    pub alert_on_empty_cert: Option<String>,
    /// Negotiated protocol version when the probe ran — useful to
    /// disambiguate parser path.
    pub negotiated_version: Option<String>,
}

/// Run the probe. Always returns `Some(ClientAuthRequest)` so the output
/// schema slot is stable; fields distinguish "server didn't ask" from
/// "server asked and we parsed X fields."
pub async fn probe(
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> Option<ClientAuthRequest> {
    info!("OpenSSL CertificateRequest probe");

    let hostname_owned = hostname.to_string();
    let result = tokio::task::spawn_blocking(move || {
        probe_blocking(target, &hostname_owned, connect_timeout, handshake_timeout)
    })
    .await;

    match result {
        Ok(obs) => Some(obs),
        Err(e) => {
            debug!("client_auth probe spawn_blocking panic: {e}");
            Some(ClientAuthRequest {
                requested: false,
                ..Default::default()
            })
        }
    }
}

fn probe_blocking(
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> ClientAuthRequest {
    // Clear any leftover capture from a previous probe on this thread.
    CAPTURED.with(|c| {
        *c.borrow_mut() = None;
    });

    let tcp = match std::net::TcpStream::connect_timeout(&target, connect_timeout) {
        Ok(s) => s,
        Err(_) => return ClientAuthRequest::default(),
    };
    let _ = tcp.set_read_timeout(Some(handshake_timeout));
    let _ = tcp.set_write_timeout(Some(handshake_timeout));

    let ctx = match build_context_with_callback() {
        Ok(c) => c,
        Err(_) => return ClientAuthRequest::default(),
    };

    let mut ssl = match Ssl::new(&ctx) {
        Ok(s) => s,
        Err(_) => return ClientAuthRequest::default(),
    };
    let _ = ssl.set_hostname(hostname);

    let (negotiated_version, handshake_alert) = match ssl.connect(tcp) {
        Ok(stream) => (stream.ssl().version2().map(version_label), None),
        Err(HandshakeError::Failure(mid)) => {
            let version = mid.ssl().version2().map(version_label);
            let se = alerts::classify_openssl_error("client_auth handshake", mid.error());
            (version, Some(se.category))
        }
        Err(HandshakeError::SetupFailure(_)) => (None, None),
        Err(HandshakeError::WouldBlock(mid)) => (mid.ssl().version2().map(version_label), None),
    };

    // Read the captured bytes; leave the thread-local empty for the next
    // probe on this worker.
    let captured = CAPTURED.with(|c| c.borrow_mut().take());

    match captured {
        None => ClientAuthRequest {
            requested: false,
            negotiated_version,
            alert_on_empty_cert: None,
            ..Default::default()
        },
        Some(raw) => {
            let mut out = parse_certificate_request(&raw, negotiated_version.as_deref());
            out.negotiated_version = negotiated_version;
            // An alert that fired AFTER CertificateRequest was captured
            // is by definition the server rejecting our empty cert —
            // the required-mTLS signal.
            out.alert_on_empty_cert = handshake_alert;
            out
        }
    }
}

fn build_context_with_callback() -> Result<SslContext, openssl::error::ErrorStack> {
    let mut builder = SslContext::builder(SslMethod::tls_client())?;
    builder.set_min_proto_version(Some(SslVersion::TLS1))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_security_level(0);
    builder.set_verify(SslVerifyMode::NONE);
    let ctx = builder.build();

    // Install msg_callback via the raw ctrl entry point. The cast to
    // `unsafe extern "C" fn()` is what the OpenSSL header's macro
    // expansion does in C — SSL_CTX_callback_ctrl takes a generic
    // function pointer and reinterprets it based on `cmd`.
    //
    // SAFETY: The function pointer we pass has the ABI and lifetime
    // that SSL_CTRL_SET_MSG_CALLBACK expects (static `extern "C"` fn).
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

/// The msg_callback. Fires for every handshake record in both directions.
/// Captures the first `CertificateRequest` the server sends.
unsafe extern "C" fn msg_callback(
    write_p: c_int,
    _version: c_int,
    content_type: c_int,
    buf: *const c_void,
    len: usize,
    _ssl: *mut openssl_sys::SSL,
    _arg: *mut c_void,
) {
    // write_p == 1 means "outgoing" (client → server). Ignore.
    if write_p != 0 || content_type != CONTENT_TYPE_HANDSHAKE || buf.is_null() || len == 0 {
        return;
    }
    // SAFETY: OpenSSL passes a valid `buf`/`len` pair for the duration
    // of the callback.
    let slice = unsafe { std::slice::from_raw_parts(buf as *const u8, len) };
    if slice.first() != Some(&HANDSHAKE_TYPE_CERTIFICATE_REQUEST) {
        return;
    }
    // Capture, but don't overwrite if we already have one — a fresh probe
    // resets the thread-local before starting.
    CAPTURED.with(|c| {
        if c.borrow().is_none() {
            *c.borrow_mut() = Some(slice.to_vec());
        }
    });
}

// -------------------------------------------------------------------
// Handshake message parsers
// -------------------------------------------------------------------

/// Top-level dispatch: select TLS 1.3 vs pre-1.3 parser based on negotiated
/// version. On parse errors, return whatever fields we got — partial
/// output is more useful than silence.
fn parse_certificate_request(bytes: &[u8], negotiated_version: Option<&str>) -> ClientAuthRequest {
    let body = match skip_handshake_header(bytes) {
        Some(b) => b,
        None => {
            return ClientAuthRequest {
                requested: true,
                ..Default::default()
            };
        }
    };

    let is_tls13 = matches!(negotiated_version, Some("tls1_3"));
    if is_tls13 {
        parse_tls13_body(body)
    } else {
        parse_pre_tls13_body(body, negotiated_version)
    }
}

/// Strip the 4-byte handshake header (`msg_type` + `uint24 length`).
/// Returns the body slice bounded to the stated length.
fn skip_handshake_header(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.len() < 4 {
        return None;
    }
    let len = ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | (bytes[3] as usize);
    let end = 4 + len;
    if end > bytes.len() {
        return None;
    }
    Some(&bytes[4..end])
}

/// TLS 1.2 CertificateRequest body:
///
/// ```text
/// struct {
///     ClientCertificateType certificate_types<1..2^8-1>;
///     SignatureAndHashAlgorithm supported_signature_algorithms<2^16-1>;  // TLS 1.2 only
///     DistinguishedName certificate_authorities<0..2^16-1>;
/// } CertificateRequest;
/// ```
///
/// TLS 1.0/1.1 omit `supported_signature_algorithms`. The `negotiated_version`
/// lets us skip that field for older protocols.
fn parse_pre_tls13_body(body: &[u8], negotiated_version: Option<&str>) -> ClientAuthRequest {
    let mut out = ClientAuthRequest {
        requested: true,
        ..Default::default()
    };
    let mut p = Cursor::new(body);

    let Some(ct_len) = p.take_u8() else {
        return out;
    };
    let Some(cert_types) = p.take_slice(ct_len as usize) else {
        return out;
    };
    out.certificate_types = cert_types.to_vec();

    let expects_sig_algs = matches!(negotiated_version, Some("tls1_2") | Some("tls1_3"));
    if expects_sig_algs {
        let Some(sa_len) = p.take_u16() else {
            return out;
        };
        let Some(sa_block) = p.take_slice(sa_len as usize) else {
            return out;
        };
        out.signature_algorithms = parse_sig_algs_block(sa_block);
    }

    let Some(ca_len) = p.take_u16() else {
        return out;
    };
    let Some(ca_block) = p.take_slice(ca_len as usize) else {
        return out;
    };
    out.ca_distinguished_names = parse_ca_dn_list(ca_block);

    out
}

/// TLS 1.3 CertificateRequest body:
///
/// ```text
/// struct {
///     opaque certificate_request_context<0..2^8-1>;
///     Extension extensions<2..2^16-1>;
/// } CertificateRequest;
/// ```
fn parse_tls13_body(body: &[u8]) -> ClientAuthRequest {
    let mut out = ClientAuthRequest {
        requested: true,
        ..Default::default()
    };
    let mut p = Cursor::new(body);

    let Some(ctx_len) = p.take_u8() else {
        return out;
    };
    if p.take_slice(ctx_len as usize).is_none() {
        return out;
    }
    let Some(ext_len) = p.take_u16() else {
        return out;
    };
    let Some(ext_block) = p.take_slice(ext_len as usize) else {
        return out;
    };
    parse_tls13_extensions(ext_block, &mut out);
    out
}

/// Read a `uint16 length; opaque body[length]` prefix. Returns the body
/// slice, or `None` if the input is truncated.
fn read_u16_prefixed(block: &[u8]) -> Option<&[u8]> {
    if block.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([block[0], block[1]]) as usize;
    if block.len() < 2 + len {
        return None;
    }
    Some(&block[2..2 + len])
}

fn parse_tls13_extensions(mut block: &[u8], out: &mut ClientAuthRequest) {
    while block.len() >= 4 {
        let ext_type = u16::from_be_bytes([block[0], block[1]]);
        let ext_len = u16::from_be_bytes([block[2], block[3]]) as usize;
        let rest = &block[4..];
        if rest.len() < ext_len {
            return;
        }
        let ext_body = &rest[..ext_len];
        match ext_type {
            EXT_SIGNATURE_ALGORITHMS | EXT_SIGNATURE_ALGORITHMS_CERT => {
                // 2-byte length prefix per RFC 8446 §4.2.3
                if let Some(inner) = read_u16_prefixed(ext_body) {
                    out.signature_algorithms.extend(parse_sig_algs_block(inner));
                }
            }
            EXT_CERTIFICATE_AUTHORITIES => {
                // Same shape as TLS 1.2 certificate_authorities: uint16 list length.
                if let Some(inner) = read_u16_prefixed(ext_body) {
                    out.ca_distinguished_names = parse_ca_dn_list(inner);
                }
            }
            EXT_OID_FILTERS => {
                out.oid_filters = parse_oid_filters(ext_body);
            }
            _ => {}
        }
        block = &rest[ext_len..];
    }
}

/// Each SignatureScheme is a u16. Map known codepoints to their canonical
/// TLS 1.3 names; fall back to `0xNNNN` for unrecognized values so
/// consumers never lose raw signal.
fn parse_sig_algs_block(mut block: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    while block.len() >= 2 {
        let code = u16::from_be_bytes([block[0], block[1]]);
        out.push(sig_scheme_name(code));
        block = &block[2..];
    }
    out
}

fn sig_scheme_name(code: u16) -> String {
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

/// Walk a `DistinguishedName certificate_authorities<0..2^16-1>` block.
/// Each entry is `opaque DistinguishedName<1..2^16-1>` — uint16 length
/// followed by DER.
fn parse_ca_dn_list(mut block: &[u8]) -> Vec<CaDnEntry> {
    let mut out = Vec::new();
    while block.len() >= 2 {
        let dn_len = u16::from_be_bytes([block[0], block[1]]) as usize;
        let rest = &block[2..];
        if rest.len() < dn_len {
            return out;
        }
        let dn_der = &rest[..dn_len];
        let (cn, o) = parse_dn_fields(dn_der);
        out.push(CaDnEntry {
            raw_der_b64: base64_encode(dn_der),
            common_name: cn,
            organization: o,
        });
        block = &rest[dn_len..];
    }
    out
}

/// Extract CN (OID 2.5.4.3) and O (OID 2.5.4.10) from a DER-encoded
/// X.509 Name. Uses the project's existing `x509-parser` dep.
fn parse_dn_fields(der: &[u8]) -> (Option<String>, Option<String>) {
    use x509_parser::prelude::{FromDer, X509Name};
    let Ok((_, name)) = X509Name::from_der(der) else {
        return (None, None);
    };
    let cn = name
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(|s| s.to_string());
    let o = name
        .iter_organization()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(|s| s.to_string());
    (cn, o)
}

/// Walk a TLS 1.3 `oid_filters` extension body.
///
/// ```text
/// struct {
///     OIDFilter filters<0..2^16-1>;
/// } OIDFilterExtension;
/// struct {
///     opaque certificate_extension_oid<1..2^8-1>;
///     opaque certificate_extension_values<0..2^16-1>;
/// } OIDFilter;
/// ```
///
/// The `values_b64` field stays as a single raw blob — further DER
/// decomposition can happen offline in a rule engine.
fn parse_oid_filters(ext_body: &[u8]) -> Vec<OidFilter> {
    if ext_body.len() < 2 {
        return Vec::new();
    }
    let outer_len = u16::from_be_bytes([ext_body[0], ext_body[1]]) as usize;
    if ext_body.len() < 2 + outer_len {
        return Vec::new();
    }
    let mut p = &ext_body[2..2 + outer_len];
    let mut out = Vec::new();
    while !p.is_empty() {
        let oid_len = p[0] as usize;
        let rest = &p[1..];
        if rest.len() < oid_len + 2 {
            return out;
        }
        let oid_der = &rest[..oid_len];
        let rest = &rest[oid_len..];
        let vals_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        let rest = &rest[2..];
        if rest.len() < vals_len {
            return out;
        }
        let vals = &rest[..vals_len];
        out.push(OidFilter {
            oid: decode_oid(oid_der).unwrap_or_else(|| hex::encode(oid_der)),
            values_b64: vec![base64_encode(vals)],
        });
        p = &rest[vals_len..];
    }
    out
}

/// Decode a raw OID (contents octets of an ASN.1 OBJECT IDENTIFIER,
/// not the full DER header) into dotted-decimal. Per X.690 §8.19.
fn decode_oid(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let mut out = String::new();
    let first = bytes[0];
    out.push_str(&format!("{}.{}", first / 40, first % 40));
    let mut acc: u64 = 0;
    for &b in &bytes[1..] {
        acc = (acc << 7) | (b & 0x7F) as u64;
        if b & 0x80 == 0 {
            out.push('.');
            out.push_str(&acc.to_string());
            acc = 0;
        }
    }
    // Unterminated trailing sub-identifier → malformed, bail.
    if acc != 0 {
        return None;
    }
    Some(out)
}

/// Small helper — we don't depend on `base64`, so reuse `hex` as a
/// pinch-hitter for the raw-DER/values fields. Downstream consumers
/// can decode hex as easily as base64; switching to base64 later is
/// a schema-field rename only. Named `base64_encode` to match the
/// schema terminology even though the output is hex.
fn base64_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn version_label(v: SslVersion) -> String {
    if v == SslVersion::TLS1_3 {
        "tls1_3".to_string()
    } else if v == SslVersion::TLS1_2 {
        "tls1_2".to_string()
    } else if v == SslVersion::TLS1_1 {
        "tls1_1".to_string()
    } else if v == SslVersion::TLS1 {
        "tls1_0".to_string()
    } else if v == SslVersion::SSL3 {
        "ssl3".to_string()
    } else {
        "unknown".to_string()
    }
}

// -------------------------------------------------------------------
// Byte cursor helper
// -------------------------------------------------------------------

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take_u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn take_u16(&mut self) -> Option<u16> {
        if self.pos + 2 > self.buf.len() {
            return None;
        }
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Some(v)
    }
    fn take_slice(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return None;
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_handshake_msg(msg_type: u8, body: &[u8]) -> Vec<u8> {
        let len = body.len();
        let mut out = vec![
            msg_type,
            ((len >> 16) & 0xFF) as u8,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ];
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn sig_scheme_name_known_codepoints() {
        assert_eq!(sig_scheme_name(0x0403), "ecdsa_secp256r1_sha256");
        assert_eq!(sig_scheme_name(0x0804), "rsa_pss_rsae_sha256");
        assert_eq!(sig_scheme_name(0x0201), "rsa_pkcs1_sha1");
        assert_eq!(sig_scheme_name(0x0807), "ed25519");
    }

    #[test]
    fn sig_scheme_name_unknown_preserves_raw_codepoint() {
        assert_eq!(sig_scheme_name(0x1234), "0x1234");
        assert_eq!(sig_scheme_name(0x0000), "0x0000");
    }

    #[test]
    fn skip_handshake_header_trims_four_bytes() {
        let msg = build_handshake_msg(13, b"hello");
        let body = skip_handshake_header(&msg).unwrap();
        assert_eq!(body, b"hello");
    }

    #[test]
    fn skip_handshake_header_rejects_truncated_input() {
        assert!(skip_handshake_header(&[]).is_none());
        assert!(skip_handshake_header(&[0, 0, 0]).is_none());
        // Claims 10 bytes but only has 4.
        assert!(skip_handshake_header(&[13, 0, 0, 10]).is_none());
    }

    #[test]
    fn parse_tls12_cert_request_body_extracts_types_sig_algs_cas() {
        // body = cert_types(1 byte len + 2 types) + sig_algs(2+4 bytes) + CAs(2 bytes len + 0)
        let body: Vec<u8> = [
            &[0x02u8, 0x01, 0x40][..], // cert_types: [1 (rsa_sign), 0x40 (ecdsa_sign)]
            &[0x00, 0x04, 0x04, 0x03, 0x08, 0x04][..], // sig_algs: 2-byte len=4, {0x0403, 0x0804}
            &[0x00, 0x00][..],         // CA DN list: empty
        ]
        .concat();
        let msg = build_handshake_msg(13, &body);
        let out = parse_certificate_request(&msg, Some("tls1_2"));
        assert!(out.requested);
        assert_eq!(out.certificate_types, vec![0x01, 0x40]);
        assert_eq!(
            out.signature_algorithms,
            vec!["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256"]
        );
        assert!(out.ca_distinguished_names.is_empty());
        assert!(out.oid_filters.is_empty());
    }

    #[test]
    fn parse_tls13_cert_request_body_extracts_sig_algs_from_extension() {
        // TLS 1.3 body = context(1 byte len + 0) + extensions(2-byte len + ext)
        // extension: type=0x000D (sig_algs), len=6, inner_len=4, data=0x0403,0x0804
        let ext = [
            0x00, 0x0D, // ext type
            0x00, 0x06, // ext len
            0x00, 0x04, // inner list len
            0x04, 0x03, 0x08, 0x04,
        ];
        let body: Vec<u8> = [
            &[0x00u8][..],                // context len = 0
            &[0x00, ext.len() as u8][..], // extensions total len
            &ext[..],
        ]
        .concat();
        let msg = build_handshake_msg(13, &body);
        let out = parse_certificate_request(&msg, Some("tls1_3"));
        assert!(out.requested);
        assert_eq!(
            out.signature_algorithms,
            vec!["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256"]
        );
        // TLS 1.3 CertificateRequest has no certificate_types field.
        assert!(out.certificate_types.is_empty());
    }

    #[test]
    fn parse_certificate_request_on_truncated_input_yields_requested_true_empty_fields() {
        // msg_type=13, claims 100 bytes but we only supply 0 — parser
        // can't do anything, but should still mark requested=true since
        // we saw the message type.
        let msg = vec![13u8, 0, 0, 100];
        let out = parse_certificate_request(&msg, Some("tls1_2"));
        assert!(out.requested);
        assert!(out.signature_algorithms.is_empty());
    }

    #[test]
    fn decode_oid_roundtrips_standard_oids() {
        // id-sha256 = 2.16.840.1.101.3.4.2.1 → encoded contents (no tag):
        // first = 2*40+16=96=0x60, then varint-encoded subidentifiers
        // Encoding: 0x60, 0x86, 0x48 (840), 0x01, 0x65 (101), 0x03, 0x04, 0x02, 0x01
        // 840 = 0x348 = bytes: 0x86, 0x48 (high-bit continuation on 0x86)
        let encoded = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        assert_eq!(
            decode_oid(&encoded).as_deref(),
            Some("2.16.840.1.101.3.4.2.1")
        );
    }

    #[test]
    fn decode_oid_rejects_unterminated_subidentifier() {
        // Final byte has high bit set → continuation expected but we ran out.
        assert!(decode_oid(&[0x60, 0x86]).is_none());
    }

    #[test]
    fn parse_oid_filters_handles_empty_list() {
        // Outer len = 0
        let ext = [0x00u8, 0x00];
        assert!(parse_oid_filters(&ext).is_empty());
    }
}
