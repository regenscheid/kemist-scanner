//! Phase D3 — ServerKeyExchange / CertificateVerify signature algorithm
//! capture.
//!
//! Records the signature algorithm the server *chose* for its signed
//! handshake message. In TLS 1.2 this is the SKE signature (DHE/ECDHE);
//! in TLS 1.3 it's the CertificateVerify signature. Distinct from the
//! `signature_algorithms` extension the server advertises — that's what
//! it *accepts*; this is what it *selected*.
//!
//! Canonical string examples: `"rsa_pkcs1_sha1"`, `"rsa_pss_rsae_sha256"`,
//! `"ecdsa_secp256r1_sha256"`. Downstream Logjam / ROBOT / weak-sig rule
//! engines key on these names.
//!
//! Implementation: OpenSSL exposes `SSL_get0_peer_signature_name` as a
//! macro around `SSL_ctrl(ssl, SSL_CTRL_GET_PEER_SIGNATURE_NAME, 0, &name)`
//! (ssl.h.in:1492). `openssl-sys` exposes `SSL_ctrl` but not the
//! constant, so we inline the value. Returns non-zero on success with a
//! static OpenSSL-owned string pointer.

use std::ffi::CStr;
use std::os::raw::{c_char, c_long, c_void};

use foreign_types::ForeignTypeRef;
use openssl::ssl::SslRef;

/// Control code for `SSL_CTRL_GET_PEER_SIGNATURE_NAME`. Stable since
/// OpenSSL 3.2; we pin 3.5 LTS so it's always available. Lifted from
/// openssl-src-300.5.5+3.5.5/openssl/include/openssl/ssl.h.in:1345.
const SSL_CTRL_GET_PEER_SIGNATURE_NAME: std::os::raw::c_int = 141;

/// Capture the signature-algorithm name from a completed handshake.
///
/// Returns `Some(name)` for any handshake where the server signed a
/// ServerKeyExchange (TLS 1.2 DHE/ECDHE) or CertificateVerify (TLS 1.3).
/// Returns `None` for TLS 1.2 RSA-kex (no SKE, no signature) and in the
/// unlikely case OpenSSL hands back a null pointer despite a success
/// return code.
pub fn snapshot(ssl: &SslRef) -> Option<String> {
    let ssl_ptr: *mut openssl_sys::SSL = ssl.as_ptr();
    let mut name_ptr: *const c_char = std::ptr::null();

    // SAFETY:
    // - `ssl_ptr` is a live `*mut SSL` obtained from `SslRef::as_ptr()` —
    //   the `SslRef` borrow keeps it valid for this call.
    // - `parg` points to a valid writable `*const c_char` destination.
    //   On success OpenSSL writes a pointer to a static string it owns;
    //   we borrow it only long enough to copy via `CStr::to_str`.
    let rc = unsafe {
        openssl_sys::SSL_ctrl(
            ssl_ptr,
            SSL_CTRL_GET_PEER_SIGNATURE_NAME,
            0,
            &mut name_ptr as *mut *const c_char as *mut c_void,
        ) as c_long
    };
    if rc <= 0 || name_ptr.is_null() {
        return None;
    }

    // SAFETY: `name_ptr` is a NUL-terminated static string owned by
    // OpenSSL on success. Copy before returning to decouple lifetimes.
    let cstr = unsafe { CStr::from_ptr(name_ptr) };
    cstr.to_str().ok().map(|s| s.to_owned())
}
