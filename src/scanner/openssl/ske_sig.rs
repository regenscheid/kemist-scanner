//! Phase D3 — ServerKeyExchange / CertificateVerify signature algorithm
//! capture.
//!
//! Records the signature algorithm the server *chose* for its signed
//! handshake message. In TLS 1.2 this is the SKE signature (DHE/ECDHE);
//! in TLS 1.3 it's the CertificateVerify signature. Distinct from the
//! `signature_algorithms` extension the server advertises — that's what
//! it *accepts*; this is what it *selected*. Under D1's per-version
//! cipher-probe surface we only see the TLS 1.2 case; the function itself
//! works for TLS 1.3 too, so Phase D7's client-auth probe path reuses it.
//!
//! Canonical string examples: `"rsa_pkcs1_sha1"`, `"rsa_pss_rsae_sha256"`,
//! `"ecdsa_secp256r1_sha256"`. Values downstream Logjam / ROBOT / weak-sig
//! rule engines key on.
//!
//! Implementation: raw FFI to `SSL_get0_peer_signature_name` (OpenSSL 3.2+).
//! The `openssl` Rust crate does not expose this at 0.10.73, so we declare
//! the prototype inline. Safe because our vendored openssl-src is pinned to
//! 3.5.5 LTS where the symbol is present.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

use foreign_types::ForeignTypeRef;
use openssl::ssl::SslRef;

extern "C" {
    /// OpenSSL 3.2+ accessor. Returns 1 when the peer signed a handshake
    /// message and the name could be written to `*name`; 0 otherwise.
    /// `*name` borrows a static OpenSSL-owned string — do not free.
    fn SSL_get0_peer_signature_name(
        ssl: *const openssl_sys::SSL,
        name: *mut *const c_char,
    ) -> c_int;
}

/// Capture the signature-algorithm name from a completed handshake.
///
/// Returns `Some(name)` for any handshake where the server signed a
/// ServerKeyExchange (TLS 1.2 DHE/ECDHE) or CertificateVerify (TLS 1.3).
/// Returns `None` for TLS 1.2 RSA-kex (no SKE, no signature) and in the
/// unlikely case OpenSSL hands back a null pointer despite a success
/// return code.
pub fn snapshot(ssl: &SslRef) -> Option<String> {
    let ssl_ptr: *const openssl_sys::SSL = ssl.as_ptr();
    let mut name_ptr: *const c_char = std::ptr::null();

    // SAFETY:
    // - `ssl_ptr` is a live `*mut SSL` obtained from `SslRef::as_ptr()` —
    //   the `SslRef` borrow keeps it valid for this call.
    // - `&mut name_ptr` is a valid writable `*mut *const c_char`.
    // - On success the callee writes an OpenSSL-owned static string pointer
    //   into `name_ptr`; we borrow it but never free.
    let rc = unsafe { SSL_get0_peer_signature_name(ssl_ptr, &mut name_ptr) };
    if rc != 1 || name_ptr.is_null() {
        return None;
    }

    // SAFETY: on success, `name_ptr` is a NUL-terminated static string
    // owned by OpenSSL. We make a copy before returning so the lifetime
    // is independent of the SSL object.
    let cstr = unsafe { CStr::from_ptr(name_ptr) };
    cstr.to_str().ok().map(|s| s.to_owned())
}
