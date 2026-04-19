//! Shared OpenSSL error → `ScannerError` classifier. Populated in Phase C.
//!
//! Parallel to `src/scanner/ciphers.rs::classify_probe_error` on the rustls
//! side — inspects `openssl::ssl::Error` + `ErrorStack` for TLS alert codes
//! and emits `tls_alert_<snake_name>` categories that match the rustls
//! path's wire format.
