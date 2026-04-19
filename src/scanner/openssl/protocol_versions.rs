//! Phase D8 — SSLv3 / TLS 1.0 / TLS 1.1 protocol-version probing. Replaces
//! the `native-tls`-backed path in `src/scanner/legacy.rs` when the
//! `legacy-probes` feature is on. SSLv3 requires the legacy provider
//! (loaded by `LegacyRuntime`) and `set_security_level(0)`.
//!
//! SSLv2 is NOT covered here — OpenSSL 3.x dropped SSLv2 entirely; the
//! raw-bytes probe in `src/scanner/legacy.rs::test_sslv2` remains the only
//! SSLv2 probe path.
