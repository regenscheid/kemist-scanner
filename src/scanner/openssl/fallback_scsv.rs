//! Phase D5 — TLS_FALLBACK_SCSV (RFC 7507) enforcement probe. Sends a
//! handshake with `SSL_MODE_SEND_FALLBACK_SCSV` and `max_proto_version`
//! below the server's known maximum; records `enforced` iff the server
//! responds with `inappropriate_fallback` (alert 86).
//!
//! Supersedes the heuristic stub at `src/scanner/mod.rs::test_fallback_scsv`
//! which always returned `Some(true)` based on TLS 1.3 availability.
