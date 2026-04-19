//! Phase D6 — Client-initiated renegotiation probe. After a completed
//! TLS 1.2 handshake, calls `SSL_renegotiate` and observes whether the
//! server honors it or emits `no_renegotiation` (alert 100). TLS 1.3
//! connections are reported as `NotAttempted` — the protocol removed
//! renegotiation entirely.
//!
//! Supersedes the heuristic stub at
//! `src/scanner/mod.rs::test_secure_renegotiation`.
