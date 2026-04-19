//! Phase D4 — FFDHE named-group probing (RFC 7919) for TLS 1.2 and 1.3.
//!
//! aws-lc-rs does not implement FFDHE arithmetic, so `src/scanner/groups.rs`
//! cannot probe these codepoints — this subsystem owns them. Cross-checks
//! the observed prime (via D2) against the advertised group to detect
//! servers that ignore `supported_groups` and hand out custom DH parameters
//! anyway.
