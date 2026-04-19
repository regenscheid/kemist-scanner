//! Phase D2 — DH parameter capture. Called as a post-handshake observer
//! after every successful DHE handshake driven by Phase D1. Captures prime
//! bit-length, generator, SHA-256 of the prime, and classifies against the
//! RFC 7919 FFDHE table (ffdhe2048…ffdhe8192) or `custom`.
