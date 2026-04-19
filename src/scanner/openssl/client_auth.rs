//! Phase D7 — CertificateRequest capture. Registers a raw
//! `SSL_CTX_set_msg_callback` to intercept the CertificateRequest
//! handshake message; parses `certificate_types` (TLS 1.2 only),
//! `signature_algorithms`, CA distinguished names, and `oid_filters`
//! (TLS 1.3 extension 48). Records the server's alert on the client's
//! empty-Certificate response without sending a real client cert.
