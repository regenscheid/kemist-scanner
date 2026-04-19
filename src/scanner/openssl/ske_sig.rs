//! Phase D3 — TLS 1.2 ServerKeyExchange signature algorithm capture.
//! Records the signature algorithm the server actually chose (via
//! `SSL_get0_peer_signature_name`, stable since OpenSSL 3.0), distinct from
//! the `signature_algorithms` extension the server advertises.
