//! Raw-socket protocol probes that bypass TLS libraries entirely.
//!
//! Hosts probes whose wire format can't be driven through rustls or
//! OpenSSL — SSLv2 (no library implementation), the byte-level
//! ServerHello extension observer, and the Heartbleed probe. All share
//! a pattern of building a TCP record manually, sending it, and
//! classifying the bytes that come back.

pub mod heartbleed;
pub mod sslv2;
pub mod static_dh;
