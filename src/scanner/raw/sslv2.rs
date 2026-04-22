//! SSLv2 protocol-version probe + SERVER-HELLO cipher-spec observation.
//!
//! SSLv2 was dropped entirely from OpenSSL 3.x and has no rustls
//! representation, so probing it requires speaking the wire format
//! directly. This module sends a canned SSL 2.0 CLIENT-HELLO over raw
//! TCP and classifies the response:
//!
//! 1. Is the reply a valid SSLv2 SERVER-HELLO? (`supported: true`)
//! 2. If so, which cipher specs did the server echo back from our
//!    offer set? (`ciphers_observed`)
//!
//! SSLv2 predates SNI (which was a TLS 1.0 extension), so the
//! ClientHello carries no hostname. Servers that route by SNI cannot
//! be addressed via SSLv2 at all — any `supported: true` observation
//! here reflects a server that answered on the IP/port regardless of
//! vhost.
//!
//! Source of the wire format: the original SSL 2.0 specification
//! (unofficial Netscape draft, superseded by SSLv3/TLS). Kept as an
//! observation for legacy-system discovery; rule engines consuming
//! kemist's output treat any `supported: true` here as a critical
//! finding.

use std::net::SocketAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::info;

use crate::model::protocol::{ProtocolSupport, TlsVersion};

/// Rich SSLv2 observation — version support + cipher specs the server
/// echoed in its SERVER-HELLO. Converted to [`ProtocolSupport`] at the
/// call site for the `versions_offered` emission; the cipher list
/// flows into `tls.cipher_suites.ssl2` separately.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslV2Observation {
    pub supported: bool,
    pub ciphers_observed: Vec<SslV2Cipher>,
    pub error: Option<String>,
}

/// Single SSLv2 cipher spec — 3-byte IANA-ish code as a `u32` plus a
/// canonical name. Names follow the SSLv2 spec's `SSL_CK_*` constants
/// (e.g. `SSL_CK_RC4_128_WITH_MD5`); unknown codes render as
/// `"SSL_CK_UNKNOWN"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslV2Cipher {
    pub name: String,
    /// Cipher spec as a 3-byte big-endian value packed into a `u32`
    /// (high byte zero). Matches how SSLv2 encodes cipher specs on
    /// the wire.
    pub code: u32,
}

impl SslV2Observation {
    /// Downcast to the legacy [`ProtocolSupport`] shape used by
    /// `versions_offered`.
    pub fn to_protocol_support(&self) -> ProtocolSupport {
        ProtocolSupport {
            version: TlsVersion::Ssl2,
            supported: self.supported,
            error: self.error.clone(),
        }
    }
}

/// Probe SSLv2 support on `target`. Never errors — transport failures
/// resolve to `supported: false` with an error reason. `ciphers_observed`
/// is populated only when the server actually sends a parseable
/// SERVER-HELLO.
pub async fn probe(
    target: SocketAddr,
    _hostname: &str,
    timeout_duration: Duration,
) -> SslV2Observation {
    info!("Testing SSLv2 support with custom implementation");

    let client_hello = build_sslv2_client_hello();

    let mut stream = match timeout(timeout_duration, TcpStream::connect(&target)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return SslV2Observation {
                supported: false,
                ciphers_observed: Vec::new(),
                error: Some(format!("Failed to connect: {}", e)),
            };
        }
        Err(_) => {
            return SslV2Observation {
                supported: false,
                ciphers_observed: Vec::new(),
                error: Some("Failed to connect".to_string()),
            };
        }
    };

    if let Err(e) = stream.write_all(&client_hello).await {
        return SslV2Observation {
            supported: false,
            ciphers_observed: Vec::new(),
            error: Some(format!("Failed to send SSLv2 ClientHello: {}", e)),
        };
    }

    let mut buffer = vec![0u8; 4096];
    match timeout(Duration::from_secs(2), stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => parse_sslv2_response(&buffer[..n]),
        _ => SslV2Observation {
            supported: false,
            ciphers_observed: Vec::new(),
            error: Some("No response to SSLv2 ClientHello".to_string()),
        },
    }
}

fn build_sslv2_client_hello() -> Vec<u8> {
    // SSLv2 CLIENT-HELLO format
    let mut hello = Vec::new();

    // Length (2 bytes) - will be updated
    hello.extend_from_slice(&[0x80, 0x2e]);

    // Message Type: CLIENT-HELLO (1)
    hello.push(0x01);

    // Version: SSL 2.0 (0x0002)
    hello.extend_from_slice(&[0x00, 0x02]);

    // Cipher Spec Length
    hello.extend_from_slice(&[0x00, 0x15]);

    // Session ID Length
    hello.extend_from_slice(&[0x00, 0x00]);

    // Challenge Length
    hello.extend_from_slice(&[0x00, 0x10]);

    // Cipher Specs (7 ciphers * 3 bytes each = 21 bytes)
    hello.extend_from_slice(&[
        0x01, 0x00, 0x80, // SSL_CK_RC4_128_WITH_MD5
        0x02, 0x00, 0x80, // SSL_CK_RC4_128_EXPORT40_WITH_MD5
        0x03, 0x00, 0x80, // SSL_CK_RC2_128_CBC_WITH_MD5
        0x04, 0x00, 0x80, // SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
        0x05, 0x00, 0x80, // SSL_CK_IDEA_128_CBC_WITH_MD5
        0x06, 0x00, 0x40, // SSL_CK_DES_64_CBC_WITH_MD5
        0x07, 0x00, 0xc0, // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
    ]);

    // Challenge (16 random bytes)
    hello.extend_from_slice(&[
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00,
    ]);

    hello
}

/// Classify a response as SSLv2 SERVER-HELLO and, when present, extract
/// the cipher_specs list.
///
/// SSLv2 SERVER-HELLO layout (after the 2-byte record header):
/// ```text
///   u8  msg_type          = 0x04
///   u8  session_id_hit
///   u8  certificate_type
///   u16 server_version
///   u16 certificate_length
///   u16 cipher_specs_length
///   u16 connection_id_length
///   opaque certificate[certificate_length]
///   opaque cipher_specs[cipher_specs_length]
///   opaque connection_id[connection_id_length]
/// ```
fn parse_sslv2_response(data: &[u8]) -> SslV2Observation {
    // Record header: high bit of byte 0 == 1 indicates 2-byte length header.
    if data.len() < 3 || (data[0] & 0x80) == 0 {
        return SslV2Observation {
            supported: false,
            ciphers_observed: Vec::new(),
            error: Some("No SSLv2 response".to_string()),
        };
    }

    // msg_type lives at byte 2.
    if data[2] != 0x04 {
        return SslV2Observation {
            supported: false,
            ciphers_observed: Vec::new(),
            error: Some(format!("Unexpected SSLv2 msg_type 0x{:02x}", data[2])),
        };
    }

    // Fixed-size prefix (after msg_type byte 2):
    //   session_id_hit (1) + cert_type (1) + server_ver (2) + cert_len (2)
    //   + cs_len (2) + conn_id_len (2) = 10 bytes, so cipher_specs starts
    //   at offset 13 + cert_len.
    if data.len() < 13 {
        return SslV2Observation {
            supported: true,
            ciphers_observed: Vec::new(),
            error: Some("server_hello_truncated".to_string()),
        };
    }

    let cert_len = u16::from_be_bytes([data[7], data[8]]) as usize;
    let cs_len = u16::from_be_bytes([data[9], data[10]]) as usize;
    let cs_start = 13 + cert_len;
    let cs_end = cs_start + cs_len;

    if cs_end > data.len() || cs_len % 3 != 0 {
        return SslV2Observation {
            supported: true,
            ciphers_observed: Vec::new(),
            error: Some("cipher_specs_region_malformed".to_string()),
        };
    }

    let mut ciphers = Vec::with_capacity(cs_len / 3);
    for chunk in data[cs_start..cs_end].chunks_exact(3) {
        let code = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32);
        ciphers.push(SslV2Cipher {
            name: sslv2_cipher_name(code).to_string(),
            code,
        });
    }

    SslV2Observation {
        supported: true,
        ciphers_observed: ciphers,
        error: None,
    }
}

/// Map a 3-byte SSLv2 cipher spec to its canonical `SSL_CK_*` name.
/// Values per the SSLv2 spec / OpenSSL's legacy `ssl2.h`. Unknown
/// codes fall through to `"SSL_CK_UNKNOWN"`.
fn sslv2_cipher_name(code: u32) -> &'static str {
    match code {
        0x010080 => "SSL_CK_RC4_128_WITH_MD5",
        0x020080 => "SSL_CK_RC4_128_EXPORT40_WITH_MD5",
        0x030080 => "SSL_CK_RC2_128_CBC_WITH_MD5",
        0x040080 => "SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5",
        0x050080 => "SSL_CK_IDEA_128_CBC_WITH_MD5",
        0x060040 => "SSL_CK_DES_64_CBC_WITH_MD5",
        0x0700C0 => "SSL_CK_DES_192_EDE3_CBC_WITH_MD5",
        0x080080 => "SSL_CK_RC4_64_WITH_MD5",
        _ => "SSL_CK_UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rejects_non_sslv2_response() {
        // High bit of first byte clear → not an SSLv2 short-header record.
        let data = [0x16, 0x03, 0x03, 0x00, 0x10];
        let obs = parse_sslv2_response(&data);
        assert!(!obs.supported);
        assert!(obs.ciphers_observed.is_empty());
        assert!(obs.error.is_some());
    }

    #[test]
    fn parse_rejects_wrong_msg_type() {
        // High bit set (SSLv2 framing) but msg_type != SERVER-HELLO.
        let data = [0x80, 0x20, 0x02, 0x00, 0x00];
        let obs = parse_sslv2_response(&data);
        assert!(!obs.supported);
        assert!(obs.error.unwrap().contains("Unexpected"));
    }

    #[test]
    fn parse_extracts_three_cipher_specs() {
        // Fabricate a valid SERVER-HELLO with three known cipher specs.
        //   80 XX           record header (high bit set)
        //   04              msg_type = SERVER-HELLO
        //   00              session_id_hit
        //   01              cert_type
        //   00 02           server_version (SSLv2)
        //   00 00           cert_length = 0 (no cert for this fixture)
        //   00 09           cipher_specs_length = 9 (three 3-byte specs)
        //   00 00           connection_id_length
        //   <9 bytes>       cipher_specs
        let mut data = vec![
            0x80, 0x15, // length placeholder
            0x04, // msg_type
            0x00, 0x01, 0x00, 0x02, // session_id_hit, cert_type, server_ver
            0x00, 0x00, // cert_len
            0x00, 0x09, // cs_len
            0x00, 0x00, // conn_id_len
        ];
        // Three cipher specs.
        data.extend_from_slice(&[0x01, 0x00, 0x80]); // RC4-128 with MD5
        data.extend_from_slice(&[0x07, 0x00, 0xC0]); // 3DES with MD5
        data.extend_from_slice(&[0x02, 0x00, 0x80]); // RC4-128-EXPORT40

        let obs = parse_sslv2_response(&data);
        assert!(obs.supported);
        assert_eq!(obs.ciphers_observed.len(), 3);
        assert_eq!(obs.ciphers_observed[0].code, 0x010080);
        assert_eq!(obs.ciphers_observed[0].name, "SSL_CK_RC4_128_WITH_MD5");
        assert_eq!(obs.ciphers_observed[1].code, 0x0700C0);
        assert_eq!(
            obs.ciphers_observed[1].name,
            "SSL_CK_DES_192_EDE3_CBC_WITH_MD5"
        );
        assert_eq!(obs.ciphers_observed[2].name, "SSL_CK_RC4_128_EXPORT40_WITH_MD5");
    }

    #[test]
    fn parse_handles_malformed_cipher_specs_length() {
        // cs_len is not a multiple of 3 — malformed.
        let data = [
            0x80, 0x15, 0x04, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x01,
            0x00, 0x80, 0x02,
        ];
        let obs = parse_sslv2_response(&data);
        assert!(obs.supported); // still a SERVER-HELLO
        assert!(obs.ciphers_observed.is_empty());
        assert_eq!(obs.error.as_deref(), Some("cipher_specs_region_malformed"));
    }

    #[test]
    fn cipher_name_maps_known_codes() {
        assert_eq!(sslv2_cipher_name(0x010080), "SSL_CK_RC4_128_WITH_MD5");
        assert_eq!(sslv2_cipher_name(0x0700C0), "SSL_CK_DES_192_EDE3_CBC_WITH_MD5");
        assert_eq!(sslv2_cipher_name(0x999999), "SSL_CK_UNKNOWN");
    }
}
