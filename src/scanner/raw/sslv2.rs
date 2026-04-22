//! SSLv2 protocol-version probe via hand-crafted ClientHello.
//!
//! SSLv2 was dropped entirely from OpenSSL 3.x and has no rustls
//! representation, so probing it requires speaking the wire format
//! directly. This module sends a canned SSL 2.0 CLIENT-HELLO over raw
//! TCP and classifies the response byte-pattern as a SERVER-HELLO
//! (`supported: true`) or anything else (`supported: false`).
//!
//! Source of the wire format: the original SSL 2.0 specification
//! (unofficial Netscape draft, superseded by SSLv3/TLS). Kept as an
//! observation for legacy-system discovery; rule engines consuming
//! kemist's output treat any `supported: true` here as a critical
//! finding.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::info;

use crate::model::protocol::{ProtocolSupport, TlsVersion};

/// Probe SSLv2 support on `target`. Returns a `ProtocolSupport`
/// keyed on `TlsVersion::Ssl2`. Never errors — transport/handshake
/// failures resolve to `supported: false` with a human-readable
/// reason string.
pub async fn probe(
    target: SocketAddr,
    _hostname: &str,
    timeout_duration: Duration,
) -> ProtocolSupport {
    info!("Testing SSLv2 support with custom implementation");

    let client_hello = build_sslv2_client_hello();

    match timeout(timeout_duration, TcpStream::connect(&target)).await {
        Ok(Ok(mut stream)) => {
            if let Err(e) = stream.write_all(&client_hello).await {
                return ProtocolSupport {
                    version: TlsVersion::Ssl2,
                    supported: false,
                    error: Some(format!("Failed to send SSLv2 ClientHello: {}", e)),
                };
            }

            let mut buffer = vec![0u8; 1024];
            match timeout(Duration::from_secs(2), stream.read(&mut buffer)).await {
                Ok(Ok(n)) if n > 0 => {
                    let supported = is_sslv2_response(&buffer[..n]);
                    ProtocolSupport {
                        version: TlsVersion::Ssl2,
                        supported,
                        error: if supported {
                            None
                        } else {
                            Some("No SSLv2 response".to_string())
                        },
                    }
                }
                _ => ProtocolSupport {
                    version: TlsVersion::Ssl2,
                    supported: false,
                    error: Some("No response to SSLv2 ClientHello".to_string()),
                },
            }
        }
        _ => ProtocolSupport {
            version: TlsVersion::Ssl2,
            supported: false,
            error: Some("Failed to connect".to_string()),
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
        0x01, 0x00, 0x80, // SSL2_RC4_128_WITH_MD5
        0x02, 0x00, 0x80, // SSL2_RC4_128_EXPORT40_WITH_MD5
        0x03, 0x00, 0x80, // SSL2_RC2_128_CBC_WITH_MD5
        0x04, 0x00, 0x80, // SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
        0x05, 0x00, 0x80, // SSL2_IDEA_128_CBC_WITH_MD5
        0x06, 0x00, 0x40, // SSL2_DES_64_CBC_WITH_MD5
        0x07, 0x00, 0xc0, // SSL2_DES_192_EDE3_CBC_WITH_MD5
    ]);

    // Challenge (16 random bytes)
    hello.extend_from_slice(&[
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00,
    ]);

    hello
}

fn is_sslv2_response(data: &[u8]) -> bool {
    // Check if it's a valid SSLv2 response
    if data.len() < 3 {
        return false;
    }

    // SSLv2 format: the highest bit of the first byte should be 1
    if data[0] & 0x80 == 0 {
        return false;
    }

    // Check if message type is SERVER-HELLO (4)
    if data.len() > 2 && data[2] == 0x04 {
        return true;
    }

    false
}
