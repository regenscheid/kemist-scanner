// src/scanner/legacy.rs
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
#[cfg(feature = "native-legacy")]
use tokio_native_tls::{native_tls, TlsConnector};
use tracing::info;

#[cfg(feature = "native-legacy")]
use crate::model::errors::ScannerError;
use crate::model::protocol::{ProtocolSupport, TlsVersion};

#[cfg(feature = "native-legacy")]
pub struct LegacyScanner {
    target: SocketAddr,
    hostname: String,
    timeout: Duration,
}

#[cfg(feature = "native-legacy")]
impl LegacyScanner {
    pub fn new(target: SocketAddr, hostname: String, timeout: Duration) -> Self {
        Self {
            target,
            hostname,
            timeout,
        }
    }

    pub async fn test_legacy_protocol(&self, version: TlsVersion) -> ProtocolSupport {
        info!("Testing {} support using native-tls", version);

        match self.connect_with_version(version).await {
            Ok(_) => ProtocolSupport {
                version,
                supported: true,
                error: None,
            },
            Err(e) => ProtocolSupport {
                version,
                supported: false,
                error: Some(e.to_string()),
            },
        }
    }

    async fn connect_with_version(&self, version: TlsVersion) -> Result<(), ScannerError> {
        // Create native-tls configuration
        let mut builder = native_tls::TlsConnector::builder();

        // Set protocol version
        match version {
            TlsVersion::Ssl2 => {
                return Err(ScannerError::internal(
                    "SSLv2 not supported by native-tls; use raw test_sslv2()",
                ));
            }
            TlsVersion::Ssl3 => {
                builder.min_protocol_version(Some(native_tls::Protocol::Sslv3));
                builder.max_protocol_version(Some(native_tls::Protocol::Sslv3));
            }
            TlsVersion::Tls10 => {
                builder.min_protocol_version(Some(native_tls::Protocol::Tlsv10));
                builder.max_protocol_version(Some(native_tls::Protocol::Tlsv10));
            }
            TlsVersion::Tls11 => {
                builder.min_protocol_version(Some(native_tls::Protocol::Tlsv11));
                builder.max_protocol_version(Some(native_tls::Protocol::Tlsv11));
            }
            _ => {
                return Err(ScannerError::internal(
                    "legacy.rs handles SSLv3/TLSv1.0/TLSv1.1 only; modern versions go through rustls",
                ));
            }
        }

        // Dangerous: accept all certificates (for scanning only)
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);

        let connector = builder
            .build()
            .map_err(|e| ScannerError::internal(format!("native-tls connector build: {e}")))?;
        let connector = TlsConnector::from(connector);

        let tcp_stream = match timeout(self.timeout, TcpStream::connect(&self.target)).await {
            Err(_) => return Err(ScannerError::connection_timeout("legacy tcp connect")),
            Ok(Err(e)) => return Err(ScannerError::from_io("legacy tcp connect", e)),
            Ok(Ok(s)) => s,
        };

        match timeout(self.timeout, connector.connect(&self.hostname, tcp_stream)).await {
            Err(_) => Err(ScannerError::handshake_timeout("legacy tls handshake")),
            Ok(Err(e)) => Err(ScannerError::internal(format!("native-tls handshake: {e}"))),
            Ok(Ok(_)) => Ok(()),
        }
    }

}

// SSLv2 special handling (if needed)
pub async fn test_sslv2(
    target: SocketAddr,
    _hostname: &str,
    timeout_duration: Duration,
) -> ProtocolSupport {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    info!("Testing SSLv2 support with custom implementation");

    // SSLv2 ClientHello format
    let client_hello = build_sslv2_client_hello();

    match timeout(timeout_duration, TcpStream::connect(&target)).await {
        Ok(Ok(mut stream)) => {
            // Send SSLv2 ClientHello
            if let Err(e) = stream.write_all(&client_hello).await {
                return ProtocolSupport {
                    version: TlsVersion::Ssl2,
                    supported: false,
                    error: Some(format!("Failed to send SSLv2 ClientHello: {}", e)),
                };
            }

            // Read response
            let mut buffer = vec![0u8; 1024];
            match timeout(Duration::from_secs(2), stream.read(&mut buffer)).await {
                Ok(Ok(n)) if n > 0 => {
                    // Analyze response to determine if SSLv2 is supported
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
