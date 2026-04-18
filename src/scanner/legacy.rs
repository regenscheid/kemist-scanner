// src/scanner/legacy.rs
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_native_tls::{native_tls, TlsConnector};
use tracing::info;

use crate::model::cipher::CipherInfo;
use crate::model::protocol::{ProtocolSupport, TlsVersion};

pub struct LegacyScanner {
    target: SocketAddr,
    hostname: String,
    timeout: Duration,
}

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

    async fn connect_with_version(&self, version: TlsVersion) -> Result<()> {
        // Create native-tls configuration
        let mut builder = native_tls::TlsConnector::builder();

        // Set protocol version
        match version {
            TlsVersion::Ssl2 => {
                // SSLv2 is usually not supported by modern libraries
                return Err(anyhow::anyhow!("SSLv2 not supported by native-tls"));
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
            _ => return Err(anyhow::anyhow!("Use rustls for TLS 1.2+")),
        }

        // Dangerous: accept all certificates (for scanning only)
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);

        let connector = builder.build()?;
        let connector = TlsConnector::from(connector);

        // Establish TCP connection
        let tcp_stream = timeout(self.timeout, TcpStream::connect(&self.target))
            .await
            .context("Connection timeout")?
            .context("Failed to establish TCP connection")?;

        // TLS handshake
        let _tls_stream = timeout(self.timeout, connector.connect(&self.hostname, tcp_stream))
            .await
            .context("TLS handshake timeout")?
            .context("TLS handshake failed")?;

        Ok(())
    }

    #[allow(dead_code)]
    pub async fn test_legacy_ciphers(&self, version: TlsVersion) -> Result<Vec<CipherInfo>> {
        // Enumerate cipher suites through OpenSSL
        // This requires lower-level implementation
        let ciphers = match version {
            TlsVersion::Ssl3 => vec![
                "SSL_RSA_WITH_RC4_128_MD5",
                "SSL_RSA_WITH_RC4_128_SHA",
                "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
                "SSL_RSA_WITH_DES_CBC_SHA",
                "SSL_RSA_EXPORT_WITH_RC4_40_MD5",
                "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA",
            ],
            TlsVersion::Tls10 | TlsVersion::Tls11 => vec![
                "TLS_RSA_WITH_AES_128_CBC_SHA",
                "TLS_RSA_WITH_AES_256_CBC_SHA",
                "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
                "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            ],
            _ => vec![],
        };

        let mut results = Vec::new();
        for cipher_name in ciphers {
            // Test each cipher suite
            if let Ok(_supported) = self.test_specific_cipher(version, cipher_name).await {
                results.push(CipherInfo {
                    id: 0, // Will need to map actual cipher suite IDs
                    iana_name: cipher_name.to_string(),
                    openssl_name: Some(cipher_name.to_string()),
                    key_exchange: self.parse_key_exchange_from_name(cipher_name),
                    authentication: self.parse_auth_from_name(cipher_name),
                    encryption: self.parse_encryption_from_name(cipher_name),
                    bits: self.parse_key_size_from_name(cipher_name),
                    mac: self.parse_hash_from_name(cipher_name),
                    protocol_version: version,
                });
            }
        }

        Ok(results)
    }

    #[allow(dead_code)]
    async fn test_specific_cipher(&self, _version: TlsVersion, _cipher: &str) -> Result<bool> {
        // This requires more fine-grained OpenSSL control
        // Temporarily return true
        Ok(true)
    }

    #[allow(dead_code)]
    fn parse_encryption_from_name(&self, cipher: &str) -> String {
        if cipher.contains("AES_256") {
            "AES-256".to_string()
        } else if cipher.contains("AES_128") {
            "AES-128".to_string()
        } else if cipher.contains("3DES") {
            "3DES".to_string()
        } else if cipher.contains("DES") {
            "DES".to_string()
        } else if cipher.contains("RC4") {
            "RC4".to_string()
        } else {
            "Unknown".to_string()
        }
    }

    #[allow(dead_code)]
    fn parse_hash_from_name(&self, cipher: &str) -> String {
        if cipher.contains("SHA384") {
            "SHA384".to_string()
        } else if cipher.contains("SHA256") {
            "SHA256".to_string()
        } else if cipher.contains("SHA") {
            "SHA1".to_string()
        } else if cipher.contains("MD5") {
            "MD5".to_string()
        } else {
            "Unknown".to_string()
        }
    }

    #[allow(dead_code)]
    fn parse_key_size_from_name(&self, cipher: &str) -> u16 {
        if cipher.contains("256") {
            256
        } else if cipher.contains("128") {
            128
        } else if cipher.contains("112") {
            112
        } else if cipher.contains("40") {
            40
        } else {
            0
        }
    }

    #[allow(dead_code)]
    fn parse_key_exchange_from_name(&self, cipher: &str) -> String {
        if cipher.contains("ECDHE") {
            "ECDHE".to_string()
        } else if cipher.contains("DHE") {
            "DHE".to_string()
        } else if cipher.contains("RSA") {
            "RSA".to_string()
        } else if cipher.contains("DH") {
            "DH".to_string()
        } else {
            "Unknown".to_string()
        }
    }

    #[allow(dead_code)]
    fn parse_auth_from_name(&self, cipher: &str) -> String {
        if cipher.contains("ECDSA") {
            "ECDSA".to_string()
        } else if cipher.contains("RSA") {
            "RSA".to_string()
        } else if cipher.contains("DSS") {
            "DSS".to_string()
        } else if cipher.contains("anon") {
            "None".to_string()
        } else {
            "Unknown".to_string()
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
