use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TlsVersion {
    Ssl2,
    Ssl3,
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

impl TlsVersion {
    pub fn all() -> Vec<Self> {
        vec![
            Self::Ssl2,
            Self::Ssl3,
            Self::Tls10,
            Self::Tls11,
            Self::Tls12,
            Self::Tls13,
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ssl2 => "SSLv2",
            Self::Ssl3 => "SSLv3",
            Self::Tls10 => "TLSv1.0",
            Self::Tls11 => "TLSv1.1",
            Self::Tls12 => "TLSv1.2",
            Self::Tls13 => "TLSv1.3",
        }
    }

    pub fn is_secure(&self) -> bool {
        matches!(self, Self::Tls12 | Self::Tls13)
    }

    pub fn is_deprecated(&self) -> bool {
        matches!(self, Self::Ssl2 | Self::Ssl3 | Self::Tls10 | Self::Tls11)
    }

    /// Get rustls protocol version
    #[allow(dead_code)]
    pub fn to_rustls_version(self) -> Option<&'static rustls::SupportedProtocolVersion> {
        match self {
            Self::Tls12 => Some(&rustls::version::TLS12),
            Self::Tls13 => Some(&rustls::version::TLS13),
            _ => None, // rustls doesn't support SSL2, SSL3, TLS1.0, TLS1.1
        }
    }
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolSupport {
    pub version: TlsVersion,
    pub supported: bool,
    pub error: Option<String>,
}

pub mod handshake {
    use super::TlsVersion;
    use bytes::BytesMut;

    /// Build a ClientHello message for testing specific TLS versions
    #[allow(dead_code)]
    pub fn build_client_hello(_version: TlsVersion) -> BytesMut {
        // This is a placeholder - actual implementation would build proper ClientHello
        // For now, rustls will handle this for TLS 1.2 and 1.3
        BytesMut::new()
    }

    /// Parse ServerHello response
    #[allow(dead_code)]
    pub fn parse_server_hello(_data: &[u8]) -> Option<TlsVersion> {
        // This is a placeholder - actual implementation would parse ServerHello
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_version_as_str() {
        assert_eq!(TlsVersion::Ssl2.as_str(), "SSLv2");
        assert_eq!(TlsVersion::Ssl3.as_str(), "SSLv3");
        assert_eq!(TlsVersion::Tls10.as_str(), "TLSv1.0");
        assert_eq!(TlsVersion::Tls11.as_str(), "TLSv1.1");
        assert_eq!(TlsVersion::Tls12.as_str(), "TLSv1.2");
        assert_eq!(TlsVersion::Tls13.as_str(), "TLSv1.3");
    }

    #[test]
    fn test_tls_version_is_secure() {
        assert!(!TlsVersion::Ssl2.is_secure());
        assert!(!TlsVersion::Ssl3.is_secure());
        assert!(!TlsVersion::Tls10.is_secure());
        assert!(!TlsVersion::Tls11.is_secure());
        assert!(TlsVersion::Tls12.is_secure());
        assert!(TlsVersion::Tls13.is_secure());
    }

    #[test]
    fn test_tls_version_is_deprecated() {
        assert!(TlsVersion::Ssl2.is_deprecated());
        assert!(TlsVersion::Ssl3.is_deprecated());
        assert!(TlsVersion::Tls10.is_deprecated());
        assert!(TlsVersion::Tls11.is_deprecated());
        assert!(!TlsVersion::Tls12.is_deprecated());
        assert!(!TlsVersion::Tls13.is_deprecated());
    }

    #[test]
    fn test_tls_version_all() {
        let all_versions = TlsVersion::all();
        assert_eq!(all_versions.len(), 6);
        assert!(all_versions.contains(&TlsVersion::Ssl2));
        assert!(all_versions.contains(&TlsVersion::Tls13));
    }

    #[test]
    fn test_tls_version_to_rustls_version() {
        assert!(TlsVersion::Tls12.to_rustls_version().is_some());
        assert!(TlsVersion::Tls13.to_rustls_version().is_some());
        assert!(TlsVersion::Ssl2.to_rustls_version().is_none());
        assert!(TlsVersion::Ssl3.to_rustls_version().is_none());
        assert!(TlsVersion::Tls10.to_rustls_version().is_none());
        assert!(TlsVersion::Tls11.to_rustls_version().is_none());
    }
}
