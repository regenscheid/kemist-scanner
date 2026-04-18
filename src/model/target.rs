//! Target specification.
//!
//! One `Target` represents a single endpoint kemist will scan: host, port,
//! optional SNI override. Targets arrive from three sources via the CLI:
//! `--target` (repeatable), `--targets-file`, `--targets-stdin`.
//!
//! ## Syntax
//! ```text
//! host
//! host:port
//! host:port#sni=alt.example.com
//! [::1]:8443
//! [::1]:8443#sni=api.example.com
//! ```
//!
//! The SNI override is load-bearing for hosting scenarios where one IP serves
//! many certs — it lets a rule engine probe a specific vhost by name without
//! changing what hostname gets reported in `scan.host`.
//!
//! Default port is 443.

use crate::model::errors::ScannerError;

pub const DEFAULT_PORT: u16 = 443;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    /// When set, sent as SNI during TLS handshakes instead of `host`.
    /// Scanner still reports `host` in `scan.host` and `scan.target`.
    pub sni_override: Option<String>,
}

impl Target {
    /// Parse one target string. See module docs for syntax.
    pub fn parse(s: &str) -> Result<Self, ScannerError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(ScannerError::internal("empty target string"));
        }

        // SNI override is signaled by `#sni=`. Split it off first so we don't
        // confuse a literal `:` inside an IPv6 address for a port separator.
        let (addr, sni_override) = match s.split_once("#sni=") {
            Some((a, sni)) => {
                let sni = sni.trim();
                if sni.is_empty() {
                    return Err(ScannerError::internal(format!(
                        "empty SNI override in target: {s}"
                    )));
                }
                (a, Some(sni.to_string()))
            }
            None => (s, None),
        };

        let (host, port) = parse_host_port(addr)?;

        Ok(Self {
            host,
            port,
            sni_override,
        })
    }

    /// Name to send as SNI — override if present, otherwise host.
    pub fn sni(&self) -> &str {
        self.sni_override.as_deref().unwrap_or(&self.host)
    }

    /// `host:port` form for the schema's `scan.target` field.
    pub fn display(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            // Raw IPv6 literal without brackets — normalize.
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

fn parse_host_port(s: &str) -> Result<(String, u16), ScannerError> {
    // IPv6 literal with brackets: `[::1]:8443` or bare `[::1]`.
    if let Some(rest) = s.strip_prefix('[') {
        let close = rest
            .find(']')
            .ok_or_else(|| ScannerError::internal(format!("unterminated IPv6 literal: {s}")))?;
        let host = rest[..close].to_string();
        let after = &rest[close + 1..];
        let port = if after.is_empty() {
            DEFAULT_PORT
        } else if let Some(p) = after.strip_prefix(':') {
            p.parse::<u16>()
                .map_err(|_| ScannerError::internal(format!("invalid port in target: {s}")))?
        } else {
            return Err(ScannerError::internal(format!(
                "malformed IPv6 target (expected ']:port' or ']'): {s}"
            )));
        };
        return Ok((host, port));
    }

    // Plain hostname or IPv4. A single `:` is a port separator; no colons →
    // default port. Multiple colons (bare IPv6) are rejected — use brackets.
    let colon_count = s.matches(':').count();
    match colon_count {
        0 => Ok((s.to_string(), DEFAULT_PORT)),
        1 => {
            let (host, port_str) = s.rsplit_once(':').unwrap();
            let port = port_str
                .parse::<u16>()
                .map_err(|_| ScannerError::internal(format!("invalid port in target: {s}")))?;
            Ok((host.to_string(), port))
        }
        _ => Err(ScannerError::internal(format!(
            "ambiguous target (bare IPv6 needs brackets): {s}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bare_hostname_with_default_port() {
        let t = Target::parse("example.com").unwrap();
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 443);
        assert_eq!(t.sni_override, None);
        assert_eq!(t.sni(), "example.com");
    }

    #[test]
    fn parses_host_with_port() {
        let t = Target::parse("example.com:8443").unwrap();
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 8443);
    }

    #[test]
    fn parses_ipv4_with_port() {
        let t = Target::parse("192.0.2.1:443").unwrap();
        assert_eq!(t.host, "192.0.2.1");
        assert_eq!(t.port, 443);
    }

    #[test]
    fn parses_ipv6_with_brackets_and_port() {
        let t = Target::parse("[::1]:8443").unwrap();
        assert_eq!(t.host, "::1");
        assert_eq!(t.port, 8443);
    }

    #[test]
    fn parses_ipv6_with_brackets_and_default_port() {
        let t = Target::parse("[::1]").unwrap();
        assert_eq!(t.host, "::1");
        assert_eq!(t.port, 443);
    }

    #[test]
    fn sni_override_applies() {
        let t = Target::parse("1.1.1.1:443#sni=cloudflare-dns.com").unwrap();
        assert_eq!(t.host, "1.1.1.1");
        assert_eq!(t.sni(), "cloudflare-dns.com");
        assert_eq!(t.sni_override.as_deref(), Some("cloudflare-dns.com"));
    }

    #[test]
    fn sni_override_on_bare_hostname() {
        let t = Target::parse("example.com#sni=alt.example.com").unwrap();
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 443);
        assert_eq!(t.sni(), "alt.example.com");
    }

    #[test]
    fn rejects_empty() {
        assert!(Target::parse("").is_err());
        assert!(Target::parse("   ").is_err());
    }

    #[test]
    fn rejects_bare_ipv6_without_brackets() {
        // `::1:443` is ambiguous — must use `[::1]:443`.
        assert!(Target::parse("::1:443").is_err());
    }

    #[test]
    fn rejects_invalid_port() {
        assert!(Target::parse("example.com:99999").is_err());
        assert!(Target::parse("example.com:abc").is_err());
    }

    #[test]
    fn rejects_empty_sni_override() {
        assert!(Target::parse("example.com#sni=").is_err());
    }

    #[test]
    fn display_normalizes_bare_ipv6() {
        // If a user somehow constructs a Target with a bare IPv6 host, display
        // adds brackets so downstream tools can parse it back.
        let t = Target {
            host: "::1".to_string(),
            port: 443,
            sni_override: None,
        };
        assert_eq!(t.display(), "[::1]:443");
    }
}
