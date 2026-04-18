# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.1.0] - 2025-06-18

### Added
- **Initial Public Release** 🎉
- **Comprehensive SSL/TLS Analysis**
  - Protocol version detection (SSL2, SSL3, TLS 1.0-1.3)
  - Cipher suite enumeration and strength classification
  - Certificate chain analysis with detailed validation
  - Security vulnerability detection (Heartbleed, CRIME, etc.)

- **Advanced Security Features**
  - TLS renegotiation testing (RFC 5746)
  - Fallback SCSV detection for downgrade protection
  - Weak cipher and certificate detection
  - Post-quantum cryptography support (ML-KEM algorithms)

- **Protocol Support**
  - **STARTTLS** support for 8 protocols: SMTP, IMAP, POP3, FTP, LDAP, XMPP, PostgreSQL, MySQL
  - IPv4/IPv6 dual-stack support
  - SNI (Server Name Indication) support

- **Performance & Architecture**
  - **Hybrid TLS Engine**: rustls 0.23 (modern) + native-tls 0.2 (legacy compatibility)
  - **AWS-LC-RS** cryptographic provider with post-quantum algorithms
  - Async implementation using Tokio for high performance
  - Memory-safe Rust implementation

- **Output & Integration**
  - Multiple output formats: Text (colored), JSON, XML
  - File export support for compliance and reporting
  - Comprehensive logging with configurable verbosity
  - Cross-platform compatibility (Linux, macOS, Windows)

- **Build & Release**
  - Automated multi-platform builds via GitHub Actions
  - Pre-compiled binaries for 4 platforms:
    - Linux x86_64
    - macOS (Intel, Apple Silicon)
    - Windows x86_64
  - SHA256 checksums for security verification
  - Dual licensing (MIT OR Apache-2.0)

### Technical Details
- **Language**: Rust 1.71+
- **TLS Libraries**: rustls 0.23 + native-tls 0.2
- **Crypto Provider**: AWS-LC-RS with post-quantum support
- **DNS Resolution**: hickory-resolver 0.24 (secure, modern)
- **Dependencies**: Zero security vulnerabilities (cargo audit clean)

### Acknowledgments
- Inspired by [rbsec/sslscan](https://github.com/rbsec/sslscan)
- Built with the amazing Rust ecosystem and cryptographic libraries

[v0.1.0]: https://github.com/shyuan/tlsferret/releases/tag/v0.1.0