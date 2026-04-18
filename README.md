# kemist

A TLS + PQC observation scanner that records what servers support and emits structured JSON for downstream rule engines.

**kemist** is a pure sensor — it faithfully records TLS configuration, PQC key agreement support, and certificate details without producing compliance verdicts, grades, or pass/fail judgments. Rule evaluation belongs in separate downstream projects that consume kemist's JSON output.

Forked from [shyuan/tlsferret](https://github.com/shyuan/tlsferret). Retains dual MIT / Apache-2.0 licensing.

## 🚀 Features

### Protocol Support
- **Complete SSL/TLS Coverage**: SSLv2, SSLv3, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3
- **Dual TLS Engine**: rustls for modern protocols + native-tls for legacy support
- **Post-Quantum Cryptography**: ML-KEM support via aws-lc-rs
- **IPv4 and IPv6**: Full dual-stack support with address family selection

### STARTTLS Support
TLSferret supports STARTTLS for the following protocols:
- **SMTP** - Email submission (port 587, 25)
- **IMAP** - Email retrieval (port 143)
- **POP3** - Email retrieval (port 110)
- **FTP** - File transfer (port 21)
- **LDAP** - Directory services (port 389)
- **XMPP** - Instant messaging (port 5222)
- **PostgreSQL** - Database (port 5432)
- **MySQL** - Database (port 3306)

### Security Analysis
- **Vulnerability Detection**: Heartbleed (CVE-2014-0160), CRIME, TLS compression
- **Downgrade Protection**: TLS Fallback SCSV (RFC 7507) testing
- **Renegotiation Security**: RFC 5746 secure renegotiation analysis
- **Certificate Validation**: Comprehensive X.509 certificate chain analysis
- **Cipher Strength Assessment**: Security grading of cipher suites and key exchange

### Certificate Analysis
- **X.509 Parsing**: Complete certificate chain analysis
- **Security Assessment**: Weak keys, deprecated algorithms, expiry validation
- **Extensions**: Subject Alternative Names (SAN), key usage analysis
- **Fingerprinting**: SHA256 and SHA1 certificate fingerprints
- **Trust Chain**: Full certificate chain verification and analysis

### Output & Integration
- **Multiple Formats**: Human-readable text, JSON, XML
- **Colored Output**: Security-graded color coding for easy assessment
- **File Export**: Save scan results for compliance and reporting
- **Detailed Logging**: Configurable verbosity levels for debugging

## 🛠️ Installation

### 📦 Pre-compiled Binaries (Recommended)

Download the latest release for your platform from the [Releases page](https://github.com/shyuan/tlsferret/releases):

#### Linux
```bash
# x86_64
curl -L https://github.com/shyuan/tlsferret/releases/latest/download/tlsferret-v0.1.0-x86_64-unknown-linux-gnu.tar.gz | tar xz
./tlsferret --help
```

#### macOS
```bash
# Intel Mac
curl -L https://github.com/shyuan/tlsferret/releases/latest/download/tlsferret-v0.1.0-x86_64-apple-darwin.tar.gz | tar xz

# Apple Silicon (M1/M2)
curl -L https://github.com/shyuan/tlsferret/releases/latest/download/tlsferret-v0.1.0-aarch64-apple-darwin.tar.gz | tar xz
```

#### Windows
Download `tlsferret-v0.1.0-x86_64-pc-windows-msvc.zip` from the releases page and extract.

### 🔧 From Source

#### Prerequisites
- Rust 1.70+ and Cargo

```bash
git clone https://github.com/shyuan/tlsferret.git
cd tlsferret
cargo build --release
```

The binary will be available at `target/release/tlsferret`

## 📖 Usage

### Basic Scanning
```bash
# Basic HTTPS scan
tlsferret example.com

# Specific port
tlsferret example.com:8443

# IPv4 only
tlsferret example.com --ipv4

# IPv6 only
tlsferret example.com --ipv6
```

### STARTTLS Scanning
```bash
# SMTP STARTTLS
tlsferret mail.example.com:587 --starttls smtp

# IMAP STARTTLS
tlsferret mail.example.com:143 --starttls imap

# PostgreSQL SSL
tlsferret db.example.com:5432 --starttls postgres

# LDAP STARTTLS
tlsferret ldap.example.com:389 --starttls ldap
```

### Advanced Options
```bash
# Test specific TLS version
tlsferret example.com --tls-version tls1.3

# Custom SNI hostname
tlsferret 192.168.1.100 --sni-name example.com

# Disable cipher suite testing (faster)
tlsferret example.com --no-ciphersuites

# Custom timeout
tlsferret example.com --timeout 10

# Verbose output
tlsferret example.com -vv
```

### Output Formats
```bash
# JSON output
tlsferret example.com --format json

# XML output
tlsferret example.com --format xml

# Save to file
tlsferret example.com --output scan-results.json --format json

# Show certificate details
tlsferret example.com --show-certificate
```

## 📊 Example Output

```bash
$ tlsferret google.com

SSL/TLS Scanner - Rust Edition
==============================
Powered by: rustls 0.23 + aws-lc-rs (post-quantum) | native-tls 0.2 | tlsferret v0.1.0

Testing SSL/TLS on google.com:443

SSL/TLS Scan Results

Target:
  Host: google.com
  IP: 142.250.77.14:443
  Port: 443

Supported Protocols:
  SSLv2      NO
  SSLv3      NO
  TLSv1.0    YES
  TLSv1.1    YES
  TLSv1.2    YES
  TLSv1.3    YES

TLS Fallback SCSV:
  Supported
  ✓ Server protects against downgrade attacks

TLS renegotiation:
  Secure renegotiation (RFC 5746): Supported
  Client-initiated renegotiation: Disabled
    ✓ Server rejects client renegotiation
  TLS compression: Disabled
    ✓ Server not vulnerable to CRIME attack

Heartbleed (CVE-2014-0160):
  Not Vulnerable
    ✓ Server is protected against Heartbleed attacks

Preferred Cipher:
  TLS13_AES_256_GCM_SHA384                           TLSv1.3     256 bits

Server Key Exchange Group(s):

  Classical Groups:
    X25519               ✓
    X448                 ✓
    secp256r1            ✓
    secp384r1            ✓
    secp521r1            ✓

  Post-Quantum Groups:
    X25519MLKEM768       ✓
    SecP256r1MLKEM768    ✓
    SecP384r1MLKEM1024   ✓
    MLKEM512             ✓
    MLKEM768             ✓
    MLKEM1024            ✓

Certificate Information:
  Subject:             CN=*.google.com
  Issuer:              C=US, O=Google Trust Services, CN=WR2
  Valid:               54 days remaining
  Public Key:          EC (secp256r1) 256 bits
  SHA256 Fingerprint:  fa0863a0a9c98317da392dbf4043e5451d8bfceafc87a5ce198b6fe573977f0d

Summary

Good:
  ✓ TLSv1.2 is enabled
  ✓ TLSv1.3 is enabled

Warnings:
  ⚠ TLSv1.0 is enabled (deprecated)
  ⚠ TLSv1.1 is enabled (deprecated)
```

## 🏗️ Architecture

TLSferret uses a hybrid approach combining two TLS libraries:

- **rustls 0.23**: Modern TLS 1.2/1.3 with aws-lc-rs crypto provider and post-quantum support
- **native-tls 0.2**: Legacy SSL3/TLS 1.0/1.1 support for comprehensive coverage

### Project Structure
```
src/
├── main.rs           # CLI interface and application entry point
├── scanner.rs        # Core scanning orchestration
├── legacy_scanner.rs # Legacy protocol support (SSL3, TLS 1.0/1.1)
├── starttls.rs       # STARTTLS protocol implementations
├── protocol.rs       # TLS protocol definitions and enums
├── cipher.rs         # Cipher suite analysis and strength grading
├── certificate.rs    # X.509 certificate parsing and validation
└── output.rs         # Result formatting (text, JSON, XML)
```

## 🔧 Development

### Building from Source
```bash
# Debug build
cargo build

# Release build with optimizations
cargo build --release

# Run tests
cargo test

# Run with verbose logging
RUST_LOG=tlsferret=debug cargo run -- example.com
```

### Contributing
Contributions are welcome! Areas for enhancement:
- Additional STARTTLS protocol support
- Enhanced cipher suite individual testing
- More vulnerability detection
- Performance optimizations
- Additional output formats

## 📄 License

This project is licensed under either of:
- MIT License ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

## 🙏 Acknowledgments

- Inspired by [rbsec/sslscan](https://github.com/rbsec/sslscan)
- Built with [rustls](https://github.com/rustls/rustls) and [native-tls](https://github.com/sfackler/rust-native-tls)
- Powered by [aws-lc-rs](https://github.com/aws/aws-lc-rs) for post-quantum cryptography