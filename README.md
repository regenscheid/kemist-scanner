# kemist

A TLS + PQC observation scanner that records what servers support and emits structured JSON for downstream rule engines.

**kemist** is a pure sensor. It faithfully records TLS configuration, PQC key-agreement support, and certificate details without producing compliance verdicts, grades, or pass/fail judgments. Rule evaluation belongs in separate downstream projects that consume kemist's JSON output.

Forked from [shyuan/tlsferret](https://github.com/shyuan/tlsferret). Retains dual MIT / Apache-2.0 licensing.

## What kemist observes

### Protocol versions
SSLv2, SSLv3, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3 — one probe per version. Each entry reports `offered: true | false | null` plus the method that produced it.

### Cipher suites (40 codepoints probed)
- **Modern AEAD / ECDHE** (9): via rustls + aws-lc-rs
- **Legacy RSA-kex, CBC, RC4, 3DES, NULL, anon-DH, PSK family, Camellia, SEED, ARIA, static DH/ECDH** (31): via vendored OpenSSL 3.5 (RSA / ECDH static-cert suites via raw-socket ClientHello where OpenSSL 3.x no longer drives them)

Each probe is a separate handshake against the target. Output carries `provider: "aws_lc_rs" | "openssl"` attribution per codepoint.

### Key-exchange groups (16 codepoints)
Classical (X25519, secp256r1/384r1/521r1, X448), FFDHE 2048-8192, standalone ML-KEM (512/768/1024), PQC hybrids (X25519MLKEM768, secp256r1MLKEM768, secp384r1MLKEM1024).

### Post-handshake observations
- TLS_FALLBACK_SCSV (RFC 7507) enforcement
- Client-initiated renegotiation behavior (RFC 5246 alert classification)
- CertificateRequest content (certificate types, signature algorithms, CA DNs, OID filters)
- TLS 1.3 EncryptedExtensions (record_size_limit per RFC 8449, compress_certificate per RFC 8879)
- Session resumption — TLS 1.2 tickets + rotation, TLS 1.3 PSK resumption + 0-RTT
- Signature-algorithm policy (four constrained handshakes)
- DH parameter capture (classification against RFC 7919) + SKE signature algorithm

### Byte-level extension observations
Extended Master Secret, secure renegotiation, OCSP stapling, SCT delivery path, Encrypt-then-MAC, heartbeat extension presence, compression, TLS 1.3 downgrade sentinel, SNI behavior.

### Active vulnerability / misconfiguration probes
- Heartbleed (CVE-2014-0160) via the pre-handshake heartbeat technique
- SNI omission comparison (IP-literal handshake vs SNI-bearing)
- Chain validation to webpki-roots

### HTTP-layer observations (optional, `--enable-http-checks`)
HSTS header (raw value + parsed directives), `security.txt`, static preload-list membership.

Full catalog in [docs/CHECKS.md](docs/CHECKS.md).

## Installation

### From source
Prerequisite: Rust toolchain (recent stable). OpenSSL is vendored via `openssl-src`; no system `libssl` required at build or runtime.

```bash
git clone https://github.com/regenscheid/kemist-scanner.git
cd kemist-scanner
cargo build --release
```

Binary at `target/release/kemist`.

### Cargo features
- `legacy-probes` *(default on)* — vendored OpenSSL 3.5 LTS for legacy protocol/cipher/group probes. `--no-default-features --features http-checks` skips the OpenSSL dep entirely (saves ~40s build time; drops SSLv3/TLS1.0/1.1 + legacy cipher coverage).
- `http-checks` *(default on)* — HSTS / security.txt / preload-list probes.

## Usage

```bash
# Single target, human-readable text output
kemist --target example.com:443

# Pretty-printed JSON (one file per target into a directory)
kemist --target example.com:443 --format json-pretty --output-dir ./scan-results

# NDJSON stream (one record per line; good for piping into jq or rule engines)
kemist --target example.com:443 --target otherhost.example:443 --format json

# Concurrent targets from a file, with HTTP-layer checks on
kemist --targets-file hosts.txt --concurrency 10 --enable-http-checks \
       --user-agent-info-url https://example.com/scanner-info

# Restrict to one TLS version
kemist --target example.com:443 --tls-version tls1.3

# Skip specific sigalg policy probes (faster scans)
kemist --target example.com:443 --sigalg-probe-skip ecdsa_only,rsa_pkcs1_only

# Include raw OCSP response bytes in output (debugging / re-validation)
kemist --target example.com:443 --format json-pretty --include-ocsp-raw
```

`kemist --help` lists every flag.

## Output

Three formats: `text` (default, human-readable summary), `json` (compact NDJSON — one line per target), `json-pretty` (indented JSON — one file per target when paired with `--output-dir`).

JSON output validates against [`schemas/output-v1.json`](schemas/output-v1.json) (JSON Schema draft 2020-12). Field-by-field reference in [docs/OUTPUT_SCHEMA.md](docs/OUTPUT_SCHEMA.md). Integration patterns for building rule engines on top in [docs/INTEGRATION.md](docs/INTEGRATION.md).

Example record shape (abridged):
```jsonc
{
  "schema_version": "2.0.0",
  "scanner": { "name": "kemist", "version": "0.4.0" },
  "capabilities": {
    "rustls_version": "0.23",
    "openssl_version": "300.5.5",
    "probed_cipher_suites": [ /* 40 suite names */ ],
    "probed_kx_groups": [ /* 16 group names */ ]
  },
  "scan": { "target": "example.com:443", "started_at": "...", "duration_ms": 8204 },
  "tls": {
    "versions_offered": { "tls1_3": { "offered": true, "method": "probe" }, /* ... */ },
    "negotiated": { "version": "TLSv1.3", "cipher_suite": "TLS13_AES_128_GCM_SHA256", "group": "X25519" },
    "cipher_suites": { /* per-suite results, 40 entries across tls1_0..tls1_3 */ },
    "groups": { /* per-group results, 16 entries */ },
    "downgrade_signaling": { "fallback_scsv_enforced": { "value": true, "method": "probe" } },
    "signature_algorithm_policy_probe": { /* 4 constrained handshakes */ },
    "session_resumption": { /* TLS 1.2 + TLS 1.3 */ },
    "extensions": { /* 15+ byte-level observations */ }
  },
  "certificates": { "leaf": { /* parsed X.509 */ }, "chain": [ /* full chain */ ] },
  "validation": { "chain_valid_to_webpki_roots": { "value": true, "method": "probe" } },
  "errors": []
}
```

## Design contracts

- **Sensor only.** The word `grade`, `verdict`, `severity`, `weak`, `compliant`, `pass`, or `fail` does not appear in any emitted record. Interpretation is downstream.
- **Tri-state observations.** Every probe distinguishes `true`, `false`, and `null` (with a `reason`) rather than conflating "not offered" with "couldn't probe." See `docs/OUTPUT_SCHEMA.md` for the full method vocabulary.
- **Infallible `scan()`.** Individual probe failures land in a target's `errors` array; the scan always returns a schema-v1 record.
- **Stable JSON schema.** `schema_version` is semver over output shape. Consumers pin on the major.

## Architecture

kemist uses two TLS libraries behind a unified `TlsBackend` trait:

- **rustls 0.23 + aws-lc-rs** — modern TLS 1.2/1.3, classical + PQC named groups.
- **OpenSSL 3.5 LTS (vendored)** — legacy protocol versions (SSLv3/TLS1.0/1.1), legacy cipher suites, FFDHE groups, post-handshake probes (renegotiation, session resumption, CertificateRequest, TLS 1.3 EncryptedExtensions). Gated by the `legacy-probes` feature (default on).

A `BackendRegistry` routes each probed codepoint to the single backend responsible for it via an explicit per-codepoint priority table. SSLv2, Heartbleed, and static-DH/ECDH cipher suites are handled via raw-socket probes that bypass both libraries. See [docs/BACKENDS.md](docs/BACKENDS.md) for how the abstraction works and how to plug in a third backend.

### Project structure
```
src/
├── main.rs               # CLI entry point + output formatting
├── lib.rs                # Public API re-exports
├── model/                # Schema types + TLS enums
├── output/
│   └── json.rs           # Schema-v1 JSON emitter
└── scanner/
    ├── mod.rs            # SslScanner + scan() orchestration
    ├── runner.rs         # Multi-target concurrency
    ├── probe.rs          # Characterization handshake + NegotiatedState
    ├── cert.rs           # X.509 parsing
    ├── ciphers.rs        # Rustls per-cipher probe loop
    ├── groups.rs         # Rustls per-group probe loop
    ├── hello.rs          # Byte-level ServerHello extension observer
    ├── http.rs           # HSTS / security.txt / preload list
    ├── sni.rs            # SNI-omitted comparison probe
    ├── backends/         # TlsBackend abstraction + concrete backends
    │   ├── mod.rs        # Trait, HandshakeConstraint, HandshakeResult,
    │   │                 # BackendInventory, BackendRegistry glue
    │   ├── registry.rs   # Per-codepoint priority routing
    │   ├── rustls/       # aws-lc-rs backend
    │   └── openssl/      # Vendored OpenSSL backend + all legacy
    │                     # probes, observers, and post-handshake actions
    └── raw/              # Probes that bypass TLS libraries
        ├── sslv2.rs      # Hand-crafted SSL 2.0 CLIENT-HELLO
        ├── heartbleed.rs # CVE-2014-0160 via pre-handshake heartbeat
        └── static_dh.rs  # Static-DH/ECDH cipher probes (dropped in OpenSSL 3.x)
```

## Development

```bash
cargo build                              # debug build
cargo build --release                    # release
cargo test                               # all tests
cargo build --no-default-features --features http-checks   # no-OpenSSL build
RUST_LOG=kemist=debug cargo run --release -- --target example.com:443
```

## License

Dual-licensed under your choice of:
- MIT License ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

## Acknowledgments

- Forked from [shyuan/tlsferret](https://github.com/shyuan/tlsferret), inspired by [rbsec/sslscan](https://github.com/rbsec/sslscan)
- Built on [rustls](https://github.com/rustls/rustls) with the [aws-lc-rs](https://github.com/aws/aws-lc-rs) crypto provider for post-quantum support, plus vendored [OpenSSL 3.5 LTS](https://www.openssl.org/) for legacy coverage
- Heartbleed probe technique adapted from [testssl.sh](https://github.com/testssl/testssl.sh)
