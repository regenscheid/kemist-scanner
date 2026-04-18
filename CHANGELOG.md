# Changelog

All notable changes to kemist are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); version
numbers follow [semver](https://semver.org/).

## [0.1.0] — 2026-04-18

Initial release. Fork of [shyuan/tlsferret](https://github.com/shyuan/tlsferret)
repositioned as a pure-observation scanner: records what servers
support, emits structured JSON. Rule evaluation lives in separate
downstream projects.

### Added — TLS observation

- Per-TLS-version enumeration (SSL 2.0 through TLS 1.3) via a mix of
  rustls, native-tls, and a raw SSL 2.0 CLIENT-HELLO probe.
- Per-cipher-suite probing for aws-lc-rs's full ship set (~9 suites).
  Single-cipher `CryptoProvider` per probe. Real `supported: true/false`
  signals from the wire. Server-ordering detection via two handshakes
  with reversed suite orderings.
- Per-kx-group probing for 12 target groups: classical (X25519/X448/
  secp256r1-521) + PQC hybrids (X25519MLKEM768/secp256r1MLKEM768/
  secp384r1MLKEM1024) + standalone ML-KEM (512/768/1024) + the
  pre-standard X25519Kyber768Draft00. Groups aws-lc-rs doesn't ship
  emit `not_probed` with a specific reason — never `supported: false`
  without a real probe.
- Characterization handshake captures rustls connection state:
  negotiated version, cipher suite, kx group, signature scheme (from
  verifier callback), ALPN, OCSP stapling bytes.
- Byte-level ServerHello probe (raw TCP, hand-crafted TLS 1.2 ClientHello)
  for Extended Master Secret (RFC 7627), Encrypt-then-MAC (RFC 7366),
  heartbeat presence (RFC 6520), renegotiation_info (RFC 5746),
  server-selected compression method, and SCT via extension 18 (RFC 6962).
- SNI-omitted probe: second handshake with `ServerName::IpAddress` (rustls
  omits SNI for IP literals). Compares leaf cert fingerprints →
  `same_cert | different_cert | rejected | error`.

### Added — certificate and validation observation

- X.509 parsing via x509-parser: subject/issuer DN + CN, SAN list,
  serial, validity, signature algorithm (raw OID + resolved name),
  public key algorithm + size + curve, SHA-256 + SHA-1 fingerprints.
- `is_pqc_signature: bool` — raw OID match against ML-DSA (FIPS 204)
  and SLH-DSA (FIPS 205) — 15-entry table, NIST CSOR arc.
- Embedded SCT count via cert extension 1.3.6.1.4.1.11129.2.4.2.
- Three independent trust observations:
  `validation.chain_valid_to_webpki_roots` (rustls `WebPkiServerVerifier`
  against Mozilla roots, with SAN-retry to isolate name failures),
  `validation.name_matches_sni` (RFC 6125 SAN matching with wildcards),
  `validation.validation_error` (canonical string when chain invalid).

### Added — HTTP observations (feature-gated)

- `http-checks` cargo feature (default on) + runtime `--enable-http-checks`
  flag gates fetch of HSTS header, `/.well-known/security.txt`, and
  HSTS preload list membership (~12-entry stub subset).
- `Strict-Transport-Security` parsed into `raw_value`, `max_age`,
  `include_subdomains`, `preload` fields.
- security.txt body emitted verbatim — not parsed.
- User-Agent configurable via `--user-agent-info-url`; defaults to
  `https://www.kemist-tls.net`.

### Added — output

- Strict JSON schema v1 (`schemas/output-v1.json`), draft-2020, with
  conditional `if/then` constraints enforcing the four-way tri-state
  contract (`probe` / `not_probed` / `not_applicable` / `error`).
- Top-level `capabilities` block for self-describing records: enabled
  features, crypto provider versions, provider-shipped cipher suite
  and kx group lists, config paths, probe limitations.
- Schema-v1-aware terminal renderer (`src/output/text.rs`) — compact
  ~55-line summary per target. Glyph legend `+`/`-`/`?`. Neutral
  colors; cyan highlight on PQC groups + PQC-signed certs. TTY-detect.
- NDJSON stream output for multi-target scans. Per-target file output
  (`--output-dir`) with `<host>_<port>_<unixtime>.json` naming.

### Added — CLI and library API

- Public `Scanner`, `ScannerConfig`, `Target`, `ScanResult`,
  `ScannerError` API in `src/lib.rs`. CLI is a thin consumer.
- Multi-target input: `--target` (repeatable), `--targets-file`,
  `--targets-stdin`. Per-target SNI override syntax:
  `host:port#sni=alt.example.com`.
- Bounded concurrency via `futures::buffer_unordered` + `Semaphore`.
  Per-target probes stay serialized.
- Retry loop (transient-category errors only, exp backoff 1/2/4s).
  Hard `--total-timeout` ceiling per target.
- Separate `--connect-timeout`, `--handshake-timeout`, `--total-timeout`,
  `--retries`, `--per-target-delay`, `--concurrency` knobs.
- Structured `errors` array on every output record. Scanner never
  aborts on probe-level failures — scans always produce complete-shaped
  records with accumulated errors.

### Removed (from the TLSferret parent)

- STARTTLS negotiation for SMTP/IMAP/POP3/FTP/LDAP/XMPP/PostgreSQL/MySQL.
  Out of scope for HTTPS-on-443 focus; may return later as an opt-in
  feature.
- All compliance-verdict fields: `CipherStrength` enum (Null/Weak/
  Medium/Strong/Recommended), `weak_signature` / `weak_key` bools,
  `client_initiated_renegotiation`, validation-issues string generator.
  kemist is a pure sensor, no verdicts anywhere in output.
- XML output. JSON (schema-validated) is the canonical machine format.
- Legacy CLI: positional target, `--sni-name`, `--timeout`, `-o`.
  Replaced with multi-target flags documented above.

### Known limits

- aws-lc-rs cipher suite coverage: 9 suites (no RC4/3DES/CBC-SHA/
  export). Servers accepting those ciphers emit as absent from the
  array rather than `supported: false`. Cross-reference against a
  fuller cipher registry for weak-cipher policies.
- aws-lc-rs kx group coverage: 6 groups. Standalone ML-KEM-512/1024,
  X448, secp521r1, secp384r1MLKEM1024, X25519Kyber768Draft00 emit
  `not_probed`. Three future extension paths documented in
  [docs/PQC.md](docs/PQC.md).
- HSTS preload list is a 12-entry stub. Full Chromium
  `transport_security_state_static.json` snapshot deferred.
- PQC signature verification not performed — OID match only. Chain
  validation via webpki-roots uses classical algorithms.

[0.1.0]: https://github.com/regenscheid/kemist-scanner/releases/tag/v0.1.0
