# Changelog

All notable changes to kemist are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); version
numbers follow [semver](https://semver.org/).

## [Unreleased]

### Added — Observation expansion workstream

Extends the raw-observation surface so downstream rule engines
(NIST SP 800-52, Mozilla profiles, custom policies) have more
inputs without the scanner rendering verdicts itself. All additions
are additive; `schema_version` remains `"1.0.0"`. See
[docs/OUTPUT_SCHEMA.md](docs/OUTPUT_SCHEMA.md) for field-by-field
semantics and [docs/CHECKS.md](docs/CHECKS.md) for per-probe
mechanics.

- `tls.certificates.chain[].extensions` — parsed X.509 v3 extensions
  per cert: Basic Constraints (`ca`, `path_len_constraint`), Key
  Usage bits (canonical RFC 5280 names), Extended Key Usage OIDs,
  Authority/Subject Key Identifier, Authority Information Access
  (OCSP + CA Issuers URLs), CRL Distribution Points URLs, Name
  Constraints (permitted/excluded subtrees), Certificate Policies
  OIDs, RFC 7633 Must-Staple flag, per-SCT detail (log_id,
  timestamp, signature). Always-on.
- `tls.extensions.truncated_hmac`, `.npn`,
  `.supported_point_formats_echoed`, `.max_fragment_length` — new
  ServerHello observations via the always-on byte-level TLS 1.2
  probe.
- `tls.downgrade_signaling.tls13_downgrade_sentinel` — RFC 8446
  §4.1.3 trailing-8-bytes ServerRandom sentinel (`tls12` /
  `lte_tls11` / `none`).
- `tls.extensions.ocsp_stapling.content` — parsed OCSP response per
  RFC 6960 §4.2: `response_status`, `signature_algorithm_oid`,
  responder ID (byName or byKey), `produced_at`,
  `single_responses_count`, and first-response fields
  (`cert_status`, `revocation_time`, `revocation_reason`,
  `this_update`, `next_update`, `cert_id`). Always-on pure parser
  (`model/ocsp_response.rs`).
- `tls.extensions.ocsp_stapling.delivery_path` (`tls1_2` / `tls1_3`)
  and `raw_hex` (gated by new `--include-ocsp-raw` CLI flag).
- `tls.extensions.record_size_limit`,
  `tls.extensions.compress_certificate_algorithms` — TLS 1.3
  EncryptedExtensions observation via OpenSSL msg-callback.
  **Known limitation:** typically absent because OpenSSL 3.5
  reserves these ext codes for internal handlers, blocking a
  matching client offer; openssl-sys 0.9.109 doesn't expose the
  native setters. Follow-up workstream to close.
- `tls.cipher_suites.<ver>[].classification` — kx+privacy family
  label per suite. 15-variant enum (`rsa_kex`, `dhe_aead`,
  `dhe_cbc`, `ecdhe_aead`, `ecdhe_cbc`, `anon`, `export`,
  `static_dh`, `static_ecdh`, `psk`, `dhe_psk`, `ecdhe_psk`,
  `rsa_psk`, `null_cipher`, `other`). Privacy-dominant concerns
  (`null_cipher`, `anon`, `export`) take precedence over kx prefix.
  TLS 1.3 suites map to `ecdhe_aead`. Exhaustive test coverage.
- Cipher-suite inventory expansion (legacy-probes): +18 TLS 1.2
  probes — PSK family (4), Camellia (4), SEED (2), ARIA (4),
  static DH / static ECDH (4).
- `tls.session_resumption` — new top-level section. TLS 1.2 today:
  `session_ticket_issued`, `ticket_lifetime_hint_secs`,
  `session_id_issued`, `ticket_rotated_across_connections`
  (two-connection probe). TLS 1.3 slots stubbed with
  `method: not_probed` pending follow-up.
- `tls.signature_algorithm_policy_probe` — four constrained
  handshakes via `SSL_CTX_set1_sigalgs_list` (`sha256_plus_only`,
  `ecdsa_only`, `rsa_pss_only`, `rsa_pkcs1_only`). Each records
  outcome, selected sigalg on completion, alert category on
  refusal. New `--sigalg-probe-skip=<csv>` CLI flag opts out
  individual constraints.

### Added — CLI

- `--include-ocsp-raw` — emit raw OCSP bytes as hex under
  `tls.extensions.ocsp_stapling.raw_hex`. Off by default.
- `--sigalg-probe-skip=<csv>` — skip individual sigalg-policy
  probes. Recognized: `sha256_plus_only`, `ecdsa_only`,
  `rsa_pss_only`, `rsa_pkcs1_only`. Unknown entries ignored.

### Changed

- **Removed** `tls.downgrade_signaling.fallback_scsv_accepted` — the
  deprecated-in-0.2.0 heuristic field is gone from the schema. Its
  replacement `fallback_scsv_enforced` has been the authoritative
  observation since 0.2.0; consumers should read that instead.
- `cipher_suites.<ver>[].classification` is now a **required** field
  on every `cipherSuiteEntry`. The classifier is total (no gaps),
  so this lands as required with exhaustive test coverage.
- `tls.extensions.ocsp_stapling` is now a richer object; existing
  `stapled` / `method` / `response_length` / `reason` shape stays.
- `impl Default for ObservationBool` returns the `{value: None,
  method: "not_probed"}` shape. Internal ergonomic change; no
  user-visible output difference.

### Known limitations (deferred to follow-up workstreams)

- TLS 1.3 EncryptedExtensions — `record_size_limit` and
  `compress_certificate_algorithms` observable only when servers
  advertise unsolicited (rare). Client-offer injection blocked by
  the openssl-sys binding gap noted above.
- TLS 1.3 session resumption + 0-RTT — structure stubbed,
  `method: not_probed`. Will need post-handshake NST read dance +
  `SSL_set_session` resumption + `SSL_write_early_data` for
  `early_data_accepted`.

## [0.2.0] — 2026-04-19

### Added — Legacy TLS & misconfiguration probe subsystem

Fills observation gaps that rustls + aws-lc-rs cannot reach. All new
probes are backed by vendored OpenSSL 3.5 LTS and gated behind the
default-on `legacy-probes` cargo feature. See
[docs/OUTPUT_SCHEMA.md](docs/OUTPUT_SCHEMA.md) for field-by-field
semantics and [docs/CHECKS.md](docs/CHECKS.md) for per-probe mechanics.

- `tls.cipher_suites.{tls1_0, tls1_1}` — new per-version sub-arrays
  for OpenSSL legacy probes (RSA-kex, RC4, DES/3DES, IDEA, NULL,
  anon-DH, DHE-RSA). TLS 1.2 legacy probes also land in the existing
  `tls.cipher_suites.tls1_2` array alongside aws-lc-rs entries; every
  entry now carries a `provider` tag (`"aws_lc_rs"` or `"openssl"`) so
  consumers that care about backend attribution can filter. OpenSSL
  entries additionally carry `openssl_name` (e.g. `"AES128-SHA"`) as a
  manual reproduction aid.
- `tls.dh_parameters` — prime bit-length, generator, SHA-256 of the
  prime, and classification against RFC 7919 FFDHE constants
  (ffdhe2048…ffdhe8192 / custom). Captured on every completed DHE
  handshake.
- `tls.groups.{tls1_2, tls1_3}` — the previously-flat groups map is
  now partitioned by TLS version. aws-lc-rs modern groups
  (classical, PQC hybrids, standalone ML-KEM) land in `tls1_3`; RFC
  7919 FFDHE outcomes appear in both `tls1_2` and `tls1_3`. Each entry
  carries a `provider` tag; OpenSSL-backed FFDHE entries also carry
  `iana_code`. The cross-check for "server completed a DHE handshake
  with a custom prime despite `supported_groups` advertising a specific
  FFDHE codepoint" surfaces as
  `{supported: false, reason: "server_ignored_group_offer_returned_custom_prime"}`
  in the tls1_2 slot of the merged groups map.
- `tls.server_key_exchange_signatures` — the signature algorithm the
  server actually chose for each TLS 1.2 ServerKeyExchange / TLS 1.3
  CertificateVerify (distinct from the algorithms it advertises).
- `tls.downgrade_signaling.fallback_scsv_enforced` — active RFC 7507
  probe. Attempts a handshake one protocol version below the server's
  max with `SSL_MODE_SEND_FALLBACK_SCSV` and observes whether the
  server returns `inappropriate_fallback`.
- `tls.renegotiation_behavior` — active probe of client-initiated
  renegotiation via `SSL_renegotiate` + `SSL_do_handshake`. Records
  whether the server accepted, rejected, or did not complete.
- `tls.client_auth_request` — server `CertificateRequest` contents
  (`certificate_types`, accepted signature algorithms, CA DN list with
  parsed CN/O, TLS 1.3 `oid_filters`) and the alert the server emits
  after our empty-Certificate response — the "required mTLS vs
  optional" signal. The scanner never sends a real client certificate.

### Changed — SSLv3 / TLS 1.0 / TLS 1.1 protocol probing

When `legacy-probes` is enabled (the default), SSLv3 / TLS 1.0 / TLS 1.1
protocol-version probes run through the vendored OpenSSL path instead
of native-tls. The output shape (`tls.versions_offered.*`) is
unchanged. Consumers can still get native-tls coverage with
`--no-default-features --features http-checks,native-legacy` (see
"Build surface" below).

### Changed — output-section unification

Two top-level sections were removed in favor of merging their contents
into the equivalent canonical locations. Both existed only in the
pre-release (Unreleased) timeline; there are no tagged-version
consumers. Migration mapping for anyone who built against the
pre-release schema:

| Old location | New location |
|---|---|
| `tls.legacy_cipher_suites[]` | `tls.cipher_suites.{tls1_0, tls1_1, tls1_2}[]` entries with `provider == "openssl"` |
| `tls.ffdhe_support.{name}.tls1_2` | `tls.groups.tls1_2.{name}` |
| `tls.ffdhe_support.{name}.tls1_3` | `tls.groups.tls1_3.{name}` |

`tls.groups` also changed shape: previously a flat
`BTreeMap<String, GroupObservation>` (TLS 1.3-only by convention),
now a nested `{tls1_2, tls1_3}` map where each sub-object is the same
`{name: GroupObservation}` structure as before.

### Changed — deprecations

- `tls.downgrade_signaling.fallback_scsv_accepted` is deprecated in
  schema v1 and always renders as
  `{value: null, method: "not_probed", reason: "superseded_by_fallback_scsv_enforced"}`.
  The previous implementation was a TLS 1.3-support heuristic that
  over-reported enforcement. Scheduled for removal in schema v2;
  consumers should migrate to `fallback_scsv_enforced`.
- `tls.extensions.secure_renegotiation` (the RFC 5746 extension
  advertisement, observed passively in the ServerHello) remains
  authoritative for that signal. The new
  `tls.renegotiation_behavior.client_initiated_verdict` is a separate
  active-probe observation — they answer different questions.

### Build surface

- New optional crates in [Cargo.toml](Cargo.toml): `openssl = "0.10"`
  with `vendored` feature; `openssl-sys = "0.9"`; `openssl-src = "=300.5.5"`
  (exact pin — OpenSSL 3.5.5 LTS); `foreign-types = "0.3"`. All gated
  behind the `legacy-probes` cargo feature.
- `native-tls` and `tokio-native-tls` converted to optional; gated
  behind the new `native-legacy` cargo feature. Both `legacy-probes`
  and `native-legacy` ship in `default` — the stock build is
  unchanged from the user's perspective.
- Escape hatches for downstream packagers:
  - `--no-default-features --features http-checks` — minimum build;
    SSLv3/TLS1.0/TLS1.1 probing and the entire legacy-probe output
    surface are disabled (render as empty / `feature_disabled`). The
    schema shape stays stable.
  - `--no-default-features --features http-checks,native-legacy` —
    skip the OpenSSL build (no `perl` / `make` needed) but keep
    SSLv3/TLS1.0/TLS1.1 protocol-version probes through native-tls.
    Other legacy-probe observations are not produced in this mode.
- [Dockerfile](Dockerfile) builder stage now installs `perl` + `make`
  for `openssl-src`; drops `pkg-config` + `libssl-dev` (vendored
  OpenSSL needs no system headers).
- [deny.toml](deny.toml) `OpenSSL` license exception extended from
  `aws-lc-sys` alone to also cover `openssl-sys` and `openssl-src`.
- OpenSSL license text added at [LICENSE-OPENSSL](LICENSE-OPENSSL) —
  required by the Apache-2.0 distribution terms of OpenSSL 3.x.

### CVE response

Pinning `openssl-src = "=300.5.5"` (exact, no caret) means every
OpenSSL CVE is now a kemist CVE. Upgrades are deliberate: a version
bump goes through normal review rather than floating. Recommended
maintainer process: subscribe to `openssl-announce@openssl.org`; run
`cargo audit` weekly in CI; gate release on green audit.

### Internal

- New subsystem at [src/scanner/openssl/](src/scanner/openssl/) — ten
  submodules (`mod`, `alerts`, `ciphers`, `dh_params`, `ske_sig`,
  `ffdhe`, `fallback_scsv`, `renegotiation`, `client_auth`,
  `protocol_versions`). Rustls probe path is unchanged except for the
  call site that invokes `run_all_probes`.
- Deleted ~90 LOC of heuristic stubs in [src/scanner/mod.rs](src/scanner/mod.rs):
  `test_fallback_scsv*`, `test_tls_renegotiation`,
  `test_secure_renegotiation`, `test_tls_compression`.
  Superseded by real wire probes.
- Deleted the `#[allow(dead_code)]` OpenSSL cipher-enumeration stubs
  in [src/scanner/legacy.rs](src/scanner/legacy.rs) (lines 97-217 of
  the pre-change file). Their intended behavior now lives in
  [src/scanner/openssl/ciphers.rs](src/scanner/openssl/ciphers.rs).

### Release-gate smoke test

Before tagging a release, run the manual smoke procedure. The docker
fixture at [tests/fixtures/legacy-server/](tests/fixtures/legacy-server/)
gives full coverage locally; the badssl.com subdomains below extend
coverage to third-party servers that deliberately misconfigure specific
things.

```bash
# Local fixture — full coverage, offline.
cd tests/fixtures/legacy-server && ./generate-certs.sh && docker compose up -d
KEMIST_LEGACY_FIXTURE_ADDR=127.0.0.1:14443 \
KEMIST_LEGACY_FIXTURE_HOSTNAME=legacy-fixture.local \
  cargo test --features legacy-probes --test openssl_probe -- --ignored
docker compose down

# badssl — requires internet, spot-checks specific misconfigs.
./target/release/kemist rc4.badssl.com:443 --json \
  | jq '.tls.legacy_cipher_suites[] | select(.supported)'           # expect RC4 entries
./target/release/kemist 3des.badssl.com:443 --json \
  | jq '.tls.legacy_cipher_suites[] | select(.supported)'           # expect 3DES
./target/release/kemist dh1024.badssl.com:443 --json \
  | jq '.tls.dh_parameters'                                          # expect prime_bits: 1024
./target/release/kemist client-cert-missing.badssl.com:443 --json \
  | jq '.tls.client_auth_request'                                    # expect requested: true
./target/release/kemist mozilla-modern.badssl.com:443 --json \
  | jq '.tls.legacy_cipher_suites | map(select(.supported)) | length' # expect 0
```

Binary-size gate is enforced in CI ([.github/workflows/ci.yml](.github/workflows/ci.yml))
at 12 MiB. Current release binary size is ~9 MiB on Linux.

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
