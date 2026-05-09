# Changelog

All notable changes to kemist are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); version
numbers follow [semver](https://semver.org/).

## [Unreleased]

(no changes yet)

## [0.4.0] — 2026-04-30

Schema v2.0. One breaking restructure (split `tls.extensions`),
several signal-quality fixes that preserve schema shape, plus two
new functional probe slots that match what ssllabs reports for the
same behavior.

### Schema — BREAKING

- **`schema_version` bumped to `"2.0.0"`.** Pin on the major; v1.x
  consumers will fail to parse v2 records. The breaking change is
  the `tls.extensions` split (below). All other v2 additions are
  additive new fields with default `not_probed: feature_disabled` /
  empty rendering on absent data.
- **`tls.extensions` split into `tls.extensions` + `tls.behavioral_probes`.**
  The following observations live under `tls.behavioral_probes`
  because they aren't TLS extensions in the RFC 5246 §7.4.1.4 /
  RFC 8446 §4.2 sense:
  `heartbeat_echoes_oversized_payload`, `compression_selected`,
  `crime_vulnerable`, `record_compression_by_version`,
  `grease_echoed`, `hello_retry_request`, `ephemeral_key_reuse`,
  `bleichenbacher_oracle_probe`. True extensions stay under
  `tls.extensions`. Polarity (`true` = good vs bad) varies per field
  within `behavioral_probes` and is
  documented per-field in the schema; the bucket is a structural
  grouping, not a polarity grouping. Dashboards reading
  `tls.extensions.{ephemeral_key_reuse,bleichenbacher_oracle_probe,...}`
  must update their JSON pointers to `tls.behavioral_probes.*`.

### Added

- **Functional TLS 1.2 session resumption probes.** Two new
  observations on `tls.session_resumption.tls1_2`:
  `session_ticket_resumption_accepted` (RFC 5077 ticket round-trip)
  and `session_id_resumption_accepted` (RFC 5246 §F.1.4 session-ID
  caching). Implemented as separate handshake pairs in
  [scanner/backends/openssl/tickets.rs](src/scanner/backends/openssl/tickets.rs):
  the probe captures the `SslSession` from the first handshake (via
  `to_owned()` on `SslSessionRef`, which up-refs `SSL_SESSION`),
  presents it on a fresh second handshake via `SSL_set_session`,
  and reads `SSL_session_reused` post-handshake. The session-ID
  variant builds the context with `SslOptions::NO_TICKET` so the
  server falls back to session-ID caching, matching ssllabs's
  "Session resumption (caching)" probe. Existing `session_ticket_issued`
  / `session_id_issued` fields stay (issuance is independently
  observable from acceptance — the cloudflare.com pattern is "IDs
  issued, not accepted"). Cost: 4 additional TLS 1.2 handshakes
  per host (was 2).
- **`tls.behavioral_probes` block.** New top-level slot under
  `tls`. Same field types as before, just re-housed. Schema
  description makes per-field polarity explicit.
- **`returned_group` + `returned_prime_bits` on FFDHE TLS 1.2
  named-group rows.** When the cross-codepoint coherence pass
  attaches `reason: "server_does_not_honor_supported_groups"` to an
  FFDHE row, the row records what prime the server actually returned
  in response to the offer
  (`"ffdhe2048"`, `"modp3072"`, `"custom"`, etc., matching the
  `tls.dh_parameters[].classification` vocabulary, plus
  `returned_prime_bits` for size when classification is `custom`).
  Both fields omitted when the row has no cross-codepoint caveat or
  direct mismatch, or when it reflects a non-FFDHE codepoint.

### Changed

- **FFDHE TLS 1.2 named-group reporting now distinguishes RFC 7919
  named-group support from static-dhparam fallback.** Previously a
  server with the RFC 7919 ffdhe2048 prime configured as its static
  `ssl_dhparam` (the Mozilla / Apache / nginx default) would report
  `supported: true` for the `ffdhe2048` codepoint even though it
  ignores `supported_groups` entirely. fs.bbg.gov is the
  motivating case: the server returns its 2048-bit prime regardless
  of which FFDHE codepoint the client offers. kemist now records the
  returned prime on every FFDHE TLS 1.2 row while preserving row-level
  support for any codepoint whose own offer matched.
  Implementation: a new cross-codepoint coherence pass in
  [output/json.rs](src/output/json.rs) — when *any* FFDHE TLS 1.2
  probe returns a prime that doesn't match the offered codepoint
  (the `IgnoredGroupReturnedDifferentPrime` outcome), every FFDHE
  TLS 1.2 row gets
  `reason: "server_does_not_honor_supported_groups"` with
  `returned_group` + `returned_prime_bits` preserving per-row evidence.
  Direct mismatches remain `supported: false`; self-matches remain
  `supported: true`. TLS 1.3 FFDHE rows are unaffected
  (wire-confirmed via `key_share` rather than inferred from prime
  hashing). Old reason string
  `server_ignored_group_offer_returned_custom_prime` is removed; the
  new string is more honest about what was concluded.
- **ECDHE ephemeral-reuse probe handles X25519 / X448.** The probe
  previously rejected non-classical-EC curves with the misleading
  error `peer_tmp_key_not_ec:id=Id(1034)` whenever the server
  selected X25519 (NID 1034) — common on modern servers per
  Mozilla's intermediate config. The check at
  [ephemeral_reuse.rs](src/scanner/backends/openssl/ephemeral_reuse.rs)
  now branches on `pkey.id()`: classical EC keys (`Id::EC`)
  serialize as uncompressed point bytes via `EcKeyRef::public_key`,
  while RFC 7748 Montgomery curves (`Id::X25519`, `Id::X448`) pull
  raw bytes via `pkey.raw_public_key()`. From the reuse-detection
  perspective both are equivalent — we just hash whatever the
  server actually sent. Anything outside those three pkey types
  falls through to a more specific error
  `peer_tmp_key_unsupported_ecdhe:id=<n>`.
- **TCP RST mid-handshake on the static-DH raw probe is now a wire
  rejection, not a probe error.** When the server slammed the
  connection with `ECONNRESET` after our minimal ClientHello (the
  fs.bbg.gov pattern — perimeter security flagging an unusual CH
  shape), kemist emitted
  `supported: null, method: error, reason: "read_reply:Connection reset by peer (os error 104)"`.
  Semantically RST-after-CH is equivalent to the existing
  clean-FIN-after-CH path the probe already classifies as
  `NotSupported` — server saw our offer, chose not to engage. New
  `HandshakeOutcome::WireRejected { reason }` variant routes
  `io::ErrorKind::ConnectionReset` to
  `supported: false, method: probe, reason: "server_rst_after_clienthello"`
  in [scanner/raw/static_dh.rs](src/scanner/raw/static_dh.rs).
  Other read errors (timeouts, generic IO) keep the legacy `Error`
  rendering.
- **HelloRetryRequest renders `not_applicable` on hosts that don't
  support TLS 1.3.** HRR is a TLS 1.3 mechanism (RFC 8446 §4.1.3).
  When the protocol probe affirmatively reports
  `tls.versions_offered.tls1_3.supported: false`, the HRR row in
  [output/json.rs](src/output/json.rs) downgrades from
  `not_probed` to `not_applicable` with reason
  `tls13_not_supported_on_host:<original_probe_error>` —
  preserving the underlying HRR-probe error in the suffix so
  consumers who care about *why* HRR wasn't observed (e.g. the
  peer-RST-on-TLS-1.3-CH pattern fs.bbg.gov exhibits) keep the
  forensic detail. Only *affirmative* TLS-1.3-not-supported
  triggers the downgrade; if the version probe itself failed
  (`error` set), the legacy `not_probed` rendering stands so a
  real measurement failure isn't buried under `not_applicable`.
- **TLS 1.3 session resumption + 0-RTT render `not_applicable` on
  hosts that don't support TLS 1.3.** Same cross-reference logic
  applied to `tls.session_resumption.tls1_3.psk_resumption_accepted`
  and `early_data_accepted`. The rustls-backed probe's
  `ServerTlsVersionIsDisabledByOurConfig` error (its way of saying
  "you asked for TLS 1.3 only, server picked something else") is
  preserved in the reason suffix.

### Internal

- **`HandshakeOutcome` gained two structured variants.**
  `IgnoredGroupReturnedDifferentPrime { returned_group,
  returned_prime_bits }` replaces the old unit
  `IgnoredGroupReturnedCustomPrime` — the FFDHE cross-check now
  carries the actual returned classification through to the JSON
  layer instead of discarding it. `WireRejected { reason }` is the
  new wire-level-rejection variant used by the static-DH raw probe
  (see Changed above). All match sites updated; the cipher / group
  rendering paths fall through to consistent rendering for both.

### Documentation

- Schema migration notes added to
  [docs/OUTPUT_SCHEMA.md](docs/OUTPUT_SCHEMA.md) and
  [docs/CHECKS.md](docs/CHECKS.md): reason-string changes for
  FFDHE named-group rows, the `extensions` / `behavioral_probes`
  split, and the new functional resumption probes. Existing field
  documentation updated where field paths moved.

## [0.3.1] — 2026-04-24

Bugfix release. Four independent fixes for issues discovered while
integrating 0.3.0 with the kemist-dashboard pipeline. No schema-shape
changes; `schema_version` remains `"1.0.0"`. All additions are
additive / defensive.

### Fixed

- **`--update-trust-stores` exit code on non-macOS hosts.** The Apple
  trust bundle has no portable refresh path — the macOS System Roots
  keychain needs `security find-certificate`, which the bundle
  updater can't automate from Rust. The 0.3.0 code surfaced this as
  `UpdateReport.outcome = Err`, so `print_reports` returned `false`
  and the CLI exited 1 even when every real fetch succeeded. That
  broke `--update-trust-stores && --update-hsts-preload` chaining
  and turned cron alerts into noise. Introduces a third
  `UpdateOutcome::Info` variant for "diagnostic, not a failure" —
  the apple note still prints, but the exit code is now
  `!any_err_present`. Real failures (cache dir missing, write
  errors, manifest-save errors, fetch errors) stay `Err` and keep
  their non-zero exit. Four unit tests lock the invariant.
- **`tls.versions_offered.tls1_3` false-true against TLS 1.2-only
  servers.** `test_rustls_protocol` built its `rustls::ClientConfig`
  via the default `builder()`, which enables both TLS 1.2 and 1.3 in
  the client's `supported_versions` extension. The "test TLS 1.3
  support" probe therefore offered both versions; on a 1.2-only
  server rustls silently negotiated 1.2, the handshake completed,
  and the scanner emitted `tls1_3.offered: true` despite every
  downstream 1.3 probe (cipher suites, groups, HRR, resumption)
  correctly failing with `protocol_version` alerts. Reproduced on
  `login.nist.gov:443`. Switched to
  `ClientConfig::builder_with_protocol_versions(&[rv])` with `rv`
  being exactly `&rustls::version::TLS12` or `&TLS13` — the same
  pinning idiom `backends/rustls/mod.rs` already uses for the group
  and cipher probes.
- **`http.preload_list_source` regex rejected real scanner output.**
  The schema's pattern permitted only `compiled_in` and
  `runtime_override:<path>`, but `scanner::http` at line 258 emits
  `cache_refreshed:<path>` after the cache file written by
  `--update-hsts-preload` gets loaded — so any scan that ran on a
  host whose preload cache had been refreshed failed downstream AJV
  validation. Widened the pattern to
  `^(compiled_in|cache_refreshed:.+|runtime_override:.+)$`, matching
  the shape `validation.trust_store_sources.*` already used.
- **`tls.dh_parameters[].classification` enum missed the RFC 3526
  Modp groups.** `DhClassification::as_schema_str` has ten variants
  — the five FFDHEs, four Modp groups (`modp1024`, `modp1536`,
  `modp2048`, `modp3072`), and `custom` — but the schema's enum only
  listed the FFDHEs + `custom`. The federal-gov scan run on
  2026-04-24 hit modp* at scale and the dashboard deploy pipeline
  rejected hundreds of records. Added the four `modp*` strings.

### Changed

- **`tls.groups.*[].iana_code` now populated for aws-lc-rs-backed
  groups.** The JSON emitter's aws-lc-rs branch hardcoded
  `iana_code: None`; the OpenSSL branch already carried the field.
  Downstream consumers therefore had to do a name→codepoint lookup
  for modern-path groups (X25519, secp256r1, secp384r1, MLKEM768,
  the PQC hybrids) but not legacy-path groups — inconsistent, so the
  field was optional in practice. Routes the emitter through the
  existing `rustls::groups::iana_code_for` helper (which the text
  renderer already used as a fallback).

### Added — regression guards

- **Schema ↔ Rust enum coverage tests.** Four new tests in
  [tests/schema_validation.rs](tests/schema_validation.rs) iterate
  every variant of each schema-constrained Rust enum
  (`Method`, `CipherClassification`, `DhClassification`) and
  emitter (`http.preload_list_source` forms), asserting each one
  round-trips the schema's enum or pattern constraint. Uses
  exhaustive `match` guards so adding a Rust variant without
  updating the schema (or the test list) produces a compile-time
  failure at the editing site. Either of the two schema-gap bugs
  above would have fired these tests before 0.3.0 shipped.

## [0.3.0] — 2026-04-23

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
- `tls.certificates.chain[].wire_position` — 0-indexed position in
  the wire-order chain the server delivered (`0` = leaf). Duplicates
  preserved; parse failures appear as gaps in the sequence. Lets
  downstream rule engines observe chain ordering directly rather
  than inferring it from array index semantics.
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
- `tls.signature_algorithm_policy_probe.*.leaf_fingerprint_sha256`
  + `.leaf_subject_dn` — captured after every successful
  constrained handshake so downstream rule engines can detect
  dual-cert deployments (e.g. RSA + ECDSA leaves on the same
  endpoint). Two distinct fingerprints across the five probes is
  the downstream-comparable signal; the scanner only records.
- `tls.extensions.delegated_credentials` — RFC 9345 observation.
  Two-path pipeline: the byte-level hello probe offers ext 0x0022
  in its TLS 1.2 ClientHello and records whether the server echoes
  an empty ext 0x0022 in ServerHello (presence only); the OpenSSL
  TLS 1.3 msg-callback walks the leaf CertificateEntry's
  extensions for ext 0x0022 and parses the `DelegatedCredential`
  header fields (`valid_time_seconds`,
  `expected_cert_verify_algorithm`). Unified shape with
  `delivery_path` identifying which path populated the record. No
  DC signature verification, no wall-clock comparison on
  `valid_time` — observation only.
- `tls.extensions.ephemeral_key_reuse` — Raccoon-class observation
  (CVE-2020-1968). For each of DHE and ECDHE the scanner picks a
  server-supported suite from the earlier cipher probe and runs
  two fresh TLS 1.2 handshakes with session caching disabled,
  comparing the server's ephemeral public value (`Y` / ECDH
  point) byte-for-byte across the pair. Records
  `dhe_public_reused_across_connections`,
  `ecdhe_public_reused_across_connections`, and the pinned suite
  names. No side-channel attempt; ephemeral reuse is the
  prerequisite signal, not the exploit.
- `tls.extensions.bleichenbacher_oracle_probe` — ROBOT /
  Bleichenbacher differential probe. Gated on `TLS_RSA_*`
  observed supported. Drives five raw-socket TLS 1.2 handshakes
  pinned to `TLS_RSA_WITH_AES_128_CBC_SHA`, one per malformed
  PKCS#1 v1.5 `ClientKeyExchange` variant
  (`correctly_formatted_pkcs1`, `invalid_0x00_02_prefix`,
  `invalid_version_0x00_02_byte_swap`, `null_separator_missing`,
  `wrong_tls_version_in_pms`), then sends
  `CKE + ChangeCipherSpec + Finished` where the Finished is
  crypto-correct under the variant's *intended* PMS:
  TLS 1.2 PRF (P_SHA256) master-secret derivation, key expansion
  (client write MAC + AES-128 keys), SHA-256 transcript hash over
  ClientHello+ServerHello+Certificate+ServerHelloDone+CKE,
  HMAC-SHA1 MAC-then-encrypt with explicit per-record IV and
  TLS CBC padding. For variant 1 (correct padding) our keys
  match the server's and Finished verifies; for variants 2–5
  the server's key derivation diverges from ours, so the
  Finished MAC check surfaces the alert differential. Records
  per-variant `alert_category` / `tcp_reset` / `elapsed_ms` /
  `other_outcome`. No `vulnerable` boolean — the five-entry
  comparison table is the observation.

### Added — CLI

- `--include-ocsp-raw` — emit raw OCSP bytes as hex under
  `tls.extensions.ocsp_stapling.raw_hex`. Off by default.
- `--sigalg-probe-skip=<csv>` — skip individual sigalg-policy
  probes. Recognized: `sha256_plus_only`, `ecdsa_only`,
  `rsa_pss_only`, `rsa_pkcs1_only`. Unknown entries ignored.

### Changed

- OpenSSL named-group probe now covers `X448`, `secp521r1`, `MLKEM512`,
  `MLKEM1024`, and `secp384r1MLKEM1024` in addition to FFDHE. Five
  aws-lc-rs `not_probed` slots flip to real `supported: true | false`
  observations. Probe module renamed `openssl::ffdhe` →
  `openssl::kx_groups`; `OpensslObservations.ffdhe_probes` →
  `kx_group_probes`. Output-schema shape unchanged.
- Removed `X25519Kyber768Draft00` from the probe inventory —
  pre-standard Cloudflare codepoint obsoleted by `X25519MLKEM768`;
  field no longer appears in `tls.groups.tls1_3`.
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
- Per-kx-group probing for 11 target groups: classical (X25519/X448/
  secp256r1-521) + PQC hybrids (X25519MLKEM768/secp256r1MLKEM768/
  secp384r1MLKEM1024) + standalone ML-KEM (512/768/1024). Groups
  aws-lc-rs doesn't ship emit `not_probed` with a specific reason —
  never `supported: false` without a real probe.
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
  X448, secp521r1, secp384r1MLKEM1024 emit `not_probed` from the
  aws-lc-rs path; the OpenSSL named-group probe fills those slots.
  See [docs/PQC.md](docs/PQC.md).
- HSTS preload list is a 12-entry stub. Full Chromium
  `transport_security_state_static.json` snapshot deferred.
- PQC signature verification not performed — OID match only. Chain
  validation via webpki-roots uses classical algorithms.

[0.1.0]: https://github.com/regenscheid/kemist-scanner/releases/tag/v0.1.0
