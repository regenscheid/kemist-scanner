# kemist observation catalog

What kemist measures, how it measures it, and what the limits are.
Every observation is a raw signal — no compliance verdicts. Rule
evaluation lives in downstream projects.

## TLS versions offered

| Version | How | Source |
|---|---|---|
| SSL 2.0 | Raw TCP + hand-crafted SSL 2.0 CLIENT-HELLO (legacy msg format) | [scanner/raw/sslv2.rs::probe](../src/scanner/raw/sslv2.rs) |
| SSL 3.0 | OpenSSL 3.5 with `min/max = SSL3`, legacy provider + seclevel 0 (gated on `legacy-probes`). Dispatched via `BackendRegistry::route_version(Ssl3)` → `OpensslBackend::handshake(version_only)`. | [backends/openssl/protocol_versions.rs](../src/scanner/backends/openssl/protocol_versions.rs) |
| TLS 1.0 | same path as SSL 3.0 | same |
| TLS 1.1 | same path as SSL 3.0 | same |
| TLS 1.2 | rustls with `with_protocol_versions(&[&TLS12])` | [scanner/mod.rs::test_rustls_protocol](../src/scanner/mod.rs) |
| TLS 1.3 | rustls with `with_protocol_versions(&[&TLS13])` | same |

Each version is a distinct handshake attempt. Success → `offered: true,
method: probe`. Server-level rejection → `offered: false, method: probe`.
Network failure → `offered: null, method: error`.

**SSLv2 SERVER-HELLO cipher_specs.** The raw-socket SSLv2 probe
doesn't just return `supported: bool`; when the server answers with
a SERVER-HELLO, the probe parses the `cipher_specs` list (3-byte
codes) the server echoed from our offer set, maps each to its
canonical `SSL_CK_*` name, and surfaces them as entries in
`tls.cipher_suites.ssl2[]`. Each entry is `supported: true` (by
definition — the server listed it as accepted). SSLv2 predates SNI,
so the probe reaches whatever TCP answers at `host:port` regardless
of vhost; for SNI-routed servers, a `supported: true` observation
here reflects the default-backend's SSLv2 state, not the SNI'd
vhost's.

## Cipher suites

**Coverage: aws-lc-rs's `ALL_CIPHER_SUITES`** — typically 9 suites at
this build's pinned version:

```
TLS13_AES_256_GCM_SHA384           0x1302
TLS13_AES_128_GCM_SHA256           0x1301
TLS13_CHACHA20_POLY1305_SHA256     0x1303
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384        0xC02C
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256        0xC02B
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256  0xCCA9
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384          0xC030
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256          0xC02F
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256    0xCCA8
```

**Mechanism.** For each suite, build a `CryptoProvider` with that single
entry in its `cipher_suites: Vec<SupportedCipherSuite>`, pass it to
`ClientConfig::builder_with_provider`, and attempt a handshake.

| Outcome | Schema |
|---|---|
| Handshake completes | `{supported: true, method: probe}` |
| Server sends HandshakeFailure alert or resets after ClientHello | `{supported: false, method: probe}` |
| TCP timeout / connection refused / other error | `{supported: null, method: error, reason: "<cat>"}` |

**What's NOT probed.** aws-lc-rs doesn't ship RC4, 3DES, null ciphers,
export-grade ciphers, or most CBC suites. Servers still accepting
those are invisible to this scanner's cipher probe path — they appear
as "the suite is not in `capabilities.probed_cipher_suites`" rather
than as `supported: false`. Downstream rule engines checking for
weak-cipher acceptance must cross-reference against a fuller cipher
registry.

**Server ordering.** `tls.cipher_suites.server_enforces_order` compares
two handshakes with reversed cipher orderings. Same negotiated suite
both times → `true` (server picks, ignores client order); different →
`false` (server honors client preference).

## Legacy ciphers & misconfiguration (OpenSSL subsystem)

Gated by the `legacy-probes` cargo feature (default-on). Fills observation
gaps that aws-lc-rs cannot reach: RSA-kex suites, RC4, DES/3DES, NULL,
anon-DH, FFDHE arithmetic, TLS_FALLBACK_SCSV enforcement, client
renegotiation behavior, and CertificateRequest contents. All probes
run against a vendored OpenSSL 3.5 LTS (`openssl-src = "=300.5.5"`).

| Observation | How | Output field | Source |
|---|---|---|---|
| Legacy cipher suite probe | Per-suite handshake with single-suite cipher list + SECLEVEL=0 + version pinned. Covers SSL 3.0 (classic RSA-kex suites incl. RC4/3DES/CBC/export/NULL — for POODLE-era CBC visibility) through TLS 1.2. | `tls.cipher_suites.{ssl3, tls1_0, tls1_1, tls1_2}[]` entries with `provider: "openssl"` | [openssl/ciphers.rs](../src/scanner/backends/openssl/ciphers.rs) |
| DH parameter capture | `SSL_get_peer_tmp_key` after every successful DHE handshake; SHA-256 of prime classified against RFC 7919 FFDHE (`ffdhe{2048,3072,4096,6144,8192}`) and RFC 2409/3526 MODP Oakley groups (`modp{1024,1536,2048,3072}`). Unknown primes → `custom` with `prime_bits` preserved | `tls.dh_parameters[]` | [openssl/dh_params.rs](../src/scanner/backends/openssl/dh_params.rs) |
| SKE / CertificateVerify signature | `SSL_ctrl(SSL_CTRL_GET_PEER_SIGNATURE_NAME, …)` post-handshake | `tls.server_key_exchange_signatures[]` | [openssl/ske_sig.rs](../src/scanner/backends/openssl/ske_sig.rs) |
| Named-group probe (FFDHE + aws-lc-rs gaps + non-NIST curves) | `set_groups_list(<name>)` × `{TLS 1.2 + DHE cipher list (FFDHE only), TLS 1.3}`; FFDHE rows cross-check observed prime against advertised codepoint. Also covers TLS 1.3 groups aws-lc-rs does not ship: `X448`, `secp521r1`, `MLKEM{512,1024}`, `secp384r1MLKEM1024`, `brainpoolP{256,384,512}r1`. Deprecated/non-NIST curves that OpenSSL 3.5 accepts by name but refuses at handshake-build time (`secp192r1`, `secp224r1`, `secp256k1`) surface as `{method: not_probed, reason: "openssl_3x_group_not_available:<name>"}` — a backend-capability signal, not a server observation. | `tls.groups.{tls1_2, tls1_3}.*` entries with `provider: "openssl"` | [openssl/kx_groups.rs](../src/scanner/backends/openssl/kx_groups.rs) |
| TLS_FALLBACK_SCSV enforcement | Characterize server max → probe one step below with `SslMode::SEND_FALLBACK_SCSV`; expect `inappropriate_fallback` alert | `tls.downgrade_signaling.fallback_scsv_enforced` | [openssl/fallback_scsv.rs](../src/scanner/backends/openssl/fallback_scsv.rs) |
| Client-initiated renegotiation | TLS 1.2 handshake → `SSL_renegotiate` → `SSL_do_handshake`; observe alert / close / success | `tls.renegotiation_behavior` | [openssl/renegotiation.rs](../src/scanner/backends/openssl/renegotiation.rs) |
| CertificateRequest capture | `SSL_CTX_set_msg_callback` (via `SSL_CTX_callback_ctrl`) intercepting msg_type 13; parse TLS 1.2 and TLS 1.3 shapes | `tls.client_auth_request` | [openssl/client_auth.rs](../src/scanner/backends/openssl/client_auth.rs) |
| TLS 1.3 EncryptedExtensions capture | `SSL_CTX_set_msg_callback` intercepts msg_type 8; parser extracts `record_size_limit` (RFC 8449) and `compress_certificate` (RFC 8879). See caveat below. | `tls.extensions.record_size_limit`, `tls.extensions.compress_certificate_algorithms` | [openssl/tls13_extensions.rs](../src/scanner/backends/openssl/tls13_extensions.rs) |
| Delegated credentials — TLS 1.3 | Same msg-callback intercepts msg_type 11 (Certificate); parser walks the leaf CertificateEntry extensions (RFC 8446 §4.4.2) for ext 0x0022; parses RFC 9345 §4.1 DelegatedCredential header (`valid_time`, `expected_cert_verify_algorithm`). No signature validation, no wall-clock comparison | `tls.extensions.delegated_credentials.{valid_time_seconds, expected_cert_verify_algorithm}` with `delivery_path = "tls1_3_certificate_entry"` | [openssl/tls13_extensions.rs](../src/scanner/backends/openssl/tls13_extensions.rs) |
| Session resumption — TLS 1.2 ticket + rotation | Two sequential TLS 1.2 handshakes with session cache mode `CLIENT`; compare `SSL_SESSION_get_id` across handshakes for rotation proxy | `tls.session_resumption.tls1_2.*` | [openssl/tickets.rs](../src/scanner/backends/openssl/tickets.rs) |
| Ephemeral DH/ECDH key reuse (Raccoon signal) | Read earlier cipher_probes for a supported DHE / ECDHE suite; pin `DHE-RSA-AES128-GCM-SHA256` / `ECDHE-RSA-AES128-GCM-SHA256`; run two fresh TLS 1.2 handshakes per family with session caching disabled; pull the server's ephemeral public value via `SSL_get_peer_tmp_key` (DH `Y` via openssl-sys `DH_get0_key` + `BN_bn2bin`; ECDH point via `EcPoint::to_bytes` uncompressed); compare SHA-256 across the pair. No side-channel attempt | `tls.extensions.ephemeral_key_reuse.*` | [openssl/ephemeral_reuse.rs](../src/scanner/backends/openssl/ephemeral_reuse.rs) |
| Signature-algorithm policy probe | Five constrained handshakes with `SSL_CTX_set1_sigalgs_list` pinned to each constraint family (`sha256_plus_only`, `ecdsa_only`, `rsa_pss_only`, `rsa_pkcs1_only`, `eddsa_only`); capture outcome + selected sigalg | `tls.signature_algorithm_policy_probe.*` | [openssl/sigalg_policy.rs](../src/scanner/backends/openssl/sigalg_policy.rs) |
| Leaf fingerprint per sigalg probe | `SSL_get_peer_certificate` after each completed constrained handshake; SHA-256 of leaf DER (lowercase hex) + subject DN via x509-parser (matches `certificates.leaf.subject_dn` formatting). Two distinct fingerprints across the probe set → dual-cert deployment signal; scanner records, downstream compares | `tls.signature_algorithm_policy_probe.*.leaf_fingerprint_sha256`, `tls.signature_algorithm_policy_probe.*.leaf_subject_dn` | [openssl/sigalg_policy.rs](../src/scanner/backends/openssl/sigalg_policy.rs) |

Error classification for every OpenSSL probe flows through
[openssl/alerts.rs](../src/scanner/backends/openssl/alerts.rs) — same
`tls_alert_<snake_name>` categories as the rustls path, so rule engines
can key on alert categories without knowing which backend produced them.

**FFDHE cross-check.** A TLS 1.2 FFDHE probe that completes a DHE
handshake but returns a prime that doesn't match the advertised
codepoint surfaces as
`{supported: false, reason: "server_ignored_group_offer_returned_custom_prime"}`.
Distinct from a plain `supported: false` — the server ignored
`supported_groups` entirely.

**CertificateRequest probe discipline.** The scanner never provisions
a real client certificate. OpenSSL's default behavior with no cert
configured is to send an empty `Certificate` message; the server's
alert on that response distinguishes required from optional mTLS.

**Feature-disabled rendering.** When `legacy-probes` is compiled off,
every field above renders as `[]` / `{}` / `null` with
`reason: "feature_disabled"` — the schema shape is stable across
feature matrices.

**Pre-1.3 protocol-version probing** (SSL 3.0, TLS 1.0, TLS 1.1) also
moves onto this subsystem when `legacy-probes` is on; see the top of
this document for the backend-selection table.

**TLS 1.3 EncryptedExtensions — known limitation.** Both
`record_size_limit` (RFC 8449) and `compress_certificate` (RFC 8879)
require the server to echo only in response to a matching client
offer. OpenSSL 3.5 reserves ext codes 27 and 28 for its internal
handlers so `SSL_CTX_add_custom_ext` refuses to register, and the
native high-level setters (`SSL_CTX_set1_cert_comp_preference`
etc.) aren't exposed in openssl-sys 0.9.109. Result: on real-world
targets both fields are typically absent. The msg_callback
infrastructure + parser are in place; a future workstream fills the
client-offer gap.

**Session resumption — rotation proxy semantics.** openssl-sys
0.9.109 doesn't expose `SSL_SESSION_get0_ticket`, so we diff the
session-ID bytes across two successive handshakes as a rotation
proxy. Treat `ticket_rotated_across_connections: false` as "likely
stable" rather than "definitely same ticket bytes." TLS 1.3 PSK
resumption + 0-RTT (`early_data_accepted`) are plumbed as
`not_probed` pending a follow-up workstream; both require a
post-handshake read dance + `SSL_write_early_data` handling.

**Sigalg policy probe — cost + CLI skip.** +5 handshakes per
target by default. `--sigalg-probe-skip=<csv>` opts out individual
constraints; skipped slots emit
`method: not_probed, reason: cli_skipped`. Interpretation:
`rsa_pkcs1_only → handshake_failure` is the modern-posture "good"
signal (server refuses PKCS#1 v1.5 signatures);
`sha256_plus_only → handshake_failure` flags SHA-1-signed cert
chains; `ecdsa_only → handshake_failure` flags RSA-only
deployments; `eddsa_only → handshake_failure` flags servers
without EdDSA (Ed25519/Ed448) support, vs
`handshake_complete` meaning an EdDSA-capable deployment.

## Key exchange groups

**Target list.** Hardcoded inventory in
[scanner/groups.rs](../src/scanner/groups.rs) (aws-lc-rs side) plus
the OpenSSL-backed extensions in
[openssl/kx_groups.rs](../src/scanner/backends/openssl/kx_groups.rs):

Classical (NIST + djb): `X25519`, `X448`, `secp256r1`, `secp384r1`,
`secp521r1`

Non-NIST curves (eIDAS / BSI profiles): `brainpoolP256r1` (0x001F),
`brainpoolP384r1` (0x0020), `brainpoolP512r1` (0x0021)

Deprecated / non-TLS-exported curves (listed for inventory, always
`method: not_probed`): `secp192r1` (0x0013), `secp224r1` (0x0015),
`secp256k1` (0x0016)

FFDHE (RFC 7919): `ffdhe2048`..`ffdhe8192`

PQC hybrids: `X25519MLKEM768` (0x11EC), `secp256r1MLKEM768` (0x11EB),
`secp384r1MLKEM1024` (0x11ED)

Standalone ML-KEM: `MLKEM512` (0x0200), `MLKEM768` (0x0201),
`MLKEM1024` (0x0202)

**Coverage.** aws-lc-rs ships a subset (typically X25519,
secp256r1, secp384r1, MLKEM768, X25519MLKEM768, secp256r1MLKEM768).
The rest are filled by the OpenSSL named-group probe, which overrides
any leftover `not_probed` slot with a real `supported: true | false`
observation. Entries that carry `method: not_probed` after both paths
have run identify a codepoint neither backend ships.

**Mechanism.** Per-group handshake with that single group pinned in
`kx_groups`. Classical ECDHE curves (X25519, X448, secp256r1/384r1/
521r1, brainpool*) are probed at **both TLS 1.2 and TLS 1.3** — the
TLS 1.2 handshake pins the cipher list to ECDHE-only
(`ECDHE:@SECLEVEL=0` on the OpenSSL side; rustls's TLS 1.2 provider
default is already ECDHE-heavy), so a successful handshake can only
use the advertised curve. ML-KEM and PQC hybrids are probed at TLS
1.3 only (they're not defined in TLS 1.2). FFDHE groups are
TLS-1.2-only on the DHE cipher path (plus TLS 1.3 key_share where
the server opts in). Outcomes classify identically to cipher probes.

**Future extension paths.** See [PQC.md](PQC.md) and the module
docstring in [src/scanner/groups.rs](../src/scanner/groups.rs).

## Certificate observations

From [scanner/cert.rs](../src/scanner/cert.rs) and
[model/cert.rs](../src/model/cert.rs):

- Subject / issuer parsed via x509-parser
- SAN list (DNS + IP, plus Email/URI entries prefixed for identification)
- `not_before` / `not_after` as ISO 8601
- `signature_algorithm_oid` — raw OID string
- `signature_algorithm_name` — resolved name, falls back to OID for unknowns
- `signature_algorithm_structured` — decomposition of the signature
  AlgorithmIdentifier into `{hash, algorithm, parameters}`.
  `algorithm` is the family in canonical snake-case (`rsa`,
  `rsa_pss`, `ecdsa`, `ed25519`, `ml_dsa_65`,
  `slh_dsa_sha2_128s`...). `hash` is the hash family
  (`sha256` / `sha384` / `sha512` / `sha1`), absent when the scheme
  hashes internally (Ed25519, Ed448, ML-DSA, SLH-DSA). For RSA-PSS
  the hash is extracted from the outer `AlgorithmIdentifier.parameters`
  SEQUENCE (context tag `[0]`); `parameters` field renders
  `mgf1-<hash>` on success or `rfc4055_defaults` when PSS parameters
  were omitted (RFC 4055 §3.1 defaults: SHA-1 + MGF1-SHA1).
- `pqc_signature_family` — present only when the signature OID is
  PQC. `ml_dsa` for FIPS 204 codepoints
  (`2.16.840.1.101.3.4.3.{17,18,19}`); `slh_dsa` for FIPS 205
  codepoints (`.{20..31}` — SHA2 family 20-25, SHAKE family 26-31);
  `composite` reserved for IETF LAMPS composite-signature drafts.
- `public_key.curve` / `public_key.curve_oid` — for EC/EdDSA keys,
  the named-curve OID is parsed from `AlgorithmIdentifier.parameters`
  (not inferred from point-length). Distinguishes secp256r1 from
  brainpoolP256r1 / secp256k1, which share a 65-byte uncompressed
  point length — byte-length heuristics silently misclassify them.
  `curve` carries the human-readable name; `curve_oid` is the
  authoritative field. Ed25519 / Ed448 use distinct algorithm OIDs
  (`1.3.101.{112,113}`) rather than `id-ecPublicKey + parameters`,
  handled via the algorithm field.
- `public_key.rsa_exponent` — the RSA public exponent `e` (RFC
  8017 §3.1), populated only for RSA keys. `u64`-encoded; values
  observed in practice are `3`, `17`, `65537`. Lets rule engines
  flag weak small-exponent keys without re-parsing SPKI bytes.
- `is_pqc_signature` — bool, OID matches ML-DSA (FIPS 204) or SLH-DSA
  (FIPS 205) table. 15-entry OID map in [scanner/cert.rs](../src/scanner/cert.rs).
  Composite/hybrid sig OIDs stubbed for future IETF draft codepoints.
- `embedded_scts` — count of entries in extension 1.3.6.1.4.1.11129.2.4.2
- `fingerprint_sha256` / `fingerprint_sha1` — full cert DER hash
- `extensions` — parsed X.509 v3 extensions per cert; see
  [OUTPUT_SCHEMA.md](OUTPUT_SCHEMA.md#certificates) for the field
  reference. Populated via x509-parser's `parsed_extension()` plus a
  byte-level RFC 7633 TLS Feature parser for Must-Staple (no
  dedicated variant in x509-parser 0.16). Per-SCT detail (`log_id`,
  `timestamp`, sig algo, signature) now lands under
  `extensions.scts[]` alongside the backwards-compat `embedded_scts`
  count.

## Trust validation

From [scanner/probe.rs::evaluate_validation](../src/scanner/probe.rs)
plus [scanner/trust_stores.rs](../src/scanner/trust_stores.rs) for
bundle loading.

Every compiled-in trust store runs its own `WebPkiServerVerifier`
attempt against the server's chain. Results land as independent
`ObservationBool` fields under `validation.chain_valid_to_<name>_roots`,
with per-store error strings collected under
`validation.per_store_validation_errors` and provenance
(`compiled_in` vs `runtime_override:<path>`) under
`validation.trust_store_sources`.

| Store | Source | Notes |
|---|---|---|
| `webpki-roots` | [webpki-roots](https://crates.io/crates/webpki-roots) crate (Mozilla CCADB) | Always available; refresh via `cargo update`. |
| `microsoft` | [data/trust_stores/microsoft_ccadb.pem](../data/trust_stores/microsoft_ccadb.pem) | Placeholder today — supply via `--trust-store microsoft:<path>`. |
| `apple` | [data/trust_stores/apple_pki.pem](../data/trust_stores/apple_pki.pem) | macOS System Roots keychain (~160 TLS roots). NOT Apple's own PKI; see [data/trust_stores/README.md](../data/trust_stores/README.md). |
| `us-fpki-common` | [data/trust_stores/us_fpki_common.pem](../data/trust_stores/us_fpki_common.pem) | Federal Common Policy CA G2 + SIA-discovered agency intermediates. |
| `us-dod` | [data/trust_stores/us_dod.pem](../data/trust_stores/us_dod.pem) | Placeholder today. |

**Runtime overrides.** `--trust-store <name>:<path>` replaces a
compiled-in bundle; `--extra-trust-store <name>:<path>` adds a new
named bundle surfaced under
`validation.chain_valid_to_custom_roots.<name>`. Extra-store names
must be lowercase ASCII + digits + hyphens.

**Per-store retry.** Each verifier retries with a SAN-derived
name when the first pass fails on `NotValidForName`, isolating
chain validity from name-match issues (same pattern as the legacy
single-store path).

**Empty bundle handling.** Placeholder PEMs (Microsoft + DoD
today) load successfully but produce no `WebPkiServerVerifier`;
the corresponding `chain_valid_to_<name>_roots` renders as
`{method: not_probed, reason: "trust_store_empty"}`, and the same
string lands in `per_store_validation_errors.<name>`.

| Other observation | How |
|---|---|
| `name_matches_sni` | Independent SAN/CN match using RFC 6125 wildcard semantics. Runs regardless of chain validity; trust-store-agnostic. |
| `validation_error` | **Legacy** — webpki-roots error string only. New integrations should key on `per_store_validation_errors` instead. |

## Extension observations

Captured via two paths — rustls connection state and a dedicated
byte-level TLS 1.2 probe.

### From rustls connection state ([scanner/probe.rs](../src/scanner/probe.rs))

| Schema field | Source |
|---|---|
| `tls.negotiated.*` | `ClientConnection::{protocol_version,negotiated_cipher_suite,negotiated_key_exchange_group,alpn_protocol}` |
| `tls.extensions.ocsp_stapling.{stapled, response_length}` | Verifier `verify_server_cert` receives `ocsp_response: &[u8]`; bytes retained for downstream parsing |
| `tls.extensions.ocsp_stapling.content` | Raw bytes parsed via [model/ocsp_response.rs](../src/model/ocsp_response.rs) (RFC 6960 BasicOCSPResponse). `cert_status`, timestamps, responder ID, serial, hash-algorithm OID |
| `tls.extensions.ocsp_stapling.delivery_path` | Derived from negotiated version: `tls1_2` for CertificateStatus flight, `tls1_3` for EncryptedExtensions status_request response |
| `tls.extensions.ocsp_stapling.raw_hex` | Gated behind `--include-ocsp-raw` CLI flag |
| `tls.extensions.alpn_offered` | What kemist sent in ClientHello |

### From byte-level ServerHello probe ([scanner/hello.rs](../src/scanner/hello.rs))

rustls doesn't expose ServerHello extensions to userland code. kemist
runs a separate raw-socket TLS 1.2 handshake, hand-crafts a ClientHello
advertising the extensions we want echoed, parses the returned
ServerHello bytes.

| Schema field | ServerHello extension |
|---|---|
| `tls.extensions.ems` | 23 (Extended Master Secret, RFC 7627) |
| `tls.extensions.encrypt_then_mac` | 22 (RFC 7366) |
| `tls.extensions.heartbeat_present` | 15 (RFC 6520) |
| `tls.extensions.secure_renegotiation` | 0xff01 (RFC 5746 renegotiation_info) |
| `tls.extensions.compression_offered` | compression_method byte in ServerHello |
| `tls.extensions.sct.delivery_paths` (tls_extension) | 18 (signed_certificate_timestamp) |
| `tls.extensions.truncated_hmac` | 4 (RFC 6066 §7 — deprecated) |
| `tls.extensions.npn` | 13172 (Google pre-ALPN, deprecated) |
| `tls.extensions.supported_point_formats_echoed` | 11 (RFC 4492 §5.1.2) — parsed canonical names |
| `tls.extensions.max_fragment_length` | 1 (RFC 6066 §4) — server-echoed code mapped to `2^9`..`2^12` |
| `tls.extensions.grease_echoed` | RFC 8701 conformance — ClientHello injects a GREASE ext codepoint (`0x0A0A`); probe walks ServerHello extensions looking for any echoed GREASE value |
| `tls.extensions.hello_retry_request` | RFC 8446 §4.1.3 — dedicated TLS 1.3 probe with empty `key_share`; ServerHello random compared to the HRR sentinel (`cf21ad74…a8339c`, SHA-256 of `"HelloRetryRequest"`) |
| `tls.extensions.delegated_credentials` (TLS 1.2 path, presence only) | 0x0022 (RFC 9345) — ClientHello offers ext 0x0022 with a SignatureSchemeList; DC-supporting servers echo an empty ext 0x0022 in ServerHello. TLS 1.3 detail fields come from a separate Certificate-message observation (see OpenSSL backend table above) |
| `tls.downgrade_protection.tls13_downgrade_sentinel` | Last 8 bytes of ServerRandom per RFC 8446 §4.1.3 |

**The byte probe is a TLS 1.2 probe.** When the server only speaks TLS
1.3, EMS/EtM/secure_renegotiation render as `not_applicable`. Heartbeat
is defined for both and renders regardless.

**TLS 1.3 downgrade sentinel.** Observed from the plaintext
ServerRandom (first 32 bytes of ServerHello). A TLS 1.3-capable
server that negotiates TLS 1.2 in response to a TLS 1.2 ClientHello
MUST set the trailing 8 bytes to `DOWNGRD\x01` per RFC 8446 §4.1.3.
Because kemist's byte probe always offers TLS 1.2, matching this
sentinel is a useful TLS-1.3-capability signal even though the probe
itself never negotiates 1.3.

### Other extension-adjacent observations

- `extensions.heartbeat_echoes_oversized_payload` — active Heartbleed
  (CVE-2014-0160) probe. Sends a raw TLS 1.2 ClientHello advertising
  the heartbeat extension, reads ServerHello; if the server doesn't
  echo the heartbeat extension in its reply, emits `false` (not
  vulnerable, feature not negotiated). Otherwise injects an 8-byte
  malformed heartbeat record (`18 03 03 00 03 01 40 00`) over
  plaintext and classifies the response as `true` (vulnerable — server
  echoed a heartbeat record with >16 bytes of leaked memory) or
  `false`. `null` with `heartbeat_probe_inconclusive` only for TCP-level
  failures. Source: [scanner/raw/heartbleed.rs](../src/scanner/raw/heartbleed.rs).

## Channel binding

Computed post-handshake from the characterization handshake's state
— no extra round-trips.

| Schema field | How | RFC |
|---|---|---|
| `tls.channel_binding.tls_exporter` | `ConnectionCommon::export_keying_material(label: "EXPORTER-Channel-Binding", context: None, out: &mut [u8; 32])` on the rustls `ClientConnection`. TLS-1.3-only (RFC 9266 §2); TLS 1.2 renders `not_applicable` with reason `not_defined_for_tls12`. | RFC 9266 |
| `tls.channel_binding.tls_server_end_point` | SHA-256 of the leaf certificate DER (first entry in the collected chain). Deterministic from cert material already captured — equals `certificates.leaf.fingerprint_sha256` byte-for-byte. | RFC 5929 §4 |

Feeds SP 800-63B AAL3 verifier-impersonation-resistance rules and
RFC 7677 / RFC 5802 SCRAM-PLUS channel-binding requirements.

## Revocation fetches (opt-in)

Gated behind `--enable-revocation-fetch`. Default off — avoids
sending per-scan traffic to responders the operator may not want
to hit. Both checks below share the flag.

### OCSP-over-HTTP fallback

Source: [src/scanner/ocsp_http.rs](../src/scanner/ocsp_http.rs).
Requires features `http-checks` + `legacy-probes` (both default-on).

| Observation | How | Output field |
|---|---|---|
| OCSP-HTTP fetch per AIA URL | `openssl::ocsp::OcspRequest::new()` + `OcspCertId::from_cert(sha1, leaf, issuer)` → DER → `reqwest` POST to AIA URL with `Content-Type: application/ocsp-request`. Response parsed via the shared [src/model/ocsp_response.rs](../src/model/ocsp_response.rs) parser. | `certificates.leaf.revocation.ocsp_http_fallback[]` |

**CertID digest: SHA-1.** RFC 6960 §A.2 calls out SHA-1 as the
interoperable default; production responders frequently reject
SHA-256 CertIDs (pre-computed responses keyed on SHA-1). The
observation surface isn't about cryptographic strength of the
CertID — it's about what the responder says about the leaf's
revocation state, and that signal is the same either way.

**No nonce.** We don't add a `Nonce` extension (RFC 6960 §4.4.1).
Nonced requests force the responder to sign a fresh reply, which
many production responders refuse because they serve
pre-computed responses from CDN caches. Skipping the nonce
matches common client behavior.

**No signature validation.** The parser extracts
`signature_algorithm_oid`, `responder_id_*`, `produced_at`,
`this_update`, `next_update`, `cert_status`, etc.; kemist does
not cryptographically validate the responder's signature against
a trusted responder chain. Rule engines that want to verify can
do so against a trust bundle they control.

**Body cap: 256 KB, timeout: 10 s per URL.**

**Coexistence with stapled OCSP.** Runs regardless of whether the
server already stapled — the two responses can differ on
timing and both are useful observations. `ocsp_stapling`
continues to carry whatever came in-band.

### CRL fetch + revocation check

Source: [src/scanner/crl_fetch.rs](../src/scanner/crl_fetch.rs).
Requires feature `http-checks` (default-on); does not require
`legacy-probes` (no OpenSSL involvement — only `reqwest` +
`x509-parser`).

| Observation | How | Output field |
|---|---|---|
| CRL fetch per DP URL | `reqwest::Client::get(url)` with 10 s timeout and 5 MB body cap. Response bytes handed to `x509_parser::revocation_list::CertificateRevocationList::from_der`; PEM-armored CAs detected via `-----BEGIN X509 CRL-----` sentinel and base64-decoded before parse. | `certificates.leaf.revocation.crl_fetch[]` |
| Leaf revocation state | Iterate `revoked_certificates`; match `raw_serial()` bit-for-bit against the leaf's raw serial. Positive match → `leaf_revoked: true` + `revocation_time` + `revocation_reason`. | same block |

**Per-scan cache.** A `HashMap<url, CrlFetchResult>` within each
scan avoids re-downloading the same CRL when multiple DPs share
a URL (or when leaf + intermediate share a CRL).

**No signature validation.** x509-parser exposes
`verify_signature(&issuer_spki)` but kemist is a sensor — we
report what the CRL *says* about the leaf, not whether the CRL
was signed by a trusted issuer. Rule engines that want
signature-validated revocation can cross-check using
`tls.extensions.crl_fetch[].crl_issuer` + the captured chain.

**No Delta CRL chasing.** Only base CRLs are fetched.

## ALPN probe matrix

Per-protocol ALPN handshake. One TLS 1.3 handshake per target token
in [src/scanner/alpn_matrix.rs](../src/scanner/alpn_matrix.rs) (`h2`,
`http/1.1`, `http/1.0`), each advertising exactly one protocol in
the `ALPN` extension. Classifies on the server's response:

| Outcome | `supported` | `reason` | Meaning |
|---|---|---|---|
| Handshake complete, ALPN echoed | `true` | — | Server accepts this protocol |
| RFC 7301 `no_application_protocol` alert | `false` | `no_application_protocol_alert` | Strict-spec rejection |
| Handshake complete, no ALPN returned | `false` | `server_did_not_select_any_alpn` | Common non-strict behavior |
| Handshake complete, different ALPN returned | `false` | `server_returned_mismatched_alpn:<proto>` | Protocol-violation-ish |
| Other TLS alert | `false` | `tls_alert_<name>` | Unrelated handshake failure |
| Transport failure | `null` (method: error) | category string | DNS / TCP / timeout |

Permissive cert verifier (no validation) — ALPN negotiation
observation is independent of chain trust. Feeds `tls.alpn_probe` in
schema. Cost: +3 handshakes per target.

Complements `negotiated.alpn` which records the server's preference
when multiple ALPNs are offered together; this matrix records per-
ALPN acceptance in isolation.

## SNI behavior probe

[scanner/sni.rs](../src/scanner/sni.rs). One extra rustls handshake
using `ServerName::IpAddress(target.ip())` — rustls is RFC 6066
compliant and omits the SNI extension for IP literals. Compare the
returned leaf's SHA-256 fingerprint to the characterization probe's.

Outcomes: `same_cert` | `different_cert` | `rejected` | `error`.

## HTTP observations (feature-gated)

`cargo feature http-checks` (default on) + runtime `--enable-http-checks`
flag. [scanner/http.rs](../src/scanner/http.rs) uses `reqwest` with
rustls+webpki-roots.

- **HSTS** — `HEAD /` + parse `Strict-Transport-Security` header. Raw
  value, parsed `max-age`, `includeSubDomains`, `preload` directives.
- **security.txt** — `GET /.well-known/security.txt`. Body emitted
  verbatim AND parsed per RFC 9116 into `contact[]`, `expires`,
  `encryption[]`, `preferred_languages[]`, `canonical[]`, `policy[]`,
  `hiring[]`, `acknowledgments[]`, `pgp_signed: bool`. Multiple
  occurrences of a directive are retained in order. Comments
  (`#`-prefixed lines) and unknown directives ignored. PGP signature
  blocks detected by sentinel strings — no signature validation.
- **Security headers** — piggybacks on the HEAD / request used for
  HSTS. Raw values captured for: `Content-Security-Policy` (+
  `-Report-Only` variant), `X-Frame-Options`, `X-Content-Type-Options`,
  `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`
  / `-Embedder-Policy` / `-Resource-Policy`, `Reporting-Endpoints`
  (falls back to legacy `Report-To` when new header absent).
  `Set-Cookie` structured into `{name, secure, http_only, same_site}`
  per cookie; cookie **values are deliberately omitted** to avoid
  capturing session tokens.
- **Redirect chain** — `GET /` followed manually (not via
  `Policy::limited`) up to 10 hops. Each hop captures the request
  URL, HTTP status, and `Location` target. The terminal entry has a
  non-3xx status and no `location`. A `status: 0` entry indicates a
  transport-level failure (DNS / TCP / TLS) at that hop.
- **Preload list** — full Chromium `transport_security_state_static.json`
  snapshot bundled at build time (~92,000 entries as of the current
  vendoring). `build.rs` parses the JSON and emits a compile-time
  `phf::Map<&'static str, bool>` for O(1) lookups without a runtime
  HashMap. Only `mode: "force-https"` entries count — HPKP-only
  pinning entries are excluded. Subdomain match walks parent labels
  against the map; any parent with `include_subdomains: true` makes
  the child `included`.
  See [data/README.md](../data/README.md) for snapshot provenance +
  refresh instructions.
  **Runtime override** — `--hsts-preload-list-path <path>` loads an
  alternate file (same Chromium format, `//` comments OK) at
  startup; output surfaces `http.preload_list_source:
  "runtime_override:<path>"` for provenance.

**Snapshot staleness.** The preload list is pinned at vendoring
time (the exact upstream revision lives in the commit that touched
`data/hsts_preload_list.json`). Operators running against targets
added/removed from the list between snapshots can refresh the data
without rebuilding by passing `--hsts-preload-list-path`. Build-time
bundling (rather than a runtime-only download) keeps builds
offline-capable and reproducible.

## STARTTLS

Not supported. kemist scopes itself to HTTPS-on-443 (and arbitrary
TLS-on-port); the original TLSferret fork's SMTP/IMAP/POP3/FTP/LDAP/
XMPP/PostgreSQL/MySQL STARTTLS negotiation was dropped early on.

## User-Agent

All HTTP requests use:

```
kemist/<version> (+<user-agent-info-url>)
```

Defaults to `https://www.kemist-tls.net`. Set `--user-agent-info-url`
to your own URL when scanning targets you don't own — it helps site
operators trace requests back to you.
