# kemist output schema v1

Formal contract: [`schemas/output-v1.json`](../schemas/output-v1.json).
This document is the human-readable field reference. Every emitted JSON
record pins `schema_version: "1.0.0"` and validates against the JSON
Schema — both are CI-enforced.

## Stability contract

Schema versioning is semver over **shape only**, not semantic meaning.

| Change kind | Version bump | Example |
|---|---|---|
| Field removed | major | Delete `tls.extensions.heartbeat_present` |
| Field type changed | major | `chain_length` int → string |
| Required field became optional | major | `certificates.chain` no longer required |
| **New optional field added** | minor | Add `tls.extensions.new_observation` |
| New enum variant in existing field | minor | Add `"quantum_safe"` to `sct.delivery_paths` |
| Wording in `reason` strings changed | patch | Rephrase `"pending_pr_5"` → `"pending"` |

Consumers **MUST** ignore unknown fields — a scanner from a later minor
may emit observations a consumer hasn't seen before.

**What the scanner will never emit**, regardless of version:
- Compliance verdicts, grades, severity rankings, pass/fail judgments
- Fields named `weak`, `strong`, `compliant`, `recommended`, `insecure`, etc.

Rule evaluation lives in downstream projects. See
[INTEGRATION.md](INTEGRATION.md) for the consumer contract.

## The tri-state contract (load-bearing)

Every probe-derived observation distinguishes **four outcomes**:

| JSON shape | Meaning |
|---|---|
| `{"value": true, "method": "probe"}` | Probed, observed affirmative. Real signal. |
| `{"value": false, "method": "probe"}` | Probed, server rejected on wire. Real negative signal. |
| `{"value": null, "method": "not_probed", "reason": "..."}` | Never probed. Provider lacks support, feature disabled, etc. |
| `{"value": null, "method": "not_applicable", "reason": "..."}` | Observation doesn't apply (e.g. EMS on TLS 1.3). |
| `{"value": null, "method": "error", "reason": "..."}` | Probe attempted, failed for a non-rejection reason. |
| `{"value": ..., "method": "connection_state"}` | Read directly from a successful rustls connection — not a dedicated probe. |

**Absence of probe is not absence of support.** A downstream rule engine
looking for "server supports weak-cipher X" must treat `not_probed` as
"unknown", never as `false`.

Some sections use a per-subject field name instead of the generic
`value` key — `versions_offered` uses `offered`, `groups.*` uses
`supported`, `cipher_suites[].` uses `supported`. The contract is the
same; the field name is load-bearing for readability.

---

## Top-level fields

```
ScanResult {
  schema_version: "1.0.0"
  scanner:      { name, version }
  capabilities: { ... }
  scan:         { ... }
  tls:          { ... }
  certificates: { ... }
  validation:   { ... }
  http?:        { ... }
  raw_handshakes?: object
  errors:       [ ... ]
}
```

### `schema_version`
String, always `"1.0.0"` in schema v1. Pin on this exact value; check
the major before interpreting anything else.

### `scanner`
```
{ name: "kemist", version: "<semver>" }
```
Identity of the tool that produced this record.

### `capabilities`
Runtime-derived state. Lets consumers interpret `not_probed` reasons
against what the scanner build was actually able to probe.

| Field | Type | Meaning |
|---|---|---|
| `enabled_features` | `string[]` | Cargo features compiled in (e.g. `http-checks`) |
| `rustls_version` | `string` | Pinned rustls version at build time |
| `aws_lc_rs_version` | `string` | aws-lc-rs version (or `"bundled"` if not parsed) |
| `openssl_version` | `string` | Pinned OpenSSL version when `legacy-probes` is on, else `"not_shipped"` |
| `probed_cipher_suites` | `string[]` | Cipher suite names the scanner probes — union across every backend compiled in. Per-suite `provider` tag under `tls.cipher_suites.*` identifies which backend ran each probe |
| `probed_kx_groups` | `string[]` | KX group names the scanner probes — union across every backend |
| `config_paths` | `string[]` | Config files consulted (reserved; currently always empty) |
| `probe_limitations` | `string[]` | Runtime-detected probe gaps (reserved) |

### `scan`
```
{
  target: "cloudflare.com:443",
  host: "cloudflare.com",
  port: 443,
  sni_sent: "cloudflare.com",
  resolved_ip?: "104.16.132.229",
  started_at: "2026-04-18T02:30:00Z",
  completed_at: "2026-04-18T02:30:12Z",
  duration_ms: 12034
}
```

`sni_sent` is what kemist put in the SNI extension — can differ from
`host` when a `#sni=` override is used in the target.

### `tls.versions_offered`
One `{offered, method, reason?}` entry per version.

```
{
  ssl2:   {offered: false, method: "probe"},
  ssl3:   {offered: false, method: "probe"},
  tls1_0: {offered: false, method: "probe"},
  tls1_1: {offered: false, method: "probe"},
  tls1_2: {offered: true,  method: "probe"},
  tls1_3: {offered: true,  method: "probe"}
}
```

### `tls.negotiated` (optional)
Present iff the characterization handshake succeeded. Fields populated
from rustls's post-handshake `ClientConnection` state:

| Field | Type | Source |
|---|---|---|
| `version` | `string` | `conn.protocol_version()` |
| `cipher_suite` | `string?` | `conn.negotiated_cipher_suite()` |
| `group` | `string?` | `conn.negotiated_key_exchange_group()` |
| `signature_scheme` | `string?` | Verifier callback `dss.scheme` |
| `alpn` | `string?` | `conn.alpn_protocol()` |

### `tls.cipher_suites`
```
{
  tls1_0: [ CipherSuiteEntry, ... ],   # OpenSSL legacy path only
  tls1_1: [ CipherSuiteEntry, ... ],   # OpenSSL legacy path only
  tls1_2: [ CipherSuiteEntry, ... ],   # aws-lc-rs + OpenSSL legacy
  tls1_3: [ CipherSuiteEntry, ... ],   # aws-lc-rs only
  server_enforces_order: ObservationBool
}

CipherSuiteEntry = {
  name:           "TLS_RSA_WITH_AES_128_CBC_SHA",
  iana_code:      "0x002F",
  supported:      bool | null,
  method:         Method,
  reason?:        string,
  openssl_name?:  "AES128-SHA",                // present only for openssl-backed probes
  provider?:      "aws_lc_rs" | "openssl",     // backend that ran the probe
  classification: "rsa_kex"                    // kx+privacy family — always present
}
```

`classification` labels each suite with its kx + privacy family.
Values: `rsa_kex`, `dhe_aead`, `dhe_cbc`, `ecdhe_aead`, `ecdhe_cbc`,
`anon`, `export`, `static_dh`, `static_ecdh`, `psk`, `dhe_psk`,
`ecdhe_psk`, `rsa_psk`, `null_cipher`, `other`. Privacy-dominant
concerns (`null_cipher`, `anon`, `export`) take precedence over the
kx prefix. TLS 1.3 suites (`TLS13_*`) map to `ecdhe_aead`. Stability
contract: values permanent within schema v1.x; new values may be
added. See the "Enum stability" section at the bottom.

One entry per probed suite, partitioned by TLS version. Suites outside
aws-lc-rs' ship set aren't probed via the rustls path — the openssl
path fills those gaps for RSA-kex / RC4 / DES/3DES / NULL / anon-DH /
EXPORT / IDEA and reports them under `provider: "openssl"`. Consumers
who want provider-specific filtering key on the `provider` field;
consumers who just want "does the server support X?" read the full
array for each version. `server_enforces_order` still compares two
aws-lc-rs handshakes with reversed cipher orderings.

### `tls.groups`
Per-TLS-version maps of key-exchange group observations:
```
{
  tls1_2: { "ffdhe2048": GroupObservation, "ffdhe3072": GroupObservation, ... },
  tls1_3: { "X25519": GroupObservation, "MLKEM768": GroupObservation,
            "ffdhe2048": GroupObservation, ... }
}

GroupObservation = {
  supported:   bool | null,
  method:      Method,
  reason?:     string,
  iana_code?:  "0x0100",                       // present for openssl-backed FFDHE probes
  provider?:   "aws_lc_rs" | "openssl"
}
```

`tls1_3` holds the aws-lc-rs modern groups (classical, PQC hybrids,
standalone ML-KEM) *plus* the TLS 1.3 outcomes for RFC 7919 FFDHE
codepoints *plus* TLS 1.3 groups OpenSSL fills when aws-lc-rs doesn't
ship them (`X448`, `secp521r1`, `MLKEM512`, `MLKEM1024`,
`secp384r1MLKEM1024`). `tls1_2` holds only FFDHE outcomes — the other
groups are TLS 1.3-only by design. `provider` distinguishes which
backend produced the observation (`aws_lc_rs` vs `openssl`).

**FFDHE cross-check.** A TLS 1.2 FFDHE entry with
`{supported: false, reason: "server_ignored_group_offer_returned_custom_prime"}`
means the server completed a DHE handshake but returned a prime that
doesn't match the advertised codepoint — i.e. it ignored
`supported_groups`. Distinct from a plain `false` (no alert / server
just refused the group).

Entries aws-lc-rs doesn't ship emit `not_probed` with
a specific reason — never `supported: false` without a real probe.

### `tls.extensions`
```
{
  ems: ObservationBool,
  secure_renegotiation: ObservationBool,
  ocsp_stapling: {
    stapled, method, reason?, response_length,
    content?,           // parsed OCSP response (RFC 6960)
    delivery_path?,     // "tls1_2" | "tls1_3"
    raw_hex?            // only with --include-ocsp-raw
  },
  sct: {delivery_paths: [...], count},
  alpn_offered: [...],
  encrypt_then_mac: ObservationBool,
  heartbeat_present: ObservationBool,
  heartbeat_echoes_oversized_payload: ObservationBool,
  compression_offered: [...],
  truncated_hmac: ObservationBool,
  npn: ObservationBool,
  supported_point_formats_echoed: [...],
  max_fragment_length?: string,             // "2^9".."2^12" or "0xNN"
  record_size_limit?: int,                  // RFC 8449 (see caveat)
  compress_certificate_algorithms: [...],   // RFC 8879 (see caveat)
  grease_echoed: ObservationBool            // RFC 8701
}
```

Notes:

- **`ocsp_stapling.content`** — parsed BasicOCSPResponse per RFC 6960 §4.2.
  Populated when a staple was delivered and parsed successfully. Fields:
  `response_status`, `signature_algorithm_oid`, `responder_id_by_name` /
  `responder_id_by_key`, `produced_at`, `single_responses_count`,
  `cert_status` (`good` / `revoked` / `unknown`), `revocation_time`,
  `revocation_reason`, `this_update`, `next_update`, `cert_id`
  (hashAlg OID + issuer name/key hashes + serial).
- **`ocsp_stapling.raw_hex`** — gated behind `--include-ocsp-raw` CLI
  flag. Off by default because the parsed `content` is what rule
  engines want and raw DER inflates output size noticeably.
- **`record_size_limit` / `compress_certificate_algorithms`** —
  captured via an OpenSSL msg-callback on the TLS 1.3
  EncryptedExtensions message. **Known limitation**: OpenSSL 3.5
  reserves these extension codes for its own internal handlers so
  we can't inject a matching client offer via `add_custom_ext`, and
  openssl-sys 0.9.109 doesn't expose the native setters. Per RFC
  8449 / 8879, servers MUST NOT advertise these unsolicited — so in
  practice both fields are typically absent on real scans. A
  future workstream will close this gap when native binding
  coverage improves.
- **`truncated_hmac` / `npn`** — observed in plaintext TLS 1.2
  ServerHello via the byte-level hello probe. Client offers both
  extensions to elicit server echoes (without actually negotiating
  them — probe bails after ServerHello).
- **`grease_echoed`** — RFC 8701 conformance observation. The
  byte-level hello probe injects a GREASE extension codepoint
  (`0x0A0A`) in the ClientHello. A correctly-behaving server
  ignores unknown extensions; an echo is a protocol violation.
  `{value: false}` = ignored (correct); `{value: true}` = echo
  detected.
- **`hello_retry_request`** — RFC 8446 §4.1.3 observation. A
  dedicated probe sends a TLS 1.3 ClientHello with an empty
  `key_share` extension, which a spec-compliant server MUST answer
  with HelloRetryRequest (ServerHello whose random equals
  `cf21ad74…a8339c`, the SHA-256 of `"HelloRetryRequest"`).
  `{value: true}` = HRR observed (TLS 1.3 server behaving
  correctly); `{value: false}` = regular ServerHello (either TLS
  1.2 fallback or an unexpected non-HRR response from a TLS 1.3
  server). This probe adds one extra handshake per target.

See [CHECKS.md](CHECKS.md) for how each observation is obtained.

### `tls.downgrade_signaling`
```
{
  fallback_scsv_enforced:  ObservationBool,
  tls13_downgrade_sentinel?: "tls12" | "lte_tls11" | "none"
}
```

- **`fallback_scsv_enforced`** — active OpenSSL-backed probe. Sends a
  handshake with `SSL_MODE_SEND_FALLBACK_SCSV` and `max_proto_version`
  one step below the server's observed max. `{value: true}` means the
  server returned `inappropriate_fallback` (RFC 7507 compliant).
  `{value: false}` means the server accepted the downgraded handshake.
  `{value: null}` with a reason string when the probe was inconclusive
  (e.g. server max already ≤ TLS 1.1 so no downgrade is possible;
  server disabled the downgrade target entirely and answered
  `protocol_version` instead).
- **`tls13_downgrade_sentinel`** — the RFC 8446 §4.1.3 last-8-bytes
  sentinel observed in the byte-level TLS 1.2 ServerHello
  ServerRandom. Always absent when the hello probe couldn't
  produce a ServerHello. `"tls12"` means the server is TLS
  1.3-capable but negotiated TLS 1.2 (real signal even though the
  byte probe only offers TLS 1.2). `"lte_tls11"` means a TLS
  1.3-capable stack negotiated TLS 1.1 or lower. `"none"` = no
  sentinel pattern match (pure-TLS-1.2/earlier server or a
  non-compliant TLS 1.3 stack).

### `tls.session_resumption`
```
{
  tls1_2: {
    session_ticket_issued: ObservationBool,
    ticket_lifetime_hint_secs?: int,
    session_id_issued: ObservationBool,
    ticket_rotated_across_connections: ObservationBool
  },
  tls1_3: {
    new_session_ticket_count?: int,
    ticket_lifetime_secs: [int, ...],
    psk_resumption_accepted: ObservationBool,
    early_data_accepted: ObservationBool
  }
}
```

Observed by opening two successive handshakes and comparing state.
`ticket_rotated_across_connections` is a best-effort proxy: kemist
diffs the session-ID bytes across handshakes because
openssl-sys 0.9.109 doesn't expose `SSL_SESSION_get0_ticket`. Treat
`false` as "likely stable ticket" rather than "definitely same
ticket bytes."

The TLS 1.3 slots currently emit `method: not_probed` with reasons
`tls13_resumption_probe_not_implemented` and
`early_data_probe_not_implemented`. A follow-up workstream will
implement them.

### `tls.signature_algorithm_policy_probe`
```
{
  sha256_plus_only: ConstrainedProbeResult,
  ecdsa_only:       ConstrainedProbeResult,
  rsa_pss_only:     ConstrainedProbeResult,
  rsa_pkcs1_only:   ConstrainedProbeResult,
  eddsa_only:       ConstrainedProbeResult
}

ConstrainedProbeResult = {
  outcome: "handshake_complete" | "handshake_failure" | "connection_closed" | "other_alert" | "not_probed",
  selected_sigalg?: string,        // server's chosen sigalg on complete
  alert?:           string,        // alert category on refusal
  method:           Method,
  reason?:          string
}
```

Five active handshakes with restricted `signature_algorithms`
offers; see [CHECKS.md](CHECKS.md#signature-algorithm-policy-probe)
for the exact sigalgs list per constraint. `eddsa_only` offers
`ed25519` (0x0807) + `ed448` (0x0808) and surfaces the server's
EdDSA-only posture — the fifth probe lets rule engines distinguish
"server supports EdDSA as one of many" from "server is configured
EdDSA-only."

The CLI flag `--sigalg-probe-skip=<csv>` opts out individual probes;
skipped slots emit `method: not_probed, reason: cli_skipped`.

Rule-engine note: `rsa_pkcs1_only` returning `handshake_failure` is
the modern-posture "good" signal — the server is refusing PKCS#1
v1.5 signatures.

### `tls.sni_behavior`
```
{
  omitted_probe: "same_cert" | "different_cert" | "rejected" | "error" | null,
  method: Method,
  reason?: string
}
```
Comparison of leaf cert fingerprints between the SNI-set characterization
handshake and a second handshake with SNI omitted (via `ServerName::IpAddress`).

### `tls.channel_binding`
```
{
  tls_exporter: {
    value?: string,        // 32-byte lower-case hex (64 chars)
    method: Method,
    reason?: string
  },
  tls_server_end_point: {
    value?: string,        // 32-byte lower-case hex (64 chars)
    method: Method,
    reason?: string
  }
}
```

Two channel-binding values derived from the characterization
handshake. No extra network round-trips.

- **`tls_exporter`** (RFC 9266) — 32-byte exporter output keyed with
  label `"EXPORTER-Channel-Binding"` and empty context, computed via
  `ConnectionCommon::export_keying_material`. TLS-1.3-only per RFC
  9266 §2; TLS 1.2 handshakes render `method: not_applicable` with
  reason `not_defined_for_tls12`.
- **`tls_server_end_point`** (RFC 5929 §4) — SHA-256 of the leaf
  certificate DER. Populated whenever a leaf cert was delivered
  (i.e., every successful characterization). Value matches
  `certificates.leaf.fingerprint_sha256` byte-for-byte (the server
  end-point binding and the cert fingerprint are the same hash over
  the same bytes).

Feeds SP 800-63B AAL3 verifier-impersonation-resistance rules and
RFC 7677 / RFC 5802 SCRAM channel-binding requirements.

### `certificates`
```
{
  leaf?: CertificateFacts,
  chain: [CertificateFacts...],
  chain_length: int
}
```

`CertificateFacts`:

| Field | Type | Meaning |
|---|---|---|
| `subject_cn` | `string?` | First CN RDN from subject |
| `subject_dn` | `string` | Full subject DN as x509-parser Display |
| `san` | `string[]` | DNS/IP/email/URI SAN entries (email/URI prefixed) |
| `issuer_cn` | `string?` | First CN RDN from issuer |
| `issuer_dn` | `string` | Full issuer DN |
| `serial` | `string` | Hex serial number |
| `not_before` | `datetime` | validity.notBefore as ISO 8601 |
| `not_after` | `datetime` | validity.notAfter |
| `validity_days` | `int` | `not_after - not_before` in days |
| `signature_algorithm_oid` | `string` | Raw OID (`"1.2.840.113549.1.1.11"`) |
| `signature_algorithm_name` | `string` | Resolved human name (`"sha256WithRSAEncryption"`, `"ML-DSA-65"`, or fallback to OID) |
| `is_pqc_signature` | `bool` | OID matches ML-DSA/SLH-DSA table — **raw match, not a judgment** |
| `public_key` | `{algorithm, size_bits, curve?, curve_oid?}` | `curve_oid` carries the named-curve OID (e.g. `"1.2.840.10045.3.1.7"` for secp256r1) — parsed from `AlgorithmIdentifier.parameters`, not byte-length matched. Lets rule engines distinguish brainpool/secp256k1 from NIST P-curves |
| `embedded_scts` | `int` | Count from extension 1.3.6.1.4.1.11129.2.4.2 |
| `fingerprint_sha256` | `string` | Hex |
| `fingerprint_sha1` | `string` | Hex |
| `extensions` | `CertExtensions` | Parsed X.509 v3 extensions — see below |

`CertExtensions`:

| Field | Type | Meaning |
|---|---|---|
| `basic_constraints` | `{ca: bool, path_len_constraint?: int}` | RFC 5280 §4.2.1.9 |
| `key_usage` | `{bits: [string, ...]}` | RFC 5280 §4.2.1.3 — canonical names: `digital_signature`, `content_commitment`, `key_encipherment`, `data_encipherment`, `key_agreement`, `key_cert_sign`, `crl_sign`, `encipher_only`, `decipher_only` |
| `extended_key_usage` | `{oids: [string, ...]}` | RFC 5280 §4.2.1.12 — `server_auth`, `client_auth`, `code_signing`, etc.; unknown OIDs in dotted-decimal |
| `authority_key_identifier` | `string?` | Hex of keyIdentifier |
| `subject_key_identifier` | `string?` | Hex of keyIdentifier |
| `authority_information_access` | `{ocsp: [...], ca_issuers: [...]}` | URIs only |
| `crl_distribution_points` | `{urls: [...]}` | `fullName` URI entries only |
| `name_constraints` | `{permitted_subtrees: [...], excluded_subtrees: [...]}` | Stringified GeneralName entries |
| `certificate_policies` | `{oids: [string, ...]}` | Policy OIDs |
| `must_staple` | `bool?` | RFC 7633 TLS Feature ext — `true` iff feature 5 (status_request) is listed |
| `scts` | `[SctDetail, ...]` | Per-SCT detail from ext 1.3.6.1.4.1.11129.2.4.2 |

`SctDetail = {log_id: hex, timestamp: RFC3339, signature_hash_algorithm: string, signature_algorithm: string, signature_hex: hex}`.
The cert-level `embedded_scts` count remains for backwards
compatibility and equals `scts.len()`.

### `validation`
Trust observations — **three independent fields**, deliberately not
collapsed into a single bool.

```
{
  chain_valid_to_webpki_roots: ObservationBool,
  name_matches_sni: ObservationBool,
  validation_error?: string
}
```

| Value | Meaning |
|---|---|
| `chain_valid_to_webpki_roots.value` | Did webpki (against Mozilla roots) validate the chain with the SNI name? Ignores name failures when retried with a SAN-derived name. |
| `name_matches_sni.value` | Does the leaf's SAN/CN match the SNI sent, using RFC 6125 wildcard semantics? Independent check — runs even when chain is invalid. |
| `validation_error` | Canonical error string when chain is invalid. Only populated when `chain_valid_to_webpki_roots.value == false`. |

Canonical `validation_error` strings:
`"expired"`, `"not_valid_yet"`, `"untrusted_root"`, `"revoked"`,
`"bad_signature"`, `"bad_encoding"`, `"unsupported_signature_algorithm"`,
`"unhandled_critical_extension"`, `"unknown_revocation_status"`,
`"name_mismatch"`, `"other:<rustls_variant>"`.

### `http` (optional)
Present iff `--enable-http-checks` was passed AND the HTTP probe
actually fired. Absent otherwise — consumers treat a missing `http`
field as "HTTP checks not in scope for this record."

```
{
  enabled: true,
  hsts?: {header_present, raw_value?, max_age?, include_subdomains?, preload?},
  preload_list_status?: "included" | "not_included",
  security_txt?: {present, url?, content_type?, body?}
}
```

`security_txt.body` is emitted verbatim — not parsed.

### `raw_handshakes` (optional, reserved)
Reserved for a future `--include-raw-handshake` flag that captures
ClientHello/ServerHello bytes (base64). Currently always absent.

### `errors`
Array of structured error records. Never aborts the scan — partial
observations live alongside their errors.

```
{ category: string, context: string, timestamp: datetime }
```

Canonical `category` strings (stable enum):
`dns_resolution_failed`, `network_unreachable`, `connection_refused`,
`connection_timeout`, `handshake_timeout`, `tls_alert_<name>`,
`cert_parse_error`, `extension_parse_error`, `http_error`,
`internal_scanner_error`.

The `<name>` suffix on `tls_alert_` is the snake_case alert identifier
(`handshake_failure`, `bad_certificate`, `unknown_ca`, etc.). Consumers
that want to aggregate across alert types should match on the
`tls_alert_` prefix and extract the remainder.

---

## Enum stability

The schema pins several fields to string enums. All values listed
below are **permanent within schema v1.x** — never renamed, never
removed. New values may be added in minor-version bumps; consumers
**MUST** tolerate unknown values gracefully rather than crashing or
rejecting the record.

| Field | Values |
|---|---|
| `cipher_suites.<ver>[].classification` | `rsa_kex`, `dhe_aead`, `dhe_cbc`, `ecdhe_aead`, `ecdhe_cbc`, `anon`, `export`, `static_dh`, `static_ecdh`, `psk`, `dhe_psk`, `ecdhe_psk`, `rsa_psk`, `null_cipher`, `other` |
| `cipher_suites.<ver>[].provider`, `groups.<ver>.*.provider` | `aws_lc_rs`, `openssl` |
| `*.method` (every `{value, method, reason?}` envelope) | `probe`, `not_probed`, `not_applicable`, `error`, `connection_state` |
| `errors[].category` | `dns_resolution_failed`, `network_unreachable`, `connection_refused`, `connection_timeout`, `handshake_timeout`, `tls_alert_<name>`, `cert_parse_error`, `extension_parse_error`, `http_error`, `internal_scanner_error` |
| `signature_algorithm_policy_probe.*.outcome` | `handshake_complete`, `handshake_failure`, `connection_closed`, `other_alert`, `not_probed` |
| `ocsp_stapling.content.cert_status` | `good`, `revoked`, `unknown` |
| `ocsp_stapling.content.response_status` | `successful`, `malformedRequest`, `internalError`, `tryLater`, `sigRequired`, `unauthorized`, `unknown_<n>` |
| `ocsp_stapling.delivery_path` | `tls1_2`, `tls1_3` |
| `downgrade_signaling.tls13_downgrade_sentinel` | `tls12`, `lte_tls11`, `none` |
| `dh_parameters[].classification` | `ffdhe2048`, `ffdhe3072`, `ffdhe4096`, `ffdhe6144`, `ffdhe8192`, `modp1024`, `modp1536`, `modp2048`, `modp3072`, `custom` |

For `category` and `response_status`, the `<name>` / `<n>` suffix
pattern is the permanent shape; new alert names or OCSP-status codes
appear as new `tls_alert_<newname>` / `unknown_<newcode>` values
without breaking the schema contract.

If kemist ever needs to retire a value (extremely rare), that
triggers a major-version bump.
