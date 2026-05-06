# kemist output schema v2

Formal contract: [`schemas/output-v1.json`](../schemas/output-v1.json).
This document is the human-readable field reference. Every emitted JSON
record pins `schema_version: "2.0.0"` and validates against the JSON
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
  schema_version: "2.0.0"
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
String, always `"2.0.0"` in schema v2. Pin on this exact value; check
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
  ssl2?: [ CipherSuiteEntry, ... ],   # raw-socket SSLv2 SERVER-HELLO echo; omitted when empty
  ssl3:  [ CipherSuiteEntry, ... ],   # OpenSSL legacy path only
  tls1_0: [ CipherSuiteEntry, ... ],  # OpenSSL legacy path only
  tls1_1: [ CipherSuiteEntry, ... ],  # OpenSSL legacy path only
  tls1_2: [ CipherSuiteEntry, ... ],  # aws-lc-rs + OpenSSL legacy
  tls1_3: [ CipherSuiteEntry, ... ],  # aws-lc-rs only
  server_enforces_order: ObservationBool
}

CipherSuiteEntry = {
  name:           "TLS_RSA_WITH_AES_128_CBC_SHA",
  iana_code:      "0x002F",                    // 2-byte for TLS; 3-byte (0xNNNNNN) for SSLv2 cipher_specs
  supported:      bool | null,
  method:         Method,
  reason?:        string,
  openssl_name?:  "AES128-SHA",                // present only for openssl-backed probes
  provider?:      "aws_lc_rs" | "openssl" | "raw_socket",  // backend that ran the probe
  classification: "rsa_kex"                    // kx+privacy family — always present
}
```

**SSLv2 special-casing.** SSLv2 predates SNI, so the probe can't
route by hostname — whatever TCP answers at `host:port` is what we
observe. Each `ssl2[]` entry represents a cipher spec the server
*echoed in its SERVER-HELLO* from our offer set; `supported` is
always `true` (the server listed it as accepted). Entry names use
the SSLv2 `SSL_CK_*` convention; `iana_code` is a 3-byte hex value
(`0x010080` etc.) rather than the 2-byte TLS codepoint. `provider`
is `raw_socket` (no TLS library involvement — pure wire-format
parsing). Empty on any modern server.

**SSL 3.0 per-cipher.** Version-level SSL 3.0 probing lands in
`versions_offered.ssl3`; per-cipher visibility in `ssl3[]` lets
rule engines distinguish "server refuses SSL 3.0 entirely" from
"server accepts SSL 3.0 with CBC suites (POODLE-vulnerable class)."
Routed through the same OpenSSL legacy path as TLS 1.0/1.1.

`classification` labels each suite with its kx + privacy family.
Values: `rsa_kex`, `dhe_aead`, `dhe_cbc`, `ecdhe_aead`, `ecdhe_cbc`,
`anon`, `export`, `static_dh`, `static_ecdh`, `psk`, `dhe_psk`,
`ecdhe_psk`, `rsa_psk`, `null_cipher`, `other`. Privacy-dominant
concerns (`null_cipher`, `anon`, `export`) take precedence over the
kx prefix. TLS 1.3 suites (`TLS13_*`) map to `ecdhe_aead`. Stability
contract: values permanent within schema v2.x; new values may be
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

**FFDHE cross-check + cross-codepoint coherence.** A TLS 1.2 FFDHE
entry with
`{reason: "server_does_not_honor_supported_groups", returned_group, returned_prime_bits}`
means the scanner has direct or cross-codepoint evidence that the
server isn't honoring `supported_groups`. The `supported` field still
answers the row-level question: did this offered codepoint complete
with its matching group?

- Direct: the server completed a DHE handshake against this
  codepoint's offer but returned a prime that didn't match. The
  `returned_group` field carries the classification of the prime the
  server *actually* sent (`"ffdhe2048"`, `"modp3072"`, `"custom"`,
  etc., matching the `tls.dh_parameters[].classification` vocabulary);
  `returned_prime_bits` carries its bit length. This row is
  `supported: false`.
- Cross-codepoint: any FFDHE codepoint probe at TLS 1.2 reported a
  direct mismatch, so every FFDHE TLS 1.2 row gets the same reason
  and returned-prime evidence. Matched rows remain `supported: true`
  because the specific offered group completed, but the reason warns
  that the host appears to serve a static prime regardless of offer
  (e.g. an RFC 7919 `ssl_dhparam` that happens to coincide with the
  requested codepoint).

Distinct from a plain `{supported: false}` (no `reason`,
no `returned_group`), which means the server cleanly refused the
group offer.

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
  grease_echoed: ObservationBool,           // RFC 8701
  delegated_credentials: {                  // RFC 9345
    value:                            ObservationBool,
    valid_time_seconds?:              int,    // TLS 1.3 path only
    expected_cert_verify_algorithm?:  string, // TLS 1.3 path only
    delivery_path?:                   "tls1_3_certificate_entry" | "tls1_2_server_hello"
  },
  ephemeral_key_reuse: {                    // Raccoon signal (CVE-2020-1968)
    dhe_public_reused_across_connections:   ObservationBool,
    ecdhe_public_reused_across_connections: ObservationBool,
    dhe_suite_probed?:                      string, // IANA name
    ecdhe_suite_probed?:                    string  // IANA name
  },
  bleichenbacher_oracle_probe: {            // ROBOT differential
    rsa_kex_suite_probed?:  string,         // IANA name of pinned suite
    method:                 Method,
    reason?:                string,
    per_variant: [
      {
        variant:          "correctly_formatted_pkcs1" | "invalid_0x00_02_prefix" |
                          "invalid_version_0x00_02_byte_swap" |
                          "null_separator_missing" | "wrong_tls_version_in_pms",
        alert_category?:  string,           // tls_alert_<name>
        tcp_reset:        bool,
        elapsed_ms:       int,
        other_outcome?:   string            // timeout | graceful_close | setup_error:*
      } * 5
    ]
  }
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
- **`bleichenbacher_oracle_probe`** — ROBOT / Bleichenbacher
  differential observation. The probe pins
  `TLS_RSA_WITH_AES_128_CBC_SHA` and for each of five malformed
  PKCS#1 v1.5 `ClientKeyExchange` variants (`correctly_formatted_pkcs1`,
  `invalid_0x00_02_prefix`, `invalid_version_0x00_02_byte_swap`,
  `null_separator_missing`, `wrong_tls_version_in_pms`) runs a
  fresh TLS 1.2 handshake up through `ServerHelloDone`, extracts
  the leaf's RSA public key, `RSA_public_encrypt(Padding::NONE)`s
  the malformed plaintext into a full modulus-sized ciphertext,
  and sends `CKE + ChangeCipherSpec + Finished`. The Finished is
  crypto-correct under the variant's *intended* PMS — TLS 1.2
  PRF (P_SHA256) master-secret derivation, key expansion to
  client-write MAC (20) + AES-128 key (16), SHA-256 transcript
  hash over ClientHello+ServerHello+Certificate+ServerHelloDone+CKE,
  HMAC-SHA1 MAC-then-encrypt with AES-128-CBC, explicit 16-byte
  per-record IV, and TLS CBC padding. For variant 1 our keys
  match the server's and Finished verifies (server responds with
  ChangeCipherSpec + its own encrypted Finished, classified as
  `other_outcome: unexpected_plaintext:handshake_record` by this
  probe since we can't decrypt the server-write side). For
  variants 2–5 the server's key derivation diverges (random PMS
  substituted on invalid padding, or `client_version` mismatch
  handling varies) so our MAC fails at the server and we observe
  the alert. Scanner records `alert_category`
  (`tls_alert_bad_record_mac`, `tls_alert_decrypt_error`,
  `tls_alert_handshake_failure`, etc.), `tcp_reset`,
  `other_outcome` (`timeout` | `graceful_close` |
  `unexpected_plaintext:*` | `setup_error:*`), and `elapsed_ms`.
  Gated on `TLS_RSA_*` suites observed at `Supported` by the
  earlier cipher probe; `method: not_probed, reason:
  no_rsa_kex_suite_supported` otherwise. The scanner does **not**
  emit a `vulnerable` boolean — the five-entry list is the
  observation.
- **`ephemeral_key_reuse`** — Raccoon-class observation
  (CVE-2020-1968). For each of DHE and ECDHE, the probe picks a
  server-supported suite from the earlier cipher probe, pins
  `DHE-RSA-AES128-GCM-SHA256` / `ECDHE-RSA-AES128-GCM-SHA256`,
  and runs two back-to-back fresh TLS 1.2 handshakes with session
  caching explicitly disabled. It then hashes the server's
  ephemeral public value (`Y` for DH, uncompressed point bytes
  for ECDH) with SHA-256 and compares the two hashes. `true` =
  byte-for-byte match across fresh handshakes (ephemeral key
  reused); `false` = distinct ephemeral keys. `not_probed` lands
  when no suite in the family was observed supported by the
  cipher probe. The scanner does not attempt the side-channel
  itself — ephemeral reuse is the prerequisite signal, not the
  exploit.
- **`delegated_credentials`** — RFC 9345 observation. Two paths
  feed one observation:
  - *TLS 1.2 path* — byte-probe ClientHello offers ext 0x0022 with
    a SignatureSchemeList; a DC-supporting server echoes an empty
    ext 0x0022 in ServerHello. Presence-only (`value`).
  - *TLS 1.3 path* — OpenSSL msg-callback on the Certificate
    handshake message walks the leaf CertificateEntry's
    extensions (RFC 8446 §4.4.2) for ext 0x0022 and parses the
    `DelegatedCredential` struct header: `valid_time_seconds`
    (RFC 9345 §4.1) and `expected_cert_verify_algorithm`
    (canonical IANA SignatureScheme name).
  When both paths observe DC on one scan, the TLS 1.3 record wins
  and `delivery_path = "tls1_3_certificate_entry"`. When only the
  TLS 1.2 path observes, `delivery_path = "tls1_2_server_hello"`
  with the detail fields absent. The scanner does **not** verify
  the DC signature against the leaf pubkey and does **not**
  compare `valid_time` against the wall clock — observation only.

**Note on revocation.** `ocsp_stapling` is a TLS-handshake
observation (server stapled or not). Out-of-band revocation
probes (CRL fetch, OCSP-over-HTTP) live under
`certificates.leaf.revocation` — they're cert-scoped, not
TLS-layer.

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
  selected_sigalg?:         string,   // server's chosen sigalg on complete
  alert?:                   string,   // alert category on refusal
  method:                   Method,
  reason?:                  string,
  leaf_fingerprint_sha256?: string,   // SHA-256 (lowercase hex) of leaf DER on complete
  leaf_subject_dn?:         string    // leaf subject DN on complete
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

**Differential cert-selection observation.** When the handshake
completes, each constrained probe records `leaf_fingerprint_sha256`
(SHA-256 of the leaf DER, lowercase hex) and `leaf_subject_dn` (same
formatting as `certificates.leaf.subject_dn`). ≥2 distinct
fingerprints across the five probes signal a dual-cert deployment
(e.g. RSA + ECDSA leaves on one endpoint); the scanner records the
fingerprints, downstream rule engines compute the comparison.

### `tls.alpn_probe`
```
[
  {protocol: "h2",       supported: true|false|null, method: Method, reason?: string},
  {protocol: "http/1.1", ...},
  {protocol: "http/1.0", ...}
]
```

Per-protocol ALPN probe matrix. One entry per token in
[`ALPN_PROBE_LIST`](../src/scanner/alpn_matrix.rs) (`h2`,
`http/1.1`, `http/1.0`). Each entry is its own handshake advertising
exactly that one protocol. Complements `negotiated.alpn` — which
tells you what the server *prefers* when multiple are offered, not
what it *supports* in isolation.

Outcomes:
- **`supported: true`** — handshake completed AND server echoed the
  offered ALPN back.
- **`supported: false`** with `reason: "no_application_protocol_alert"`
  — server strictly refused per RFC 7301 §3.2 (rare but spec-compliant).
- **`supported: false`** with `reason: "server_did_not_select_any_alpn"`
  — server completed the handshake without selecting an ALPN. Common
  on servers that don't implement RFC 7301's alert path strictly.
- **`supported: false`** with `reason: "server_returned_mismatched_alpn:<proto>"`
  — server completed the handshake but picked a different protocol
  than offered. Protocol-violation-ish; surfaces the substituted value.
- **`supported: false`** with `reason: "tls_alert_<name>"` — an
  unrelated TLS alert killed the handshake.
- **`supported: null`**, `method: "error"` — transport-level failure.

Cost: +3 handshakes per target. Each handshake uses a permissive
cert verifier; no cert validation is performed.

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
  chain_length: int,
  alternates?: [CertificateAlternate...]
}
```

`alternates` contains full chains observed by constrained probe
handshakes when they differ from the primary characterization leaf,
deduplicated by leaf SHA-256 fingerprint. Today this is populated from
the OpenSSL signature-algorithm policy probes, with `observed_via`
values such as `signature_algorithm_policy.rsa_pss_only`. Validation
and revocation fields still describe only the primary chain.

`CertificateAlternate = {observed_via: string[], leaf?: CertificateFacts, chain: CertificateFacts[], chain_length: int}`.

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
| `signature_algorithm_structured` | `{hash?, algorithm, parameters?}` | Structured decomposition of the signature AlgorithmIdentifier. `hash` is the canonical hash family (`"sha256"`, `"sha384"`, `"sha512"`, `"sha1"`); absent when the scheme hashes internally (Ed25519, Ed448, ML-DSA, SLH-DSA). `algorithm` is the family name: `"rsa"`, `"rsa_pss"`, `"ecdsa"`, `"ed25519"`, `"ed448"`, `"ml_dsa_44"` / `"ml_dsa_65"` / `"ml_dsa_87"`, `"slh_dsa_sha2_128s"` etc. `parameters` carries `"mgf1-<hash>"` for RSA-PSS (or `"rfc4055_defaults"` when PSS parameters were absent). |
| `pqc_signature_family` | `string?` | `"ml_dsa"` (FIPS 204) / `"slh_dsa"` (FIPS 205) / `"composite"` (IETF LAMPS) when the signature OID is PQC; absent otherwise. Replaces the earlier `is_pqc_signature: bool` — `has_pqc = pqc_signature_family !== undefined` recovers the old semantics. |
| `public_key` | `{algorithm, size_bits, curve?, curve_oid?, rsa_exponent?}` | `curve_oid` carries the named-curve OID (e.g. `"1.2.840.10045.3.1.7"` for secp256r1) — parsed from `AlgorithmIdentifier.parameters`, not byte-length matched. `rsa_exponent` populated for RSA keys only (values observed: 3, 17, 65537); lets rule engines flag small-exponent keys. |
| `revocation` | `{ocsp_http_fallback?: [...], crl_fetch?: [...]}` | Out-of-band revocation observations — fetched only for the leaf, only when `--enable-revocation-fetch` is set. Absent on chain entries. See the **Revocation observations** section below for field-level detail. |
| `embedded_scts` | `int` | Count from extension 1.3.6.1.4.1.11129.2.4.2 |
| `fingerprint_sha256` | `string` | Hex |
| `fingerprint_sha1` | `string` | Hex |
| `wire_position` | `int` | 0-indexed position in the wire-order chain the server delivered. `0` = leaf; subsequent integers are intermediates in delivered order. Duplicates are preserved; parse failures appear as gaps. Emitted so downstream rule engines observe chain ordering directly rather than relying on array index semantics. |
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

### Revocation observations (`certificates.leaf.revocation`)

Out-of-band revocation probes scoped to the leaf cert. Populated
only for the leaf and only when `--enable-revocation-fetch` is
set. Distinct from `tls.extensions.ocsp_stapling`, which captures
the server's TLS-handshake stapling *behavior* regardless of cert
scope. Non-leaf chain entries render `revocation` as absent.

```
{
  ocsp_http_fallback?: [
    {url, http_status?, response_length, content?, error?}, ...
  ],
  crl_fetch?: [
    {url, http_status?, this_update?, next_update?, crl_issuer?,
     revoked_cert_count?, leaf_revoked?, revocation_time?,
     revocation_reason?, error?}, ...
  ]
}
```

**`ocsp_http_fallback`** — For each AIA `OCSP` URL the leaf
advertises, the scanner builds an OCSPRequest (CertID over leaf +
issuer, SHA-1 digest for interop) via `openssl::ocsp` and POSTs
it with `Content-Type: application/ocsp-request`. The parsed
response lands in `content` with the same shape as
`tls.extensions.ocsp_stapling.content`. Cap: 256 KB response
body, 10 s per-URL timeout. Error categories in `error`:
`post_failed:<...>`, `http_status_<code>`,
`response_exceeds_size_cap:<bytes>`, `leaf_parse_failed:<...>`,
`issuer_parse_failed:<...>`, `response_parse_failed:<...>`.

**`crl_fetch`** — For each URL in `extensions.crl_distribution_points.urls`,
GET + parse the CRL and scan for the leaf's serial. `leaf_revoked`
is `true` (leaf serial in the list), `false` (fetched + parsed +
searched + absent — canonical "not revoked"), or `null`
(fetch / parse failed). On positive revocation,
`revocation_time` + `revocation_reason` (RFC 5280 §5.3.1 names:
`Unspecified`, `KeyCompromise`, `CACompromise`,
`AffiliationChanged`, `Superseded`, `CessationOfOperation`,
`CertificateHold`, `RemoveFromCRL`, `PrivilegeWithdrawn`,
`AaCompromise`). PEM-wrapped CRLs handled transparently. Caps:
5 MB body, 10 s per-URL timeout. Per-scan cache keyed on URL.

### `validation`
Trust observations — **multi-store chain validation** plus a
trust-store-agnostic name-match check. Every compiled-in store
produces its own `ObservationBool`; `--extra-trust-store` entries
land in `chain_valid_to_custom_roots`.

```
{
  chain_valid_to_webpki_roots:         ObservationBool,
  chain_valid_to_microsoft_roots:      ObservationBool,
  chain_valid_to_apple_roots:          ObservationBool,
  chain_valid_to_us_fpki_common_roots: ObservationBool,
  chain_valid_to_us_dod_roots:         ObservationBool,
  chain_valid_to_custom_roots?:        { <name>: ObservationBool, ... },
  name_matches_sni:                    ObservationBool,
  validation_error?:                   string,                         // legacy — webpki-roots error
  per_store_validation_errors?:        { <name>: string, ... },
  trust_store_sources?:                { <name>: string, ... }          // compiled_in | runtime_override:<path>
}
```

| Field | Source / semantics |
|---|---|
| `chain_valid_to_webpki_roots` | Mozilla root store via the `webpki-roots` crate. |
| `chain_valid_to_microsoft_roots` | `data/trust_stores/microsoft_ccadb.pem`. Microsoft CCADB export (placeholder in current snapshot — supply via `--trust-store microsoft:<path>`). |
| `chain_valid_to_apple_roots` | `data/trust_stores/apple_pki.pem`. Apple Root CA G2 + G3. |
| `chain_valid_to_us_fpki_common_roots` | `data/trust_stores/us_fpki_common.pem`. Federal Common Policy CA G2 + 11 SIA-discovered agency intermediates (DigiCert Federal SSP, Entrust Federal Root, Federal Bridge CA G4, State Dept AD Root, Treasury Root, WidePoint ORC). |
| `chain_valid_to_us_dod_roots` | `data/trust_stores/us_dod.pem`. DoD PKI (placeholder in current snapshot). |
| `chain_valid_to_custom_roots.<name>` | Per-entry `--extra-trust-store` bundle. |
| `name_matches_sni` | Store-agnostic SAN/CN match per RFC 6125. |
| `validation_error` | **Legacy.** Error from webpki-roots validation only, kept for backwards-compatible consumers. New integrations should consume `per_store_validation_errors`. |
| `per_store_validation_errors.<name>` | Per-store error category string. Populated only for stores whose chain validation failed. Same taxonomy as `validation_error`. |
| `trust_store_sources.<name>` | Provenance: `"compiled_in"` / `"cache_refreshed:<path>"` (loaded from `kemist --update-trust-stores` output) / `"runtime_override:<path>"` (user-supplied via `--trust-store NAME:PATH`). |
| `trust_store_bundle_metadata.<name>` | Per-bundle manifest: `source`, `fetched_at` (ISO 8601), `sha256`, `entry_count`, optional `upstream_version`. Populated only when the store was loaded from the refreshed cache — compile-time + runtime-override loads omit metadata. Lets rule engines pin observations to a specific snapshot. |

Canonical per-store error strings:
`"expired"`, `"not_valid_yet"`, `"untrusted_root"`, `"revoked"`,
`"bad_signature"`, `"bad_encoding"`, `"unsupported_signature_algorithm"`,
`"unhandled_critical_extension"`, `"unknown_revocation_status"`,
`"name_mismatch"`, `"trust_store_empty"` (placeholder / empty
bundle — see `--trust-store`), `"other:<rustls_variant>"`.

**Placeholder bundles.** Stores shipping as empty placeholder PEM
(Microsoft + DoD today) render as
`{value: null, method: "not_probed", reason: "trust_store_empty"}`
with `per_store_validation_errors.<name>: "trust_store_empty"`.
Supply a current bundle via `--trust-store <name>:<path>` to
replace; see [data/trust_stores/README.md](../data/trust_stores/README.md)
for refresh commands.

### `http` (optional)
Present iff `--enable-http-checks` was passed AND the HTTP probe
actually fired. Absent otherwise — consumers treat a missing `http`
field as "HTTP checks not in scope for this record."

```
{
  enabled: true,
  hsts?: {header_present, raw_value?, max_age?, include_subdomains?, preload?},
  preload_list_status?: "included" | "not_included",
  security_txt?: {present, url?, content_type?, body?, parsed?},
  security_headers?: {
    content_security_policy?, content_security_policy_report_only?,
    x_frame_options?, x_content_type_options?,
    referrer_policy?, permissions_policy?,
    cross_origin_opener_policy?, cross_origin_embedder_policy?,
    cross_origin_resource_policy?,
    reporting_endpoints?,
    set_cookies: [{name, secure, http_only, same_site?}, ...]
  },
  redirect_chain?: [{url, status, location?}, ...]
}
```

**`security_txt`.** `body` is the verbatim response text (subject
to reqwest's default text decoding). `parsed` adds an RFC 9116
structural decomposition: `contact[]` (required by spec; one or
more URL/email entries), `expires` (ISO 8601 string, preserved
as-is — downstream rule engines compare against current time),
`encryption[]`, `preferred_languages[]`, `canonical[]`, `policy[]`,
`hiring[]`, `acknowledgments[]`, `pgp_signed: bool` (presence of a
PGP cleartext-signature block; no signature validation).
`parsed` is absent when the body yielded no recognized directives.

**`security_headers`.** Raw header values captured from the HEAD /
response. Absent fields mean the header wasn't sent. CSP /
frame-options / referrer-policy etc. are raw strings so rule
engines can apply their own directive-level policies.
`reporting_endpoints` surfaces `Reporting-Endpoints` when present,
falling back to the legacy `Report-To` header. `set_cookies[]`
captures per-cookie security-flag observations (`secure`,
`http_only`, `same_site`) — **cookie values are intentionally
omitted** to avoid capturing session tokens or other sensitive
material in observation output.

**`redirect_chain`.** Hops observed when fetching `GET /` with
redirect-following enabled, bounded at 10 hops. Each entry carries
the request URL, HTTP status, and `Location` target for that hop.
The terminal entry has a non-3xx status and `location` absent.
A `status: 0` entry indicates a transport-level failure
(DNS / TCP / TLS) at that hop.

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
below are **permanent within schema v2.x** — never renamed, never
removed. New values may be added in minor-version bumps; consumers
**MUST** tolerate unknown values gracefully rather than crashing or
rejecting the record.

| Field | Values |
|---|---|
| `cipher_suites.<ver>[].classification` | `rsa_kex`, `dhe_aead`, `dhe_cbc`, `ecdhe_aead`, `ecdhe_cbc`, `anon`, `export`, `static_dh`, `static_ecdh`, `psk`, `dhe_psk`, `ecdhe_psk`, `rsa_psk`, `null_cipher`, `other` |
| `cipher_suites.<ver>[].provider`, `groups.<ver>.*.provider` | `aws_lc_rs`, `openssl`, `raw_socket` (`raw_socket` only for SSLv2 cipher_specs; classical TLS versions use `aws_lc_rs` / `openssl`) |
| `*.method` (every `{value, method, reason?}` envelope) | `probe`, `not_probed`, `not_applicable`, `error`, `connection_state` |
| `errors[].category` | `dns_resolution_failed`, `network_unreachable`, `connection_refused`, `connection_timeout`, `handshake_timeout`, `tls_alert_<name>`, `cert_parse_error`, `extension_parse_error`, `http_error`, `internal_scanner_error` |
| `signature_algorithm_policy_probe.*.outcome` | `handshake_complete`, `handshake_failure`, `connection_closed`, `other_alert`, `not_probed` |
| `ocsp_stapling.content.cert_status` | `good`, `revoked`, `unknown` |
| `ocsp_stapling.content.response_status` | `successful`, `malformedRequest`, `internalError`, `tryLater`, `sigRequired`, `unauthorized`, `unknown_<n>` |
| `ocsp_stapling.delivery_path` | `tls1_2`, `tls1_3` |
| `downgrade_signaling.tls13_downgrade_sentinel` | `tls12`, `lte_tls11`, `none` |
| `dh_parameters[].classification` | `ffdhe2048`, `ffdhe3072`, `ffdhe4096`, `ffdhe6144`, `ffdhe8192`, `modp1024`, `modp1536`, `modp2048`, `modp3072`, `custom` |
| `certificates.*.pqc_signature_family` | `ml_dsa`, `slh_dsa`, `composite` (absent for classical signatures) |
| `certificates.*.signature_algorithm_structured.algorithm` | `rsa`, `rsa_pss`, `ecdsa`, `ed25519`, `ed448`, `ml_dsa_44`, `ml_dsa_65`, `ml_dsa_87`, `slh_dsa_sha2_{128,192,256}{s,f}`, `slh_dsa_shake_{128,192,256}{s,f}`, `unknown` |
| `certificates.*.signature_algorithm_structured.hash` | `sha1`, `sha256`, `sha384`, `sha512` (absent when the scheme hashes internally) |

For `category` and `response_status`, the `<name>` / `<n>` suffix
pattern is the permanent shape; new alert names or OCSP-status codes
appear as new `tls_alert_<newname>` / `unknown_<newcode>` values
without breaking the schema contract.

If kemist ever needs to retire a value (extremely rare), that
triggers a major-version bump.
