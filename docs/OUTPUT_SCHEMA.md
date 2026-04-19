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
| `native_tls_version` | `string` | native-tls version for legacy SSLv3/TLS 1.0/1.1 |
| `provider_cipher_suites` | `string[]` | Cipher suite names aws-lc-rs shipped — defines the probe set |
| `provider_kx_groups` | `string[]` | KX group names aws-lc-rs shipped — defines the probe set |
| `config_paths` | `string[]` | Config files consulted (reserved for PR 13 extensions) |
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
  tls1_2: [ {name, iana_code, supported, method, reason?}, ... ],
  tls1_3: [ {name, iana_code, supported, method, reason?}, ... ],
  server_enforces_order: ObservationBool
}
```

One entry per aws-lc-rs-shipped suite, probed individually. `iana_code`
is a `"0xNNNN"` string (four hex chars). `server_enforces_order` compares
two handshakes with reversed cipher orderings.

Suites outside aws-lc-rs' ship set are **absent from the arrays** — the
scanner can't probe what the provider doesn't implement. Consumers
cross-check against `capabilities.provider_cipher_suites`.

### `tls.groups`
Map keyed by group name (e.g. `"X25519MLKEM768"`, `"secp256r1"`):
```
{
  "X25519MLKEM768": {supported: true, method: "probe"},
  "MLKEM512": {supported: null, method: "not_probed",
               reason: "aws_lc_rs_no_mlkem512_support"},
  ...
}
```

12 target groups (classical, PQC hybrids, standalone ML-KEM,
Kyber768Draft00). Entries aws-lc-rs doesn't ship emit `not_probed` with
a specific reason — never `supported: false` without a real probe.

### `tls.extensions`
```
{
  ems: ObservationBool,
  secure_renegotiation: ObservationBool,
  ocsp_stapling: {stapled, method, reason?, response_length},
  sct: {delivery_paths: [...], count},
  alpn_offered: [...],
  encrypt_then_mac: ObservationBool,
  heartbeat_present: ObservationBool,
  heartbeat_echoes_oversized_payload: ObservationBool,
  compression_offered: [...]
}
```

See [CHECKS.md](CHECKS.md) for how each observation is obtained.

### `tls.downgrade_signaling`
```
{
  fallback_scsv_accepted: ObservationBool,  // DEPRECATED — see below
  fallback_scsv_enforced:  ObservationBool
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
- **`fallback_scsv_accepted`** — **DEPRECATED** in schema v1; scheduled
  for removal in schema v2. Earlier kemist versions populated this with
  a TLS 1.3-support heuristic that gave false positives. From this
  version on it always renders `{value: null, method: "not_probed",
  reason: "superseded_by_fallback_scsv_enforced"}`. Consumers should
  migrate to `fallback_scsv_enforced`.

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
| `public_key` | `{algorithm, size_bits, curve?}` | |
| `embedded_scts` | `int` | Count from extension 1.3.6.1.4.1.11129.2.4.2 |
| `fingerprint_sha256` | `string` | Hex |
| `fingerprint_sha1` | `string` | Hex |

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
