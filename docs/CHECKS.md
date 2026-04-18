# kemist observation catalog

What kemist measures, how it measures it, and what the limits are.
Every observation is a raw signal — no compliance verdicts. Rule
evaluation lives in downstream projects.

## TLS versions offered

| Version | How | Source |
|---|---|---|
| SSL 2.0 | Raw TCP + hand-crafted SSL 2.0 CLIENT-HELLO (legacy msg format) | [scanner/legacy.rs::test_sslv2](../src/scanner/legacy.rs) |
| SSL 3.0 | native-tls with min/max protocol pinned | `scanner/legacy.rs::test_legacy_protocol` |
| TLS 1.0 | native-tls with min/max protocol pinned | same |
| TLS 1.1 | native-tls with min/max protocol pinned | same |
| TLS 1.2 | rustls with `with_protocol_versions(&[&TLS12])` | [scanner/mod.rs::test_rustls_protocol](../src/scanner/mod.rs) |
| TLS 1.3 | rustls with `with_protocol_versions(&[&TLS13])` | same |

Each version is a distinct handshake attempt. Success → `offered: true,
method: probe`. Server-level rejection → `offered: false, method: probe`.
Network failure → `offered: null, method: error`.

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
as "the suite is not in `capabilities.provider_cipher_suites`" rather
than as `supported: false`. Downstream rule engines checking for
weak-cipher acceptance must cross-reference against a fuller cipher
registry.

**Server ordering.** `tls.cipher_suites.server_enforces_order` compares
two handshakes with reversed cipher orderings. Same negotiated suite
both times → `true` (server picks, ignores client order); different →
`false` (server honors client preference).

## Key exchange groups

**Target list.** 12 hardcoded entries ([scanner/groups.rs](../src/scanner/groups.rs)):

Classical: `X25519`, `X448`, `secp256r1`, `secp384r1`, `secp521r1`

PQC hybrids: `X25519MLKEM768` (0x11EC), `secp256r1MLKEM768` (0x11EB),
`secp384r1MLKEM1024` (0x11ED)

Standalone ML-KEM: `MLKEM512` (0x0200), `MLKEM768` (0x0201),
`MLKEM1024` (0x0202)

Pre-standard: `X25519Kyber768Draft00` (0x6399) — Cloudflare research
codepoint, obsoleted by `X25519MLKEM768`

**Coverage gap.** aws-lc-rs ships only ~6 of the 12 (typically X25519,
secp256r1, secp384r1, MLKEM768, X25519MLKEM768, secp256r1MLKEM768).
The others emit `{supported: null, method: not_probed, reason:
"aws_lc_rs_no_<name>_support"}` — never `supported: false` without a
real probe.

**Mechanism.** Per-group TLS 1.3 handshake with that single group in
`kx_groups`. Outcomes classify identically to cipher probes.

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
- `is_pqc_signature` — bool, OID matches ML-DSA (FIPS 204) or SLH-DSA
  (FIPS 205) table. 15-entry OID map in [scanner/cert.rs](../src/scanner/cert.rs).
  Composite/hybrid sig OIDs stubbed for future IETF draft codepoints.
- `embedded_scts` — count of entries in extension 1.3.6.1.4.1.11129.2.4.2
- `fingerprint_sha256` / `fingerprint_sha1` — full cert DER hash

## Trust validation

From [scanner/probe.rs::evaluate_validation](../src/scanner/probe.rs):

| Observation | How |
|---|---|
| `chain_valid_to_webpki_roots` | rustls `WebPkiServerVerifier` against `webpki-roots` Mozilla CA bundle. Retries with a SAN-derived name if first pass fails on `NotValidForName`, isolating chain validity from name mismatch. |
| `name_matches_sni` | Independent SAN/CN match using RFC 6125 wildcard semantics. Runs regardless of chain validity. |
| `validation_error` | Canonical error string when chain is invalid — see [OUTPUT_SCHEMA.md](OUTPUT_SCHEMA.md). |

## Extension observations

Captured via two paths — rustls connection state and a dedicated
byte-level TLS 1.2 probe.

### From rustls connection state ([scanner/probe.rs](../src/scanner/probe.rs))

| Schema field | Source |
|---|---|
| `tls.negotiated.*` | `ClientConnection::{protocol_version,negotiated_cipher_suite,negotiated_key_exchange_group,alpn_protocol}` |
| `tls.extensions.ocsp_stapling` | Verifier `verify_server_cert` receives `ocsp_response: &[u8]`; we record the length and whether it was non-empty |
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

**The byte probe is a TLS 1.2 probe.** When the server only speaks TLS
1.3, EMS/EtM/secure_renegotiation render as `not_applicable`. Heartbeat
is defined for both and renders regardless.

### Other extension-adjacent observations

- `extensions.heartbeat_echoes_oversized_payload` — active probe from
  the pre-kemist TLSferret code. Sends a malformed heartbeat with
  oversized payload length; records whether the server echoed more
  bytes than we sent. Raw wire signal (not a CVE verdict).
- `downgrade_signaling.fallback_scsv_accepted` — heuristic SCSV
  observation from the same legacy code. Keeps the raw signal; rename
  from the original TLSferret `fallback_scsv_supported`.

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
  verbatim, **not parsed**.
- **Preload list** — static 12-entry lookup covering `github.com`,
  `paypal.com`, `reddit.com`, `cisa.gov`, `mozilla.org`, `wikipedia.org`,
  `twitter.com`, `gov.uk`, `example.com`, `cloudflare.com`, and two
  `www.*` variants. Subdomain match for entries marked
  `include_subdomains: true`.

**The preload list is a stub.** Shipping a full Chromium
`transport_security_state_static.json` snapshot (~15,000 entries) is
deferred — the current list covers common test targets. Non-listed
hosts emit `not_included` regardless of their real Chrome status.

## STARTTLS

Not supported. The original TLSferret fork had SMTP/IMAP/POP3/FTP/LDAP/
XMPP/PostgreSQL/MySQL STARTTLS negotiation; kemist dropped it at PR 1
per the spec's HTTPS-on-443 focus.

## User-Agent

All HTTP requests use:

```
kemist/<version> (+<user-agent-info-url>)
```

Defaults to `https://www.kemist-tls.net`. Set `--user-agent-info-url`
to your own URL when scanning targets you don't own — it helps site
operators trace requests back to you.
