# Post-quantum crypto in kemist

What kemist observes about PQC deployments, where the coverage gaps
are, and how to extend it.

## Current observation coverage

### Key exchange (TLS 1.3 named groups)

| Group | IANA | aws-lc-rs ships | Probe outcome |
|---|---|---|---|
| X25519MLKEM768 | 0x11EC | **yes** | `supported: true/false, method: probe` |
| secp256r1MLKEM768 | 0x11EB | **yes** | same |
| MLKEM768 (standalone) | 0x0201 | **yes** | same |
| secp384r1MLKEM1024 | 0x11ED | no | `supported: null, method: not_probed` |
| MLKEM512 | 0x0200 | no | `not_probed` |
| MLKEM1024 | 0x0202 | no | `not_probed` |
| X25519Kyber768Draft00 | 0x6399 | no | `not_probed` (pre-standard) |

The aws-lc-rs-exposed set is whatever your build's pinned version
ships. Check `capabilities.provider_kx_groups` in any emitted record
to see what was actually in scope for probing.

### Signatures (certificate OID match)

| OID | Algorithm | Detected |
|---|---|---|
| 2.16.840.1.101.3.4.3.17 | ML-DSA-44 | `is_pqc_signature: true` |
| 2.16.840.1.101.3.4.3.18 | ML-DSA-65 | `is_pqc_signature: true` |
| 2.16.840.1.101.3.4.3.19 | ML-DSA-87 | `is_pqc_signature: true` |
| 2.16.840.1.101.3.4.3.20 | SLH-DSA-SHA2-128s | `is_pqc_signature: true` |
| .21–.25 | SLH-DSA-SHA2-{128f,192s,192f,256s,256f} | `is_pqc_signature: true` |
| .26–.31 | SLH-DSA-SHAKE-{128s,128f,192s,192f,256s,256f} | `is_pqc_signature: true` |

Table in [src/scanner/cert.rs](../src/scanner/cert.rs). The flag is a
**raw OID match**, not a judgment — downstream consumers decide whether
`is_pqc_signature: true` is good, bad, or interesting for their policy.

Composite / hybrid signature OIDs (IETF LAMPS drafts) are not yet in
the table. When those stabilize at IANA, they'll be added.

## What's NOT observed

- **PQC cipher suites.** The TLS cipher suite list is orthogonal to
  kx groups — you negotiate a cipher (AEAD) and a kx group separately
  in TLS 1.3. There are no PQC cipher suites per se, just PQC key
  exchange groups.
- **Standalone ML-KEM-512 / ML-KEM-1024 probe results.** aws-lc-rs
  doesn't ship those. They emit `not_probed` with a specific reason.
- **PQC signature verification.** kemist detects PQC signatures by
  OID but does not verify them — we use a permissive verifier for
  cert collection and let webpki-roots handle classical chain
  validation. Validating ML-DSA signatures requires an implementation
  kemist doesn't currently link in.

## Extending probe coverage

Three paths for probing groups beyond the aws-lc-rs ship set:

### (a) Wait for aws-lc-rs

NIST-standardized parameter sets land in aws-lc-rs on AWS's release
cadence. Pinning to a newer aws-lc-rs version picks them up without
code changes. Check `capabilities.provider_kx_groups` in new builds —
any time a group moves from `not_probed` to a real result, that's
aws-lc-rs catching up.

### (b) Raw-ClientHello probing

Hand-craft a TLS 1.3 ClientHello with the target codepoint in
`key_share` and a dummy payload, read the response. No crypto
implementation needed — we probe intent, not completion.

The template lives in [src/scanner/hello.rs](../src/scanner/hello.rs)
(used today for byte-level extension observation). Classification:

- ServerHello echoing the group → `supported: true`
- `handshake_failure` alert → `supported: false`
- `HelloRetryRequest` requesting a different group → `supported: false`

Documented in the [src/scanner/groups.rs](../src/scanner/groups.rs)
module header as a future path.

### (c) Alternate crypto backend

Plug a second `CryptoProvider` — e.g. liboqs-sys with oqs-provider
bindings, or a future `rustls-post-quantum` crate with broader
coverage — and route groups aws-lc-rs doesn't ship through it. Keeps
the `SupportedKxGroup` abstraction uniform, no byte-level code, but
adds binary weight and another crypto implementation to vet.

Also documented in the groups.rs module header.

### Comparing the three paths

| Path | Ship cost | Extensibility | Trust boundary |
|---|---|---|---|
| (a) Wait for aws-lc-rs | zero | one crypto vendor | single, well-vetted |
| (b) Raw-ClientHello | self-contained in kemist | any codepoint | no new crypto |
| (c) Alternate backend | new dependency | up to the backend's coverage | each backend vetted separately |

Neither (b) nor (c) is on the immediate roadmap — the current coverage
is honest about its gaps, and the cost of adding either is bounded.

## Testing PQC observations

Live targets that exercise PQC paths today:

| Target | What to expect |
|---|---|
| `pq.cloudflareresearch.com` | `negotiated.group = X25519MLKEM768` (hybrid) |
| `cloudflare.com` | negotiates X25519MLKEM768 on recent Cloudflare edges |
| `www.google.com` | increasingly negotiates X25519MLKEM768 |

For certs: there are not yet publicly-deployed ML-DSA or SLH-DSA
certificates on the open web. Test against locally-generated PQC certs
or NIST's experimental test servers to exercise the
`is_pqc_signature: true` path.
