# TLS backend abstraction

kemist talks to multiple TLS libraries through one trait —
`TlsBackend` — so that probe dispatch is decoupled from "which library
can actually speak this codepoint." The abstraction lives under
[`src/scanner/backends/`](../src/scanner/backends/).

## Why

The original code hand-routed per probe type: every call site knew
"use rustls for TLS 1.3 groups, use OpenSSL for FFDHE." Adding a third
TLS library (BoringSSL, s2n-tls, liboqs) would have required edits at
8–12 sites. With the abstraction:

1. One trait impl per backend, declaring which codepoints it can probe.
2. One entry in a priority table per codepoint the new backend claims.
3. No changes to orchestrator flow, JSON emitter, or probe drivers.

## Core types

### `TlsBackend` ([mod.rs](../src/scanner/backends/mod.rs))

```rust
#[async_trait]
pub trait TlsBackend: Send + Sync {
    fn id(&self) -> &'static str;
    fn inventory(&self) -> &BackendInventory;
    fn constraint_capabilities(&self) -> ConstraintCapabilities;
    async fn handshake(
        &self,
        constraint: HandshakeConstraint,
        ctx: &ProbeContext,
    ) -> Result<HandshakeResult, UnsatisfiableConstraint>;
}
```

Every backend advertises its codepoint universe (`BackendInventory`),
its per-axis constraint capabilities (`ConstraintCapabilities`), and
a single `handshake()` primitive that accepts a `HandshakeConstraint`
and returns a `HandshakeResult`. Orchestrator code composes higher-level
probes (cipher enumeration, FALLBACK_SCSV, sigalg_policy) out of
`handshake()` calls.

### `BackendInventory`

Declares which codepoints this backend can probe. For rustls, derived
at runtime from `aws_lc_rs::ALL_CIPHER_SUITES` / `ALL_KX_GROUPS`; for
OpenSSL, sourced from the hardcoded target tables in
[`backends/openssl/ciphers.rs`](../src/scanner/backends/openssl/ciphers.rs)
and [`backends/openssl/kx_groups.rs`](../src/scanner/backends/openssl/kx_groups.rs).

### `HandshakeConstraint`

Seven orthogonal axes the caller can pin:

| Axis | Meaning |
|---|---|
| `version_range: Option<(TlsVersion, TlsVersion)>` | min/max pinned TLS version (equal → single-version probe) |
| `cipher_suites: Option<Vec<u16>>` | restrict ClientHello cipher list to these IANA codepoints |
| `groups: Option<Vec<u16>>` | restrict `supported_groups` / `key_share` |
| `sigalgs: Option<Vec<u16>>` | restrict `signature_algorithms` |
| `alpn: Option<Vec<Vec<u8>>>` | ALPN identifiers to advertise |
| `send_fallback_scsv: bool` | include `TLS_FALLBACK_SCSV` (RFC 7507) |
| `seclevel_zero: bool` | OpenSSL-only: `SSL_CTX_set_security_level(0)` |

Backends that can't honor a combination return
`Err(UnsatisfiableConstraint { reason })`. The orchestrator surfaces
this as `method: not_probed` with the backend's reason string — probes
are never silently dropped.

### `HandshakeResult`

Outcome (`HandshakeOutcome`) plus optional observer slots: negotiated
state, certificate chain (DER + parsed), ALPN, alert category, DH
parameters (OpenSSL-only), SKE signature name, OCSP bytes, observed
signature scheme. Not every probe populates every slot — cipher probes
fill `outcome` only; characterization handshakes fill `negotiated`;
TLS 1.2 DHE probes fill `dh_parameters`.

### `BackendRegistry` ([registry.rs](../src/scanner/backends/registry.rs))

Owns the set of available backends + per-codepoint priority tables.
Exposes:

- `merged_cipher_codepoints()` / `merged_group_codepoints()` / `merged_versions()` — union across all backends
- `route_cipher(code)` / `route_group(code)` / `route_version(v)` — returns the `&dyn TlsBackend` responsible for that codepoint, or `None` if unclaimed

Current routing:

| Codepoint class | Backend |
|---|---|
| TLS 1.2/1.3 AEAD suites (aws-lc-rs universe) | rustls |
| Legacy CBC / RSA-kex / RC4 / 3DES / NULL / anon / PSK / Camellia / SEED / ARIA / static DH | OpenSSL |
| X25519 / secp256r1 / secp384r1 / X25519MLKEM768 / secp256r1MLKEM768 / MLKEM768 | rustls |
| X448 / secp521r1 / MLKEM512 / MLKEM1024 / secp384r1MLKEM1024 | OpenSSL |
| FFDHE2048-8192 (RFC 7919) | OpenSSL |
| TLS 1.2 / TLS 1.3 | rustls |
| SSLv3 / TLS 1.0 / TLS 1.1 | OpenSSL |

The two inventories don't overlap today, but registration uses
`entry().or_insert()` so "rustls claims it first, OpenSSL fills gaps"
is explicit — a future third backend that tries to claim an occupied
codepoint has to be added deliberately to the priority table.

## Probe surfaces

Four distinct shapes, each with a different home:

| Surface | Example | Dispatch |
|---|---|---|
| **Codepoint-driven** | cipher / group / version enumeration, sigalg_policy, FALLBACK_SCSV | `backend.handshake(HandshakeConstraint)` |
| **Post-handshake observers** | DH parameter capture, SKE sigalg, OCSP bytes | Optional typed slots on `HandshakeResult` |
| **Post-handshake actions** | client-initiated renegotiation, session resumption, CertificateRequest capture, TLS 1.3 EncryptedExtensions capture | Inherent methods on the concrete backend struct |
| **Raw-socket** | SSLv2, Heartbleed, byte-level ServerHello extension observation | Free functions under [`src/scanner/raw/`](../src/scanner/raw/); bypass `TlsBackend` entirely |

## Adding a new backend

Concretely, to add (say) a `BoringsslBackend`:

1. **Inventory.** Add `boringssl_inventory()` in
   [`backends/mod.rs`](../src/scanner/backends/mod.rs) that enumerates the
   codepoints BoringSSL ships and returns a `BackendInventory`.

2. **Backend impl.** Create `src/scanner/backends/boringssl/mod.rs`
   defining `BoringsslBackend` + `impl TlsBackend`. Implement
   `handshake()` for the constraint shapes you care about; return
   `UnsatisfiableConstraint` for everything else.

3. **Register.** Add a field to `BackendRegistry` and one line to
   `BackendRegistry::new()` populating the priority tables. Decide per
   codepoint class whether BoringSSL wins, loses, or fills gaps
   relative to the existing backends — make those choices explicit in
   the routing table, don't rely on iteration order.

4. **Feature gate.** Wire the backend through a cargo feature so users
   can compile-time-exclude it when they don't want the dep (mirrors
   how `legacy-probes` gates the OpenSSL backend today).

5. **Tests.** Unit tests under the new module verifying:
   - `id()` returns the expected identifier
   - `constraint_capabilities()` matches what `handshake()` actually
     supports (catches drift)
   - Each supported constraint shape returns a well-formed
     `HandshakeResult`

No changes to the JSON emitter, orchestrator loop, schema, or other
backends. Verify byte-identical output on a known target before
landing — the refactor's snapshot protocol applies to new backends too.

## Why codepoint-driven routing instead of "first backend wins"

A backend that claims a codepoint takes ownership of probing it. If
two backends both ship e.g. secp256r1, the registry must explicitly
decide which one answers — anything else leads to silent drift when
backends' upstream inventories change. Today's table puts rustls
first and lets OpenSSL fill gaps; switching this globally is one
HashMap insert order change, not a codebase sweep.

## Post-handshake actions live outside the trait

Renegotiation, session resumption, CertificateRequest capture, and
TLS 1.3 EncryptedExtensions capture are inherent methods on
`OpensslBackend` rather than trait methods. They each require
backend-specific hooks (`SSL_renegotiate`, `SSL_CTX_set_msg_callback`,
session cache mode) that don't meaningfully generalize. Keeping them
as concrete-type methods means the orchestrator calls them directly
when the OpenSSL backend is present — no least-common-denominator
trait that strips them down.
