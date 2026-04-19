# Legacy-probe integration fixture

Deliberately misconfigured TLS server for exercising the legacy-probes
subsystem. Boots an nginx 1.25 container on OpenSSL 1.1.1 that accepts
weak primitives (RC4, DES, 3DES, NULL, anon) with a 1024-bit custom DH
prime and `ssl_verify_client optional`.

**Never expose this to an untrusted network.** Everything about it is
wrong on purpose.

## Quick start

```
# One-time (~30s, generates 1024-bit DH params):
./generate-certs.sh

# Boot:
docker compose up -d

# Run the ignored integration tests from the repo root:
KEMIST_LEGACY_FIXTURE_ADDR=127.0.0.1:14443 \
KEMIST_LEGACY_FIXTURE_HOSTNAME=legacy-fixture.local \
cargo test --features legacy-probes --test openssl_probe -- --ignored

# Teardown:
docker compose down
```

## What you should see

- `tls.legacy_cipher_suites[]` — RC4, DES, 3DES, NULL, anon-DH entries
  all `supported: true`. RSA-kex suites supported. Stock nginx does
  **not** offer export-grade ciphers even with SECLEVEL=0 — those
  remain `supported: false`.
- `tls.dh_parameters[]` — at least one entry with
  `{prime_bits: 1024, classification: "custom"}` from any successful
  DHE-RSA handshake.
- `tls.ffdhe_support.*` — the default nginx/OpenSSL 1.1.1 build does
  not advertise `ffdhe*` negotiation, so all five codepoints render
  `supported: false` at both TLS versions (handshake_failure alert).
- `tls.downgrade_signaling.fallback_scsv_enforced` —
  `{value: true}` because OpenSSL 1.1.1 enforces RFC 7507 by default.
- `tls.renegotiation_behavior.client_initiated_verdict` —
  `"rejected"` because nginx disables renegotiation.
- `tls.client_auth_request` — populated with the CA DN
  `CN=kemist test CA, O=kemist`; `requested: true`;
  `alert_on_empty_cert: null` (server accepted our empty cert because
  `ssl_verify_client optional` lets the handshake continue).

## Files

| File | Purpose |
|---|---|
| `docker-compose.yml` | Service definition, port binding, healthcheck |
| `nginx.conf` | Deliberately weak TLS config |
| `generate-certs.sh` | One-shot cert + DH param generation |
| `server.crt` / `server.key` | Self-signed leaf (gitignored, regenerated) |
| `client-ca.crt` | CA advertised in CertificateRequest (gitignored) |
| `dh1024.pem` | 1024-bit custom DH prime (gitignored) |

The four `.pem` / `.crt` / `.key` artifacts are `.gitignore`'d — always
regenerate locally and in CI via `generate-certs.sh`. They're fast
enough to produce (~30s cold) that pinning them into the repo isn't
worth the supply-chain surface.
