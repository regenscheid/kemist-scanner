#!/usr/bin/env bash
# Generate the certificates + DH parameters the legacy-probe fixture uses.
# Idempotent: skips work if all artifacts are already present.
#
# Outputs (in this directory):
#   - server.crt / server.key   — self-signed leaf for legacy-fixture.local
#   - client-ca.crt             — CA advertised in CertificateRequest
#   - dh1024.pem                — deliberately weak custom DH prime
#
# Requires `openssl` on PATH. The host's openssl is fine — these are test
# fixtures, not something the scanner binary itself consumes.

set -euo pipefail
cd "$(dirname "$0")"

if [[ -f server.crt && -f server.key && -f client-ca.crt && -f dh1024.pem ]]; then
  echo "fixture certs already present; skipping"
  exit 0
fi

# 1024-bit DH — deliberately weak. Classifies as `custom` (not RFC 7919).
# Generation is slow (~30s) but only runs once per checkout.
echo "generating 1024-bit DH parameters (slow)..."
openssl dhparam -out dh1024.pem 1024

# Server leaf: self-signed, CN = legacy-fixture.local, SAN includes the
# same. Key is RSA-2048 so the handshake is fast.
echo "generating server RSA-2048 key + self-signed cert..."
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key -out server.crt \
  -days 365 \
  -subj "/CN=legacy-fixture.local/O=kemist-test" \
  -addext "subjectAltName = DNS:legacy-fixture.local,IP:127.0.0.1"

# CA cert advertised in the CertificateRequest sent by nginx under
# `ssl_verify_client optional`. Self-signed, unused for real verification
# — the scanner just needs a DN to parse.
echo "generating CA cert for CertificateRequest..."
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout /tmp/kemist-fixture-ca.key -out client-ca.crt \
  -days 365 \
  -subj "/CN=kemist test CA/O=kemist/OU=testing"
rm -f /tmp/kemist-fixture-ca.key

# Make files readable by nginx in the container (UID-independent).
chmod 644 server.crt server.key client-ca.crt dh1024.pem

echo "fixture certs ready."
