//! Phase D1 — Legacy cipher enumeration and RSA-kex probing across
//! TLS 1.0/1.1/1.2. Covers RC4, single-DES, 3DES, IDEA, NULL, anon-DH,
//! EXPORT suites; drives DH parameter capture (D2) and SKE signature
//! capture (D3) on every successful DHE-RSA handshake.
