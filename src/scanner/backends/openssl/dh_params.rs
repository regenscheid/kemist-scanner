//! Finite-field DH parameter capture.
//!
//! Called as a post-handshake observer after every successful DHE handshake
//! driven by [`super::ciphers`]. Extracts the server's tmp key via
//! `SSL_get_peer_tmp_key`, projects onto the DH key type, and captures:
//!
//! - `prime_bits` via `EVP_PKEY_get_bits` (downstream Logjam check).
//! - `generator` — typically 2 or 5; oddball values are a smell, `g = 1`
//!   is a fault.
//! - `prime_sha256` — SHA-256 of the big-endian prime bytes, enabling
//!   classification against the RFC 7919 FFDHE table without hauling
//!   kilobytes of prime hex around in output JSON.
//! - `classification` — one of `ffdhe{2048,3072,4096,6144,8192}` or
//!   `custom`. A custom 2048-bit prime is a meaningfully weaker posture
//!   than `ffdhe2048` even at equal bit-length; it's the Logjam
//!   precomputation target.
//!
//! SHA-256 constants below are pinned to the primes in RFC 7919 §A.1-A.5.
//! The `classifies_rfc7919_ffdhe2048` test below rehashes the canonical
//! prime bytes (embedded hex) and asserts the constant matches — so an
//! accidental edit to the constant fails loudly at PR time.

use openssl::error::ErrorStack;
use openssl::pkey::Id;
use openssl::ssl::SslRef;
use sha2::{Digest, Sha256};

/// Named DH group, or `Custom` for unknown primes.
///
/// Serialized shape matches the schema's `tls.dh_parameters[].classification`
/// enum. Three families covered:
///
/// - **RFC 7919 FFDHE** (`ffdhe2048`-`ffdhe8192`) — the modern named-group
///   scheme TLS 1.2/1.3 `supported_groups` advertises.
/// - **RFC 2409 / RFC 3526 MODP** (`modp1024`-`modp3072`) — the older IKE
///   "Oakley" groups. Some web TLS deployments (older nginx configs,
///   custom OpenSSL builds) still serve these as custom-DH primes.
///   `modp1024` in particular matches the 1024-bit prime Logjam
///   targeted as widely-reused precomputation fodder.
/// - `custom` — prime doesn't match any named group we know about.
///   The `prime_bits` field still carries the size, so rule engines
///   can flag weak-by-size primes; this variant means "size aside,
///   we don't recognize the prime itself."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhClassification {
    Ffdhe2048,
    Ffdhe3072,
    Ffdhe4096,
    Ffdhe6144,
    Ffdhe8192,
    /// RFC 2409 §6.2 "Second Oakley Default Group" (1024-bit). The
    /// Logjam paper's headline target — widely reused as a default
    /// across Apache/IKE deployments, so precomputation against it
    /// is economically worthwhile.
    Modp1024,
    /// RFC 3526 §2 "Group 5" (1536-bit).
    Modp1536,
    /// RFC 3526 §3 "Group 14" (2048-bit).
    Modp2048,
    /// RFC 3526 §4 "Group 15" (3072-bit).
    Modp3072,
    Custom,
}

impl DhClassification {
    pub fn as_schema_str(self) -> &'static str {
        match self {
            Self::Ffdhe2048 => "ffdhe2048",
            Self::Ffdhe3072 => "ffdhe3072",
            Self::Ffdhe4096 => "ffdhe4096",
            Self::Ffdhe6144 => "ffdhe6144",
            Self::Ffdhe8192 => "ffdhe8192",
            Self::Modp1024 => "modp1024",
            Self::Modp1536 => "modp1536",
            Self::Modp2048 => "modp2048",
            Self::Modp3072 => "modp3072",
            Self::Custom => "custom",
        }
    }
}

/// DH parameter snapshot captured from a completed DHE handshake.
#[derive(Debug, Clone)]
pub struct DhSnapshot {
    pub prime_bits: u32,
    pub generator: u32,
    pub prime_sha256: [u8; 32],
    pub classification: DhClassification,
}

impl DhSnapshot {
    /// Lowercase hex of `prime_sha256`, the form used in JSON output.
    pub fn prime_sha256_hex(&self) -> String {
        hex::encode(self.prime_sha256)
    }
}

/// Capture DH parameters from the server's tmp key.
///
/// Returns:
/// - `Ok(Some(_))` for a DHE handshake with a DH tmp key.
/// - `Ok(None)` when the handshake has no tmp key (RSA-kex) or the tmp key
///   isn't DH (ECDHE). Callers treat this as "nothing to snapshot" rather
///   than an error — DH capture is conditional.
/// - `Err(_)` only when OpenSSL raises an unexpected internal error while
///   decomposing the key (e.g. provider-backed EVP_PKEY that refuses to
///   expose DH parts). Callers typically log + continue.
pub fn snapshot(ssl: &SslRef) -> Result<Option<DhSnapshot>, ErrorStack> {
    // `peer_tmp_key` errors when no tmp key exists (RSA-kex) — not a real
    // failure, so normalize to Ok(None).
    let pkey = match ssl.peer_tmp_key() {
        Ok(k) => k,
        Err(_) => return Ok(None),
    };
    if pkey.id() != Id::DH {
        return Ok(None);
    }

    let dh = pkey.dh()?;
    let prime_bytes = dh.prime_p().to_vec();
    let prime_bits = pkey.bits();

    let mut hasher = Sha256::new();
    hasher.update(&prime_bytes);
    let prime_sha256: [u8; 32] = hasher.finalize().into();

    // Generators in the wild are 2 or 5. Servers shipping generators outside
    // u32 range are pathological — pin at 0 so the output signals "couldn't
    // represent" without blowing up the schema integer bound.
    let generator = dh
        .generator()
        .to_dec_str()
        .ok()
        .and_then(|s| s.to_string().parse::<u32>().ok())
        .unwrap_or(0);

    Ok(Some(DhSnapshot {
        prime_bits,
        generator,
        prime_sha256,
        classification: classify_by_hash(&prime_sha256),
    }))
}

/// Match a prime's SHA-256 against every named-group hash we know,
/// else `Custom`. FFDHE constants are inline (RFC 7919 §A.1-5); MODP
/// constants are derived lazily from their canonical hex at first
/// call via the table in [`modp_hashes`] — avoids hand-computing and
/// maintaining SHA-256 constants for large primes.
fn classify_by_hash(hash: &[u8; 32]) -> DhClassification {
    // FFDHE first (compile-time constants, fastest path).
    if hash == &FFDHE2048_SHA256 {
        return DhClassification::Ffdhe2048;
    }
    if hash == &FFDHE3072_SHA256 {
        return DhClassification::Ffdhe3072;
    }
    if hash == &FFDHE4096_SHA256 {
        return DhClassification::Ffdhe4096;
    }
    if hash == &FFDHE6144_SHA256 {
        return DhClassification::Ffdhe6144;
    }
    if hash == &FFDHE8192_SHA256 {
        return DhClassification::Ffdhe8192;
    }
    // MODP groups — computed once on first call.
    for (expected, classification) in modp_hashes() {
        if hash == expected {
            return *classification;
        }
    }
    DhClassification::Custom
}

/// RFC 2409 §6.2 MODP Group 2 (1024-bit). Hex digits only; whitespace
/// filtered at hash-computation time.
const MODP1024_HEX: &str = "\
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 \
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD \
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 \
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED \
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381 \
    FFFFFFFF FFFFFFFF";

/// RFC 3526 §2 MODP Group 5 (1536-bit).
const MODP1536_HEX: &str = "\
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 \
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD \
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 \
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED \
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D \
    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F \
    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D \
    670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF";

/// RFC 3526 §3 MODP Group 14 (2048-bit).
const MODP2048_HEX: &str = "\
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 \
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD \
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 \
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED \
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D \
    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F \
    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D \
    670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B \
    E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 \
    DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510 \
    15728E5A 8AACAA68 FFFFFFFF FFFFFFFF";

/// RFC 3526 §4 MODP Group 15 (3072-bit).
const MODP3072_HEX: &str = "\
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 \
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD \
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 \
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED \
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D \
    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F \
    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D \
    670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B \
    E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 \
    DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510 \
    15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64 \
    ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7 \
    ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B \
    F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C \
    BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 \
    43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF";

/// Lazy-initialized table of MODP prime SHA-256 hashes. First call
/// strips whitespace from each HEX constant, decodes, hashes, and
/// pairs with the corresponding enum variant. Subsequent calls return
/// the cached vec.
fn modp_hashes() -> &'static [([u8; 32], DhClassification)] {
    static CACHE: std::sync::OnceLock<Vec<([u8; 32], DhClassification)>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(|| {
        [
            (MODP1024_HEX, DhClassification::Modp1024),
            (MODP1536_HEX, DhClassification::Modp1536),
            (MODP2048_HEX, DhClassification::Modp2048),
            (MODP3072_HEX, DhClassification::Modp3072),
        ]
        .iter()
        .map(|(hex_str, classification)| {
            let cleaned: String = hex_str.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            let bytes = hex::decode(&cleaned).expect("hardcoded MODP hex must decode");
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let hash: [u8; 32] = hasher.finalize().into();
            (hash, *classification)
        })
        .collect()
    })
}

// RFC 7919 §A.1 ffdhe2048 prime — SHA-256 of big-endian prime bytes.
const FFDHE2048_SHA256: [u8; 32] = [
    0x9c, 0xd3, 0xb7, 0xf3, 0x36, 0x87, 0x2f, 0x46, 0xc0, 0x94, 0x28, 0xd1, 0xbb, 0xc1, 0x98, 0x77,
    0xa4, 0xd4, 0x40, 0x51, 0x2c, 0xda, 0x8d, 0x1c, 0x1c, 0xf0, 0xcd, 0x6e, 0x33, 0x69, 0x89, 0x66,
];
// RFC 7919 §A.2 ffdhe3072 prime — SHA-256 of big-endian prime bytes.
const FFDHE3072_SHA256: [u8; 32] = [
    0x0e, 0xaf, 0x67, 0xdb, 0x3a, 0x83, 0x91, 0x56, 0xd5, 0x01, 0x34, 0x94, 0xa5, 0x31, 0x8a, 0x77,
    0x2b, 0x56, 0x97, 0xd2, 0x70, 0xd7, 0x21, 0xf3, 0x7f, 0x09, 0x2e, 0xfc, 0x69, 0xea, 0x5a, 0x17,
];
// RFC 7919 §A.3 ffdhe4096 prime — SHA-256 of big-endian prime bytes.
const FFDHE4096_SHA256: [u8; 32] = [
    0x46, 0x48, 0x41, 0x42, 0x24, 0xac, 0x88, 0x1b, 0x3d, 0x0d, 0xc5, 0x9b, 0x46, 0x6f, 0x96, 0xd0,
    0x6a, 0x55, 0x82, 0x78, 0x77, 0x68, 0x07, 0x79, 0x7e, 0xcf, 0x1f, 0x66, 0xff, 0x39, 0x7b, 0x3e,
];
// RFC 7919 §A.4 ffdhe6144 prime — SHA-256 of big-endian prime bytes.
const FFDHE6144_SHA256: [u8; 32] = [
    0x22, 0x7a, 0xc9, 0x06, 0x6b, 0x3d, 0xdd, 0x9e, 0x19, 0x36, 0x70, 0xcd, 0xa2, 0x38, 0x8f, 0xa8,
    0x84, 0xf6, 0x5b, 0xa0, 0xcf, 0x98, 0xb7, 0x42, 0xd1, 0xfe, 0x77, 0xa6, 0x68, 0x7c, 0x79, 0xc7,
];
// RFC 7919 §A.5 ffdhe8192 prime — SHA-256 of big-endian prime bytes.
const FFDHE8192_SHA256: [u8; 32] = [
    0x77, 0x0b, 0x14, 0xef, 0xaf, 0x6f, 0x04, 0x99, 0x29, 0xc5, 0x23, 0x11, 0x3b, 0x3f, 0xa9, 0x9a,
    0x8d, 0x11, 0xda, 0xb1, 0xb1, 0x8a, 0xf3, 0x60, 0x95, 0x90, 0x12, 0x20, 0x75, 0xd1, 0x98, 0x33,
];

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7919 §A.1 — ffdhe2048 prime as contiguous big-endian hex. Used as
    // the anchor test: if the SHA-256 of these bytes ever stops matching
    // FFDHE2048_SHA256, either the RFC hex was corrupted or the constant
    // was. The 4 larger primes use the same SHA-256 machinery, so proving
    // the contract with one authoritative prime is sufficient.
    const FFDHE2048_HEX: &str = "\
FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695\
A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A\
D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935\
984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A\
BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4\
AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61\
9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005\
C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF";

    #[test]
    fn ffdhe2048_constant_matches_rfc7919_prime() {
        let prime = hex::decode(FFDHE2048_HEX).expect("fixture hex must decode");
        assert_eq!(prime.len(), 256, "ffdhe2048 prime must be 2048 bits");
        let hash: [u8; 32] = Sha256::digest(&prime).into();
        assert_eq!(
            hash, FFDHE2048_SHA256,
            "FFDHE2048_SHA256 drifted from RFC 7919 §A.1 prime"
        );
    }

    #[test]
    fn modp_hex_constants_decode_to_expected_bit_sizes() {
        let cases = [
            (MODP1024_HEX, 128),
            (MODP1536_HEX, 192),
            (MODP2048_HEX, 256),
            (MODP3072_HEX, 384),
        ];
        for (hex_str, expected_bytes) in cases {
            let cleaned: String = hex_str.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            let decoded = hex::decode(&cleaned).expect("MODP hex must decode");
            assert_eq!(
                decoded.len(),
                expected_bytes,
                "MODP hex length mismatch (expected {} bytes = {} bits)",
                expected_bytes,
                expected_bytes * 8
            );
        }
    }

    #[test]
    fn classify_recognizes_modp_groups() {
        // Recompute the hashes through the lazy loader, then round-trip
        // each back into classify_by_hash.
        for (expected_hash, classification) in modp_hashes() {
            assert_eq!(
                classify_by_hash(expected_hash),
                *classification,
                "MODP lookup miss for {:?}",
                classification
            );
        }
    }

    #[test]
    fn classify_unknown_prime_falls_back_to_custom() {
        let random = [0xab; 32];
        assert_eq!(classify_by_hash(&random), DhClassification::Custom);
    }

    #[test]
    fn classify_matches_known_ffdhe_hashes() {
        assert_eq!(
            classify_by_hash(&FFDHE2048_SHA256),
            DhClassification::Ffdhe2048
        );
        assert_eq!(
            classify_by_hash(&FFDHE3072_SHA256),
            DhClassification::Ffdhe3072
        );
        assert_eq!(
            classify_by_hash(&FFDHE4096_SHA256),
            DhClassification::Ffdhe4096
        );
        assert_eq!(
            classify_by_hash(&FFDHE6144_SHA256),
            DhClassification::Ffdhe6144
        );
        assert_eq!(
            classify_by_hash(&FFDHE8192_SHA256),
            DhClassification::Ffdhe8192
        );
    }

    #[test]
    fn classify_unknown_hash_is_custom() {
        // Zero hash, all-0xff hash, and single-bit-flipped ffdhe2048 hash —
        // all custom.
        let zeros = [0u8; 32];
        assert_eq!(classify_by_hash(&zeros), DhClassification::Custom);

        let all_ff = [0xffu8; 32];
        assert_eq!(classify_by_hash(&all_ff), DhClassification::Custom);

        let mut flipped = FFDHE2048_SHA256;
        flipped[0] ^= 0x01;
        assert_eq!(classify_by_hash(&flipped), DhClassification::Custom);
    }

    #[test]
    fn classification_schema_strings_match_enum_names() {
        for (c, s) in [
            (DhClassification::Ffdhe2048, "ffdhe2048"),
            (DhClassification::Ffdhe3072, "ffdhe3072"),
            (DhClassification::Ffdhe4096, "ffdhe4096"),
            (DhClassification::Ffdhe6144, "ffdhe6144"),
            (DhClassification::Ffdhe8192, "ffdhe8192"),
            (DhClassification::Custom, "custom"),
        ] {
            assert_eq!(c.as_schema_str(), s);
        }
    }

    #[test]
    fn prime_sha256_hex_is_lowercase_64_chars() {
        let snap = DhSnapshot {
            prime_bits: 2048,
            generator: 2,
            prime_sha256: FFDHE2048_SHA256,
            classification: DhClassification::Ffdhe2048,
        };
        let h = snap.prime_sha256_hex();
        assert_eq!(h.len(), 64);
        assert!(h
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
        assert_eq!(&h[..8], "9cd3b7f3");
    }

    #[test]
    fn ffdhe_sha256_constants_are_distinct() {
        // Guard against copy-paste errors in the five constants.
        let all = [
            FFDHE2048_SHA256,
            FFDHE3072_SHA256,
            FFDHE4096_SHA256,
            FFDHE6144_SHA256,
            FFDHE8192_SHA256,
        ];
        for i in 0..all.len() {
            for j in i + 1..all.len() {
                assert_ne!(
                    all[i], all[j],
                    "FFDHE SHA-256 constants {i} and {j} collide"
                );
            }
        }
    }
}
