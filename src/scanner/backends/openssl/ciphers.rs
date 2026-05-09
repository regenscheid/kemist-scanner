//! Legacy cipher enumeration and RSA-kex probing across TLS 1.0 / TLS 1.1
//! / TLS 1.2.
//!
//! Covers RSA-kex, RC4, single-DES/3DES, NULL, anon-DH, and a few DHE-RSA
//! suites (the last category drives the [`super::dh_params`] and
//! [`super::ske_sig`] post-handshake observers).
//!
//! Probe discipline: one suite per ClientHello, single TLS version pinned
//! via `set_min/max_proto_version`, `set_security_level(0)` to unblock the
//! weak primitives, `SslVerifyMode::NONE` (we never validate in probes).
//! Outcome classification mirrors the rustls path at
//! `src/scanner/ciphers.rs:182-193` — any `tls_alert_*` or
//! `connection_refused` is `NotSupported`; other errors are `Error`.
//!
//! Execution: synchronous OpenSSL handshake wrapped in `spawn_blocking` so
//! it cooperates with the tokio runtime without pulling in `tokio-openssl`.

use std::net::SocketAddr;
use std::time::Duration;

use openssl::pkey::Id;
use openssl::ssl::{HandshakeError, Ssl, SslContext, SslMethod, SslRef, SslVerifyMode, SslVersion};
use sha2::{Digest, Sha256};
use tracing::{debug, info};

use crate::model::cert::CertificateInfo;
use crate::model::errors::ScannerError;
use crate::model::protocol::TlsVersion;
use crate::scanner::backends::{is_wire_rejection, HandshakeOutcome};
use crate::scanner::openssl::alerts;
use crate::scanner::openssl::dh_params::{self, DhSnapshot};
use crate::scanner::openssl::ske_sig;

/// One per-suite probe result.
#[derive(Debug, Clone)]
pub struct LegacyCipherResult {
    /// IANA-style suite name, e.g. `"TLS_RSA_WITH_AES_128_CBC_SHA"`.
    pub name: String,
    /// OpenSSL shorthand name, e.g. `"AES128-SHA"`. Needed to reproduce the
    /// probe by hand during triage.
    pub openssl_name: String,
    /// IANA codepoint (e.g. `0x002F`).
    pub iana_code: u16,
    /// TLS version the probe targeted. Each suite may be probed at multiple
    /// versions; those appear as separate result entries.
    pub version: TlsVersion,
    pub outcome: HandshakeOutcome,
    /// Populated by [`crate::scanner::openssl::dh_params::snapshot`] for any
    /// handshake whose server `tmp_key` is DH (i.e. DHE-RSA suites). `None`
    /// for RSA-kex, ECDHE, and failed handshakes.
    pub dh_snapshot: Option<DhSnapshot>,
    /// Populated by [`super::ske_sig::snapshot`] — the server's chosen
    /// TLS 1.2 ServerKeyExchange (or TLS 1.3 CertificateVerify)
    /// signature algorithm name.
    pub ske_sig: Option<String>,
    /// Parsed peer certificate chain observed during this particular
    /// per-cipher handshake. Empty when the handshake failed or the
    /// chain could not be parsed.
    pub cert_chain: Vec<CertificateInfo>,
    /// Leaf certificate SHA-256 fingerprint for joining this per-cipher
    /// observation back to the exact certificate chain the server chose.
    pub leaf_fingerprint_sha256: Option<String>,
    /// SHA-256 over concatenated DER certificates in the observed chain.
    pub chain_fingerprint_sha256: Option<String>,
    /// Ephemeral group observed in the handshake, when OpenSSL exposes it.
    pub group: Option<String>,
}

/// Aggregate output of the legacy cipher probe pass.
#[derive(Debug, Clone, Default)]
pub struct LegacyCipherProbeOutput {
    pub results: Vec<LegacyCipherResult>,
}

/// Static target-list row. Keeps allocations zero for the common case.
struct Target {
    iana_name: &'static str,
    openssl_name: &'static str,
    iana_code: u16,
    version: TlsVersion,
}

/// Hardcoded target list. Each row is one probe; the same suite at multiple
/// TLS versions is split into multiple rows so per-version server behavior
/// is observable. Source of OpenSSL short names: `openssl ciphers -V`.
const TARGETS: &[Target] = &[
    // --- TLS 1.2 ---
    // RSA key-exchange family (Logjam / ROBOT exposure surface)
    Target {
        iana_name: "TLS_RSA_WITH_AES_128_CBC_SHA",
        openssl_name: "AES128-SHA",
        iana_code: 0x002F,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_RSA_WITH_AES_256_CBC_SHA",
        openssl_name: "AES256-SHA",
        iana_code: 0x0035,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_RSA_WITH_AES_128_CBC_SHA256",
        openssl_name: "AES128-SHA256",
        iana_code: 0x003C,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_RSA_WITH_AES_256_CBC_SHA256",
        openssl_name: "AES256-SHA256",
        iana_code: 0x003D,
        version: TlsVersion::Tls12,
    },
    // Obsolete primitives
    Target {
        iana_name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        openssl_name: "DES-CBC3-SHA",
        iana_code: 0x000A,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_RSA_WITH_RC4_128_SHA",
        openssl_name: "RC4-SHA",
        iana_code: 0x0005,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_RSA_WITH_RC4_128_MD5",
        openssl_name: "RC4-MD5",
        iana_code: 0x0004,
        version: TlsVersion::Tls12,
    },
    // NULL ciphers (no encryption — should always be rejected)
    Target {
        iana_name: "TLS_RSA_WITH_NULL_SHA",
        openssl_name: "NULL-SHA",
        iana_code: 0x0002,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_RSA_WITH_NULL_MD5",
        openssl_name: "NULL-MD5",
        iana_code: 0x0001,
        version: TlsVersion::Tls12,
    },
    // Anonymous DH (no server auth)
    Target {
        iana_name: "TLS_DH_anon_WITH_AES_128_CBC_SHA",
        openssl_name: "ADH-AES128-SHA",
        iana_code: 0x0034,
        version: TlsVersion::Tls12,
    },
    // DHE-RSA — gates the DH-parameter observer + SKE signature observer
    Target {
        iana_name: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        openssl_name: "DHE-RSA-AES128-SHA",
        iana_code: 0x0033,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        openssl_name: "DHE-RSA-AES256-SHA",
        iana_code: 0x0039,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        openssl_name: "DHE-RSA-AES128-SHA256",
        iana_code: 0x0067,
        version: TlsVersion::Tls12,
    },
    // --- DHE-RSA AEAD (FFDHE forward-secret GCM, RFC 5288) ---
    // Required for some FIPS profiles that mandate FFDHE + AEAD. The
    // CBC-mode DHE-RSA probes above exercise the same key-exchange
    // path but not the AEAD record layer.
    Target {
        iana_name: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        openssl_name: "DHE-RSA-AES128-GCM-SHA256",
        iana_code: 0x009E,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        openssl_name: "DHE-RSA-AES256-GCM-SHA384",
        iana_code: 0x009F,
        version: TlsVersion::Tls12,
    },
    // --- ECDHE CBC-mode (RFC 4492 + RFC 5289) ---
    // Forward-secret but CBC record layer; 800-52r2 §3.3.1.1 still
    // lists some of these, deployments supporting legacy clients
    // continue to offer them. Closes the `EcdheCbc` classification
    // gap — without these rows, a rule engine checking
    // "no CBC in TLS 1.2" can't see them as `supported: true/false`,
    // only as `not_probed`.
    Target {
        iana_name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        openssl_name: "ECDHE-RSA-AES128-SHA",
        iana_code: 0xC013,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        openssl_name: "ECDHE-RSA-AES256-SHA",
        iana_code: 0xC014,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        openssl_name: "ECDHE-RSA-AES128-SHA256",
        iana_code: 0xC027,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        openssl_name: "ECDHE-RSA-AES256-SHA384",
        iana_code: 0xC028,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        openssl_name: "ECDHE-ECDSA-AES128-SHA",
        iana_code: 0xC009,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        openssl_name: "ECDHE-ECDSA-AES256-SHA",
        iana_code: 0xC00A,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        openssl_name: "ECDHE-ECDSA-AES128-SHA256",
        iana_code: 0xC023,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        openssl_name: "ECDHE-ECDSA-AES256-SHA384",
        iana_code: 0xC024,
        version: TlsVersion::Tls12,
    },
    // --- AES-CCM (RFC 6655 + RFC 7251) ---
    // IoT / constrained-device profiles (RFC 7925) mandate AES-CCM.
    // OpenSSL 3.x ships CCM in the default provider; if `openssl-src`
    // is rebuilt with `no-camellia no-seed` the CCM entries stay,
    // only the earlier two families are affected.
    Target {
        iana_name: "TLS_RSA_WITH_AES_128_CCM",
        openssl_name: "AES128-CCM",
        iana_code: 0xC09C,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_RSA_WITH_AES_256_CCM",
        openssl_name: "AES256-CCM",
        iana_code: 0xC09D,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_RSA_WITH_AES_128_CCM_8",
        openssl_name: "AES128-CCM8",
        iana_code: 0xC0A0,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_RSA_WITH_AES_256_CCM_8",
        openssl_name: "AES256-CCM8",
        iana_code: 0xC0A1,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_DHE_RSA_WITH_AES_128_CCM",
        openssl_name: "DHE-RSA-AES128-CCM",
        iana_code: 0xC09E,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_DHE_RSA_WITH_AES_256_CCM",
        openssl_name: "DHE-RSA-AES256-CCM",
        iana_code: 0xC09F,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_DHE_RSA_WITH_AES_128_CCM_8",
        openssl_name: "DHE-RSA-AES128-CCM8",
        iana_code: 0xC0A2,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_DHE_RSA_WITH_AES_256_CCM_8",
        openssl_name: "DHE-RSA-AES256-CCM8",
        iana_code: 0xC0A3,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
        openssl_name: "ECDHE-ECDSA-AES128-CCM",
        iana_code: 0xC0AC,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
        openssl_name: "ECDHE-ECDSA-AES256-CCM",
        iana_code: 0xC0AD,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
        openssl_name: "ECDHE-ECDSA-AES128-CCM8",
        iana_code: 0xC0AE,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
        openssl_name: "ECDHE-ECDSA-AES256-CCM8",
        iana_code: 0xC0AF,
        version: TlsVersion::Tls12,
    },
    // --- PSK family ---
    // Without a pre-shared secret the scanner can't complete a PSK
    // handshake. On most servers these probes alert
    // unknown_psk_identity or handshake_failure, classified as
    // `supported: false`. Real `supported: true` is rare outside
    // closed ecosystems. The observation still has signal: an alert
    // specifically tied to PSK means the server parsed the PSK cipher
    // offer, even if it couldn't authenticate it.
    Target {
        iana_name: "TLS_PSK_WITH_AES_128_CBC_SHA",
        openssl_name: "PSK-AES128-CBC-SHA",
        iana_code: 0x008C,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_PSK_WITH_AES_128_GCM_SHA256",
        openssl_name: "PSK-AES128-GCM-SHA256",
        iana_code: 0x00A8,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
        openssl_name: "DHE-PSK-AES128-GCM-SHA256",
        iana_code: 0x00AA,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
        openssl_name: "ECDHE-PSK-AES128-CBC-SHA",
        iana_code: 0xC035,
        version: TlsVersion::Tls12,
    },
    // --- Camellia ---
    Target {
        iana_name: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
        openssl_name: "CAMELLIA128-SHA",
        iana_code: 0x0041,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
        openssl_name: "CAMELLIA256-SHA",
        iana_code: 0x0084,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
        openssl_name: "DHE-RSA-CAMELLIA128-SHA",
        iana_code: 0x0045,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
        openssl_name: "ECDHE-RSA-CAMELLIA128-SHA256",
        iana_code: 0xC076,
        version: TlsVersion::Tls12,
    },
    // --- SEED ---
    Target {
        iana_name: "TLS_RSA_WITH_SEED_CBC_SHA",
        openssl_name: "SEED-SHA",
        iana_code: 0x0096,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
        openssl_name: "DHE-RSA-SEED-SHA",
        iana_code: 0x009A,
        version: TlsVersion::Tls12,
    },
    // --- ARIA ---
    Target {
        iana_name: "TLS_RSA_WITH_ARIA_128_GCM_SHA256",
        openssl_name: "ARIA128-GCM-SHA256",
        iana_code: 0xC050,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_RSA_WITH_ARIA_256_GCM_SHA384",
        openssl_name: "ARIA256-GCM-SHA384",
        iana_code: 0xC051,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",
        openssl_name: "DHE-RSA-ARIA128-GCM-SHA256",
        iana_code: 0xC052,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
        // OpenSSL 3.x collapsed the RSA-signature qualifier on ARIA
        // ECDHE suites; the accepted name is `ECDHE-ARIA128-GCM-SHA256`
        // without the `-RSA-` segment. IANA codepoint 0xC060 is still
        // the RSA-authenticated variant.
        openssl_name: "ECDHE-ARIA128-GCM-SHA256",
        iana_code: 0xC060,
        version: TlsVersion::Tls12,
    },
    // --- Static DH / static ECDH ---
    // Require the server's CERTIFICATE to embed a DH/ECDH public key
    // (not the common ephemeral-DH + signed-cert pattern). Modern CAs
    // don't issue those certs, so real-world `supported: true` is
    // effectively zero. Probes exist for completeness.
    Target {
        iana_name: "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
        openssl_name: "DH-RSA-AES128-SHA",
        iana_code: 0x0031,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
        openssl_name: "DH-DSS-AES128-SHA",
        iana_code: 0x0030,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
        openssl_name: "ECDH-RSA-AES128-SHA",
        iana_code: 0xC00E,
        version: TlsVersion::Tls12,
    },
    Target {
        iana_name: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
        openssl_name: "ECDH-ECDSA-AES128-SHA",
        iana_code: 0xC004,
        version: TlsVersion::Tls12,
    },
    // --- TLS 1.1 ---
    Target {
        iana_name: "TLS_RSA_WITH_AES_128_CBC_SHA",
        openssl_name: "AES128-SHA",
        iana_code: 0x002F,
        version: TlsVersion::Tls11,
    },
    Target {
        iana_name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        openssl_name: "DES-CBC3-SHA",
        iana_code: 0x000A,
        version: TlsVersion::Tls11,
    },
    Target {
        iana_name: "TLS_RSA_WITH_RC4_128_SHA",
        openssl_name: "RC4-SHA",
        iana_code: 0x0005,
        version: TlsVersion::Tls11,
    },
    // --- TLS 1.0 ---
    Target {
        iana_name: "TLS_RSA_WITH_AES_128_CBC_SHA",
        openssl_name: "AES128-SHA",
        iana_code: 0x002F,
        version: TlsVersion::Tls10,
    },
    Target {
        iana_name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        openssl_name: "DES-CBC3-SHA",
        iana_code: 0x000A,
        version: TlsVersion::Tls10,
    },
    Target {
        iana_name: "TLS_RSA_WITH_RC4_128_SHA",
        openssl_name: "RC4-SHA",
        iana_code: 0x0005,
        version: TlsVersion::Tls10,
    },
    // --- SSL 3.0 per-cipher probes ---
    // Version-level SSL3 probing lands in `protocol_versions.rs`; these
    // entries add per-suite visibility so rule engines can distinguish
    // "server rejects SSL3 entirely" from "server accepts SSL3 but
    // negotiates CBC (POODLE-vulnerable cipher class)." Same driver as
    // the TLS 1.0/1.1 rows — `probe_single_suite_blocking` passes
    // `SslVersion::SSL3` through via `tls_version_to_ossl`, and the
    // seclevel=0 + legacy-provider setup already applied to TLS 1.0
    // handshakes covers these codepoints too.
    Target {
        iana_name: "TLS_RSA_WITH_AES_128_CBC_SHA",
        openssl_name: "AES128-SHA",
        iana_code: 0x002F,
        version: TlsVersion::Ssl3,
    },
    Target {
        iana_name: "TLS_RSA_WITH_AES_256_CBC_SHA",
        openssl_name: "AES256-SHA",
        iana_code: 0x0035,
        version: TlsVersion::Ssl3,
    },
    Target {
        iana_name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        openssl_name: "DES-CBC3-SHA",
        iana_code: 0x000A,
        version: TlsVersion::Ssl3,
    },
    Target {
        iana_name: "TLS_RSA_WITH_RC4_128_SHA",
        openssl_name: "RC4-SHA",
        iana_code: 0x0005,
        version: TlsVersion::Ssl3,
    },
    Target {
        iana_name: "TLS_RSA_WITH_RC4_128_MD5",
        openssl_name: "RC4-MD5",
        iana_code: 0x0004,
        version: TlsVersion::Ssl3,
    },
    Target {
        iana_name: "TLS_RSA_WITH_DES_CBC_SHA",
        openssl_name: "DES-CBC-SHA",
        iana_code: 0x0009,
        version: TlsVersion::Ssl3,
    },
    Target {
        iana_name: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
        openssl_name: "EXP-RC4-MD5",
        iana_code: 0x0003,
        version: TlsVersion::Ssl3,
    },
    Target {
        iana_name: "TLS_NULL_WITH_NULL_NULL",
        openssl_name: "NULL-MD5",
        iana_code: 0x0001,
        version: TlsVersion::Ssl3,
    },
];

/// Emit this backend's cipher inventory as `(iana_code, iana_name, version)`
/// rows. Used by `scanner::backends::openssl_inventory` so the single
/// source of truth for "what does the OpenSSL backend probe" is
/// this `TARGETS` table rather than a parallel hand-maintained list.
pub fn inventory_entries() -> Vec<(u16, &'static str, TlsVersion)> {
    TARGETS
        .iter()
        .map(|t| (t.iana_code, t.iana_name, t.version))
        .collect()
}

/// Probe a single cipher identified by `(iana_code, version)`. Thin
/// wrapper over `probe_single_suite_blocking` that looks up the
/// matching `TARGETS` row and runs the probe on a `spawn_blocking`
/// thread. Returns a `ProbeRun` with `HandshakeOutcome::Error` when no
/// row matches — a programmer error on the caller's part since
/// `inventory_entries()` and this function read the same table.
///
/// Special-case: the four static-DH/ECDH cipher suites OpenSSL 3.x
/// removed entirely (0x0030, 0x0031, 0xC004, 0xC00E) route to
/// `raw::static_dh` instead. OpenSSL can't drive them at all, but a
/// raw-socket ClientHello can — we just need to send one codepoint
/// and classify the response.
pub(crate) async fn probe_single_by_code(
    target: SocketAddr,
    hostname: &str,
    iana_code: u16,
    version: TlsVersion,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> ProbeRun {
    if matches!(iana_code, 0x0030 | 0x0031 | 0xC004 | 0xC00E) {
        let outcome = crate::scanner::raw::static_dh::probe(
            target,
            hostname,
            iana_code,
            connect_timeout,
            handshake_timeout,
        )
        .await;
        return ProbeRun {
            outcome,
            dh_snapshot: None,
            ske_sig: None,
            cert_chain: Vec::new(),
            leaf_fingerprint_sha256: None,
            chain_fingerprint_sha256: None,
            group: None,
        };
    }

    let Some(row) = TARGETS
        .iter()
        .find(|t| t.iana_code == iana_code && t.version == version)
    else {
        return ProbeRun {
            outcome: HandshakeOutcome::Error(format!(
                "openssl_unknown_target:0x{:04X}:{:?}",
                iana_code, version
            )),
            dh_snapshot: None,
            ske_sig: None,
            cert_chain: Vec::new(),
            leaf_fingerprint_sha256: None,
            chain_fingerprint_sha256: None,
            group: None,
        };
    };
    let hostname_owned = hostname.to_string();
    let openssl_name = row.openssl_name.to_string();
    let version_copy = row.version;

    tokio::task::spawn_blocking(move || {
        probe_single_suite_blocking(
            target,
            &hostname_owned,
            &openssl_name,
            version_copy,
            connect_timeout,
            handshake_timeout,
        )
    })
    .await
    .unwrap_or_else(|join_err| ProbeRun {
        outcome: HandshakeOutcome::Error(format!("spawn_blocking_panic: {join_err}")),
        dh_snapshot: None,
        ske_sig: None,
        cert_chain: Vec::new(),
        leaf_fingerprint_sha256: None,
        chain_fingerprint_sha256: None,
        group: None,
    })
}

/// Probe every suite in [`TARGETS`]. Each probe runs in `spawn_blocking` so
/// the blocking OpenSSL handshake doesn't park a tokio worker thread.
/// Honors `per_probe_delay` between consecutive probes.
pub async fn probe_legacy_suites(
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    per_probe_delay: Duration,
) -> LegacyCipherProbeOutput {
    info!(
        "OpenSSL legacy cipher probe: {} suites across TLS 1.0/1.1/1.2",
        TARGETS.len()
    );

    let mut results = Vec::with_capacity(TARGETS.len());
    let last = TARGETS.len().saturating_sub(1);

    for (i, t) in TARGETS.iter().enumerate() {
        let run = probe_single_by_code(
            target,
            hostname,
            t.iana_code,
            t.version,
            connect_timeout,
            handshake_timeout,
        )
        .await;

        debug!(
            suite = %t.openssl_name,
            version = ?t.version,
            outcome = ?run.outcome,
            dh_captured = run.dh_snapshot.is_some(),
            ske_sig = ?run.ske_sig,
            "legacy probe result"
        );

        results.push(LegacyCipherResult {
            name: t.iana_name.to_string(),
            openssl_name: t.openssl_name.to_string(),
            iana_code: t.iana_code,
            version: t.version,
            outcome: run.outcome,
            dh_snapshot: run.dh_snapshot,
            ske_sig: run.ske_sig,
            cert_chain: run.cert_chain,
            leaf_fingerprint_sha256: run.leaf_fingerprint_sha256,
            chain_fingerprint_sha256: run.chain_fingerprint_sha256,
            group: run.group,
        });

        if i < last && !per_probe_delay.is_zero() {
            tokio::time::sleep(per_probe_delay).await;
        }
    }

    LegacyCipherProbeOutput { results }
}

/// Internal return value of [`probe_single_suite_blocking`] — outcome plus
/// any post-handshake observations (DH parameter snapshot, SKE signature).
/// Exposed pub(crate) so `backends::openssl` can surface the observer
/// fields through `HandshakeResult`.
pub(crate) struct ProbeRun {
    pub(crate) outcome: HandshakeOutcome,
    pub(crate) dh_snapshot: Option<DhSnapshot>,
    pub(crate) ske_sig: Option<String>,
    pub(crate) cert_chain: Vec<CertificateInfo>,
    pub(crate) leaf_fingerprint_sha256: Option<String>,
    pub(crate) chain_fingerprint_sha256: Option<String>,
    pub(crate) group: Option<String>,
}

/// Synchronous single-suite probe. Called inside `spawn_blocking`. Never
/// panics, never returns Err; failure categories fold into
/// `HandshakeOutcome::Error`. On handshake success, also observes DH
/// parameters if the server's tmp key is DH.
fn probe_single_suite_blocking(
    target: SocketAddr,
    hostname: &str,
    openssl_cipher_name: &str,
    version: TlsVersion,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> ProbeRun {
    let Some(ossl_version) = tls_version_to_ossl(version) else {
        return ProbeRun {
            outcome: HandshakeOutcome::Error(format!(
                "unsupported_tls_version_for_openssl:{version:?}"
            )),
            dh_snapshot: None,
            ske_sig: None,
            cert_chain: Vec::new(),
            leaf_fingerprint_sha256: None,
            chain_fingerprint_sha256: None,
            group: None,
        };
    };

    // TCP connect under connect_timeout. `connect_timeout` enforces
    // the SYN deadline; after that the socket read/write timeouts bound
    // the handshake phase.
    let tcp = match std::net::TcpStream::connect_timeout(&target, connect_timeout) {
        Ok(s) => s,
        Err(e) => {
            let se = ScannerError::from_io("openssl tcp connect", e);
            return ProbeRun {
                outcome: classify_scanner_error(se),
                dh_snapshot: None,
                ske_sig: None,
                cert_chain: Vec::new(),
                leaf_fingerprint_sha256: None,
                chain_fingerprint_sha256: None,
                group: None,
            };
        }
    };
    let _ = tcp.set_read_timeout(Some(handshake_timeout));
    let _ = tcp.set_write_timeout(Some(handshake_timeout));

    let ctx = match build_legacy_context(ossl_version, openssl_cipher_name) {
        Ok(c) => c,
        Err(stack) => {
            // `no cipher match` from `SSL_CTX_set_cipher_list` means
            // the cipher name isn't in the vendored OpenSSL 3.x build
            // at all — static-DH/ECDH suites (0x0030, 0x0031, 0xC004,
            // 0xC00E) were removed upstream, other suites may need
            // additional openssl-src features. Surface these as
            // `NotProbed` with a deterministic reason rather than an
            // Error, because the scanner cannot generate any
            // server-side signal — it never gets as far as sending a
            // ClientHello. Other build errors (misconfigured SSL_CTX
            // flags, provider load issues) still map to Error.
            let stack_str = stack.to_string();
            let outcome = if stack_str.contains("no cipher match") {
                HandshakeOutcome::NotProbed(format!(
                    "openssl_3x_cipher_not_available:{openssl_cipher_name}"
                ))
            } else {
                HandshakeOutcome::Error(format!("openssl_ctx_build: {stack}"))
            };
            return ProbeRun {
                outcome,
                dh_snapshot: None,
                ske_sig: None,
                cert_chain: Vec::new(),
                leaf_fingerprint_sha256: None,
                chain_fingerprint_sha256: None,
                group: None,
            };
        }
    };

    let mut ssl = match Ssl::new(&ctx) {
        Ok(s) => s,
        Err(stack) => {
            return ProbeRun {
                outcome: HandshakeOutcome::Error(format!("openssl_ssl_new: {stack}")),
                dh_snapshot: None,
                ske_sig: None,
                cert_chain: Vec::new(),
                leaf_fingerprint_sha256: None,
                chain_fingerprint_sha256: None,
                group: None,
            }
        }
    };
    // Best-effort SNI; failure here is unlikely and non-fatal.
    let _ = ssl.set_hostname(hostname);

    match ssl.connect(tcp) {
        Ok(stream) => {
            // Handshake completed. Observe DH parameters and the server's
            // signature algorithm. Both return None for handshakes where
            // the observation doesn't apply (e.g. RSA-kex has no SKE
            // signature; ECDHE has no DH parameters). A snapshot-level
            // ErrorStack from the DH observer is swallowed — the
            // Supported outcome is the primary signal.
            let dh_snapshot = dh_params::snapshot(stream.ssl()).unwrap_or(None);
            let ske_sig = ske_sig::snapshot(stream.ssl());
            let cert_snapshot = cert_chain_observation(stream.ssl());
            let group = negotiated_group(stream.ssl(), dh_snapshot.as_ref());
            ProbeRun {
                outcome: HandshakeOutcome::Supported,
                dh_snapshot,
                ske_sig,
                cert_chain: cert_snapshot.cert_chain,
                leaf_fingerprint_sha256: cert_snapshot.leaf_fingerprint_sha256,
                chain_fingerprint_sha256: cert_snapshot.chain_fingerprint_sha256,
                group,
            }
        }
        Err(HandshakeError::Failure(mid)) => {
            let se = alerts::classify_openssl_error("openssl handshake", mid.error());
            ProbeRun {
                outcome: classify_scanner_error(se),
                dh_snapshot: None,
                ske_sig: None,
                cert_chain: Vec::new(),
                leaf_fingerprint_sha256: None,
                chain_fingerprint_sha256: None,
                group: None,
            }
        }
        Err(HandshakeError::SetupFailure(stack)) => ProbeRun {
            outcome: HandshakeOutcome::Error(format!("openssl_setup: {stack}")),
            dh_snapshot: None,
            ske_sig: None,
            cert_chain: Vec::new(),
            leaf_fingerprint_sha256: None,
            chain_fingerprint_sha256: None,
            group: None,
        },
        Err(HandshakeError::WouldBlock(_)) => {
            // Shouldn't happen with blocking socket + set_*_timeout; if it
            // does, record as Error so the anomaly surfaces rather than
            // masquerading as NotSupported.
            ProbeRun {
                outcome: HandshakeOutcome::Error("openssl_would_block".to_string()),
                dh_snapshot: None,
                ske_sig: None,
                cert_chain: Vec::new(),
                leaf_fingerprint_sha256: None,
                chain_fingerprint_sha256: None,
                group: None,
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
struct CertChainSnapshot {
    cert_chain: Vec<CertificateInfo>,
    leaf_fingerprint_sha256: Option<String>,
    chain_fingerprint_sha256: Option<String>,
}

fn cert_chain_observation(ssl: &SslRef) -> CertChainSnapshot {
    let mut raw_chain = Vec::new();
    if let Some(cert) = ssl.peer_certificate() {
        if let Ok(der) = cert.to_der() {
            raw_chain.push(der);
        }
    }
    if let Some(chain) = ssl.peer_cert_chain() {
        for cert in chain {
            if let Ok(der) = cert.to_der() {
                if raw_chain.first() != Some(&der) {
                    raw_chain.push(der);
                }
            }
        }
    }

    let cert_chain: Vec<CertificateInfo> = raw_chain
        .iter()
        .enumerate()
        .filter_map(|(i, der)| {
            CertificateInfo::from_der(der).ok().map(|mut c| {
                c.wire_position = i as u32;
                c
            })
        })
        .collect();
    let leaf_fingerprint_sha256 = cert_chain
        .first()
        .map(|c| c.fingerprint_sha256.clone())
        .or_else(|| raw_chain.first().map(|der| fingerprint_der(der)));
    let chain_fingerprint_sha256 = (!raw_chain.is_empty()).then(|| fingerprint_chain(&raw_chain));

    CertChainSnapshot {
        cert_chain,
        leaf_fingerprint_sha256,
        chain_fingerprint_sha256,
    }
}

fn fingerprint_der(der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(der);
    hex::encode(hasher.finalize())
}

fn fingerprint_chain(raw_chain: &[Vec<u8>]) -> String {
    let mut hasher = Sha256::new();
    for der in raw_chain {
        hasher.update(der);
    }
    hex::encode(hasher.finalize())
}

fn negotiated_group(ssl: &SslRef, dh_snapshot: Option<&DhSnapshot>) -> Option<String> {
    if let Some(snapshot) = dh_snapshot {
        return Some(snapshot.classification.as_schema_str().to_string());
    }
    let pkey = ssl.peer_tmp_key().ok()?;
    match pkey.id() {
        Id::EC => {
            let ec = pkey.ec_key().ok()?;
            ec.group()
                .curve_name()
                .and_then(|nid| nid.short_name().ok().map(str::to_string))
        }
        Id::X25519 => Some("X25519".to_string()),
        Id::X448 => Some("X448".to_string()),
        _ => None,
    }
}

/// Build a single-suite `SslContext` pinned to one TLS version. Mirrors the
/// plan's §5 constraints: seclevel 0, verify NONE, one cipher.
fn build_legacy_context(
    ossl_version: SslVersion,
    cipher_list: &str,
) -> Result<SslContext, openssl::error::ErrorStack> {
    let mut builder = SslContext::builder(SslMethod::tls_client())?;
    builder.set_min_proto_version(Some(ossl_version))?;
    builder.set_max_proto_version(Some(ossl_version))?;
    builder.set_security_level(0);
    // `@SECLEVEL=0` in the cipher STRING is load-bearing in addition to
    // `set_security_level(0)` on the SSL_CTX. The cipher-list parser
    // applies its own seclevel filter based on the string; without the
    // `@SECLEVEL=0` prefix, OpenSSL 3.x uses the default SECLEVEL (2),
    // which excludes RC4, single-DES, and other <80-bit-security
    // primitives even with the legacy provider loaded — causing
    // `set_cipher_list` to return "no cipher match" before any handshake
    // is attempted.
    builder.set_cipher_list(&format!("{}:@SECLEVEL=0", cipher_list))?;
    builder.set_verify(SslVerifyMode::NONE);
    // Dummy PSK client callback. Without this, OpenSSL refuses to
    // construct a ClientHello for PSK-family cipher suites because it
    // has no identity/key to put in the `pre_shared_key` extension —
    // the handshake fails client-side before any bytes leave the
    // socket, surfacing as `internal_scanner_error` with no context.
    // Installing a bogus identity/key lets the ClientHello go out;
    // real servers reply with `unknown_psk_identity` (alert 115) or
    // `handshake_failure` (alert 40), which the classifier maps to
    // `NotSupported` — the observation we actually want from a PSK
    // probe against an unknown-secret target.
    //
    // The callback runs only when a PSK-family suite is selected; it
    // never fires for non-PSK probes.
    builder.set_psk_client_callback(|_ssl, _hint, identity_out, psk_out| {
        let identity = b"kemist-probe";
        let psk = [0u8; 32];
        if identity_out.len() < identity.len() + 1 || psk_out.len() < psk.len() {
            // Buffer too small — return a zero-length PSK, OpenSSL
            // then aborts with SSL_R_PSK_IDENTITY_NOT_FOUND. Handshake
            // still fails cleanly.
            return Ok(0);
        }
        identity_out[..identity.len()].copy_from_slice(identity);
        identity_out[identity.len()] = 0;
        psk_out[..psk.len()].copy_from_slice(&psk);
        Ok(psk.len())
    });
    Ok(builder.build())
}

/// Project our TLS version enum onto OpenSSL's constants. SSLv2 has no
/// OpenSSL 3.x representation (the protocol was dropped entirely); SSLv3
/// resolves but requires the legacy provider and seclevel 0 —
/// `protocol_versions.rs` handles the SSLv3 pathway explicitly, this
/// probe restricts itself to TLS 1.0+.
fn tls_version_to_ossl(v: TlsVersion) -> Option<SslVersion> {
    match v {
        TlsVersion::Tls10 => Some(SslVersion::TLS1),
        TlsVersion::Tls11 => Some(SslVersion::TLS1_1),
        TlsVersion::Tls12 => Some(SslVersion::TLS1_2),
        TlsVersion::Tls13 => Some(SslVersion::TLS1_3),
        TlsVersion::Ssl3 => Some(SslVersion::SSL3),
        TlsVersion::Ssl2 => None,
    }
}

/// Fold a [`ScannerError`] into the probe-outcome shape.
///
/// Uses the shared `is_wire_rejection` predicate. This (OpenSSL) path
/// emits the `category` only in Error; the rustls-path `classify_probe_error`
/// includes both category and context — schema v1 depends on that asymmetry.
fn classify_scanner_error(e: ScannerError) -> HandshakeOutcome {
    if is_wire_rejection(&e) {
        HandshakeOutcome::NotSupported
    } else {
        HandshakeOutcome::Error(e.category)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_table_iana_codes_are_unique_per_version() {
        // Duplicate (iana_code, version) pairs would double-probe the same
        // cell and produce ambiguous output. Enforce uniqueness.
        use std::collections::HashSet;
        let mut seen: HashSet<(u16, TlsVersion)> = HashSet::new();
        for t in TARGETS {
            let key = (t.iana_code, t.version);
            assert!(
                seen.insert(key),
                "duplicate target ({:#06x}, {:?})",
                t.iana_code,
                t.version
            );
        }
    }

    #[test]
    fn target_table_restricts_versions_to_ssl3_through_tls12() {
        // This probe's scope is SSL 3.0 / TLS 1.0 / TLS 1.1 / TLS 1.2.
        // SSLv2 is handled by the raw-socket probe in `raw/sslv2.rs`;
        // TLS 1.3 has no legacy-cipher observables that OpenSSL adds
        // over aws-lc-rs.
        for t in TARGETS {
            assert!(
                matches!(
                    t.version,
                    TlsVersion::Ssl3 | TlsVersion::Tls10 | TlsVersion::Tls11 | TlsVersion::Tls12
                ),
                "target {} has out-of-scope version {:?}",
                t.iana_name,
                t.version
            );
        }
    }

    #[test]
    fn target_table_names_use_iana_prefix_convention() {
        for t in TARGETS {
            assert!(
                t.iana_name.starts_with("TLS_"),
                "target {} missing TLS_ prefix",
                t.iana_name
            );
            assert!(
                !t.openssl_name.is_empty(),
                "target {} has empty openssl name",
                t.iana_name
            );
        }
    }

    #[test]
    fn tls_version_mapping_covers_every_target() {
        for t in TARGETS {
            assert!(
                tls_version_to_ossl(t.version).is_some(),
                "target {} version {:?} has no OpenSSL mapping",
                t.iana_name,
                t.version
            );
        }
    }

    #[test]
    fn classify_scanner_error_promotes_alerts_and_refused_to_not_supported() {
        // Alerts are server signals — NotSupported.
        let alert = ScannerError::tls_alert("handshake_failure", "ctx");
        assert!(matches!(
            classify_scanner_error(alert),
            HandshakeOutcome::NotSupported
        ));

        // connection_refused at TCP level is a real refusal, but some
        // servers reset post-ClientHello without sending an alert — the
        // cipher is effectively NotSupported. Parity with rustls path.
        let refused = ScannerError::connection_refused("ctx");
        assert!(matches!(
            classify_scanner_error(refused),
            HandshakeOutcome::NotSupported
        ));
    }

    #[test]
    fn classify_scanner_error_preserves_other_categories_as_error() {
        let timeout = ScannerError::connection_timeout("ctx");
        match classify_scanner_error(timeout) {
            HandshakeOutcome::Error(cat) => assert_eq!(cat, "connection_timeout"),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn target_table_includes_every_required_category() {
        let has = |needle: &str| {
            TARGETS
                .iter()
                .any(|t| t.openssl_name.contains(needle) || t.iana_name.contains(needle))
        };
        assert!(has("RC4"), "RC4 family missing from target table");
        assert!(has("3DES") || has("DES-CBC3"), "3DES missing");
        assert!(has("NULL"), "NULL ciphers missing");
        assert!(has("ADH"), "anon-DH missing");
        assert!(
            has("DHE-RSA"),
            "DHE-RSA missing — DH parameter observer won't fire"
        );
    }
}
