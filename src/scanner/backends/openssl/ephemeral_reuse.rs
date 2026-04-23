//! Ephemeral DH / ECDH key reuse observation.
//!
//! Runs two sequential TLS 1.2 handshakes against a DHE suite and
//! two against an ECDHE suite, capturing the server's ephemeral
//! public value each time (DH public `Y`; ECDH point bytes). Hashes
//! each public value with SHA-256 and compares the two hashes within
//! a family. A byte-for-byte match across two fresh handshakes is the
//! observable signal that the server reuses its ephemeral key —
//! relevant for Raccoon (CVE-2020-1968) and similar side-channel
//! exposure assessments.
//!
//! The scanner **records the comparison result**; it does not render
//! a verdict. Downstream rule engines interpret.
//!
//! ## Gate
//!
//! The probe reads the earlier cipher-probe results and picks the
//! first observed-supported suite per family (DHE, ECDHE). When no
//! suite is supported in a family, that family's slot lands as
//! `method: not_probed` with `reason: "no_*_suite_supported"`. The
//! outer observation still emits with the other family populated.
//!
//! ## Non-goals
//!
//! - No comparison to a historical reuse window; observation is
//!   per-scan, two connections.
//! - No analysis of the DH group itself; the `tls.dh_parameters`
//!   observation covers that separately.
//! - No attempt at the Raccoon side-channel itself; ephemeral reuse
//!   is the prerequisite signal, not the exploit.

use std::net::SocketAddr;
use std::os::raw::c_int;
use std::time::Duration;

use foreign_types::ForeignTypeRef;
use openssl::bn::BigNumContext;
use openssl::ec::PointConversionForm;
use openssl::pkey::Id;
use openssl::ssl::{HandshakeError, Ssl, SslContext, SslMethod, SslRef, SslVerifyMode, SslVersion};
use sha2::{Digest, Sha256};
use tracing::{debug, info};

use crate::model::scan_result::{EphemeralKeyReuseObservation, ObservationBool};
use crate::scanner::openssl::ciphers::{LegacyCipherProbeOutput, LegacyCipherResult};
use crate::scanner::backends::HandshakeOutcome;

extern "C" {
    /// `DH_get0_key(*const DH, *mut *const BIGNUM pub_key, *mut *const BIGNUM priv_key)`.
    /// Handwritten binding is exposed by openssl-sys at this version;
    /// we call through the same external symbol.
    fn DH_get0_key(
        dh: *const openssl_sys::DH,
        pub_key: *mut *const openssl_sys::BIGNUM,
        priv_key: *mut *const openssl_sys::BIGNUM,
    );
    fn BN_num_bits(bn: *const openssl_sys::BIGNUM) -> c_int;
    fn BN_bn2bin(bn: *const openssl_sys::BIGNUM, to: *mut u8) -> c_int;
}

/// Which ephemeral KX family we're probing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Dhe,
    Ecdhe,
}

impl Family {
    /// OpenSSL cipher-list token that pins the handshake to a single
    /// AES-128-GCM-SHA256 suite for this family. We pick GCM because
    /// it's the broadest-compatible AEAD across modern TLS 1.2 stacks.
    fn openssl_suite_token(self) -> &'static str {
        match self {
            Family::Dhe => "DHE-RSA-AES128-GCM-SHA256",
            Family::Ecdhe => "ECDHE-RSA-AES128-GCM-SHA256",
        }
    }

    /// Canonical IANA name for the suite `openssl_suite_token` maps to.
    fn iana_suite_name(self) -> &'static str {
        match self {
            Family::Dhe => "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            Family::Ecdhe => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        }
    }

    /// IANA-name prefix that identifies suites in this family when we
    /// inspect earlier cipher-probe output for support.
    fn iana_prefix(self) -> &'static str {
        match self {
            Family::Dhe => "TLS_DHE_",
            Family::Ecdhe => "TLS_ECDHE_",
        }
    }
}

/// Orchestrate the probe. Always returns a populated
/// [`EphemeralKeyReuseObservation`] — one or both family slots may
/// be `not_probed` when the earlier cipher probe didn't observe a
/// supported suite in that family.
pub async fn probe(
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    cipher_probes: Option<&LegacyCipherProbeOutput>,
) -> EphemeralKeyReuseObservation {
    info!("OpenSSL ephemeral key reuse probe");

    let dhe_suite = pick_supported_suite(cipher_probes, Family::Dhe);
    let ecdhe_suite = pick_supported_suite(cipher_probes, Family::Ecdhe);

    let hostname_owned = hostname.to_string();
    let dhe = match dhe_suite {
        Some(_) => {
            let h = hostname_owned.clone();
            tokio::task::spawn_blocking(move || {
                probe_family_blocking(Family::Dhe, target, &h, connect_timeout, handshake_timeout)
            })
            .await
            .unwrap_or_else(|e| {
                debug!("ephemeral_reuse DHE spawn_blocking panic: {e}");
                ObservationBool::error(&format!("spawn_blocking_panic:{e}"))
            })
        }
        None => ObservationBool::not_probed("no_dhe_suite_supported"),
    };
    let ecdhe = match ecdhe_suite {
        Some(_) => {
            let h = hostname_owned.clone();
            tokio::task::spawn_blocking(move || {
                probe_family_blocking(
                    Family::Ecdhe,
                    target,
                    &h,
                    connect_timeout,
                    handshake_timeout,
                )
            })
            .await
            .unwrap_or_else(|e| {
                debug!("ephemeral_reuse ECDHE spawn_blocking panic: {e}");
                ObservationBool::error(&format!("spawn_blocking_panic:{e}"))
            })
        }
        None => ObservationBool::not_probed("no_ecdhe_suite_supported"),
    };

    EphemeralKeyReuseObservation {
        dhe_public_reused_across_connections: dhe,
        ecdhe_public_reused_across_connections: ecdhe,
        dhe_suite_probed: dhe_suite,
        ecdhe_suite_probed: ecdhe_suite,
    }
}

/// Select a suite observed at `HandshakeOutcome::Supported` for this
/// family. Prefer the canonical AES-128-GCM-SHA256 entry (so the
/// probe's actual cipher pin matches what we report as "probed"); fall
/// back to *any* supported suite in the family, still pinning to the
/// canonical one for the reuse handshakes — if the server advertises
/// the canonical one available, we'll land it; otherwise the
/// handshake fails and the observation renders `error`.
fn pick_supported_suite(
    cipher_probes: Option<&LegacyCipherProbeOutput>,
    family: Family,
) -> Option<String> {
    let list = cipher_probes?;
    let canonical = family.iana_suite_name();
    // Prefer exact canonical match.
    if list
        .results
        .iter()
        .any(|r| r.name == canonical && is_supported(r))
    {
        return Some(canonical.to_string());
    }
    // Otherwise: any supported suite in the family.
    list.results
        .iter()
        .find(|r| r.name.starts_with(family.iana_prefix()) && is_supported(r))
        .map(|r| r.name.clone())
}

fn is_supported(r: &LegacyCipherResult) -> bool {
    matches!(r.outcome, HandshakeOutcome::Supported)
}

fn probe_family_blocking(
    family: Family,
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> ObservationBool {
    let ctx = match build_context(family.openssl_suite_token()) {
        Ok(c) => c,
        Err(e) => return ObservationBool::error(&format!("ctx_build:{e}")),
    };

    let first =
        match single_handshake(&ctx, family, target, hostname, connect_timeout, handshake_timeout)
        {
            Ok(h) => h,
            Err(reason) => {
                return ObservationBool::not_probed(&format!("first_handshake:{reason}"))
            }
        };
    let second =
        match single_handshake(&ctx, family, target, hostname, connect_timeout, handshake_timeout)
        {
            Ok(h) => h,
            Err(reason) => {
                return ObservationBool::not_probed(&format!("second_handshake:{reason}"))
            }
        };

    ObservationBool::probe(first == second)
}

fn build_context(openssl_cipher: &str) -> Result<SslContext, openssl::error::ErrorStack> {
    let mut builder = SslContext::builder(SslMethod::tls_client())?;
    // Pin TLS 1.2. DHE-RSA-AES128-GCM-SHA256 + ECDHE-RSA-AES128-GCM-SHA256
    // are TLS 1.2 suites; TLS 1.3 would renegotiate ephemeral keys per
    // its own rules and is out of scope for the Raccoon-style signal.
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_security_level(0);
    builder.set_verify(SslVerifyMode::NONE);
    builder.set_cipher_list(openssl_cipher)?;
    // Explicitly disable session caching to force a full fresh
    // handshake on each connection. A resumed session would hide a
    // reused ephemeral key from the observation.
    builder.set_options(openssl::ssl::SslOptions::NO_TICKET);
    Ok(builder.build())
}

/// Run one handshake and capture the SHA-256 of the server's
/// ephemeral public value. Returns a 32-byte hash on success, a
/// short reason string on failure.
fn single_handshake(
    ctx: &SslContext,
    family: Family,
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> Result<[u8; 32], String> {
    let tcp = std::net::TcpStream::connect_timeout(&target, connect_timeout)
        .map_err(|e| format!("tcp_connect:{e}"))?;
    let _ = tcp.set_read_timeout(Some(handshake_timeout));
    let _ = tcp.set_write_timeout(Some(handshake_timeout));

    let mut ssl = Ssl::new(ctx).map_err(|e| format!("ssl_new:{e}"))?;
    let _ = ssl.set_hostname(hostname);

    let stream = match ssl.connect(tcp) {
        Ok(s) => s,
        Err(HandshakeError::Failure(mid)) => {
            return Err(format!("handshake_failure:{}", mid.error()))
        }
        Err(HandshakeError::SetupFailure(e)) => return Err(format!("setup_failure:{e}")),
        Err(HandshakeError::WouldBlock(_)) => return Err("would_block".to_string()),
    };

    let hash = extract_pub_hash(stream.ssl(), family)?;
    Ok(hash)
}

/// Pull the server's ephemeral public-value bytes from the completed
/// handshake and return their SHA-256. Returns an error string when
/// the peer tmp key isn't available or can't be serialized.
fn extract_pub_hash(ssl: &SslRef, family: Family) -> Result<[u8; 32], String> {
    let pkey = ssl
        .peer_tmp_key()
        .map_err(|_| "no_peer_tmp_key".to_string())?;

    let bytes = match family {
        Family::Dhe => {
            if pkey.id() != Id::DH {
                return Err(format!("peer_tmp_key_not_dh:id={:?}", pkey.id()));
            }
            let dh = pkey.dh().map_err(|e| format!("pkey.dh:{e}"))?;
            dh_pub_value_bytes(&dh)?
        }
        Family::Ecdhe => {
            if pkey.id() != Id::EC {
                return Err(format!("peer_tmp_key_not_ec:id={:?}", pkey.id()));
            }
            let ec = pkey.ec_key().map_err(|e| format!("pkey.ec_key:{e}"))?;
            let group = ec.group();
            let mut ctx = BigNumContext::new().map_err(|e| format!("bn_ctx:{e}"))?;
            ec.public_key()
                .to_bytes(group, PointConversionForm::UNCOMPRESSED, &mut ctx)
                .map_err(|e| format!("ec_point_to_bytes:{e}"))?
        }
    };

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hasher.finalize().into())
}

/// Extract the DH public value `Y` as big-endian bytes via FFI. The
/// openssl crate doesn't expose `DH_get0_key`; we descend through
/// `dh.as_ptr()` and call the openssl-sys binding directly.
fn dh_pub_value_bytes(dh: &openssl::dh::DhRef<openssl::pkey::Public>) -> Result<Vec<u8>, String> {
    unsafe {
        let mut pub_key: *const openssl_sys::BIGNUM = std::ptr::null();
        let mut _priv_key: *const openssl_sys::BIGNUM = std::ptr::null();
        DH_get0_key(dh.as_ptr(), &mut pub_key, &mut _priv_key);
        if pub_key.is_null() {
            return Err("dh_pub_key_null".to_string());
        }
        let bits = BN_num_bits(pub_key);
        if bits <= 0 {
            return Err("dh_pub_key_zero_bits".to_string());
        }
        let nbytes = ((bits as usize) + 7) / 8;
        let mut buf = vec![0u8; nbytes];
        let written = BN_bn2bin(pub_key, buf.as_mut_ptr());
        if written < 0 {
            return Err("bn_bn2bin_failed".to_string());
        }
        buf.truncate(written as usize);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::protocol::TlsVersion;
    use crate::scanner::backends::HandshakeOutcome;
    use crate::scanner::openssl::ciphers::{LegacyCipherProbeOutput, LegacyCipherResult};

    fn cipher_result(name: &str, outcome: HandshakeOutcome) -> LegacyCipherResult {
        LegacyCipherResult {
            name: name.to_string(),
            openssl_name: String::new(),
            iana_code: 0,
            version: TlsVersion::Tls12,
            outcome,
            dh_snapshot: None,
            ske_sig: None,
        }
    }

    #[test]
    fn pick_supported_prefers_canonical_aes128_gcm() {
        let out = LegacyCipherProbeOutput {
            results: vec![
                cipher_result("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", HandshakeOutcome::Supported),
                cipher_result(
                    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                    HandshakeOutcome::Supported,
                ),
            ],
        };
        let picked = pick_supported_suite(Some(&out), Family::Dhe);
        assert_eq!(picked.as_deref(), Some("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"));
    }

    #[test]
    fn pick_supported_falls_back_to_any_family_suite() {
        let out = LegacyCipherProbeOutput {
            results: vec![cipher_result(
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                HandshakeOutcome::Supported,
            )],
        };
        let picked = pick_supported_suite(Some(&out), Family::Ecdhe);
        assert_eq!(picked.as_deref(), Some("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"));
    }

    #[test]
    fn pick_supported_returns_none_when_no_family_match() {
        let out = LegacyCipherProbeOutput {
            results: vec![cipher_result(
                "TLS_RSA_WITH_AES_128_CBC_SHA",
                HandshakeOutcome::Supported,
            )],
        };
        assert!(pick_supported_suite(Some(&out), Family::Dhe).is_none());
        assert!(pick_supported_suite(Some(&out), Family::Ecdhe).is_none());
    }

    #[test]
    fn pick_supported_ignores_unsupported_entries() {
        let out = LegacyCipherProbeOutput {
            results: vec![
                cipher_result(
                    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                    HandshakeOutcome::NotSupported,
                ),
                cipher_result(
                    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
                    HandshakeOutcome::Error("tls_alert_handshake_failure".to_string()),
                ),
            ],
        };
        assert!(pick_supported_suite(Some(&out), Family::Dhe).is_none());
    }

    #[test]
    fn pick_supported_returns_none_on_missing_probe_output() {
        assert!(pick_supported_suite(None, Family::Dhe).is_none());
        assert!(pick_supported_suite(None, Family::Ecdhe).is_none());
    }

    #[test]
    fn family_tokens_are_canonical() {
        assert_eq!(Family::Dhe.openssl_suite_token(), "DHE-RSA-AES128-GCM-SHA256");
        assert_eq!(
            Family::Ecdhe.openssl_suite_token(),
            "ECDHE-RSA-AES128-GCM-SHA256"
        );
        assert_eq!(
            Family::Dhe.iana_suite_name(),
            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
        );
        assert_eq!(
            Family::Ecdhe.iana_suite_name(),
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        );
    }
}
