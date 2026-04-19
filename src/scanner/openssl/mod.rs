//! OpenSSL-backed legacy TLS & misconfiguration probe subsystem.
//!
//! Fills observation gaps that rustls + aws-lc-rs cannot reach: RSA key
//! exchange, RC4/DES/3DES/NULL/anon ciphers, TLS 1.2 finite-field DH
//! parameters, FFDHE named groups, TLS_FALLBACK_SCSV enforcement,
//! client-initiated renegotiation, and CertificateRequest contents.
//!
//! Gated by the `legacy-probes` cargo feature; see Cargo.toml. The subsystem
//! is additive — it does not modify the rustls probe path.

pub mod alerts;
pub mod ciphers;
pub mod client_auth;
pub mod dh_params;
pub mod fallback_scsv;
pub mod ffdhe;
pub mod protocol_versions;
pub mod renegotiation;
pub mod ske_sig;

use ::openssl::provider::Provider;

use crate::model::errors::ScannerError;
use crate::scanner::ScanConfig;

/// Holds the OpenSSL default + legacy providers for the scanner's lifetime.
///
/// The legacy provider enables RC4, single-DES, MD4, and SSLv3-era primitives
/// that the default provider excludes in OpenSSL 3.x. Both must be loaded
/// before any `SSL_CTX` is built; the providers' lifetimes are tied to this
/// struct via RAII.
pub struct LegacyRuntime {
    // Providers must stay alive for every probe; dropping them unloads the
    // backing `OSSL_PROVIDER`. Named with leading underscore to silence the
    // "unused field" lint — the Drop side-effect is the whole point.
    _default: Provider,
    _legacy: Provider,
}

impl LegacyRuntime {
    /// Load the default + legacy providers into the global library context.
    /// Returns a non-transient `ScannerError` on failure — the whole
    /// legacy-probe subsystem is unavailable for this run.
    pub fn load() -> Result<Self, ScannerError> {
        let default = Provider::load(None, "default").map_err(|e| {
            ScannerError::openssl_provider_load_failed(format!(
                "OSSL_PROVIDER_load(default): {e}"
            ))
        })?;
        let legacy = Provider::load(None, "legacy").map_err(|e| {
            ScannerError::openssl_provider_load_failed(format!(
                "OSSL_PROVIDER_load(legacy): {e}"
            ))
        })?;
        Ok(Self {
            _default: default,
            _legacy: legacy,
        })
    }
}

/// Aggregate output of every probe in the OpenSSL subsystem. Each Phase-D
/// module fills its slot; default is empty.
///
/// Not serialized directly — `src/output/json.rs` consumes this and emits
/// individual `tls.*` sections per the schema.
#[derive(Debug, Default, Clone)]
pub struct OpensslObservations {
    /// Per-probe non-fatal errors collected during the scan. Populated so
    /// every "not probed" outcome carries a reason string rather than going
    /// silent.
    pub probe_errors: Vec<ScannerError>,
}

/// Orchestration entry point. Loads providers, then runs each D1-D8 probe
/// honoring the scan config's `per_target_delay`. Returns `Err` only on
/// fatal setup (provider load failure); per-probe errors land in
/// `OpensslObservations::probe_errors` and the scan continues.
pub async fn run_all_probes(_cfg: &ScanConfig) -> Result<OpensslObservations, ScannerError> {
    let _runtime = LegacyRuntime::load()?;
    // Phase B scaffolding: no live probes yet. Phase D modules plug in here.
    Ok(OpensslObservations::default())
}
