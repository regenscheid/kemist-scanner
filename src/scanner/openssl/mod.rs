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
    /// D1 — Per-suite probe results for RSA-kex, RC4, DES/3DES, NULL,
    /// anon-DH, DHE-RSA, etc. across TLS 1.0/1.1/1.2.
    pub cipher_probes: Option<ciphers::LegacyCipherProbeOutput>,
    /// D4 — RFC 7919 FFDHE named-group probes across TLS 1.2 and TLS 1.3,
    /// with D2 cross-check for servers that ignore `supported_groups`.
    pub ffdhe_probes: Option<ffdhe::FfdheProbeOutput>,
    /// D5 — `TLS_FALLBACK_SCSV` (RFC 7507) enforcement observation.
    pub fallback_scsv: Option<fallback_scsv::FallbackScsvResult>,
    /// D6 — Client-initiated renegotiation verdict.
    pub renegotiation: Option<renegotiation::RenegotiationObservation>,
    /// Per-probe non-fatal errors collected during the scan. Populated so
    /// every "not probed" outcome carries a reason string rather than going
    /// silent.
    pub probe_errors: Vec<ScannerError>,
}

/// Orchestration entry point. Loads providers, then runs each D1-D8 probe
/// honoring the scan config's `per_target_delay`. Returns `Err` only on
/// fatal setup (provider load failure); per-probe errors land in
/// `OpensslObservations::probe_errors` and the scan continues.
pub async fn run_all_probes(cfg: &ScanConfig) -> Result<OpensslObservations, ScannerError> {
    let _runtime = LegacyRuntime::load()?;

    let mut out = OpensslObservations::default();

    // D1 — legacy cipher enumeration. D2 and D3 observers run inside
    // the per-suite handshake driver.
    let cipher_out = ciphers::probe_legacy_suites(
        cfg.target,
        &cfg.hostname,
        cfg.timeout,
        cfg.timeout,
        cfg.per_target_delay,
    )
    .await;
    out.cipher_probes = Some(cipher_out);

    // D4 — FFDHE named-group probing (TLS 1.2 + TLS 1.3).
    let ffdhe_out = ffdhe::probe_ffdhe_groups(
        cfg.target,
        &cfg.hostname,
        cfg.timeout,
        cfg.timeout,
        cfg.per_target_delay,
    )
    .await;
    out.ffdhe_probes = Some(ffdhe_out);

    // D5 — TLS_FALLBACK_SCSV (RFC 7507) enforcement.
    let scsv = fallback_scsv::probe(cfg.target, &cfg.hostname, cfg.timeout, cfg.timeout).await;
    out.fallback_scsv = Some(scsv);

    // D6 — Client-initiated renegotiation behavior.
    let reneg = renegotiation::probe(cfg.target, &cfg.hostname, cfg.timeout, cfg.timeout).await;
    out.renegotiation = Some(reneg);

    // D7-D8 hook in here as those modules land live.

    Ok(out)
}
