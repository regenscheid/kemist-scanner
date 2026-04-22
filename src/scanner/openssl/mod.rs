//! OpenSSL-backed legacy TLS & misconfiguration probe subsystem.
//!
//! Fills observation gaps that rustls + aws-lc-rs cannot reach: RSA key
//! exchange, RC4/DES/3DES/NULL/anon ciphers, TLS 1.2 finite-field DH
//! parameters, FFDHE named groups, TLS_FALLBACK_SCSV enforcement,
//! client-initiated renegotiation, and CertificateRequest contents.
//!
//! Gated by the `legacy-probes` cargo feature; see Cargo.toml. The subsystem
//! is additive — it does not modify the rustls probe path.

pub mod ciphers;
pub mod fallback_scsv;
pub mod kx_groups;
pub mod protocol_versions;
pub mod sigalg_policy;
// Post-handshake actions, observers, alert classification, and the
// OpenSSL `TlsBackend` impl all live under `src/scanner/backends/openssl/`
// as of Stage 4c. This module retains the entry-point probe drivers
// that callers in `src/scanner/mod.rs` still invoke directly; Stage 4d
// will inline them into the orchestrator and delete this module.
pub use crate::scanner::backends::openssl::{
    alerts, client_auth, dh_params, renegotiation, ske_sig, tickets, tls13_extensions,
};

use std::sync::OnceLock;

use ::openssl::provider::Provider;

use crate::model::errors::ScannerError;
use crate::scanner::ScanConfig;

/// Ensures the OpenSSL `default` and `legacy` providers are loaded exactly
/// once for the lifetime of the process, then stay loaded.
///
/// Implementation: `Provider::load` returns an RAII handle whose `Drop`
/// calls `OSSL_PROVIDER_unload`. `Provider` doesn't implement `Send`/`Sync`
/// so we can't store it in a static. Instead we intentionally
/// `std::mem::forget` the handles after a successful load — the providers
/// stay in OpenSSL's global registry, any thread can build `SSL_CTX`
/// against them, and we never need to touch the handle again.
///
/// The return value is a `&'static Result<(), ScannerError>` — on the
/// unlikely-but-real failure path (missing legacy provider for some
/// vendored builds, for instance), every caller gets the same cached
/// error rather than re-hitting the C library per probe.
pub fn ensure_legacy_providers() -> &'static Result<(), ScannerError> {
    static CELL: OnceLock<Result<(), ScannerError>> = OnceLock::new();
    CELL.get_or_init(|| {
        let default = Provider::load(None, "default").map_err(|e| {
            ScannerError::openssl_provider_load_failed(format!("OSSL_PROVIDER_load(default): {e}"))
        })?;
        let legacy = Provider::load(None, "legacy").map_err(|e| {
            ScannerError::openssl_provider_load_failed(format!("OSSL_PROVIDER_load(legacy): {e}"))
        })?;
        // Pin both providers for the process lifetime; see function
        // docstring for why this leak is deliberate.
        std::mem::forget(default);
        std::mem::forget(legacy);
        Ok(())
    })
}

/// Aggregate output of every probe in the OpenSSL subsystem. Each
/// submodule fills its slot; default is empty.
///
/// Not serialized directly — `src/output/json.rs` consumes this and emits
/// individual `tls.*` sections per the schema.
#[derive(Debug, Default, Clone)]
pub struct OpensslObservations {
    /// Per-suite probe results for RSA-kex, RC4, DES/3DES, NULL,
    /// anon-DH, DHE-RSA, PSK / Camellia / SEED / ARIA / static DH
    /// families across TLS 1.0/1.1/1.2.
    pub cipher_probes: Option<ciphers::LegacyCipherProbeOutput>,
    /// Per-group TLS 1.2 (FFDHE) and TLS 1.3 (FFDHE + non-FFDHE groups
    /// aws-lc-rs doesn't ship) probes, with a cross-check for FFDHE
    /// servers that ignore `supported_groups` and return a custom prime.
    pub kx_group_probes: Option<kx_groups::KxGroupProbeOutput>,
    /// `TLS_FALLBACK_SCSV` (RFC 7507) enforcement observation.
    pub fallback_scsv: Option<fallback_scsv::FallbackScsvResult>,
    /// Client-initiated renegotiation verdict.
    pub renegotiation: Option<renegotiation::RenegotiationObservation>,
    /// Server `CertificateRequest` observation. `None` when the
    /// probe's outer setup failed; `Some(req)` with `req.requested: false`
    /// when the server did not request a client certificate.
    pub client_auth: Option<client_auth::ClientAuthRequest>,
    /// TLS 1.3 EncryptedExtensions observation — `record_size_limit` +
    /// `compress_certificate`. `None` when the handshake didn't reach
    /// EncryptedExtensions (target doesn't speak TLS 1.3, or the
    /// connection failed before the message arrived).
    pub tls13_extensions: Option<tls13_extensions::Tls13EncryptedExtensions>,
    /// Session resumption observation — TLS 1.2 ticket + rotation
    /// today, TLS 1.3 PSK + 0-RTT stubbed for a future workstream.
    /// `None` when the probe's outer setup failed (rare).
    pub session_resumption: Option<crate::model::scan_result::SessionResumption>,
    /// Constrained-sigalg handshake outcomes for the four canonical
    /// constraint families. `None` only when the outer probe setup
    /// failed; per-constraint skip lands as `method: not_probed`
    /// inside.
    pub sigalg_policy: Option<crate::model::scan_result::SignatureAlgorithmPolicyProbe>,
    /// Per-probe non-fatal errors collected during the scan. Populated so
    /// every "not probed" outcome carries a reason string rather than going
    /// silent.
    pub probe_errors: Vec<ScannerError>,
}

/// Orchestration entry point. Loads providers, then runs each probe
/// honoring the scan config's `per_target_delay`. Returns `Err` only on
/// fatal setup (provider load failure); per-probe errors land in
/// `OpensslObservations::probe_errors` and the scan continues.
pub async fn run_all_probes(cfg: &ScanConfig) -> Result<OpensslObservations, ScannerError> {
    if let Err(e) = ensure_legacy_providers() {
        return Err(e.clone());
    }

    let mut out = OpensslObservations::default();

    // Legacy cipher enumeration. DH parameter + SKE signature
    // observers run inside the per-suite handshake driver.
    let cipher_out = ciphers::probe_legacy_suites(
        cfg.target,
        &cfg.hostname,
        cfg.timeout,
        cfg.timeout,
        cfg.per_target_delay,
    )
    .await;
    out.cipher_probes = Some(cipher_out);

    // Named-group probing (FFDHE across TLS 1.2 + TLS 1.3; groups
    // aws-lc-rs doesn't ship at TLS 1.3).
    let kx_out = kx_groups::probe_kx_groups(
        cfg.target,
        &cfg.hostname,
        cfg.timeout,
        cfg.timeout,
        cfg.per_target_delay,
    )
    .await;
    out.kx_group_probes = Some(kx_out);

    // TLS_FALLBACK_SCSV (RFC 7507) enforcement.
    let scsv = fallback_scsv::probe(cfg.target, &cfg.hostname, cfg.timeout, cfg.timeout).await;
    out.fallback_scsv = Some(scsv);

    // Client-initiated renegotiation behavior.
    let reneg = renegotiation::probe(cfg.target, &cfg.hostname, cfg.timeout, cfg.timeout).await;
    out.renegotiation = Some(reneg);

    // CertificateRequest capture via msg_callback.
    let ca = client_auth::probe(cfg.target, &cfg.hostname, cfg.timeout, cfg.timeout).await;
    out.client_auth = ca;

    // TLS 1.3 EncryptedExtensions capture (record_size_limit,
    // compress_certificate). Same msg_callback pattern as client_auth.
    let ee = tls13_extensions::probe(cfg.target, &cfg.hostname, cfg.timeout, cfg.timeout).await;
    out.tls13_extensions = Some(ee);

    // Session resumption (TLS 1.2 ticket issuance + rotation;
    // TLS 1.3 stubbed for a follow-up workstream).
    let sr = tickets::probe(cfg.target, &cfg.hostname, cfg.timeout, cfg.timeout).await;
    out.session_resumption = Some(sr);

    // Signature-algorithm policy probe (four constrained handshakes;
    // `--sigalg-probe-skip` opts out individual ones).
    let sap = sigalg_policy::probe(
        cfg.target,
        &cfg.hostname,
        cfg.timeout,
        cfg.timeout,
        &cfg.sigalg_probe_skip,
    )
    .await;
    out.sigalg_policy = Some(sap);

    Ok(out)
}
