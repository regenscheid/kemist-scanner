//! Connection-state characterization.
//!
//! Runs a single successful rustls handshake and captures everything
//! `rustls::ClientConnection` exposes post-handshake: negotiated version,
//! cipher suite, kx group, ALPN, plus verifier-side signals captured during
//! callbacks (OCSP response bytes, signature scheme from CertificateVerify).
//!
//! This is passive — no separate probe per version or per group. It complements
//! (doesn't replace) `test_protocol_support`, which still enumerates every
//! TLS version's offered/not-offered state via its own handshakes.
//!
//! What rustls does NOT expose as of 0.23.x:
//! - Whether EMS (RFC 7627) was negotiated on a TLS 1.2 connection
//! - Whether the server sent the RFC 5746 renegotiation_info extension
//! - SCT delivery via TLS extension (only embedded-in-cert SCTs are
//!   accessible via x509 parsing)
//!
//! Those fields are populated instead by the dedicated byte-level TLS
//! 1.2 ServerHello probe in `scanner/hello.rs`, or `not_applicable`
//! on TLS 1.3 where they don't apply.


use rustls::client::danger::ServerCertVerifier;
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::CertificateError;
use tokio_rustls::rustls;

use crate::model::cert::CertificateInfo;
use crate::model::protocol::TlsVersion;
use crate::scanner::cert as cert_ops;

/// State captured from a successful characterization handshake. Every field
/// is `Option` because rustls may not expose a value for every connection
/// (e.g. some versions report no kx group).
#[derive(Debug, Clone, Default)]
pub struct NegotiatedState {
    pub version: Option<TlsVersion>,
    pub cipher_suite_name: Option<String>,
    /// IANA cipher-suite codepoint.
    pub cipher_suite_id: Option<u16>,
    pub kx_group_name: Option<String>,
    /// IANA kx group codepoint.
    pub kx_group_id: Option<u16>,
    pub alpn_negotiated: Option<String>,
    /// Signature scheme used for the TLS 1.2/1.3 CertificateVerify, captured
    /// via `ServerCertVerifier::verify_tls{12,13}_signature`.
    pub signature_scheme: Option<String>,
    pub ocsp_stapled: bool,
    pub ocsp_response_len: usize,
    /// Raw DER bytes of the OCSP response rustls handed to
    /// `verify_server_cert`. `None` when no staple was delivered.
    /// Consumers (the JSON output builder) may parse these via
    /// [`crate::model::ocsp_response::parse`] or emit them verbatim
    /// as hex behind a CLI flag.
    pub ocsp_response_bytes: Option<Vec<u8>>,
    /// RFC 9266 `tls-exporter` channel binding — 32 bytes of exporter
    /// output with label `"EXPORTER-Channel-Binding"` and empty
    /// context. `None` on TLS 1.2 (RFC 9266 is TLS 1.3-only) or when
    /// the exporter call fails. Lower-case hex.
    pub channel_binding_tls_exporter: Option<String>,
    /// RFC 5929 §4 `tls-server-end-point` — SHA-256 of the leaf
    /// certificate DER. Deterministic from material already captured;
    /// always populated when a leaf cert was delivered. Lower-case
    /// hex, 64 chars.
    pub channel_binding_server_end_point: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CharacterizationOutput {
    pub negotiated: Option<NegotiatedState>,
    pub certificates: Vec<CertificateInfo>,
    /// DER bytes of the chain as received on the wire. Used by offline
    /// validation; not emitted directly to the schema.
    pub cert_der: Vec<Vec<u8>>,
    /// The ALPN list the client proposed. Surfaced in the output schema
    /// so downstream consumers can interpret `alpn_negotiated` against
    /// what was actually offered.
    pub alpn_offered: Vec<String>,
    /// Trust observations computed after the handshake completes. Three
    /// independent observations — chain validity, name match, and the
    /// first-failure category string when chain validity is false.
    pub validation: ValidationResult,
}

/// Multi-trust-store validation output. Each compiled-in store gets
/// its own `(valid, error)` pair. `chain_valid_to_custom_roots`
/// holds entries for `--extra-trust-store` stores. `trust_store_sources`
/// records provenance per store (`"compiled_in"` vs
/// `"runtime_override:<path>"`).
///
/// All `*_chain_valid_*` fields are `Option<bool>` because a
/// failed/absent handshake leaves them unevaluated, and empty
/// bundles (placeholder PEMs) render as `None` with reason
/// `"trust_store_empty"`.
#[derive(Debug, Clone, Default)]
pub struct ValidationResult {
    pub chain_valid_to_webpki_roots: Option<bool>,
    pub chain_valid_to_microsoft_roots: Option<bool>,
    pub chain_valid_to_apple_roots: Option<bool>,
    pub chain_valid_to_us_fpki_common_roots: Option<bool>,
    pub chain_valid_to_us_dod_roots: Option<bool>,
    /// `--extra-trust-store` entries, keyed on the user-supplied
    /// name.
    pub chain_valid_to_custom_roots: std::collections::BTreeMap<String, Option<bool>>,
    pub name_matches_sni: Option<bool>,
    /// Spec-canonical error strings when chain validation fails
    /// against **webpki-roots** specifically:
    /// `"expired"`, `"not_valid_yet"`, `"untrusted_root"`, `"revoked"`,
    /// `"bad_signature"`, `"bad_encoding"`, `"unsupported_signature_algorithm"`,
    /// `"name_mismatch"` (only populated when chain is otherwise valid but
    /// name fails — see probe module docs), or `"other:<rustls_error>"` for
    /// unexpected categories. `None` when the chain validated cleanly.
    /// Legacy field — new integrations should consume
    /// `per_store_validation_errors` instead.
    pub validation_error: Option<String>,
    /// Per-store validation error messages, keyed by canonical
    /// store name (`"webpki-roots"`, `"microsoft"`, `"apple"`,
    /// `"us-fpki-common"`, `"us-dod"`, plus any `--extra-trust-store`
    /// names). Populated only for stores that produced an error.
    /// Same error-string taxonomy as `validation_error`.
    pub per_store_validation_errors: std::collections::BTreeMap<String, String>,
    /// Provenance breadcrumb — `"compiled_in"` / `"cache_refreshed:<path>"`
    /// / `"runtime_override:<path>"`. One entry per store attempted.
    pub trust_store_sources: std::collections::BTreeMap<String, String>,
    /// Cached-bundle manifest metadata per store. Populated only
    /// for stores whose bundle came from the manifest-backed cache;
    /// compile-time + runtime-override loads have no entry here.
    pub trust_store_bundle_metadata: std::collections::BTreeMap<
        String,
        crate::scanner::bundle_cache::BundleMetadata,
    >,
}

// `characterize_connection` + `StateCollector` moved to
// `crate::scanner::backends::rustls::characterize` as part of the
// backend-organization refactor. Re-exported below so existing
// callers (src/scanner/mod.rs, tests) keep resolving through
// `crate::scanner::probe::characterize_connection`.
pub use crate::scanner::backends::rustls::characterize::characterize_connection;

#[allow(dead_code)]
const _MOVED_TO_BACKENDS_RUSTLS_CHARACTERIZE: () = ();


/// Offline validation pipeline. Runs after the handshake with the raw
/// DER bytes + already-parsed `CertificateInfo`s. Produces three
/// independent observations:
///
/// 1. **`name_matches_sni`** — parsed purely from the leaf's SAN/CN.
///    Never consults webpki.
/// 2. **`chain_valid_to_webpki_roots`** — uses rustls's `WebPkiServerVerifier`
///    against the Mozilla root store bundled in `webpki-roots`. When the
///    first pass fails with `NotValidForName`, retry with a SAN-derived name
///    to isolate chain validity from name matching.
/// 3. **`validation_error`** — populated only when chain validation fails.
///    Maps rustls `CertificateError` variants to spec-canonical strings.
pub fn evaluate_validation(
    cert_der: &[Vec<u8>],
    certificates: &[CertificateInfo],
    sni: &str,
) -> ValidationResult {
    if cert_der.is_empty() || certificates.is_empty() {
        return ValidationResult::default();
    }

    // 1. Name match — trust-store-agnostic.
    let leaf = &certificates[0];
    let name_matches = cert_ops::name_matches_sni(&leaf.san, &leaf.subject, sni);

    let end_entity = CertificateDer::from(cert_der[0].clone());
    let intermediates: Vec<CertificateDer<'static>> = cert_der[1..]
        .iter()
        .map(|der| CertificateDer::from(der.clone()))
        .collect();

    let now = UnixTime::now();
    let sni_srv = match ServerName::try_from(sni.to_string()) {
        Ok(s) => s,
        Err(_) => ServerName::try_from("invalid.kemist-placeholder.invalid".to_string())
            .expect("literal placeholder always valid"),
    };

    // 2. Multi-store chain validation. Run every loaded store
    // independently; collect per-store (valid, error) pairs plus
    // source breadcrumbs.
    let mut result = ValidationResult {
        name_matches_sni: Some(name_matches),
        ..Default::default()
    };

    let Some(registry) = crate::scanner::trust_stores::registry() else {
        // Registry not installed (shouldn't happen — main.rs calls
        // install_registry early). Emit a single diagnostic.
        result.validation_error = Some("trust_store_registry_not_installed".to_string());
        return result;
    };

    // Read the manifest once so per-store metadata attachment is
    // O(n_stores) with zero I/O per lookup.
    let manifest = crate::scanner::bundle_cache::Manifest::load();

    for (name, store) in &registry.stores {
        result.trust_store_sources.insert(
            name.clone(),
            store.source.to_breadcrumb(),
        );
        // Attach manifest metadata only for cache-refreshed stores
        // — compile-time and runtime-override loads have no
        // upstream provenance data we can accurately surface.
        if matches!(
            store.source,
            crate::scanner::trust_stores::TrustStoreSource::CacheRefreshed(_)
        ) {
            if let Some(meta) = manifest.bundles.get(name) {
                result
                    .trust_store_bundle_metadata
                    .insert(name.clone(), meta.clone());
            }
        }
        let (valid, error) = validate_one_store(
            name,
            store,
            &end_entity,
            &intermediates,
            &sni_srv,
            &leaf.san,
            now,
        );

        match name.as_str() {
            "webpki-roots" => {
                result.chain_valid_to_webpki_roots = valid;
                // Legacy single-error field keeps webpki-roots' error
                // so existing rule engines that read `validation_error`
                // keep working.
                if let (Some(false), Some(e)) = (&valid, &error) {
                    result.validation_error = Some(e.clone());
                }
            }
            "microsoft" => result.chain_valid_to_microsoft_roots = valid,
            "apple" => result.chain_valid_to_apple_roots = valid,
            "us-fpki-common" => result.chain_valid_to_us_fpki_common_roots = valid,
            "us-dod" => result.chain_valid_to_us_dod_roots = valid,
            _ => {
                // --extra-trust-store entry.
                result
                    .chain_valid_to_custom_roots
                    .insert(name.clone(), valid);
            }
        }

        if let Some(e) = error {
            result.per_store_validation_errors.insert(name.clone(), e);
        }
    }

    result
}

/// Run chain validation against a single loaded trust store. Returns
/// `(Option<bool>, Option<String>)` matching the per-store slots in
/// [`ValidationResult`]: value-level `None` means "could not probe"
/// (empty bundle, verifier-build failure), `Some(true)` / `Some(false)`
/// is a definite answer. Error string populates only when
/// `valid = Some(false)` OR when probing was structurally impossible
/// (no verifier → reason `trust_store_empty`).
fn validate_one_store(
    name: &str,
    store: &crate::scanner::trust_stores::LoadedStore,
    end_entity: &CertificateDer<'static>,
    intermediates: &[CertificateDer<'static>],
    sni_srv: &ServerName<'static>,
    san: &[String],
    now: UnixTime,
) -> (Option<bool>, Option<String>) {
    let Some(verifier) = &store.verifier else {
        return (None, Some("trust_store_empty".to_string()));
    };
    let first_try =
        verifier.verify_server_cert(end_entity, intermediates, sni_srv, &[], now);
    let _ = name;
    match &first_try {
        Ok(_) => (Some(true), None),
        Err(rustls::Error::InvalidCertificate(CertificateError::NotValidForName))
        | Err(rustls::Error::InvalidCertificate(
            CertificateError::NotValidForNameContext { .. },
        )) => {
            // Retry with a SAN-derived name to isolate chain validity
            // from the name-matching concern.
            let (valid, err) =
                retry_with_san_name(verifier, end_entity, intermediates, san, now);
            (Some(valid), err)
        }
        Err(e) => (Some(false), Some(classify_cert_error(e))),
    }
}

fn retry_with_san_name(
    verifier: &WebPkiServerVerifier,
    end_entity: &CertificateDer<'static>,
    intermediates: &[CertificateDer<'static>],
    san: &[String],
    now: UnixTime,
) -> (bool, Option<String>) {
    let Some(probe_name) = cert_ops::first_san_dns(san) else {
        // No usable SAN to retry with — we can tell the chain isn't valid
        // for the SNI we sent, but can't say whether the chain would be
        // valid for any name. Emit `name_mismatch` and leave chain_valid
        // as false so downstream consumers don't over-interpret.
        return (false, Some("name_mismatch".to_string()));
    };
    let Ok(name) = ServerName::try_from(probe_name) else {
        return (false, Some("name_mismatch".to_string()));
    };
    match verifier.verify_server_cert(end_entity, intermediates, &name, &[], now) {
        Ok(_) => (true, None),
        Err(rustls::Error::InvalidCertificate(CertificateError::NotValidForName))
        | Err(rustls::Error::InvalidCertificate(CertificateError::NotValidForNameContext {
            ..
        })) => {
            // Unexpected: even with a SAN-derived name webpki rejects on name.
            // Treat as a name failure with chain undetermined, but emit
            // false for chain_valid so consumers get a signal.
            (false, Some("name_mismatch".to_string()))
        }
        Err(e) => (false, Some(classify_cert_error(&e))),
    }
}

fn classify_cert_error(e: &rustls::Error) -> String {
    use CertificateError as CE;
    match e {
        rustls::Error::InvalidCertificate(inner) => match inner {
            CE::Expired | CE::ExpiredContext { .. } => "expired".to_string(),
            CE::NotValidYet | CE::NotValidYetContext { .. } => "not_valid_yet".to_string(),
            CE::Revoked => "revoked".to_string(),
            CE::UnknownIssuer => "untrusted_root".to_string(),
            CE::BadSignature => "bad_signature".to_string(),
            CE::BadEncoding => "bad_encoding".to_string(),
            CE::UnsupportedSignatureAlgorithm => "unsupported_signature_algorithm".to_string(),
            CE::UnhandledCriticalExtension => "unhandled_critical_extension".to_string(),
            CE::UnknownRevocationStatus => "unknown_revocation_status".to_string(),
            CE::NotValidForName | CE::NotValidForNameContext { .. } => "name_mismatch".to_string(),
            other => format!("other:{other:?}"),
        },
        other => format!("other:{other}"),
    }
}

// `build_webpki_verifier` was the pre-S1 single-store entry point.
// Multi-store validation in [`evaluate_validation`] now drives
// verifier construction via
// [`crate::scanner::trust_stores::build_default_registry`] — that
// registry owns the webpki-roots verifier plus the four additional
// bundles.

