//! Multi-trust-store chain validation.
//!
//! kemist's baseline trust check uses Mozilla's CA bundle via the
//! `webpki-roots` crate — that covers the common "does this cert
//! chain validate under a browser-default trust set?" question.
//! Rule engines with environment-specific compliance requirements
//! (SP 800-52r2 §3.4.1 agency trust anchors, Microsoft CCADB,
//! Apple's ecosystem, FPKI Common Policy, DoD PKI) need to know
//! whether the cert *also* chains under their specific trust
//! program.
//!
//! This module loads per-store trust anchors at startup and builds
//! one `WebPkiServerVerifier` per store. The chain validation runs
//! against each store independently, producing a per-store
//! `(valid: bool, error?: String)` pair that surfaces in
//! `certificates.validation.chain_valid_to_<name>_roots`.
//!
//! ## Store inventory
//! - `webpki-roots` — Mozilla CA bundle via the `webpki-roots`
//!   crate. Shipped with kemist; updated via `cargo update` on the
//!   crate. Source: not loaded from `data/trust_stores/`.
//! - `microsoft` — `data/trust_stores/microsoft_ccadb.pem`.
//! - `apple` — `data/trust_stores/apple_pki.pem`.
//! - `us-fpki-common` — `data/trust_stores/us_fpki_common.pem`.
//! - `us-dod` — `data/trust_stores/us_dod.pem`.
//!
//! Empty placeholder bundles render as `method: not_probed, reason:
//! "trust_store_empty"` per store; operators refresh via
//! `--trust-store <name>:<path>` without rebuilding.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::CertificateDer;
use rustls::RootCertStore;

/// Canonical compile-time store names. Matches the CLI `--trust-store`
/// enum and the schema's `chain_valid_to_<name>_roots` field naming
/// convention (with underscores).
pub const COMPILED_STORE_NAMES: &[&str] = &[
    "webpki-roots",
    "microsoft",
    "apple",
    "us-fpki-common",
    "us-dod",
];

/// Provenance breadcrumb: where the bundle backing a given store
/// came from. `CompiledIn` → build-time bundle; `CacheRefreshed(path)`
/// → loaded from the platform cache written by
/// `kemist --update-trust-stores`; `RuntimeOverride(path)` →
/// loaded from a user-supplied path via `--trust-store name:path`.
#[derive(Debug, Clone)]
pub enum TrustStoreSource {
    CompiledIn,
    /// Loaded from the app cache directory after a successful
    /// `--update-trust-stores` refresh. The path is the concrete
    /// cache file that was read (e.g.
    /// `~/Library/Caches/kemist/trust_stores/microsoft.pem`).
    CacheRefreshed(PathBuf),
    RuntimeOverride(PathBuf),
}

impl TrustStoreSource {
    pub fn to_breadcrumb(&self) -> String {
        match self {
            Self::CompiledIn => "compiled_in".to_string(),
            Self::CacheRefreshed(p) => {
                format!("cache_refreshed:{}", p.display())
            }
            Self::RuntimeOverride(p) => {
                format!("runtime_override:{}", p.display())
            }
        }
    }
}

/// One loaded store — a `WebPkiServerVerifier` pre-built against
/// its trust anchors, plus the source breadcrumb. `None` when the
/// bundle was empty (placeholder PEM or override file with no
/// certs) — validation against that store becomes `not_probed` with
/// reason `trust_store_empty`.
pub struct LoadedStore {
    pub verifier: Option<Arc<WebPkiServerVerifier>>,
    pub source: TrustStoreSource,
}

/// Global registry of loaded trust stores. Keyed on canonical name
/// (hyphenated, lowercase). Set once at startup via
/// [`install_registry`]; `None` → no stores configured (should not
/// happen in practice — even without overrides the compiled stores
/// load unconditionally).
pub struct TrustStoreRegistry {
    pub stores: BTreeMap<String, LoadedStore>,
}

static REGISTRY: OnceLock<TrustStoreRegistry> = OnceLock::new();

/// Install the registry at startup. Fails silently on duplicate call
/// (OnceLock semantics).
pub fn install_registry(registry: TrustStoreRegistry) {
    let _ = REGISTRY.set(registry);
}

/// Accessor — returns `None` until [`install_registry`] has run.
pub fn registry() -> Option<&'static TrustStoreRegistry> {
    REGISTRY.get()
}

/// Build the default registry: compiled-in PEM bundles for the four
/// stores plus webpki-roots from the crate. Runtime overrides +
/// extra stores are applied on top by the caller.
pub fn build_default_registry(
    overrides: &BTreeMap<String, PathBuf>,
    extras: &BTreeMap<String, PathBuf>,
) -> Result<TrustStoreRegistry, String> {
    let mut stores = BTreeMap::new();

    // webpki-roots — handled specially since its source is a crate,
    // not a PEM file. Still honors --trust-store webpki-roots:<path>.
    stores.insert(
        "webpki-roots".to_string(),
        load_webpki_roots(overrides.get("webpki-roots"))?,
    );

    // Compiled-in PEM bundles for the other four.
    macro_rules! load_compiled {
        ($name:literal, $bundle:expr) => {
            stores.insert(
                $name.to_string(),
                load_pem_store($name, overrides.get($name), $bundle)?,
            );
        };
    }
    load_compiled!(
        "microsoft",
        include_bytes!("../../data/trust_stores/microsoft_ccadb.pem").as_slice()
    );
    load_compiled!(
        "apple",
        include_bytes!("../../data/trust_stores/apple_pki.pem").as_slice()
    );
    load_compiled!(
        "us-fpki-common",
        include_bytes!("../../data/trust_stores/us_fpki_common.pem").as_slice()
    );
    load_compiled!(
        "us-dod",
        include_bytes!("../../data/trust_stores/us_dod.pem").as_slice()
    );

    // Extra stores from --extra-trust-store.
    for (name, path) in extras {
        validate_extra_name(name)?;
        if COMPILED_STORE_NAMES.contains(&name.as_str()) {
            return Err(format!(
                "extra trust store name `{name}` collides with a compiled-in store; \
                 use --trust-store {name}:<path> to override instead"
            ));
        }
        let store = load_store_from_path(path)?;
        stores.insert(name.clone(), store);
    }

    Ok(TrustStoreRegistry { stores })
}

/// Load the webpki-roots-backed store. Override path wins over
/// cache wins over the built-in crate bundle.
fn load_webpki_roots(override_path: Option<&PathBuf>) -> Result<LoadedStore, String> {
    if let Some(path) = override_path {
        return Ok(LoadedStore {
            verifier: build_verifier_from_pem(&std::fs::read(path).map_err(|e| {
                format!(
                    "failed to read --trust-store webpki-roots override {}: {e}",
                    path.display()
                )
            })?)?,
            source: TrustStoreSource::RuntimeOverride(path.clone()),
        });
    }

    // webpki-roots refresh: the updater doesn't refetch the crate —
    // users get fresh roots via `cargo update`. Still check the
    // cache path in case an operator placed a manual override
    // there via `kemist --update-trust-stores` fetched metadata.
    if let Some(loaded) = try_load_from_cache("webpki-roots") {
        return Ok(loaded);
    }

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Ok(LoadedStore {
        verifier: WebPkiServerVerifier::builder(Arc::new(roots)).build().ok(),
        source: TrustStoreSource::CompiledIn,
    })
}

/// Load a compiled-in PEM bundle. Precedence:
/// 1. `--trust-store name:<path>` runtime override → load that path.
/// 2. Cache file (`$cache/trust_stores/<name>.pem`) that matches
///    the manifest's SHA-256 → load cache.
/// 3. Compile-time `include_bytes!` bundle.
fn load_pem_store(
    name: &str,
    override_path: Option<&PathBuf>,
    compiled_pem: &[u8],
) -> Result<LoadedStore, String> {
    if let Some(path) = override_path {
        let pem = std::fs::read(path).map_err(|e| {
            format!(
                "failed to read --trust-store {name} override {}: {e}",
                path.display()
            )
        })?;
        return Ok(LoadedStore {
            verifier: build_verifier_from_pem(&pem)?,
            source: TrustStoreSource::RuntimeOverride(path.clone()),
        });
    }
    if let Some(loaded) = try_load_from_cache(name) {
        return Ok(loaded);
    }
    Ok(LoadedStore {
        verifier: build_verifier_from_pem(compiled_pem)?,
        source: TrustStoreSource::CompiledIn,
    })
}

/// Try the cache directory: `$cache/trust_stores/<name>.pem`. A
/// hit requires the file exists AND its SHA-256 matches the
/// manifest's record. Both safeguards prevent the scanner from
/// honoring tampered or stale on-disk state.
fn try_load_from_cache(name: &str) -> Option<LoadedStore> {
    let dir = crate::scanner::bundle_cache::trust_store_dir()?;
    let path = dir.join(format!("{name}.pem"));
    let bytes = crate::scanner::bundle_cache::read_verified(&path, name)?;
    match build_verifier_from_pem(&bytes) {
        Ok(verifier) => Some(LoadedStore {
            verifier,
            source: TrustStoreSource::CacheRefreshed(path),
        }),
        Err(e) => {
            tracing::debug!(%name, error = %e, "cached bundle failed to parse; falling back to compiled");
            None
        }
    }
}

fn load_store_from_path(path: &PathBuf) -> Result<LoadedStore, String> {
    let pem = std::fs::read(path)
        .map_err(|e| format!("failed to read extra trust store {}: {e}", path.display()))?;
    Ok(LoadedStore {
        verifier: build_verifier_from_pem(&pem)?,
        source: TrustStoreSource::RuntimeOverride(path.clone()),
    })
}

/// Parse a PEM bundle (with optional `#`-style comments / blank
/// lines outside the BEGIN/END framing — they're ignored by
/// `rustls_pemfile`). Returns `None` when the bundle has zero
/// valid certs — callers emit `not_probed` with reason
/// `trust_store_empty`.
fn build_verifier_from_pem(pem: &[u8]) -> Result<Option<Arc<WebPkiServerVerifier>>, String> {
    let mut cursor = std::io::Cursor::new(pem);
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut cursor).collect();
    let certs: Vec<CertificateDer<'static>> = certs
        .map_err(|e| format!("pem parse: {e}"))?
        .into_iter()
        .collect();
    if certs.is_empty() {
        return Ok(None);
    }
    let mut roots = RootCertStore::empty();
    for cert in certs {
        // Ignore unparseable anchors rather than failing the whole
        // bundle — some vendor bundles include deprecated or
        // malformed anchors that webpki rejects individually.
        let _ = roots.add(cert);
    }
    if roots.is_empty() {
        return Ok(None);
    }
    Ok(WebPkiServerVerifier::builder(Arc::new(roots)).build().ok())
}

fn validate_extra_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("extra trust store name cannot be empty".to_string());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(format!(
            "extra trust store name `{name}` must be lowercase ASCII + digits + hyphens only"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_pem_yields_none_verifier() {
        let verifier = build_verifier_from_pem(b"# just a comment\n").unwrap();
        assert!(verifier.is_none());
    }

    #[test]
    fn validate_extra_name_accepts_lowercase_hyphens_digits() {
        assert!(validate_extra_name("internal").is_ok());
        assert!(validate_extra_name("my-corp-2025").is_ok());
        assert!(validate_extra_name("us-pki-v3").is_ok());
    }

    #[test]
    fn validate_extra_name_rejects_bad_chars() {
        assert!(validate_extra_name("").is_err());
        assert!(validate_extra_name("With_Underscore").is_err());
        assert!(validate_extra_name("UPPER").is_err());
        assert!(validate_extra_name("has space").is_err());
        assert!(validate_extra_name("has.dot").is_err());
    }

    #[test]
    fn build_registry_loads_compiled_bundles() {
        // Need the aws-lc-rs crypto provider installed before
        // building a WebPkiServerVerifier. main.rs does this at
        // startup; unit tests need to opt in directly. Ignore
        // duplicate-install errors — other tests in this suite may
        // have already installed it.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let overrides = BTreeMap::new();
        let extras = BTreeMap::new();
        let registry = build_default_registry(&overrides, &extras).unwrap();
        // All 5 compiled-in store names must be present.
        for name in COMPILED_STORE_NAMES {
            assert!(registry.stores.contains_key(*name), "missing store: {name}");
        }
        // Every compiled store currently ships with a real bundle —
        // webpki-roots via crate, apple from macOS System Roots,
        // microsoft from CCADB V5 × AllCertificatePEMs intersection,
        // us-fpki-common from FCPCA G2 + SIA intermediates, us-dod
        // from dl.dod.cyber.mil. If any flips to placeholder in the
        // future, loosen this assertion per-store.
        for name in COMPILED_STORE_NAMES {
            assert!(
                registry.stores[*name].verifier.is_some(),
                "store {name} expected to have a real verifier (bundle non-empty)"
            );
        }
    }
}
