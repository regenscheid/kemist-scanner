//! Cross-platform cache directory for refreshable trust-store and
//! HSTS bundles.
//!
//! kemist ships with compile-time bundles for every store
//! (`include_bytes!` against files in `data/`). Operators can
//! refresh without rebuilding via `kemist --update-trust-stores`
//! and `kemist --update-hsts-preload`, which fetch upstream data
//! and write to the platform cache directory provided by the
//! `directories` crate:
//!
//! | Platform | Cache root |
//! |---|---|
//! | Linux   | `$XDG_CACHE_HOME/kemist/` (default `~/.cache/kemist/`) |
//! | macOS   | `~/Library/Caches/kemist/` |
//! | Windows | `%LOCALAPPDATA%\kemist\cache\` |
//!
//! The scanner loader checks the cache first; if a bundle file
//! exists there AND the manifest confirms its integrity (SHA-256
//! match, non-empty), that file is used. Otherwise the loader falls
//! through to the compile-time bundle. This preserves offline and
//! reproducible builds as the default while letting operators
//! refresh on demand.
//!
//! ## Manifest format
//!
//! Every cache write updates a sibling `manifest.json` with per-
//! bundle metadata: `source`, `fetched_at` (RFC 3339 UTC),
//! `sha256`, `cert_count` / `entry_count`, `upstream_version`
//! (when the upstream data exposes one — e.g. DoD's `v5_14`).
//! Downstream consumers (rule engines, the scanner itself) can
//! read the manifest to tie observations back to a specific
//! snapshot.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Current manifest format version. Bump when the on-disk layout
/// changes incompatibly. Scanner reads old versions tolerantly
/// (see [`Manifest::load`]).
pub const MANIFEST_VERSION: u32 = 1;

/// Root kemist cache directory, platform-appropriate. `None` when
/// the `directories` crate couldn't resolve a cache root (very
/// unusual — happens when `HOME` is unset on Unix, for example).
/// Callers treat a `None` here as "no runtime cache available;
/// use compile-time bundles only."
pub fn cache_root() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "kemist").map(|d| d.cache_dir().to_path_buf())
}

/// Path to the trust-store cache sub-directory. Does not create
/// the directory; callers invoke [`ensure_dir`] before writing.
pub fn trust_store_dir() -> Option<PathBuf> {
    cache_root().map(|r| r.join("trust_stores"))
}

/// Path to the HSTS preload cache file. Single file — the Chromium
/// snapshot is a monolithic JSON.
pub fn hsts_preload_path() -> Option<PathBuf> {
    cache_root().map(|r| r.join("hsts_preload_list.json"))
}

/// Path to the manifest sibling. Single file covering every
/// refreshable bundle (trust stores + HSTS).
pub fn manifest_path() -> Option<PathBuf> {
    cache_root().map(|r| r.join("manifest.json"))
}

/// Manifest shape written to `manifest.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Format version — see [`MANIFEST_VERSION`].
    pub version: u32,
    /// Bundles keyed by name (`microsoft`, `apple`, `us-fpki-common`,
    /// `us-dod`, `hsts_preload`, `webpki-roots` — the crate-sourced
    /// store records its crate version here even though it doesn't
    /// have an on-disk cache entry).
    #[serde(default)]
    pub bundles: BTreeMap<String, BundleMetadata>,
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            version: MANIFEST_VERSION,
            bundles: BTreeMap::new(),
        }
    }
}

/// Per-bundle metadata — one entry per cached bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleMetadata {
    /// Source URL(s) or description — human-readable, multi-source
    /// entries separated by ` + ` (e.g. the Microsoft bundle
    /// combines the CCADB V5 metadata query with the
    /// AllCertificatePEMs decade pulls).
    pub source: String,
    /// ISO 8601 / RFC 3339 UTC timestamp of the fetch that produced
    /// this cache entry.
    pub fetched_at: String,
    /// SHA-256 of the cached file contents (lower-case hex). Lets
    /// the scanner verify the cached file matches what was last
    /// written — detects manual tampering or corruption.
    pub sha256: String,
    /// Number of certificates in the bundle (for trust stores) or
    /// number of preload entries (for HSTS). Surfaces in scan
    /// output so rule engines can confirm the expected bundle size.
    pub entry_count: usize,
    /// Upstream-declared version string when the source exposes one
    /// — e.g. DoD's ZIP carries `v5_14` in its filename; webpki-
    /// roots' crate version. `None` for sources that have no
    /// version-string convention (Chromium preload JSON, FCPCA G2
    /// PEMs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_version: Option<String>,
}

impl Manifest {
    /// Load the manifest from disk. Returns `Default::default()`
    /// when the file doesn't exist or is malformed — the scanner
    /// treats a missing / corrupt manifest as "no cache available."
    pub fn load() -> Self {
        let Some(path) = manifest_path() else {
            return Self::default();
        };
        let Ok(bytes) = std::fs::read(&path) else {
            return Self::default();
        };
        match serde_json::from_slice::<Manifest>(&bytes) {
            Ok(mut m) => {
                // Future-proof: unknown higher versions are downgraded
                // to defaults so we don't misinterpret a forward-compat
                // field. Current version hasn't needed this yet.
                if m.version != MANIFEST_VERSION {
                    m = Self::default();
                }
                m
            }
            Err(_) => Self::default(),
        }
    }

    /// Persist the manifest to disk, creating the cache root if
    /// needed. Returns the path written on success.
    pub fn save(&self) -> Result<PathBuf, String> {
        let path =
            manifest_path().ok_or_else(|| "cache root unavailable (no HOME?)".to_string())?;
        if let Some(parent) = path.parent() {
            ensure_dir(parent)?;
        }
        let pretty =
            serde_json::to_vec_pretty(self).map_err(|e| format!("manifest serialize: {e}"))?;
        std::fs::write(&path, pretty)
            .map_err(|e| format!("manifest write {}: {e}", path.display()))?;
        Ok(path)
    }
}

/// Create a directory (and ancestors) if missing. Errors surface
/// as human-readable strings for top-level CLI reporting.
pub fn ensure_dir(path: &Path) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(|e| format!("create {}: {e}", path.display()))
}

/// Compute SHA-256 hex of a byte slice — used for manifest
/// `sha256` fields and for the scanner's on-load integrity check.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut s = String::with_capacity(out.len() * 2);
    for b in out {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Read a cached bundle file and verify it matches the manifest's
/// recorded SHA-256. Returns `None` when:
/// - the file doesn't exist
/// - the manifest has no entry for this bundle
/// - the file's hash doesn't match (treat as corrupt; fall back to
///   compile-time)
///
/// A manifest mismatch is logged at debug level but the scanner
/// still falls back cleanly — refreshing via
/// `--update-trust-stores` fixes it.
pub fn read_verified(path: &Path, bundle_name: &str) -> Option<Vec<u8>> {
    let bytes = std::fs::read(path).ok()?;
    let manifest = Manifest::load();
    let Some(meta) = manifest.bundles.get(bundle_name) else {
        // No manifest entry. The file exists but we have no record
        // of provenance — treat conservatively as unavailable to
        // avoid honoring untracked on-disk state.
        tracing::debug!(
            %bundle_name,
            "cache file exists but manifest has no entry; ignoring"
        );
        return None;
    };
    let actual = sha256_hex(&bytes);
    if actual != meta.sha256 {
        tracing::debug!(
            %bundle_name,
            expected = %meta.sha256,
            actual = %actual,
            "cache file SHA-256 mismatch; ignoring"
        );
        return None;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_is_lowercase_64_chars() {
        let h = sha256_hex(b"");
        assert_eq!(h.len(), 64);
        assert!(h
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // Known empty-string SHA-256.
        assert_eq!(
            h,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn manifest_default_is_empty_current_version() {
        let m = Manifest::default();
        assert_eq!(m.version, MANIFEST_VERSION);
        assert!(m.bundles.is_empty());
    }

    #[test]
    fn manifest_roundtrips_through_json() {
        let mut m = Manifest::default();
        m.bundles.insert(
            "apple".to_string(),
            BundleMetadata {
                source: "macOS System Roots keychain".to_string(),
                fetched_at: "2026-04-23T02:00:00Z".to_string(),
                sha256: "abc".to_string(),
                entry_count: 160,
                upstream_version: None,
            },
        );
        let json = serde_json::to_string(&m).unwrap();
        let back: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.version, MANIFEST_VERSION);
        assert_eq!(back.bundles.len(), 1);
        assert_eq!(back.bundles["apple"].entry_count, 160);
    }

    #[test]
    fn cache_root_returns_platform_path_or_none() {
        // On any sane build environment this resolves; on rare CI
        // setups where HOME is unset it returns None. Test both
        // paths are shape-compatible.
        let root = cache_root();
        if let Some(p) = root {
            let s = p.display().to_string();
            assert!(s.contains("kemist"), "expected `kemist` in path: {s}");
        }
    }
}
