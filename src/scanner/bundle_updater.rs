//! Orchestrator for `kemist --update-trust-stores` /
//! `--update-hsts-preload`. Calls the per-bundle fetchers in
//! [`crate::scanner::bundle_fetcher`], writes each bundle + its
//! manifest entry to the platform cache directory via
//! [`crate::scanner::bundle_cache`].
//!
//! Failure semantics: one failed fetch does NOT halt the others.
//! Each bundle produces either an `Ok` that updates the manifest
//! or an `Err(reason)` that's logged but leaves the prior cached
//! bundle + manifest entry (if any) untouched. The exit code
//! reflects whether ANY bundle failed — operators running under
//! cron can alert on non-zero.

#![cfg(all(feature = "http-checks", feature = "legacy-probes"))]

use std::path::Path;

use crate::scanner::bundle_cache::{
    ensure_dir, sha256_hex, trust_store_dir, BundleMetadata, Manifest,
};
use crate::scanner::bundle_fetcher;

/// Per-bundle update result surfaced to the CLI for human-readable
/// reporting.
pub struct UpdateReport {
    pub name: String,
    pub outcome: Result<UpdateOk, String>,
}

pub struct UpdateOk {
    pub path: std::path::PathBuf,
    pub entry_count: usize,
    pub bytes: usize,
    pub sha256_prefix: String,
}

/// Refresh every compiled trust store. Returns per-bundle results
/// in invocation order. Writes the updated manifest once all
/// fetches have completed so a crash mid-way leaves the old
/// manifest entries for the succeeded-but-not-yet-manifested
/// bundles intact.
pub async fn update_all_trust_stores() -> Vec<UpdateReport> {
    let mut reports = Vec::new();
    let mut manifest = Manifest::load();

    let Some(dir) = trust_store_dir() else {
        reports.push(UpdateReport {
            name: "<setup>".to_string(),
            outcome: Err(
                "cache directory unavailable (directories crate returned None)".to_string(),
            ),
        });
        return reports;
    };
    if let Err(e) = ensure_dir(&dir) {
        reports.push(UpdateReport {
            name: "<setup>".to_string(),
            outcome: Err(format!("failed to create cache dir: {e}")),
        });
        return reports;
    }

    // Order matches the plan's compiled-store sequence. webpki-roots
    // isn't refreshable from the network (it's a Rust crate); we skip
    // it here — `cargo update` is the refresh path.
    for (name, fetcher) in per_bundle_fetchers() {
        let report = refresh_one(name, &dir, &mut manifest, fetcher).await;
        reports.push(report);
    }

    // Apple on non-macOS hosts: there's no portable way to extract
    // the macOS System Roots keychain. Report explicitly so
    // operators know why the bundle didn't refresh.
    reports.push(UpdateReport {
        name: "apple".to_string(),
        outcome: Err(apple_refresh_note()),
    });

    if let Err(e) = manifest.save() {
        reports.push(UpdateReport {
            name: "<manifest>".to_string(),
            outcome: Err(format!("manifest save: {e}")),
        });
    }
    reports
}

/// Refresh just the HSTS preload list. Uses the same manifest
/// file as the trust-store refresh.
pub async fn update_hsts_preload() -> UpdateReport {
    let mut manifest = Manifest::load();
    let Some(path) = crate::scanner::bundle_cache::hsts_preload_path() else {
        return UpdateReport {
            name: "hsts_preload".to_string(),
            outcome: Err("cache path unavailable".to_string()),
        };
    };
    if let Some(parent) = path.parent() {
        if let Err(e) = ensure_dir(parent) {
            return UpdateReport {
                name: "hsts_preload".to_string(),
                outcome: Err(format!("cache dir: {e}")),
            };
        }
    }
    let outcome = match bundle_fetcher::fetch_hsts_preload().await {
        Ok((bytes, mut meta)) => match std::fs::write(&path, &bytes) {
            Ok(()) => {
                meta.sha256 = sha256_hex(&bytes);
                manifest
                    .bundles
                    .insert("hsts_preload".to_string(), meta.clone());
                let _ = manifest.save();
                Ok(UpdateOk {
                    path,
                    entry_count: meta.entry_count,
                    bytes: bytes.len(),
                    sha256_prefix: meta.sha256[..16].to_string(),
                })
            }
            Err(e) => Err(format!("write cache file: {e}")),
        },
        Err(e) => Err(e),
    };
    UpdateReport {
        name: "hsts_preload".to_string(),
        outcome,
    }
}

/// Pretty-print a batch of reports for the CLI. Returns `true`
/// when every entry succeeded.
pub fn print_reports(label: &str, reports: &[UpdateReport]) -> bool {
    let mut ok = true;
    println!("kemist {label} update:");
    for r in reports {
        match &r.outcome {
            Ok(o) => {
                println!(
                    "  {:20} ok  {} entries, {} bytes, sha256 {}...",
                    r.name, o.entry_count, o.bytes, o.sha256_prefix
                );
            }
            Err(e) => {
                ok = false;
                println!("  {:20} FAILED: {}", r.name, e);
            }
        }
    }
    ok
}

/// Note emitted for the Apple bundle on non-macOS hosts, or as an
/// informational "refresh via keychain" pointer on macOS. The
/// fetcher module can't cross-compile `security find-certificate`
/// into a portable binary; documenting here keeps the refresh path
/// visible to operators.
fn apple_refresh_note() -> String {
    if cfg!(target_os = "macos") {
        "apple: refresh not yet automated — run `security find-certificate -a -p \
         /System/Library/Keychains/SystemRootCertificates.keychain > \
         $(kemist --cache-dir)/trust_stores/apple.pem` to refresh manually \
         (the `directories` cache path is the same one `--update-trust-stores` writes to)"
            .to_string()
    } else {
        "apple: no portable refresh path — Apple's TLS trust store lives in the \
         macOS System Roots keychain and requires `security find-certificate` to \
         extract. Refresh from a Mac and copy the resulting PEM to this host's \
         cache dir, or leave the compile-time bundle in place."
            .to_string()
    }
}

type BundleFetchFn =
    fn() -> futures::future::BoxFuture<'static, Result<(Vec<u8>, BundleMetadata), String>>;

fn per_bundle_fetchers() -> Vec<(&'static str, BundleFetchFn)> {
    vec![
        ("microsoft", || Box::pin(bundle_fetcher::fetch_microsoft())),
        ("us-fpki-common", || {
            Box::pin(bundle_fetcher::fetch_us_fpki_common())
        }),
        ("us-dod", || Box::pin(bundle_fetcher::fetch_us_dod())),
    ]
}

async fn refresh_one(
    name: &str,
    dir: &Path,
    manifest: &mut Manifest,
    fetcher: BundleFetchFn,
) -> UpdateReport {
    let path = dir.join(format!("{name}.pem"));
    let outcome = match fetcher().await {
        Ok((bytes, mut meta)) => match std::fs::write(&path, &bytes) {
            Ok(()) => {
                let digest = sha256_hex(&bytes);
                meta.sha256 = digest.clone();
                manifest.bundles.insert(name.to_string(), meta.clone());
                Ok(UpdateOk {
                    path: path.clone(),
                    entry_count: meta.entry_count,
                    bytes: bytes.len(),
                    sha256_prefix: digest[..16].to_string(),
                })
            }
            Err(e) => Err(format!("write {}: {e}", path.display())),
        },
        Err(e) => Err(e),
    };
    UpdateReport {
        name: name.to_string(),
        outcome,
    }
}
