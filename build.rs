//! Build-time code generation for kemist.
//!
//! Two tasks today:
//! 1. Trigger rebuild when `Cargo.toml` changes (for version strings).
//! 2. Parse the vendored Chromium HSTS preload snapshot
//!    (`data/hsts_preload_list.json`) into a compile-time
//!    `phf::Map<&'static str, bool>` written to
//!    `$OUT_DIR/hsts_preload.rs`. The runtime module at
//!    `src/scanner/http.rs` consumes it via `include!`.
//!
//! The preload JSON has JavaScript-style `//` comments, so we parse
//! it with `json5` rather than `serde_json`. Only entries with
//! `mode == "force-https"` are included — entries carrying HPKP pins
//! without HSTS don't count for preload-status.

use std::env;
use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct PreloadFile {
    entries: Vec<PreloadEntry>,
}

#[derive(Debug, Deserialize)]
struct PreloadEntry {
    name: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    include_subdomains: bool,
}

fn main() {
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=data/hsts_preload_list.json");

    build_preload_phf();
}

fn build_preload_phf() {
    let src = PathBuf::from("data/hsts_preload_list.json");
    let raw = fs::read_to_string(&src).unwrap_or_else(|e| {
        panic!(
            "failed to read HSTS preload snapshot at {}: {e}",
            src.display()
        )
    });

    let parsed: PreloadFile =
        json5::from_str(&raw).unwrap_or_else(|e| panic!("failed to parse {}: {e}", src.display()));

    // `entries` carries force-https, pinning-only, and other variants.
    // Only `mode == "force-https"` is an HSTS preload entry. Other
    // entries exist for HPKP (pins-only) and test fixtures and must
    // NOT register as preloaded.
    let mut map = phf_codegen::Map::<&str>::new();
    // We need the keys to outlive the builder since phf_codegen takes
    // `&str` with 'static lifetime from the caller's perspective.
    // Leak the parsed strings — they live for the entire build-script
    // process, which is exactly the phf_codegen build scope.
    let mut included = 0usize;
    for entry in parsed.entries {
        if entry.mode != "force-https" {
            continue;
        }
        let name = Box::leak(entry.name.into_boxed_str()) as &'static str;
        map.entry(name, &entry.include_subdomains.to_string());
        included += 1;
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR set by cargo"));
    let dest = out_dir.join("hsts_preload.rs");

    let body = format!(
        "/// Compile-time HSTS preload map generated from \
         `data/hsts_preload_list.json` by build.rs.\n\
         /// Key: host name (lowercase). Value: `include_subdomains`.\n\
         /// Count: {included} entries.\n\
         pub static HSTS_PRELOAD: phf::Map<&'static str, bool> = {};\n",
        map.build()
    );
    fs::write(&dest, body).unwrap_or_else(|e| panic!("failed to write {}: {e}", dest.display()));

    println!("cargo:warning=generated HSTS preload PHF with {included} entries");
}
