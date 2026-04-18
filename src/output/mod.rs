//! Output layer.
//!
//! `json` submodule owns the schema-v1 emission path (the canonical form).
//! The old legacy text/XML emitters were deleted once PR 4 gave main.rs
//! its own `print_text_summary` over `ScanResult`, and PR 7 removed the
//! last references to the legacy `ScanResults` cipher fields. PR 12 will
//! add a dedicated schema-aware text renderer.

pub mod json;

use clap::ValueEnum;

use crate::model::errors::ScannerError;
use crate::scanner::ScanResults;

pub use json::JsonEmitContext;

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum OutputFormat {
    Text,
    Json,
    JsonPretty,
}

pub fn print_json_results(
    results: &ScanResults,
    ctx: &JsonEmitContext,
    pretty: bool,
) -> Result<(), ScannerError> {
    if pretty {
        json::print_json_pretty(results, ctx)
    } else {
        json::print_json(results, ctx)
    }
}

pub fn save_results(
    results: &ScanResults,
    ctx: &JsonEmitContext,
    path: &str,
    _format: OutputFormat,
) -> Result<(), ScannerError> {
    // File output is JSON regardless of format (text format to a file was
    // never well-defined). main.rs handles NDJSON / per-target file routing
    // directly against the schema-v1 `ScanResult`.
    json::write_json(results, ctx, path)
}
