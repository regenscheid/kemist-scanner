//! Output layer.
//!
//! `json` submodule owns the schema-v1 emission path (the canonical form).
//! `text` submodule renders a compact human-readable summary of the same
//! `ScanResult` for interactive debugging.

pub mod json;
pub mod text;

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
