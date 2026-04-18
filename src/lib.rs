//! kemist library surface.
//!
//! PR 2: exposes internal modules so `tests/` integration tests can build
//! `ScanResult` fixtures and validate them against `schemas/output-v1.json`.
//! PR 4 expands this into a stable public API (`Scanner`, `Target`, config).
//! Until then, downstream consumers should not depend on these re-exports.

pub mod model;
pub mod output;
pub mod scanner;
