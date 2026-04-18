//! kemist — TLS + PQC observation scanner (library surface).
//!
//! ## Quick start
//!
//! ```no_run
//! use kemist::{Scanner, ScannerConfig, Target};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let scanner = Scanner::new(ScannerConfig::default());
//! let target = Target::parse("cloudflare.com:443")?;
//! let result = scanner.scan(target).await;
//! println!("{}", serde_json::to_string_pretty(&result)?);
//! # Ok(())
//! # }
//! ```
//!
//! ## Design contract
//! - [`Scanner::scan`] is infallible: it always returns a schema-v1
//!   [`ScanResult`], even when every probe failed. Partial data lives
//!   alongside [`ScannerError`] entries in the `errors` array.
//! - [`Scanner::scan_many`] bounds concurrency across distinct targets.
//!   Probes to a single target are always serialized.
//! - The emitted JSON validates against `schemas/output-v1.json`. No
//!   compliance verdicts, grades, or pass/fail judgments appear anywhere
//!   in the output.

pub mod model;
pub mod output;
pub mod scanner;

// Stable public API — these are the types downstream consumers import.
pub use crate::model::errors::ScannerError;
pub use crate::model::scan_result::ScanResult;
pub use crate::model::target::Target;
pub use crate::scanner::runner::{Scanner, ScannerConfig};
