//! **kemist** — TLS + PQC observation scanner.
//!
//! kemist records what a TLS server supports and emits structured JSON
//! that downstream rule engines consume. It is a **pure sensor**: no
//! compliance verdicts, grades, or pass/fail judgments appear in its
//! output. That split is deliberate and permanent — rule evaluation
//! lives in separate projects.
//!
//! # Quick start
//!
//! ```no_run
//! use kemist::{Scanner, ScannerConfig, Target};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! // Install the rustls crypto provider (required once, process-wide).
//! rustls::crypto::aws_lc_rs::default_provider()
//!     .install_default()
//!     .expect("install rustls provider");
//!
//! let scanner = Scanner::new(ScannerConfig::default());
//! let target = Target::parse("pq.cloudflareresearch.com:443")?;
//! let result = scanner.scan(target).await;
//!
//! println!("{}", serde_json::to_string_pretty(&result)?);
//! # Ok(())
//! # }
//! ```
//!
//! # Design contract
//!
//! - [`Scanner::scan`] is **infallible**: it always returns a schema-v1
//!   [`ScanResult`], even when every probe failed. Partial observations
//!   coexist with [`ScannerError`] entries in the `errors` array.
//! - [`Scanner::scan_many`] bounds concurrency across distinct targets
//!   via `tokio::sync::Semaphore`. Probes to a single target are always
//!   serialized — no parallel connections to the same host.
//! - Emitted JSON validates against `schemas/output-v1.json` (draft-2020).
//!   Schema versioning is semver over shape — consumers pin on the major.
//! - No compliance verdicts appear anywhere in the output. Searching the
//!   schema or any emitted record for `grade`, `verdict`, `severity`,
//!   `weak`, `compliant`, `pass`, `fail` returns zero matches. (Except
//!   `downgrade_signaling.fallback_scsv_accepted` — the word "downgrade"
//!   is an observation category, not a verdict. The suffix `_accepted`
//!   refers to a wire-level server behavior.)
//!
//! # The tri-state contract
//!
//! Every probe-derived observation distinguishes four outcomes:
//!
//! ```text
//! {value: true,  method: "probe"}                          → probed, affirmative
//! {value: false, method: "probe"}                          → probed, server rejected on wire
//! {value: null,  method: "not_probed",     reason: "..."}  → probe not attempted
//! {value: null,  method: "not_applicable", reason: "..."}  → observation doesn't apply
//! {value: null,  method: "error",          reason: "..."}  → probe attempted, failed unexpectedly
//! {value: ...,   method: "connection_state"}               → read from rustls post-handshake state
//! ```
//!
//! **Absence of probe is not absence of support.** Consumers MUST
//! treat `null + not_probed` as "unknown", never as "false".
//!
//! # Output schema
//!
//! Documentation: [`docs/OUTPUT_SCHEMA.md`](https://github.com/andrewre/kemist/blob/main/docs/OUTPUT_SCHEMA.md).
//! Formal JSON Schema: [`schemas/output-v1.json`](https://github.com/andrewre/kemist/blob/main/schemas/output-v1.json).
//!
//! # Observation catalog
//!
//! See [`docs/CHECKS.md`](https://github.com/andrewre/kemist/blob/main/docs/CHECKS.md)
//! for what kemist observes, how it observes each thing, and where the
//! coverage gaps are.
//!
//! # Integration guide
//!
//! See [`docs/INTEGRATION.md`](https://github.com/andrewre/kemist/blob/main/docs/INTEGRATION.md)
//! for patterns on building rule engines, compliance scorecards, and PQC
//! readiness dashboards on top of kemist's output.

pub mod model;
pub mod output;
pub mod scanner;

// Stable public API. These types define the contract downstream
// consumers depend on; internal module reshaping won't change them.
pub use crate::model::errors::ScannerError;
pub use crate::model::scan_result::ScanResult;
pub use crate::model::target::Target;
pub use crate::scanner::runner::{Scanner, ScannerConfig};
