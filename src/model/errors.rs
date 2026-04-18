//! Structured scanner errors.
//!
//! Every probe-level failure produces a `ScannerError` that accumulates into
//! `ScanResults.scan_errors`, is copied through to the schema-v1 `errors` array,
//! and keeps the scan running. The scanner never aborts on a single probe
//! failure — the final record is always complete-shaped even if every probe
//! failed.
//!
//! Wire shape (serialized): `{category, context, timestamp}` — stable across
//! schema-v1 minor bumps. Rust-side constructors keep internal call sites
//! concise while ensuring `category` strings match the spec's canonical list.

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fmt;

/// Canonical error categories from the scanner spec. The category string on
/// the wire is the snake_case enum name, except `tls_alert_<name>` which
/// carries the specific alert identifier as a suffix per the spec.
///
/// This type is also the schema-v1 `errors[]` record shape — it has no
/// separate wire representation.
#[derive(Debug, Clone, Serialize)]
pub struct ScannerError {
    pub category: String,
    pub context: String,
    pub timestamp: DateTime<Utc>,
}

impl ScannerError {
    fn new(category: &str, context: impl Into<String>) -> Self {
        Self {
            category: category.to_string(),
            context: context.into(),
            timestamp: Utc::now(),
        }
    }

    pub fn dns_resolution_failed(context: impl Into<String>) -> Self {
        Self::new("dns_resolution_failed", context)
    }

    pub fn network_unreachable(context: impl Into<String>) -> Self {
        Self::new("network_unreachable", context)
    }

    pub fn connection_refused(context: impl Into<String>) -> Self {
        Self::new("connection_refused", context)
    }

    pub fn connection_timeout(context: impl Into<String>) -> Self {
        Self::new("connection_timeout", context)
    }

    pub fn handshake_timeout(context: impl Into<String>) -> Self {
        Self::new("handshake_timeout", context)
    }

    /// TLS alert observed during handshake. `alert_name` is the snake_case
    /// alert identifier (e.g. `"handshake_failure"`, `"bad_certificate"`).
    pub fn tls_alert(alert_name: &str, context: impl Into<String>) -> Self {
        Self::new(&format!("tls_alert_{}", alert_name), context)
    }

    pub fn cert_parse_error(context: impl Into<String>) -> Self {
        Self::new("cert_parse_error", context)
    }

    pub fn extension_parse_error(context: impl Into<String>) -> Self {
        Self::new("extension_parse_error", context)
    }

    pub fn http_error(context: impl Into<String>) -> Self {
        Self::new("http_error", context)
    }

    /// Fallback for unclassified failures. Populated context should describe
    /// the operation that failed — downstream consumers use `category` first,
    /// `context` for incident diagnosis.
    pub fn internal(context: impl Into<String>) -> Self {
        Self::new("internal_scanner_error", context)
    }

    /// Classify a `std::io::Error` into a ScannerError category. Inspects
    /// `ErrorKind` first, then falls back to string heuristics for TLS
    /// alerts surfaced through tokio_rustls. PR 5 will replace string
    /// matching with direct rustls connection-state inspection where
    /// available.
    pub fn from_io(op: &str, e: std::io::Error) -> Self {
        use std::io::ErrorKind;
        let ctx = format!("{op}: {e}");
        match e.kind() {
            ErrorKind::ConnectionRefused => Self::connection_refused(ctx),
            ErrorKind::TimedOut => Self::connection_timeout(ctx),
            ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset => {
                Self::connection_refused(ctx)
            }
            _ => {
                let msg = e.to_string().to_lowercase();
                if msg.contains("unreachable") {
                    Self::network_unreachable(ctx)
                } else if let Some(alert_name) = extract_tls_alert_name(&msg) {
                    Self::tls_alert(&alert_name, ctx)
                } else {
                    Self::internal(ctx)
                }
            }
        }
    }
}

/// Best-effort extractor for "received ... alert" / "peer sent alert" style
/// messages from rustls. Returns a snake_case alert identifier or `None`.
fn extract_tls_alert_name(msg: &str) -> Option<String> {
    let msg = msg.to_lowercase();
    if !(msg.contains("alert")) {
        return None;
    }
    // Walk tokens looking for the word following "alert" or "received".
    for candidate in ["alert ", "alert:", "alert("] {
        if let Some(idx) = msg.find(candidate) {
            let rest = &msg[idx + candidate.len()..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    Some("unknown".to_string())
}

impl fmt::Display for ScannerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.category, self.context)
    }
}

impl std::error::Error for ScannerError {}

impl From<std::io::Error> for ScannerError {
    fn from(e: std::io::Error) -> Self {
        Self::from_io("io", e)
    }
}

impl From<tokio::time::error::Elapsed> for ScannerError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        Self::connection_timeout("tokio timeout elapsed")
    }
}

impl From<serde_json::Error> for ScannerError {
    fn from(e: serde_json::Error) -> Self {
        Self::internal(format!("serde_json: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_strings_are_snake_case_and_stable() {
        assert_eq!(
            ScannerError::dns_resolution_failed("x").category,
            "dns_resolution_failed"
        );
        assert_eq!(
            ScannerError::tls_alert("handshake_failure", "x").category,
            "tls_alert_handshake_failure"
        );
        assert_eq!(
            ScannerError::internal("x").category,
            "internal_scanner_error"
        );
    }

    #[test]
    fn io_classification_respects_error_kind() {
        use std::io::{Error, ErrorKind};
        let refused = Error::new(ErrorKind::ConnectionRefused, "nope");
        assert_eq!(
            ScannerError::from_io("op", refused).category,
            "connection_refused"
        );

        let timed_out = Error::new(ErrorKind::TimedOut, "slow");
        assert_eq!(
            ScannerError::from_io("op", timed_out).category,
            "connection_timeout"
        );
    }

    #[test]
    fn tls_alert_extraction_from_rustls_style_messages() {
        let e = std::io::Error::other("received fatal alert: bad_certificate");
        let se = ScannerError::from_io("tls", e);
        assert!(se.category.starts_with("tls_alert_"));
    }
}
