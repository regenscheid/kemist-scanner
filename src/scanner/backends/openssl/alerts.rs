//! Shared OpenSSL error → `ScannerError` classifier.
//!
//! Parallels [`crate::scanner::ciphers::classify_probe_error`] on the rustls
//! side — maps `openssl::ssl::Error` into the same `tls_alert_<snake_name>`
//! categories that rule engines already key on. Load-bearing invariant:
//! downstream consumers should not need to know which backend produced a
//! given alert.
//!
//! Extraction strategy per the plan's risk mitigation (openssl-src reason-name
//! renames have historically broken string matchers):
//! 1. Numeric path — walk the `ErrorStack`, read `reason_code()` directly,
//!    and extract the alert byte. OpenSSL packs TLS alert reason codes as
//!    `1000 + alert_code` across the `SSL_R_{SSLV3,TLSV1}_ALERT_*` families.
//! 2. String fallback — match `reason()` against known patterns if the
//!    numeric path misses.
//! 3. Unknown alerts fall through to `tls_alert_unknown` with the numeric
//!    value preserved in the context string.

use openssl::ssl::{Error as SslError, ErrorCode};

use crate::model::errors::ScannerError;

/// Map a TLS alert numeric code (RFC 8446 §6) to its snake_case name.
///
/// Used by [`classify_openssl_error`] to produce stable `tls_alert_<name>`
/// categories. Returns `"unknown"` for unmapped codes — callers that want
/// to preserve the numeric value should include it in their context string.
pub fn alert_code_to_name(code: u8) -> &'static str {
    match code {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        21 => "decryption_failed",
        22 => "record_overflow",
        30 => "decompression_failure",
        40 => "handshake_failure",
        41 => "no_certificate",
        42 => "bad_certificate",
        43 => "unsupported_certificate",
        44 => "certificate_revoked",
        45 => "certificate_expired",
        46 => "certificate_unknown",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        49 => "access_denied",
        50 => "decode_error",
        51 => "decrypt_error",
        60 => "export_restriction",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        90 => "user_canceled",
        100 => "no_renegotiation",
        109 => "missing_extension",
        110 => "unsupported_extension",
        111 => "certificate_unobtainable",
        112 => "unrecognized_name",
        113 => "bad_certificate_status_response",
        114 => "bad_certificate_hash_value",
        115 => "unknown_psk_identity",
        116 => "certificate_required",
        120 => "no_application_protocol",
        _ => "unknown",
    }
}

/// Classify an `openssl::ssl::Error` into a [`ScannerError`]. The resulting
/// category matches the rustls-path taxonomy: `tls_alert_<name>`,
/// `connection_refused`, `connection_timeout`, etc.
///
/// `op` is a short human-readable label for the operation (e.g.
/// `"legacy handshake"`) and is prepended to the context string for
/// diagnosis.
pub fn classify_openssl_error(op: &str, e: &SslError) -> ScannerError {
    match e.code() {
        ErrorCode::SYSCALL => match e.io_error() {
            // SYSCALL with an inner io::Error: defer to the shared io
            // classifier so connection_refused / network_unreachable /
            // connection_timeout categories land consistently.
            Some(io) => ScannerError::from_io(op, clone_io_error(io)),
            // SYSCALL without an inner error usually means unexpected EOF —
            // often a server that hard-closes on an unacceptable ClientHello.
            None => ScannerError::connection_refused(format!("{op}: unexpected EOF")),
        },
        ErrorCode::SSL => match e.ssl_error() {
            Some(stack) => classify_error_stack(op, stack),
            None => ScannerError::internal(format!("{op}: SSL error without stack")),
        },
        ErrorCode::ZERO_RETURN => {
            ScannerError::tls_alert("close_notify", format!("{op}: peer sent close_notify"))
        }
        // WANT_READ / WANT_WRITE should not surface here — the async SSL
        // wrapper handles the retry loop. Seeing one means a logic bug
        // above us. Record as internal so it doesn't masquerade as a
        // server-side signal.
        code => {
            ScannerError::internal(format!("{op}: unexpected SSL error code {}", code.as_raw()))
        }
    }
}

/// Walk an `ErrorStack` for an alert-bearing reason. Numeric path first,
/// string fallback second.
fn classify_error_stack(op: &str, stack: &openssl::error::ErrorStack) -> ScannerError {
    for err in stack.errors() {
        if let Some(alert_code) = alert_code_from_reason_code(err.reason_code()) {
            return ScannerError::tls_alert(alert_code_to_name(alert_code), format!("{op}: {err}"));
        }
        if let Some(alert_code) = alert_code_from_reason_string(err.reason()) {
            return ScannerError::tls_alert(alert_code_to_name(alert_code), format!("{op}: {err}"));
        }
    }

    // No alert found. Preserve the stack's top error as context.
    let ctx = stack
        .errors()
        .first()
        .map(|e| format!("{op}: {e}"))
        .unwrap_or_else(|| format!("{op}: empty error stack"));
    ScannerError::internal(ctx)
}

/// OpenSSL packs TLS alert reasons as `1000 + alert_code` across
/// `SSL_R_{SSLV3,TLSV1}_ALERT_*`. Extract the alert byte when the reason
/// code lands in that range.
fn alert_code_from_reason_code(reason: std::os::raw::c_int) -> Option<u8> {
    if (1000..=1999).contains(&reason) {
        let candidate = reason - 1000;
        if candidate <= u8::MAX as std::os::raw::c_int {
            return Some(candidate as u8);
        }
    }
    None
}

/// Fallback path: match OpenSSL's human-readable reason string. Kept narrow
/// so string churn in a minor OpenSSL bump fails a unit test rather than
/// silently misclassifying. The numeric path handles the happy case; this
/// catches only the reason names that don't fit the `1000 + code` packing.
fn alert_code_from_reason_string(reason: Option<&'static str>) -> Option<u8> {
    let r = reason?.to_lowercase();
    // Format: "<version> alert <name>" — e.g. "tlsv1 alert inappropriate fallback".
    let needle = " alert ";
    let idx = r.find(needle)?;
    let name = r[idx + needle.len()..].trim().replace(' ', "_");
    alert_name_to_code(&name)
}

/// Reverse lookup, used only by the string-fallback path.
fn alert_name_to_code(name: &str) -> Option<u8> {
    // Inverse of `alert_code_to_name` for the 15 entries rule engines
    // actually consume. Non-exhaustive on purpose — obscure alerts can
    // fall through to the numeric path.
    match name {
        "close_notify" => Some(0),
        "unexpected_message" => Some(10),
        "handshake_failure" => Some(40),
        "bad_certificate" => Some(42),
        "unsupported_certificate" => Some(43),
        "illegal_parameter" => Some(47),
        "decode_error" => Some(50),
        "protocol_version" => Some(70),
        "insufficient_security" => Some(71),
        "internal_error" => Some(80),
        "inappropriate_fallback" => Some(86),
        "no_renegotiation" => Some(100),
        "missing_extension" => Some(109),
        "unrecognized_name" => Some(112),
        "certificate_required" => Some(116),
        _ => None,
    }
}

/// `io::Error` isn't `Clone`; reconstruct a shallow copy so we can feed it
/// to `ScannerError::from_io` without consuming the borrow.
fn clone_io_error(e: &std::io::Error) -> std::io::Error {
    std::io::Error::new(e.kind(), e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_code_table_covers_rfc8446_section6() {
        // The 15 codes called out in the plan's §8.8 table — the set rule
        // engines rely on. New additions go here so schema consumers notice.
        let expected: &[(u8, &str)] = &[
            (0, "close_notify"),
            (10, "unexpected_message"),
            (40, "handshake_failure"),
            (42, "bad_certificate"),
            (43, "unsupported_certificate"),
            (47, "illegal_parameter"),
            (50, "decode_error"),
            (70, "protocol_version"),
            (71, "insufficient_security"),
            (80, "internal_error"),
            (86, "inappropriate_fallback"),
            (100, "no_renegotiation"),
            (109, "missing_extension"),
            (112, "unrecognized_name"),
            (116, "certificate_required"),
        ];
        for (code, name) in expected {
            assert_eq!(
                alert_code_to_name(*code),
                *name,
                "alert code {} should map to {}",
                code,
                name
            );
        }
    }

    #[test]
    fn unknown_alert_code_returns_unknown() {
        assert_eq!(alert_code_to_name(255), "unknown");
        assert_eq!(alert_code_to_name(99), "unknown");
    }

    #[test]
    fn numeric_reason_code_extraction() {
        // SSL_R_TLSV1_ALERT_INAPPROPRIATE_FALLBACK = 1086 → alert 86
        assert_eq!(alert_code_from_reason_code(1086), Some(86));
        // SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE = 1040 → alert 40
        assert_eq!(alert_code_from_reason_code(1040), Some(40));
        // SSL_R_TLSV1_ALERT_PROTOCOL_VERSION = 1070 → alert 70
        assert_eq!(alert_code_from_reason_code(1070), Some(70));
        // Boundary cases
        assert_eq!(alert_code_from_reason_code(999), None);
        assert_eq!(alert_code_from_reason_code(2000), None);
        // Out-of-u8 range lands None — packed alerts never exceed 255
        assert_eq!(alert_code_from_reason_code(1300), None);
    }

    #[test]
    fn string_fallback_parses_openssl_reason_format() {
        assert_eq!(
            alert_code_from_reason_string(Some("tlsv1 alert inappropriate fallback")),
            Some(86)
        );
        assert_eq!(
            alert_code_from_reason_string(Some("sslv3 alert handshake failure")),
            Some(40)
        );
        assert_eq!(
            alert_code_from_reason_string(Some("tlsv13 alert certificate required")),
            Some(116)
        );
    }

    #[test]
    fn string_fallback_rejects_non_alert_reasons() {
        assert_eq!(alert_code_from_reason_string(None), None);
        assert_eq!(
            alert_code_from_reason_string(Some("some other reason")),
            None
        );
        assert_eq!(alert_code_from_reason_string(Some("alert")), None);
    }

    #[test]
    fn reverse_lookup_round_trips_15_core_codes() {
        for code in [
            0, 10, 40, 42, 43, 47, 50, 70, 71, 80, 86, 100, 109, 112, 116,
        ] {
            let name = alert_code_to_name(code);
            assert_eq!(
                alert_name_to_code(name),
                Some(code),
                "reverse lookup failed for {}",
                name
            );
        }
    }

    // `classify_openssl_error` is exercised at integration level — the
    // openssl crate doesn't expose a public constructor for `SslError`
    // with arbitrary cause, so unit tests can only reach the pure helpers
    // above. The docker-fixture integration tests in
    // `tests/openssl_probe.rs` cover the classifier against real
    // handshake failures.
}
