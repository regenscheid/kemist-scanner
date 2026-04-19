//! Validates that a freshly built ScanResult (with every field populated by the
//! PR 2 conversion layer) conforms to schemas/output-v1.json.
//!
//! Later PRs add real probe-derived values; this test only guards the shape
//! contract, which must never regress even when values change.

use chrono::{TimeZone, Utc};
use kemist::model::errors::ScannerError;
use kemist::model::protocol::{ProtocolSupport, TlsVersion};
use kemist::output::json::{build_scan_result, JsonEmitContext};
use kemist::scanner::{ScanResults, TlsRenegotiation};

fn fixture_results() -> ScanResults {
    ScanResults {
        target: "127.0.0.1:443".to_string(),
        hostname: "example.test".to_string(),
        port: 443,
        scan_time: Utc.with_ymd_and_hms(2026, 4, 17, 14, 0, 0).unwrap(),
        protocol_support: vec![
            ProtocolSupport {
                version: TlsVersion::Ssl2,
                supported: false,
                error: None,
            },
            ProtocolSupport {
                version: TlsVersion::Ssl3,
                supported: false,
                error: None,
            },
            ProtocolSupport {
                version: TlsVersion::Tls10,
                supported: false,
                error: None,
            },
            ProtocolSupport {
                version: TlsVersion::Tls11,
                supported: false,
                error: None,
            },
            ProtocolSupport {
                version: TlsVersion::Tls12,
                supported: true,
                error: None,
            },
            ProtocolSupport {
                version: TlsVersion::Tls13,
                supported: true,
                error: None,
            },
        ],
        certificate_chain: vec![],
        tls_renegotiation: TlsRenegotiation {
            secure_renegotiation: Some(true),
            compression_supported: Some(false),
        },
        heartbeat_echoes_oversized_payload: Some(false),
        fallback_scsv_accepted: Some(true),
        negotiated: None,
        alpn_offered: vec![],
        validation: kemist::scanner::probe::ValidationResult::default(),
        cipher_probes: None,
        group_probes: None,
        sni_behavior: None,
        hello_observed: None,
        http_observations: None,
        #[cfg(feature = "legacy-probes")]
        openssl_observations: None,
        scan_errors: vec![],
    }
}

fn fixture_ctx() -> JsonEmitContext {
    JsonEmitContext {
        host: "example.test".to_string(),
        port: 443,
        sni_sent: "example.test".to_string(),
        resolved_ip: Some("127.0.0.1".to_string()),
        started_at: Utc.with_ymd_and_hms(2026, 4, 17, 14, 0, 0).unwrap(),
        completed_at: Utc.with_ymd_and_hms(2026, 4, 17, 14, 0, 8).unwrap(),
        enabled_features: vec![],
        config_paths: vec![],
    }
}

fn load_schema() -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("schemas/output-v1.json");
    let bytes = std::fs::read(&path).expect("schemas/output-v1.json must be present");
    serde_json::from_slice(&bytes).expect("schema must parse as JSON")
}

#[test]
fn empty_fixture_record_matches_schema_v1() {
    let results = fixture_results();
    let ctx = fixture_ctx();
    let record = build_scan_result(&results, &ctx);

    let record_value = serde_json::to_value(&record).expect("serialize");
    let schema_value = load_schema();

    let validator = jsonschema::validator_for(&schema_value).expect("schema compiles");
    let errors: Vec<_> = validator.iter_errors(&record_value).collect();
    if !errors.is_empty() {
        for e in &errors {
            eprintln!("schema error at {}: {}", e.instance_path, e);
        }
        panic!(
            "ScanResult failed schema v1 validation with {} error(s)",
            errors.len()
        );
    }
}

#[test]
fn schema_version_is_pinned_to_1_0_0() {
    let results = fixture_results();
    let ctx = fixture_ctx();
    let record = build_scan_result(&results, &ctx);
    assert_eq!(record.schema_version, "1.0.0");
}

#[test]
fn duration_ms_computed_from_bookends() {
    let results = fixture_results();
    let ctx = fixture_ctx();
    let record = build_scan_result(&results, &ctx);
    assert_eq!(record.scan.duration_ms, 8_000);
}

#[test]
fn scan_errors_flow_through_to_output_record() {
    let mut results = fixture_results();
    results.scan_errors.push(ScannerError::connection_refused(
        "TCP connect refused by peer",
    ));
    results.scan_errors.push(ScannerError::tls_alert(
        "handshake_failure",
        "peer rejected ClientHello",
    ));

    let ctx = fixture_ctx();
    let record = build_scan_result(&results, &ctx);

    assert_eq!(record.errors.len(), 2);
    assert_eq!(record.errors[0].category, "connection_refused");
    assert_eq!(record.errors[1].category, "tls_alert_handshake_failure");

    // Record remains complete-shaped + schema-valid despite errors.
    let record_value = serde_json::to_value(&record).expect("serialize");
    let schema_value = load_schema();
    let validator = jsonschema::validator_for(&schema_value).expect("schema compiles");
    let errs: Vec<_> = validator.iter_errors(&record_value).collect();
    assert!(
        errs.is_empty(),
        "partial-failure record failed schema validation: {:?}",
        errs.iter()
            .map(|e| format!("{}: {}", e.instance_path, e))
            .collect::<Vec<_>>()
    );
}

#[test]
fn error_category_strings_are_canonical() {
    assert_eq!(
        ScannerError::dns_resolution_failed("x").category,
        "dns_resolution_failed"
    );
    assert_eq!(
        ScannerError::handshake_timeout("x").category,
        "handshake_timeout"
    );
    assert_eq!(
        ScannerError::tls_alert("bad_certificate", "x").category,
        "tls_alert_bad_certificate"
    );
}
