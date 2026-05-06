//! Validates that a freshly built `ScanResult` conforms to
//! `schemas/output-v1.json`.
//!
//! Probe-derived values change over time; this test only guards the
//! shape contract, which must never regress.

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
        negotiated: None,
        alpn_offered: vec![],
        validation: kemist::scanner::probe::ValidationResult::default(),
        cipher_probes: None,
        group_probes: None,
        sni_behavior: None,
        hello_observed: None,
        hrr_observed: None,
        sslv2_observation: None,
        alpn_matrix: None,
        #[cfg(all(feature = "http-checks", feature = "legacy-probes"))]
        ocsp_http_fetch: None,
        #[cfg(feature = "http-checks")]
        crl_fetch: None,
        cert_chain_der: Vec::new(),
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
        include_ocsp_raw: false,
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
            "ScanResult failed schema validation with {} error(s)",
            errors.len()
        );
    }
}

#[test]
fn schema_version_is_pinned_to_2_0_0() {
    let results = fixture_results();
    let ctx = fixture_ctx();
    let record = build_scan_result(&results, &ctx);
    assert_eq!(record.schema_version, "2.0.0");
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

// --------------------------------------------------------------------
// Legacy-probe output schema coverage. Synthesize a populated
// `OpensslObservations` and verify the resulting JSON still validates
// against `schemas/output-v1.json`, plus that every new `tls.*` section
// actually carries the values the builders produced.
// --------------------------------------------------------------------

#[cfg(feature = "legacy-probes")]
#[test]
fn fully_populated_openssl_observations_match_schema_v1() {
    use kemist::model::protocol::TlsVersion;
    use kemist::model::scan_result::{
        ConstrainedProbeResult, Method as ScanMethod, ObservationBool, SessionResumption,
        SigalgOutcome, SignatureAlgorithmPolicyProbe, Tls12Resumption, Tls13Resumption,
    };
    use kemist::scanner::backends::HandshakeOutcome;
    use kemist::scanner::openssl::{
        ciphers::{LegacyCipherProbeOutput, LegacyCipherResult},
        client_auth::{CaDnEntry, ClientAuthRequest, OidFilter},
        dh_params::{DhClassification, DhSnapshot},
        fallback_scsv::FallbackScsvResult,
        kx_groups::{KxGroupProbeOutput, KxGroupProbeResult},
        renegotiation::{RenegotiationObservation, RenegotiationVerdict},
        tls13_extensions::{DelegatedCredentialFacts, Tls13EncryptedExtensions},
        OpensslObservations,
    };

    // DH snapshot matching ffdhe2048 so the dh_parameters entry covers
    // the non-custom classification branch.
    let dh = DhSnapshot {
        prime_bits: 2048,
        generator: 2,
        prime_sha256: [
            0x9c, 0xd3, 0xb7, 0xf3, 0x36, 0x87, 0x2f, 0x46, 0xc0, 0x94, 0x28, 0xd1, 0xbb, 0xc1,
            0x98, 0x77, 0xa4, 0xd4, 0x40, 0x51, 0x2c, 0xda, 0x8d, 0x1c, 0x1c, 0xf0, 0xcd, 0x6e,
            0x33, 0x69, 0x89, 0x66,
        ],
        classification: DhClassification::Ffdhe2048,
    };

    // Cipher-probe list covering every cipher-side HandshakeOutcome variant and the
    // DHE + SKE-sig observer slots.
    let cipher_probes = LegacyCipherProbeOutput {
        results: vec![
            LegacyCipherResult {
                name: "TLS_RSA_WITH_AES_128_CBC_SHA".to_string(),
                openssl_name: "AES128-SHA".to_string(),
                iana_code: 0x002F,
                version: TlsVersion::Tls12,
                outcome: HandshakeOutcome::Supported,
                dh_snapshot: None,
                ske_sig: None,
            },
            LegacyCipherResult {
                name: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA".to_string(),
                openssl_name: "DHE-RSA-AES128-SHA".to_string(),
                iana_code: 0x0033,
                version: TlsVersion::Tls12,
                outcome: HandshakeOutcome::Supported,
                dh_snapshot: Some(dh.clone()),
                ske_sig: Some("rsa_pkcs1_sha1".to_string()),
            },
            LegacyCipherResult {
                name: "TLS_RSA_WITH_NULL_SHA".to_string(),
                openssl_name: "NULL-SHA".to_string(),
                iana_code: 0x0002,
                version: TlsVersion::Tls12,
                outcome: HandshakeOutcome::NotSupported,
                dh_snapshot: None,
                ske_sig: None,
            },
            LegacyCipherResult {
                name: "TLS_RSA_WITH_RC4_128_SHA".to_string(),
                openssl_name: "RC4-SHA".to_string(),
                iana_code: 0x0005,
                version: TlsVersion::Tls10,
                outcome: HandshakeOutcome::Error("connection_timeout".to_string()),
                dh_snapshot: None,
                ske_sig: None,
            },
            // Static-DH raw probe variant: server tore the connection
            // down with a TCP RST after our minimal ClientHello.
            // Renders as `supported: false` with the explicit reason
            // string capturing how the server rejected.
            LegacyCipherResult {
                name: "TLS_DH_RSA_WITH_AES_128_CBC_SHA".to_string(),
                openssl_name: "DH-RSA-AES128-SHA".to_string(),
                iana_code: 0x0031,
                version: TlsVersion::Tls12,
                outcome: HandshakeOutcome::WireRejected {
                    reason: "server_rst_after_clienthello".to_string(),
                },
                dh_snapshot: None,
                ske_sig: None,
            },
        ],
    };

    // Named-group probe: FFDHE rows exercising Supported / NotSupported /
    // IgnoredGroupReturnedDifferentPrime, plus a non-FFDHE row demonstrating
    // an OpenSSL override of an aws-lc-rs `not_probed` slot.
    //
    // The ffdhe3072 mismatch here triggers the cross-codepoint
    // coherence note. The ffdhe2048 self-match remains supported,
    // but both rows carry `reason:
    // server_does_not_honor_supported_groups` with returned-prime
    // evidence preserved.
    let kx_group_probes = KxGroupProbeOutput {
        results: vec![
            KxGroupProbeResult {
                group_name: "ffdhe2048".to_string(),
                iana_code: 0x0100,
                tls12_outcome: HandshakeOutcome::Supported,
                tls13_outcome: HandshakeOutcome::NotSupported,
            },
            KxGroupProbeResult {
                group_name: "ffdhe3072".to_string(),
                iana_code: 0x0101,
                tls12_outcome: HandshakeOutcome::IgnoredGroupReturnedDifferentPrime {
                    returned_group: "ffdhe2048".to_string(),
                    returned_prime_bits: 2048,
                },
                tls13_outcome: HandshakeOutcome::NotProbed("provider_limit".to_string()),
            },
            KxGroupProbeResult {
                group_name: "ffdhe4096".to_string(),
                iana_code: 0x0102,
                tls12_outcome: HandshakeOutcome::Error("tls_alert_protocol_version".to_string()),
                tls13_outcome: HandshakeOutcome::NotSupported,
            },
            KxGroupProbeResult {
                group_name: "secp521r1".to_string(),
                iana_code: 0x0019,
                tls12_outcome: HandshakeOutcome::NotProbed("tls12_not_applicable".to_string()),
                tls13_outcome: HandshakeOutcome::NotSupported,
            },
        ],
    };

    let fallback_scsv = FallbackScsvResult {
        enforced: Some(true),
        reason: "inappropriate_fallback_alert_at_tls1_2_with_server_max_tls1_3".to_string(),
    };

    let renegotiation = RenegotiationObservation {
        secure_renegotiation_advertised: None,
        client_initiated_verdict: RenegotiationVerdict::ClientInitiatedRejected,
        reason: Some("tls_alert_no_renegotiation".to_string()),
    };

    let client_auth = ClientAuthRequest {
        requested: true,
        certificate_types: vec![0x01, 0x40],
        signature_algorithms: vec![
            "ecdsa_secp256r1_sha256".to_string(),
            "rsa_pss_rsae_sha256".to_string(),
        ],
        ca_distinguished_names: vec![CaDnEntry {
            raw_der_b64: "3017310f300d06035504030c064b65696d737407".to_string(),
            common_name: Some("kemist test CA".to_string()),
            organization: Some("kemist".to_string()),
        }],
        oid_filters: vec![OidFilter {
            oid: "1.3.6.1.5.5.7.3.2".to_string(),
            values_b64: vec!["deadbeef".to_string()],
        }],
        alert_on_empty_cert: Some("tls_alert_certificate_required".to_string()),
        negotiated_version: Some("tls1_3".to_string()),
    };

    // TLS 1.3 EncryptedExtensions + Certificate observations. The DC
    // slot exercises the RFC 9345 populated shape.
    let tls13_ee = Tls13EncryptedExtensions {
        parsed: true,
        record_size_limit: Some(16385),
        compress_certificate_algorithms: vec!["zlib".to_string(), "brotli".to_string()],
        delegated_credential: Some(DelegatedCredentialFacts {
            valid_time_seconds: 604_800,
            expected_cert_verify_algorithm_code: 0x0403,
            expected_cert_verify_algorithm: "ecdsa_secp256r1_sha256".to_string(),
        }),
        error: None,
    };

    // Session resumption. TLS 1.2 fully populated via the two-connection
    // probe; TLS 1.3 slots deliberately NotProbed to exercise the
    // documented "pending follow-up" shape.
    let session_resumption = SessionResumption {
        tls1_2: Tls12Resumption {
            session_ticket_issued: ObservationBool::probe(true),
            ticket_lifetime_hint_secs: Some(7200),
            session_id_issued: ObservationBool::probe(true),
            ticket_rotated_across_connections: ObservationBool::probe(true),
            // Functional resumption results: this fixture mirrors the
            // cloudflare.com pattern that motivated the v2 split —
            // tickets resume successfully, session-ID caching does
            // not (server issues IDs but doesn't accept them back).
            session_ticket_resumption_accepted: ObservationBool::probe(true),
            session_id_resumption_accepted: ObservationBool::probe(false),
        },
        tls1_3: Tls13Resumption {
            new_session_ticket_count: None,
            ticket_lifetime_secs: Vec::new(),
            psk_resumption_accepted: ObservationBool::not_probed(
                "tls13_resumption_probe_not_implemented",
            ),
            early_data_accepted: ObservationBool::not_probed("early_data_probe_not_implemented"),
        },
    };

    // Sigalg policy probe. All five constraints populated,
    // mirroring the cloudflare.com real-scan shape (three complete
    // with distinct selected sigalgs, rsa_pkcs1_only refused).
    // ecdsa_only carries a different leaf fingerprint from the
    // other complete probes to exercise the dual-cert observation.
    let ecdsa_leaf_fp = "a".repeat(64);
    let rsa_leaf_fp = "b".repeat(64);
    let complete = |sigalg: &str, fp: &str| ConstrainedProbeResult {
        outcome: SigalgOutcome::HandshakeComplete,
        selected_sigalg: Some(sigalg.to_string()),
        alert: None,
        method: ScanMethod::Probe,
        reason: None,
        leaf_fingerprint_sha256: Some(fp.to_string()),
        leaf_subject_dn: Some("CN=example.com, O=Test, C=US".to_string()),
    };
    let sigalg_policy = SignatureAlgorithmPolicyProbe {
        sha256_plus_only: complete("ecdsa_secp256r1_sha256", &ecdsa_leaf_fp),
        ecdsa_only: complete("ecdsa_secp256r1_sha256", &ecdsa_leaf_fp),
        rsa_pss_only: complete("rsa_pss_rsae_sha256", &rsa_leaf_fp),
        rsa_pkcs1_only: ConstrainedProbeResult {
            outcome: SigalgOutcome::HandshakeFailure,
            selected_sigalg: None,
            alert: Some("tls_alert_handshake_failure".to_string()),
            method: ScanMethod::Probe,
            reason: Some("tls_alert_handshake_failure".to_string()),
            leaf_fingerprint_sha256: None,
            leaf_subject_dn: None,
        },
        eddsa_only: ConstrainedProbeResult {
            outcome: SigalgOutcome::HandshakeFailure,
            selected_sigalg: None,
            alert: Some("tls_alert_handshake_failure".to_string()),
            method: ScanMethod::Probe,
            reason: Some("tls_alert_handshake_failure".to_string()),
            leaf_fingerprint_sha256: None,
            leaf_subject_dn: None,
        },
    };

    // Ephemeral key reuse observation — DHE reused, ECDHE not
    // reused. Mirrors a realistic mixed signal the fixture emits to
    // exercise both populated branches.
    let ephemeral_key_reuse = kemist::model::scan_result::EphemeralKeyReuseObservation {
        dhe_public_reused_across_connections: ObservationBool::probe(true),
        ecdhe_public_reused_across_connections: ObservationBool::probe(false),
        dhe_suite_probed: Some("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256".to_string()),
        ecdhe_suite_probed: Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string()),
    };

    // ROBOT probe — five variants with varied outcomes covering each
    // branch of the classifier: alert, TCP reset, timeout, graceful
    // close, and unexpected plaintext.
    let bleichenbacher_oracle_probe = kemist::model::scan_result::BleichenbacherOracleProbe {
        rsa_kex_suite_probed: Some("TLS_RSA_WITH_AES_128_CBC_SHA".to_string()),
        method: ScanMethod::Probe,
        reason: None,
        per_variant: vec![
            kemist::model::scan_result::RobotVariantObservation {
                variant: "correctly_formatted_pkcs1".to_string(),
                alert_category: Some("tls_alert_bad_record_mac".to_string()),
                tcp_reset: false,
                elapsed_ms: 42,
                other_outcome: None,
            },
            kemist::model::scan_result::RobotVariantObservation {
                variant: "invalid_0x00_02_prefix".to_string(),
                alert_category: Some("tls_alert_handshake_failure".to_string()),
                tcp_reset: false,
                elapsed_ms: 18,
                other_outcome: None,
            },
            kemist::model::scan_result::RobotVariantObservation {
                variant: "invalid_version_0x00_02_byte_swap".to_string(),
                alert_category: None,
                tcp_reset: true,
                elapsed_ms: 15,
                other_outcome: None,
            },
            kemist::model::scan_result::RobotVariantObservation {
                variant: "null_separator_missing".to_string(),
                alert_category: None,
                tcp_reset: false,
                elapsed_ms: 5000,
                other_outcome: Some("timeout".to_string()),
            },
            kemist::model::scan_result::RobotVariantObservation {
                variant: "wrong_tls_version_in_pms".to_string(),
                alert_category: None,
                tcp_reset: false,
                elapsed_ms: 38,
                other_outcome: Some("graceful_close".to_string()),
            },
        ],
    };

    let mut results = fixture_results();
    results.openssl_observations = Some(OpensslObservations {
        cipher_probes: Some(cipher_probes),
        kx_group_probes: Some(kx_group_probes),
        fallback_scsv: Some(fallback_scsv),
        renegotiation: Some(renegotiation),
        client_auth: Some(client_auth),
        tls13_extensions: Some(tls13_ee),
        session_resumption: Some(session_resumption),
        sigalg_policy: Some(sigalg_policy),
        ephemeral_key_reuse: Some(ephemeral_key_reuse),
        bleichenbacher_oracle_probe: Some(bleichenbacher_oracle_probe),
        probe_errors: vec![],
    });

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
            "populated legacy-probe record failed schema validation: {} error(s)",
            errors.len()
        );
    }

    // Cross-check the output actually carries the new fields — schema
    // validation alone doesn't prove the builder populated anything; it
    // only proves the shape is legal. Legacy probes land in the merged
    // tls.cipher_suites.* and tls.groups.{tls1_2,tls1_3} locations.
    let tls = record_value.get("tls").unwrap();
    let cs = tls.get("cipher_suites").unwrap();
    // Fixture has 1 TLS 1.0 row (RC4-SHA), 0 TLS 1.1 rows, 4 TLS 1.2
    // rows (AES128-SHA supported + DHE-RSA-AES128-SHA supported +
    // NULL-SHA rejected + DH-RSA-AES128-SHA wire-rejected).
    assert_eq!(cs.get("tls1_0").unwrap().as_array().unwrap().len(), 1);
    assert_eq!(cs.get("tls1_1").unwrap().as_array().unwrap().len(), 0);
    assert_eq!(cs.get("tls1_2").unwrap().as_array().unwrap().len(), 4);
    // Every emitted entry carries the provider tag.
    for v in ["tls1_0", "tls1_2"] {
        for row in cs.get(v).unwrap().as_array().unwrap() {
            assert_eq!(
                row.get("provider").unwrap().as_str(),
                Some("openssl"),
                "legacy probe entry should be tagged provider=openssl"
            );
        }
    }
    assert_eq!(
        tls.get("dh_parameters").unwrap().as_array().unwrap().len(),
        1
    );
    let groups = tls.get("groups").unwrap();
    // Three FFDHE probe rows produce three tls1_2 + three tls1_3 entries.
    assert_eq!(groups.get("tls1_2").unwrap().as_object().unwrap().len(), 3);
    assert_eq!(groups.get("tls1_3").unwrap().as_object().unwrap().len(), 4);
    // Override discipline: the secp521r1 row has no prior aws-lc-rs
    // observation in this fixture, so the OpenSSL-path observation
    // lands directly with provider=openssl.
    let s521 = groups
        .get("tls1_3")
        .unwrap()
        .get("secp521r1")
        .expect("secp521r1 override lands in tls1_3");
    assert_eq!(s521.get("supported").unwrap().as_bool(), Some(false));
    assert_eq!(s521.get("provider").unwrap().as_str(), Some("openssl"));
    assert_eq!(
        tls.get("server_key_exchange_signatures")
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(tls.get("renegotiation_behavior").is_some());
    assert!(tls.get("client_auth_request").is_some());
    // No more legacy_cipher_suites / ffdhe_support at top level.
    assert!(tls.get("legacy_cipher_suites").is_none());
    assert!(tls.get("ffdhe_support").is_none());
    assert_eq!(
        tls.get("downgrade_signaling")
            .unwrap()
            .get("fallback_scsv_enforced")
            .unwrap()
            .get("value")
            .unwrap()
            .as_bool(),
        Some(true)
    );
    // Every cipher suite entry carries a classification from the
    // 15-variant enum. Cross-check that non-null strings from the
    // documented set land on every emitted entry.
    let valid_classifications: &[&str] = &[
        "rsa_kex",
        "dhe_aead",
        "dhe_cbc",
        "ecdhe_aead",
        "ecdhe_cbc",
        "anon",
        "export",
        "static_dh",
        "static_ecdh",
        "psk",
        "dhe_psk",
        "ecdhe_psk",
        "rsa_psk",
        "null_cipher",
        "other",
    ];
    for v in ["tls1_0", "tls1_1", "tls1_2", "tls1_3"] {
        for row in cs.get(v).unwrap().as_array().unwrap() {
            let c = row
                .get("classification")
                .expect("every CipherSuiteEntry has classification")
                .as_str()
                .expect("classification is a string");
            assert!(
                valid_classifications.contains(&c),
                "unknown classification {c:?} in tls.{v}"
            );
        }
    }

    // TLS 1.3 EncryptedExtensions fields land under
    // tls.extensions.{record_size_limit, compress_certificate_algorithms}.
    let ext = tls.get("extensions").unwrap();
    assert_eq!(
        ext.get("record_size_limit").and_then(|v| v.as_u64()),
        Some(16385)
    );
    let comp = ext
        .get("compress_certificate_algorithms")
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(
        comp.iter().map(|v| v.as_str().unwrap()).collect::<Vec<_>>(),
        vec!["zlib", "brotli"]
    );

    // session_resumption TLS 1.2 slots carry real probe values;
    // TLS 1.3 slots stay NotProbed.
    let sr = tls.get("session_resumption").unwrap();
    let sr12 = sr.get("tls1_2").unwrap();
    assert_eq!(
        sr12.get("session_ticket_issued")
            .unwrap()
            .get("value")
            .unwrap()
            .as_bool(),
        Some(true)
    );
    assert_eq!(
        sr12.get("ticket_lifetime_hint_secs")
            .and_then(|v| v.as_u64()),
        Some(7200)
    );
    assert_eq!(
        sr12.get("ticket_rotated_across_connections")
            .unwrap()
            .get("value")
            .unwrap()
            .as_bool(),
        Some(true)
    );
    // Functional resumption fields. Fixture mirrors the cloudflare.com
    // pattern: tickets work, session-ID caching doesn't.
    assert_eq!(
        sr12.get("session_ticket_resumption_accepted")
            .unwrap()
            .get("value")
            .unwrap()
            .as_bool(),
        Some(true)
    );
    assert_eq!(
        sr12.get("session_id_resumption_accepted")
            .unwrap()
            .get("value")
            .unwrap()
            .as_bool(),
        Some(false)
    );
    let sr13 = sr.get("tls1_3").unwrap();
    assert_eq!(
        sr13.get("psk_resumption_accepted")
            .unwrap()
            .get("method")
            .unwrap()
            .as_str(),
        Some("not_probed")
    );
    assert_eq!(
        sr13.get("early_data_accepted")
            .unwrap()
            .get("method")
            .unwrap()
            .as_str(),
        Some("not_probed")
    );

    // Four sigalg-policy constraints each land with the
    // fixture's canonical outcomes.
    let sap = tls.get("signature_algorithm_policy_probe").unwrap();
    for name in ["sha256_plus_only", "ecdsa_only", "rsa_pss_only"] {
        let slot = sap.get(name).unwrap();
        assert_eq!(
            slot.get("outcome").unwrap().as_str(),
            Some("handshake_complete"),
            "{name} should complete on fixture",
        );
        assert!(slot.get("selected_sigalg").unwrap().is_string());
    }
    let rsa_pkcs1 = sap.get("rsa_pkcs1_only").unwrap();
    assert_eq!(
        rsa_pkcs1.get("outcome").unwrap().as_str(),
        Some("handshake_failure")
    );
    assert_eq!(
        rsa_pkcs1.get("alert").unwrap().as_str(),
        Some("tls_alert_handshake_failure")
    );
}

#[cfg(feature = "legacy-probes")]
#[test]
fn ffdhe_cross_check_reason_surfaces_in_output() {
    use kemist::scanner::backends::HandshakeOutcome;
    use kemist::scanner::openssl::{
        kx_groups::{KxGroupProbeOutput, KxGroupProbeResult},
        OpensslObservations,
    };

    let mut results = fixture_results();
    results.openssl_observations = Some(OpensslObservations {
        cipher_probes: None,
        kx_group_probes: Some(KxGroupProbeOutput {
            results: vec![KxGroupProbeResult {
                group_name: "ffdhe2048".to_string(),
                iana_code: 0x0100,
                tls12_outcome: HandshakeOutcome::IgnoredGroupReturnedDifferentPrime {
                    returned_group: "custom".to_string(),
                    returned_prime_bits: 1024,
                },
                tls13_outcome: HandshakeOutcome::Supported,
            }],
        }),
        fallback_scsv: None,
        renegotiation: None,
        client_auth: None,
        tls13_extensions: None,
        session_resumption: None,
        sigalg_policy: None,
        ephemeral_key_reuse: None,
        bleichenbacher_oracle_probe: None,
        probe_errors: vec![],
    });

    let ctx = fixture_ctx();
    let record = build_scan_result(&results, &ctx);
    let value = serde_json::to_value(&record).expect("serialize");
    // FFDHE TLS 1.2 outcome now lives in the merged
    // `tls.groups.tls1_2.{name}` slot.
    let tls12 = value
        .pointer("/tls/groups/tls1_2/ffdhe2048")
        .expect("tls.groups.tls1_2.ffdhe2048 present");
    assert_eq!(tls12.get("supported").unwrap().as_bool(), Some(false));
    assert_eq!(
        tls12.get("reason").unwrap().as_str(),
        Some("server_does_not_honor_supported_groups")
    );
    assert_eq!(
        tls12.get("returned_group").unwrap().as_str(),
        Some("custom")
    );
    assert_eq!(
        tls12.get("returned_prime_bits").unwrap().as_u64(),
        Some(1024)
    );
}

/// Cross-codepoint coherence: when one FFDHE row reports
/// `IgnoredGroupReturnedDifferentPrime`, every FFDHE TLS 1.2 row gets
/// the same explicit reason. A sibling that matched its own offer
/// remains `supported: true`; its `returned_group` records the row's
/// own group classification, since that is the prime the server
/// returned in response to the offer.
#[cfg(feature = "legacy-probes")]
#[test]
fn ffdhe_cross_codepoint_coherence_notes_self_match() {
    use kemist::scanner::backends::HandshakeOutcome;
    use kemist::scanner::openssl::{
        kx_groups::{KxGroupProbeOutput, KxGroupProbeResult},
        OpensslObservations,
    };

    let mut results = fixture_results();
    results.openssl_observations = Some(OpensslObservations {
        cipher_probes: None,
        kx_group_probes: Some(KxGroupProbeOutput {
            results: vec![
                KxGroupProbeResult {
                    group_name: "ffdhe2048".to_string(),
                    iana_code: 0x0100,
                    tls12_outcome: HandshakeOutcome::Supported,
                    tls13_outcome: HandshakeOutcome::NotSupported,
                },
                KxGroupProbeResult {
                    group_name: "ffdhe3072".to_string(),
                    iana_code: 0x0101,
                    tls12_outcome: HandshakeOutcome::IgnoredGroupReturnedDifferentPrime {
                        returned_group: "ffdhe2048".to_string(),
                        returned_prime_bits: 2048,
                    },
                    tls13_outcome: HandshakeOutcome::NotSupported,
                },
            ],
        }),
        fallback_scsv: None,
        renegotiation: None,
        client_auth: None,
        tls13_extensions: None,
        session_resumption: None,
        sigalg_policy: None,
        ephemeral_key_reuse: None,
        bleichenbacher_oracle_probe: None,
        probe_errors: vec![],
    });

    let ctx = fixture_ctx();
    let record = build_scan_result(&results, &ctx);
    let value = serde_json::to_value(&record).expect("serialize");

    // ffdhe2048 self-match stays supported; returned_group reflects
    // the matching prime the server actually returned.
    let two = value
        .pointer("/tls/groups/tls1_2/ffdhe2048")
        .expect("ffdhe2048 row present");
    assert_eq!(two.get("supported").unwrap().as_bool(), Some(true));
    assert_eq!(
        two.get("reason").unwrap().as_str(),
        Some("server_does_not_honor_supported_groups")
    );
    assert_eq!(
        two.get("returned_group").unwrap().as_str(),
        Some("ffdhe2048")
    );
    assert_eq!(two.get("returned_prime_bits").unwrap().as_u64(), Some(2048));

    // ffdhe3072 row carries the original mismatch evidence.
    let three = value
        .pointer("/tls/groups/tls1_2/ffdhe3072")
        .expect("ffdhe3072 row present");
    assert_eq!(three.get("supported").unwrap().as_bool(), Some(false));
    assert_eq!(
        three.get("reason").unwrap().as_str(),
        Some("server_does_not_honor_supported_groups")
    );
    assert_eq!(
        three.get("returned_group").unwrap().as_str(),
        Some("ffdhe2048")
    );
    assert_eq!(
        three.get("returned_prime_bits").unwrap().as_u64(),
        Some(2048)
    );
}

/// Negative case: with no mismatch evidence, the cross-codepoint
/// coherence pass leaves a Supported FFDHE row untouched (no
/// `returned_group`, no reason string).
#[cfg(feature = "legacy-probes")]
#[test]
fn ffdhe_supported_unchanged_without_mismatch_evidence() {
    use kemist::scanner::backends::HandshakeOutcome;
    use kemist::scanner::openssl::{
        kx_groups::{KxGroupProbeOutput, KxGroupProbeResult},
        OpensslObservations,
    };

    let mut results = fixture_results();
    results.openssl_observations = Some(OpensslObservations {
        cipher_probes: None,
        kx_group_probes: Some(KxGroupProbeOutput {
            results: vec![
                KxGroupProbeResult {
                    group_name: "ffdhe2048".to_string(),
                    iana_code: 0x0100,
                    tls12_outcome: HandshakeOutcome::Supported,
                    tls13_outcome: HandshakeOutcome::NotSupported,
                },
                KxGroupProbeResult {
                    group_name: "ffdhe3072".to_string(),
                    iana_code: 0x0101,
                    tls12_outcome: HandshakeOutcome::NotSupported,
                    tls13_outcome: HandshakeOutcome::NotSupported,
                },
            ],
        }),
        fallback_scsv: None,
        renegotiation: None,
        client_auth: None,
        tls13_extensions: None,
        session_resumption: None,
        sigalg_policy: None,
        ephemeral_key_reuse: None,
        bleichenbacher_oracle_probe: None,
        probe_errors: vec![],
    });

    let ctx = fixture_ctx();
    let record = build_scan_result(&results, &ctx);
    let value = serde_json::to_value(&record).expect("serialize");
    let two = value
        .pointer("/tls/groups/tls1_2/ffdhe2048")
        .expect("ffdhe2048 row present");
    assert_eq!(two.get("supported").unwrap().as_bool(), Some(true));
    assert!(two.get("reason").is_none());
    assert!(two.get("returned_group").is_none());
    assert!(two.get("returned_prime_bits").is_none());
}

#[cfg(not(feature = "legacy-probes"))]
#[test]
fn legacy_probes_disabled_renders_empty_schema_sections() {
    // Schema shape is stable regardless of feature state: the new tls.*
    // sections still appear, they're just empty / null / not_probed.
    let results = fixture_results();
    let ctx = fixture_ctx();
    let record = build_scan_result(&results, &ctx);
    let record_value = serde_json::to_value(&record).expect("serialize");

    let schema_value = load_schema();
    let validator = jsonschema::validator_for(&schema_value).expect("schema compiles");
    assert!(validator
        .iter_errors(&record_value)
        .collect::<Vec<_>>()
        .is_empty());

    let tls = record_value.get("tls").unwrap();
    // cipher_suites.tls1_0/1_1 are always present, empty when
    // legacy-probes is off. tls1_2/1_3 depend on whether rustls cipher
    // probes ran (fixture has them absent).
    let cs = tls.get("cipher_suites").unwrap();
    assert_eq!(cs.get("tls1_0").unwrap().as_array().unwrap().len(), 0);
    assert_eq!(cs.get("tls1_1").unwrap().as_array().unwrap().len(), 0);
    // groups keeps its per-version shape even with feature off.
    let groups = tls.get("groups").unwrap();
    assert_eq!(groups.get("tls1_2").unwrap().as_object().unwrap().len(), 0);
    // No merged-away fields at top level.
    assert!(tls.get("legacy_cipher_suites").is_none());
    assert!(tls.get("ffdhe_support").is_none());
    assert_eq!(
        tls.get("dh_parameters").unwrap().as_array().unwrap().len(),
        0
    );
    assert_eq!(
        tls.get("renegotiation_behavior")
            .unwrap()
            .get("reason")
            .unwrap()
            .as_str(),
        Some("feature_disabled")
    );
    // Session-resumption + sigalg-policy shape is stable under
    // http-checks only: both
    // sections always emit, with `method: not_probed` / reason
    // `feature_disabled` slots rather than being absent.
    let sr = tls.get("session_resumption").unwrap();
    assert_eq!(
        sr.get("tls1_2")
            .unwrap()
            .get("session_ticket_issued")
            .unwrap()
            .get("reason")
            .unwrap()
            .as_str(),
        Some("feature_disabled")
    );
    let sap = tls.get("signature_algorithm_policy_probe").unwrap();
    for name in [
        "sha256_plus_only",
        "ecdsa_only",
        "rsa_pss_only",
        "rsa_pkcs1_only",
        "eddsa_only",
    ] {
        assert_eq!(
            sap.get(name).unwrap().get("outcome").unwrap().as_str(),
            Some("not_probed"),
            "{name} should be not_probed under http-checks only"
        );
        assert_eq!(
            sap.get(name).unwrap().get("reason").unwrap().as_str(),
            Some("feature_disabled")
        );
    }
}

// --------------------------------------------------------------------
// Schema ↔ Rust enum coverage.
//
// The fixture-driven tests above validate that a synthesized record
// *shape* matches the schema, but they can't catch enum drift —
// e.g. the scanner adds a new `DhClassification` variant and forgets
// to extend the schema enum. That shipped twice in 0.3.0
// (`preload_list_source: cache_refreshed:*` and the four `modp*` DH
// classifications) and made it to production before dashboard AJV
// caught it.
//
// These tests enumerate every variant of each schema-constrained
// Rust enum and assert its serialized form is accepted by the
// schema. They use an exhaustive `match` guard so adding a variant
// to the Rust enum without updating the test produces a compile
// error at the exact site where the dev is already editing.
// --------------------------------------------------------------------

/// Walk `$defs.<name>.enum` in the loaded schema and return it as
/// a set of strings. Panics on shape mismatch — structural breakage
/// here is a schema bug, not a test bug.
fn schema_def_enum(schema: &serde_json::Value, def_name: &str) -> Vec<String> {
    schema
        .get("$defs")
        .and_then(|d| d.get(def_name))
        .and_then(|m| m.get("enum"))
        .and_then(|e| e.as_array())
        .unwrap_or_else(|| panic!("$defs.{def_name}.enum not an array in schema"))
        .iter()
        .map(|v| {
            v.as_str()
                .unwrap_or_else(|| panic!("$defs.{def_name}.enum entry not a string: {v}"))
                .to_string()
        })
        .collect()
}

#[test]
fn method_enum_every_variant_matches_schema() {
    use kemist::model::scan_result::Method;
    // Keep this list in sync with the Method enum. The `match` below
    // is the compile-time guard — adding a variant without touching
    // the array fails to compile.
    let all = [
        Method::Probe,
        Method::NotProbed,
        Method::NotApplicable,
        Method::Error,
        Method::ConnectionState,
    ];
    for v in &all {
        let _guard: &str = match v {
            Method::Probe => "probe",
            Method::NotProbed => "not_probed",
            Method::NotApplicable => "not_applicable",
            Method::Error => "error",
            Method::ConnectionState => "connection_state",
        };
    }

    let schema = load_schema();
    let schema_enum = schema_def_enum(&schema, "method");
    for v in &all {
        // Method serializes via serde snake_case — that serialized
        // form is what actually lands in the output JSON, so we
        // validate that rather than a hand-written table.
        let serialized = serde_json::to_value(v).expect("Method serializes");
        let as_str = serialized
            .as_str()
            .expect("Method serializes as JSON string")
            .to_string();
        assert!(
            schema_enum.contains(&as_str),
            "Method::{v:?} serializes as {as_str:?} but schema $defs.method.enum is {schema_enum:?}",
        );
    }
}

#[test]
fn cipher_classification_every_variant_matches_schema() {
    use kemist::model::cipher_classification::CipherClassification;
    let all = [
        CipherClassification::RsaKex,
        CipherClassification::DheAead,
        CipherClassification::DheCbc,
        CipherClassification::EcdheAead,
        CipherClassification::EcdheCbc,
        CipherClassification::Anon,
        CipherClassification::Export,
        CipherClassification::StaticDh,
        CipherClassification::StaticEcdh,
        CipherClassification::Psk,
        CipherClassification::DhePsk,
        CipherClassification::EcdhePsk,
        CipherClassification::RsaPsk,
        CipherClassification::NullCipher,
        CipherClassification::Other,
    ];
    for v in &all {
        // Exhaustiveness guard — add the new variant here AND above.
        let _guard: () = match v {
            CipherClassification::RsaKex
            | CipherClassification::DheAead
            | CipherClassification::DheCbc
            | CipherClassification::EcdheAead
            | CipherClassification::EcdheCbc
            | CipherClassification::Anon
            | CipherClassification::Export
            | CipherClassification::StaticDh
            | CipherClassification::StaticEcdh
            | CipherClassification::Psk
            | CipherClassification::DhePsk
            | CipherClassification::EcdhePsk
            | CipherClassification::RsaPsk
            | CipherClassification::NullCipher
            | CipherClassification::Other => (),
        };
    }

    let schema = load_schema();
    let schema_enum = schema
        .pointer("/$defs/cipherSuiteEntry/properties/classification/enum")
        .and_then(|e| e.as_array())
        .expect("$defs.cipherSuiteEntry.properties.classification.enum missing")
        .iter()
        .map(|v| v.as_str().expect("enum entry is string").to_string())
        .collect::<Vec<_>>();

    for v in &all {
        let serialized = serde_json::to_value(v).expect("CipherClassification serializes");
        let as_str = serialized
            .as_str()
            .expect("CipherClassification serializes as JSON string")
            .to_string();
        assert!(
            schema_enum.contains(&as_str),
            "CipherClassification::{v:?} serializes as {as_str:?} but schema enum is {schema_enum:?}",
        );
    }
}

#[cfg(feature = "legacy-probes")]
#[test]
fn dh_classification_every_variant_matches_schema() {
    use kemist::scanner::openssl::dh_params::DhClassification;
    let all = [
        DhClassification::Ffdhe2048,
        DhClassification::Ffdhe3072,
        DhClassification::Ffdhe4096,
        DhClassification::Ffdhe6144,
        DhClassification::Ffdhe8192,
        DhClassification::Modp1024,
        DhClassification::Modp1536,
        DhClassification::Modp2048,
        DhClassification::Modp3072,
        DhClassification::Custom,
    ];
    for v in &all {
        let _guard: () = match v {
            DhClassification::Ffdhe2048
            | DhClassification::Ffdhe3072
            | DhClassification::Ffdhe4096
            | DhClassification::Ffdhe6144
            | DhClassification::Ffdhe8192
            | DhClassification::Modp1024
            | DhClassification::Modp1536
            | DhClassification::Modp2048
            | DhClassification::Modp3072
            | DhClassification::Custom => (),
        };
    }

    let schema = load_schema();
    let schema_enum = schema
        .pointer("/$defs/dhParametersObservation/properties/classification/enum")
        .and_then(|e| e.as_array())
        .expect("$defs.dhParametersObservation.properties.classification.enum missing")
        .iter()
        .map(|v| v.as_str().expect("enum entry is string").to_string())
        .collect::<Vec<_>>();

    for v in &all {
        let emitted = v.as_schema_str();
        assert!(
            schema_enum.contains(&emitted.to_string()),
            "DhClassification::{v:?}.as_schema_str() == {emitted:?} but schema enum is {schema_enum:?}",
        );
    }
}

#[cfg(all(feature = "http-checks", feature = "legacy-probes"))]
#[test]
fn preload_list_source_all_emitted_forms_match_schema_pattern() {
    // All three forms the scanner can emit into http.preload_list_source:
    //   - "compiled_in"                (the default PHF bundled at build)
    //   - "runtime_override:<path>"    (--hsts-preload-list-path)
    //   - "cache_refreshed:<path>"     (cache file written by
    //                                   --update-hsts-preload)
    // The third form shipped in 0.3.0 without being added to the
    // regex alternation — any scan that ran after --update-hsts-preload
    // failed AJV validation downstream until this test (and the fix)
    // landed.
    let forms = [
        "compiled_in",
        "runtime_override:/etc/kemist/preload.json",
        "cache_refreshed:/home/op/.cache/kemist/hsts_preload_list.json",
    ];

    // Validate via the full schema: substitute each form into a
    // fixture record, serialize, and run jsonschema. This round-
    // trips through the exact same validator downstream consumers
    // use — no regex parsing in the test.
    let schema_value = load_schema();
    let validator = jsonschema::validator_for(&schema_value).expect("schema compiles");
    let results = fixture_results();
    let ctx = fixture_ctx();
    let base = build_scan_result(&results, &ctx);
    let mut base_value = serde_json::to_value(&base).expect("serialize base");

    for form in &forms {
        // Inject a minimally-valid http object carrying the form.
        base_value["http"] = serde_json::json!({
            "enabled": true,
            "preload_list_source": form,
        });
        let errors: Vec<_> = validator.iter_errors(&base_value).collect();
        assert!(
            errors.is_empty(),
            "preload_list_source form {form:?} rejected by schema: {:?}",
            errors
                .iter()
                .map(|e| format!("{}: {}", e.instance_path, e))
                .collect::<Vec<_>>(),
        );
    }
}

/// HRR cross-reference: when the protocol probe affirmatively reports
/// TLS 1.3 as not supported, the HRR row degrades to `not_applicable`
/// with `tls13_not_supported_on_host` (HRR is a TLS 1.3 mechanism, so
/// the question is moot). The underlying probe error is preserved in
/// the reason for forensic continuity. fs.bbg.gov is the motivating
/// case: the host RSTs every TLS 1.3 ClientHello, so the HRR probe
/// reports `read_io: Connection reset by peer` and the protocol probe
/// reports tls1_3 not supported.
#[test]
fn hrr_renders_not_applicable_when_tls13_unsupported_with_underlying_error() {
    use kemist::scanner::hello::HelloRetryRequestObservation;

    let mut results = fixture_results();
    // Flip TLS 1.3 to not_supported (no error → affirmative no).
    for p in results.protocol_support.iter_mut() {
        if p.version == TlsVersion::Tls13 {
            p.supported = false;
            p.error = None;
        }
    }
    results.hrr_observed = Some(HelloRetryRequestObservation {
        hrr_observed: None,
        error: Some("read_io: Connection reset by peer (os error 104)".to_string()),
    });

    let ctx = fixture_ctx();
    let record = build_scan_result(&results, &ctx);
    let value = serde_json::to_value(&record).expect("serialize");
    let hrr = value
        .pointer("/tls/behavioral_probes/hello_retry_request")
        .expect("hello_retry_request slot present");
    assert!(hrr.get("value").unwrap().is_null());
    assert_eq!(hrr.get("method").unwrap().as_str(), Some("not_applicable"));
    let reason = hrr.get("reason").unwrap().as_str().unwrap();
    assert!(
        reason.starts_with("tls13_not_supported_on_host:"),
        "expected tls13_not_supported_on_host prefix, got {reason}"
    );
    assert!(
        reason.contains("Connection reset by peer"),
        "expected underlying probe error preserved in reason, got {reason}"
    );
}

/// HRR cross-reference: when the HRR probe never ran but TLS 1.3 is
/// affirmatively unsupported, the row still degrades to
/// `not_applicable` with the bare `tls13_not_supported_on_host`
/// reason — no probe error to preserve.
#[test]
fn hrr_renders_not_applicable_when_tls13_unsupported_and_probe_did_not_run() {
    let mut results = fixture_results();
    for p in results.protocol_support.iter_mut() {
        if p.version == TlsVersion::Tls13 {
            p.supported = false;
            p.error = None;
        }
    }
    results.hrr_observed = None;

    let ctx = fixture_ctx();
    let record = build_scan_result(&results, &ctx);
    let value = serde_json::to_value(&record).expect("serialize");
    let hrr = value
        .pointer("/tls/behavioral_probes/hello_retry_request")
        .expect("hello_retry_request slot present");
    assert_eq!(hrr.get("method").unwrap().as_str(), Some("not_applicable"));
    assert_eq!(
        hrr.get("reason").unwrap().as_str(),
        Some("tls13_not_supported_on_host")
    );
}

/// Negative case: when the TLS 1.3 protocol probe itself failed
/// (`error` set, `supported` indeterminate), the HRR row keeps the
/// legacy `not_probed` rendering with the underlying read_io reason
/// — we don't quietly bury a real measurement failure under
/// `not_applicable`.
#[test]
fn hrr_keeps_not_probed_when_tls13_probe_inconclusive() {
    use kemist::scanner::hello::HelloRetryRequestObservation;

    let mut results = fixture_results();
    for p in results.protocol_support.iter_mut() {
        if p.version == TlsVersion::Tls13 {
            p.supported = false;
            p.error = Some("connection_timeout".to_string());
        }
    }
    results.hrr_observed = Some(HelloRetryRequestObservation {
        hrr_observed: None,
        error: Some("read_io: Connection reset by peer (os error 104)".to_string()),
    });

    let ctx = fixture_ctx();
    let record = build_scan_result(&results, &ctx);
    let value = serde_json::to_value(&record).expect("serialize");
    let hrr = value
        .pointer("/tls/behavioral_probes/hello_retry_request")
        .expect("hello_retry_request slot present");
    assert_eq!(hrr.get("method").unwrap().as_str(), Some("not_probed"));
    assert!(hrr
        .get("reason")
        .unwrap()
        .as_str()
        .unwrap()
        .contains("Connection reset by peer"));
}

/// TLS 1.3 session resumption + 0-RTT cross-reference: when the
/// protocol probe affirmatively reports TLS 1.3 as not supported,
/// `psk_resumption_accepted` and `early_data_accepted` (both TLS 1.3
/// mechanisms) degrade from `not_probed` to `not_applicable` with
/// `tls13_not_supported_on_host`. The original probe error is
/// preserved in the reason for forensic continuity. fs.bbg.gov is
/// the motivating case: rustls's resumption probe fails handshake #1
/// with `ServerTlsVersionIsDisabledByOurConfig` because the server
/// only speaks TLS 1.2.
#[cfg(feature = "legacy-probes")]
#[test]
fn session_resumption_tls13_renders_not_applicable_when_tls13_unsupported() {
    use kemist::model::scan_result::{
        ObservationBool, SessionResumption, Tls12Resumption, Tls13Resumption,
    };
    use kemist::scanner::openssl::OpensslObservations;

    let mut results = fixture_results();
    for p in results.protocol_support.iter_mut() {
        if p.version == TlsVersion::Tls13 {
            p.supported = false;
            p.error = None;
        }
    }
    results.openssl_observations = Some(OpensslObservations {
        cipher_probes: None,
        kx_group_probes: None,
        fallback_scsv: None,
        renegotiation: None,
        client_auth: None,
        tls13_extensions: None,
        session_resumption: Some(SessionResumption {
            tls1_2: Tls12Resumption {
                session_ticket_issued: ObservationBool::probe(true),
                ticket_lifetime_hint_secs: Some(7200),
                session_id_issued: ObservationBool::probe(false),
                ticket_rotated_across_connections: ObservationBool::probe(true),
                session_ticket_resumption_accepted: ObservationBool::probe(true),
                session_id_resumption_accepted: ObservationBool::not_applicable(
                    "no_session_issued_in_first_handshake",
                ),
            },
            tls1_3: Tls13Resumption {
                new_session_ticket_count: None,
                ticket_lifetime_secs: Vec::new(),
                psk_resumption_accepted: ObservationBool::not_probed(
                    "handshake1:peer is incompatible: ServerTlsVersionIsDisabledByOurConfig",
                ),
                early_data_accepted: ObservationBool::not_probed(
                    "handshake1:peer is incompatible: ServerTlsVersionIsDisabledByOurConfig",
                ),
            },
        }),
        sigalg_policy: None,
        ephemeral_key_reuse: None,
        bleichenbacher_oracle_probe: None,
        probe_errors: vec![],
    });

    let ctx = fixture_ctx();
    let record = build_scan_result(&results, &ctx);
    let value = serde_json::to_value(&record).expect("serialize");

    let psk = value
        .pointer("/tls/session_resumption/tls1_3/psk_resumption_accepted")
        .expect("psk_resumption_accepted slot present");
    assert_eq!(psk.get("method").unwrap().as_str(), Some("not_applicable"));
    let psk_reason = psk.get("reason").unwrap().as_str().unwrap();
    assert!(
        psk_reason.starts_with("tls13_not_supported_on_host:"),
        "expected tls13_not_supported_on_host prefix, got {psk_reason}"
    );
    assert!(psk_reason.contains("ServerTlsVersionIsDisabledByOurConfig"));

    let ed = value
        .pointer("/tls/session_resumption/tls1_3/early_data_accepted")
        .expect("early_data_accepted slot present");
    assert_eq!(ed.get("method").unwrap().as_str(), Some("not_applicable"));
    assert!(ed
        .get("reason")
        .unwrap()
        .as_str()
        .unwrap()
        .starts_with("tls13_not_supported_on_host:"));

    // TLS 1.2 portion of the same struct is untouched — those rows
    // measure session_id / session_ticket / rotation, none of which
    // depend on TLS 1.3 capability.
    let session_ticket = value
        .pointer("/tls/session_resumption/tls1_2/session_ticket_issued")
        .expect("tls1_2 session_ticket_issued slot present");
    assert_eq!(
        session_ticket.get("method").unwrap().as_str(),
        Some("probe")
    );
    assert_eq!(session_ticket.get("value").unwrap().as_bool(), Some(true));
}

/// Negative case: when the TLS 1.3 protocol probe itself was
/// inconclusive (`error` set), session resumption rows keep their
/// original `not_probed` rendering — we don't bury a real
/// measurement failure under `not_applicable`.
#[cfg(feature = "legacy-probes")]
#[test]
fn session_resumption_keeps_not_probed_when_tls13_probe_inconclusive() {
    use kemist::model::scan_result::{
        ObservationBool, SessionResumption, Tls12Resumption, Tls13Resumption,
    };
    use kemist::scanner::openssl::OpensslObservations;

    let mut results = fixture_results();
    for p in results.protocol_support.iter_mut() {
        if p.version == TlsVersion::Tls13 {
            p.supported = false;
            p.error = Some("connection_timeout".to_string());
        }
    }
    results.openssl_observations = Some(OpensslObservations {
        cipher_probes: None,
        kx_group_probes: None,
        fallback_scsv: None,
        renegotiation: None,
        client_auth: None,
        tls13_extensions: None,
        session_resumption: Some(SessionResumption {
            tls1_2: Tls12Resumption {
                session_ticket_issued: ObservationBool::not_probed("handshake_failed"),
                ticket_lifetime_hint_secs: None,
                session_id_issued: ObservationBool::not_probed("handshake_failed"),
                ticket_rotated_across_connections: ObservationBool::not_probed("handshake_failed"),
                session_ticket_resumption_accepted: ObservationBool::not_probed("handshake_failed"),
                session_id_resumption_accepted: ObservationBool::not_probed("handshake_failed"),
            },
            tls1_3: Tls13Resumption {
                new_session_ticket_count: None,
                ticket_lifetime_secs: Vec::new(),
                psk_resumption_accepted: ObservationBool::not_probed("handshake1_timeout"),
                early_data_accepted: ObservationBool::not_probed("handshake1_timeout"),
            },
        }),
        sigalg_policy: None,
        ephemeral_key_reuse: None,
        bleichenbacher_oracle_probe: None,
        probe_errors: vec![],
    });

    let ctx = fixture_ctx();
    let record = build_scan_result(&results, &ctx);
    let value = serde_json::to_value(&record).expect("serialize");
    let psk = value
        .pointer("/tls/session_resumption/tls1_3/psk_resumption_accepted")
        .expect("psk_resumption_accepted slot present");
    assert_eq!(psk.get("method").unwrap().as_str(), Some("not_probed"));
    assert_eq!(
        psk.get("reason").unwrap().as_str(),
        Some("handshake1_timeout")
    );
}

/// `HandshakeOutcome::WireRejected { reason }` — emitted by the
/// raw-socket static-DH cipher probe when the server tears the
/// connection down with a TCP RST after our ClientHello — must
/// render as `supported: false, method: probe, reason: <verbatim>`.
/// Distinct from `Error` (which gives `supported: null`) and from a
/// plain `NotSupported` (which gives no reason).
#[cfg(feature = "legacy-probes")]
#[test]
fn wire_rejected_cipher_renders_as_supported_false_with_reason() {
    use kemist::scanner::backends::HandshakeOutcome;
    use kemist::scanner::openssl::{
        ciphers::{LegacyCipherProbeOutput, LegacyCipherResult},
        OpensslObservations,
    };

    let mut results = fixture_results();
    results.openssl_observations = Some(OpensslObservations {
        cipher_probes: Some(LegacyCipherProbeOutput {
            results: vec![LegacyCipherResult {
                name: "TLS_DH_RSA_WITH_AES_128_CBC_SHA".to_string(),
                openssl_name: "DH-RSA-AES128-SHA".to_string(),
                iana_code: 0x0031,
                version: TlsVersion::Tls12,
                outcome: HandshakeOutcome::WireRejected {
                    reason: "server_rst_after_clienthello".to_string(),
                },
                dh_snapshot: None,
                ske_sig: None,
            }],
        }),
        kx_group_probes: None,
        fallback_scsv: None,
        renegotiation: None,
        client_auth: None,
        tls13_extensions: None,
        session_resumption: None,
        sigalg_policy: None,
        ephemeral_key_reuse: None,
        bleichenbacher_oracle_probe: None,
        probe_errors: vec![],
    });

    let ctx = fixture_ctx();
    let record = build_scan_result(&results, &ctx);
    let value = serde_json::to_value(&record).expect("serialize");
    let entries = value
        .pointer("/tls/cipher_suites/tls1_2")
        .expect("cipher_suites.tls1_2 present")
        .as_array()
        .expect("array");
    let entry = entries
        .iter()
        .find(|e| e.get("iana_code").and_then(|c| c.as_str()) == Some("0x0031"))
        .expect("0x0031 entry present");
    assert_eq!(entry.get("supported").unwrap().as_bool(), Some(false));
    assert_eq!(entry.get("method").unwrap().as_str(), Some("probe"));
    assert_eq!(
        entry.get("reason").unwrap().as_str(),
        Some("server_rst_after_clienthello")
    );
}

/// Positive case: when TLS 1.3 is supported and the HRR probe
/// returned a definitive answer, the row reports `method: probe` —
/// the cross-reference doesn't interfere with successful probes.
#[test]
fn hrr_renders_probe_when_tls13_supported_and_hrr_observed() {
    use kemist::scanner::hello::HelloRetryRequestObservation;

    let mut results = fixture_results();
    // protocol_support already has tls1_3 supported in the fixture.
    results.hrr_observed = Some(HelloRetryRequestObservation {
        hrr_observed: Some(true),
        error: None,
    });

    let ctx = fixture_ctx();
    let record = build_scan_result(&results, &ctx);
    let value = serde_json::to_value(&record).expect("serialize");
    let hrr = value
        .pointer("/tls/behavioral_probes/hello_retry_request")
        .expect("hello_retry_request slot present");
    assert_eq!(hrr.get("method").unwrap().as_str(), Some("probe"));
    assert_eq!(hrr.get("value").unwrap().as_bool(), Some(true));
}
