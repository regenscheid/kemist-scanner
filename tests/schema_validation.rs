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
        ],
    };

    // Named-group probe: FFDHE rows exercising Supported / NotSupported /
    // IgnoredGroupReturnedCustomPrime, plus a non-FFDHE row demonstrating
    // an OpenSSL override of an aws-lc-rs `not_probed` slot.
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
                tls12_outcome: HandshakeOutcome::IgnoredGroupReturnedCustomPrime,
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
    // Fixture has 1 TLS 1.0 row (RC4-SHA), 0 TLS 1.1 rows, 2 TLS 1.2
    // rows (AES128-SHA supported + DHE-RSA-AES128-SHA supported +
    // NULL-SHA rejected = 3).
    assert_eq!(cs.get("tls1_0").unwrap().as_array().unwrap().len(), 1);
    assert_eq!(cs.get("tls1_1").unwrap().as_array().unwrap().len(), 0);
    assert_eq!(cs.get("tls1_2").unwrap().as_array().unwrap().len(), 3);
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
                tls12_outcome: HandshakeOutcome::IgnoredGroupReturnedCustomPrime,
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
        Some("server_ignored_group_offer_returned_custom_prime")
    );
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
