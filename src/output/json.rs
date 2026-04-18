//! JSON emission for schema v1.
//!
//! Converts internal `ScanResults` (probe data, unchanged since PR 1) into the
//! canonical `ScanResult` shape defined in [`crate::model::scan_result`] and
//! emits it. This conversion layer is the authoritative mapping from "what the
//! scanner measured" to "what the JSON contract says."

use chrono::{DateTime, Utc};
use std::collections::BTreeMap;

use crate::model::cert::CertificateInfo;
use crate::model::errors::ScannerError;
use crate::model::protocol::TlsVersion;
use crate::model::scan_result::{
    Capabilities, CertificateFacts, Certificates, CipherSuiteEntry, DowngradeSignaling,
    GroupObservation, Method, ObservationBool, OcspStapling, PublicKey, ScanMetadata, ScanResult,
    Scanner as ScannerMeta, SctObservation, SniBehavior, Tls, TlsCipherSuites, TlsExtensions,
    TlsNegotiated, TlsVersionsOffered, Validation, VersionOffered, SCHEMA_VERSION,
};
use crate::scanner::ScanResults;

/// Inputs that the scanner does not yet capture but that schema v1 requires.
/// Supplied by `main.rs` around the `SslScanner::scan()` call.
pub struct JsonEmitContext {
    pub host: String,
    pub port: u16,
    pub sni_sent: String,
    pub resolved_ip: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub enabled_features: Vec<String>,
    pub config_paths: Vec<String>,
}

pub fn build_scan_result(results: &ScanResults, ctx: &JsonEmitContext) -> ScanResult {
    let duration_ms = (ctx.completed_at - ctx.started_at)
        .num_milliseconds()
        .max(0) as u64;

    ScanResult {
        schema_version: SCHEMA_VERSION.to_string(),
        scanner: ScannerMeta {
            name: env!("CARGO_PKG_NAME").to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        capabilities: build_capabilities(ctx),
        scan: ScanMetadata {
            target: format!("{}:{}", ctx.host, ctx.port),
            host: ctx.host.clone(),
            port: ctx.port,
            sni_sent: ctx.sni_sent.clone(),
            resolved_ip: ctx.resolved_ip.clone(),
            started_at: ctx.started_at,
            completed_at: ctx.completed_at,
            duration_ms,
        },
        tls: build_tls(results),
        certificates: build_certificates(&results.certificate_chain),
        validation: build_validation(results),
        http: None,
        raw_handshakes: None,
        errors: results.scan_errors.clone(),
    }
}

fn build_capabilities(ctx: &JsonEmitContext) -> Capabilities {
    // Versions parsed from Cargo.toml at compile time. Best-effort — downstream
    // consumers should not depend on the exact format of these strings.
    let (rustls_version, aws_lc_rs_version, native_tls_version) = parse_dependency_versions();

    // Provider-exposed cipher suites + kx groups — what aws-lc-rs ships at
    // build time. Downstream consumers combine this with per-suite/per-group
    // `not_probed` reasons to know what was actually in scope.
    let provider_cipher_suites: Vec<String> = rustls::crypto::aws_lc_rs::ALL_CIPHER_SUITES
        .iter()
        .map(|s| format!("{:?}", s.suite()))
        .collect();
    let provider_kx_groups: Vec<String> = rustls::crypto::aws_lc_rs::ALL_KX_GROUPS
        .iter()
        .map(|g| format!("{:?}", g.name()))
        .collect();

    Capabilities {
        enabled_features: ctx.enabled_features.clone(),
        rustls_version,
        aws_lc_rs_version,
        native_tls_version,
        provider_cipher_suites,
        provider_kx_groups,
        config_paths: ctx.config_paths.clone(),
        probe_limitations: Vec::new(),
    }
}

fn build_tls(results: &ScanResults) -> Tls {
    Tls {
        versions_offered: build_versions_offered(&results.protocol_support),
        negotiated: build_negotiated_from_state(results),
        cipher_suites: build_cipher_suites(results),
        groups: build_groups(results),
        extensions: build_extensions(results),
        downgrade_signaling: DowngradeSignaling {
            fallback_scsv_accepted: match results.fallback_scsv_accepted {
                Some(v) => ObservationBool::probe(v),
                None => ObservationBool::not_probed("scsv_heuristic_inconclusive"),
            },
        },
        sni_behavior: build_sni_behavior(results),
    }
}

fn build_versions_offered(
    probes: &[crate::model::protocol::ProtocolSupport],
) -> TlsVersionsOffered {
    let find = |v: TlsVersion| -> VersionOffered {
        match probes.iter().find(|p| p.version == v) {
            Some(p) => {
                if let Some(err) = &p.error {
                    if !p.supported {
                        // probe ran and returned "not supported" — keep as probe,
                        // not error. Error reason only when probe itself failed.
                        let _ = err;
                        VersionOffered::probe(false)
                    } else {
                        VersionOffered::probe(true)
                    }
                } else {
                    VersionOffered::probe(p.supported)
                }
            }
            None => VersionOffered::not_probed("version_not_in_probe_set"),
        }
    };
    TlsVersionsOffered {
        ssl2: find(TlsVersion::Ssl2),
        ssl3: find(TlsVersion::Ssl3),
        tls1_0: find(TlsVersion::Tls10),
        tls1_1: find(TlsVersion::Tls11),
        tls1_2: find(TlsVersion::Tls12),
        tls1_3: find(TlsVersion::Tls13),
    }
}

fn build_negotiated_from_state(results: &ScanResults) -> Option<TlsNegotiated> {
    // The characterization handshake captures what actually got negotiated.
    // When characterization failed (e.g. connection refused), leave the
    // schema's `tls.negotiated` field absent rather than synthesizing.
    let n = results.negotiated.as_ref()?;
    let version = n
        .version
        .map(|v| v.as_str().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    Some(TlsNegotiated {
        version,
        cipher_suite: n.cipher_suite_name.clone(),
        group: n.kx_group_name.clone(),
        signature_scheme: n.signature_scheme.clone(),
        alpn: n.alpn_negotiated.clone(),
    })
}

fn build_cipher_suites(results: &ScanResults) -> TlsCipherSuites {
    let Some(probes) = &results.cipher_probes else {
        // Probes didn't run (e.g. --no-ciphersuites, or connection refused
        // before probing started). Emit an empty schema structure with
        // server_enforces_order marked not_probed.
        return TlsCipherSuites {
            tls1_2: Vec::new(),
            tls1_3: Vec::new(),
            server_enforces_order: ObservationBool::not_probed("cipher_probes_did_not_run"),
        };
    };

    let to_entry = |r: &crate::scanner::ciphers::CipherProbeResult| {
        use crate::scanner::ciphers::ProbeOutcome;
        let (supported, method, reason) = match &r.outcome {
            ProbeOutcome::Supported => (Some(true), Method::Probe, None),
            ProbeOutcome::NotSupported => (Some(false), Method::Probe, None),
            ProbeOutcome::Error(e) => (None, Method::Error, Some(e.clone())),
        };
        CipherSuiteEntry {
            name: r.name.clone(),
            iana_code: format!("0x{:04X}", r.iana_code),
            supported,
            method,
            reason,
        }
    };

    let mut tls1_2 = Vec::new();
    let mut tls1_3 = Vec::new();
    for r in &probes.results {
        let entry = to_entry(r);
        match r.version {
            TlsVersion::Tls12 => tls1_2.push(entry),
            TlsVersion::Tls13 => tls1_3.push(entry),
            _ => {}
        }
    }

    let server_enforces_order = match probes.server_enforces_order {
        Some(v) => ObservationBool::probe(v),
        None => match &probes.order_probe_error {
            Some(e) => ObservationBool::error(e),
            None => ObservationBool::not_probed("order_probe_inconclusive"),
        },
    };

    TlsCipherSuites {
        tls1_2,
        tls1_3,
        server_enforces_order,
    }
}

fn build_groups(results: &ScanResults) -> BTreeMap<String, GroupObservation> {
    let mut map = BTreeMap::new();
    let Some(probes) = &results.group_probes else {
        return map;
    };
    for r in &probes.results {
        use crate::scanner::groups::GroupProbeOutcome;
        let obs = match &r.outcome {
            GroupProbeOutcome::Supported => GroupObservation {
                supported: Some(true),
                method: Method::Probe,
                reason: None,
            },
            GroupProbeOutcome::NotSupported => GroupObservation {
                supported: Some(false),
                method: Method::Probe,
                reason: None,
            },
            GroupProbeOutcome::Error(ctx) => GroupObservation {
                supported: None,
                method: Method::Error,
                reason: Some(ctx.clone()),
            },
            GroupProbeOutcome::NotProbed(reason) => GroupObservation::not_probed(reason.as_str()),
        };
        map.insert(r.name.clone(), obs);
    }
    map
}

fn build_extensions(results: &ScanResults) -> TlsExtensions {
    // The byte probe runs its own TLS 1.2 handshake independent of the
    // main characterization. If the probe negotiated TLS 1.3 (possible if
    // the server is strict-1.3), ems/etm/reneg are genuinely
    // not_applicable. If it negotiated TLS 1.2, the observations are
    // meaningful. If the probe failed entirely (alert, timeout), fall
    // back to the characterization version as a weaker hint — a server
    // that only speaks TLS 1.3 can't meaningfully report these fields.
    let hello = results.hello_observed.as_ref();
    let hello_ok = hello.map(|h| h.server_hello_parsed).unwrap_or(false);
    let hello_version = hello.and_then(|h| h.server_negotiated_version);
    let char_tls13 = matches!(
        results.negotiated.as_ref().and_then(|n| n.version),
        Some(TlsVersion::Tls13)
    );
    let hello_fail_reason = hello
        .and_then(|h| h.error.clone())
        .unwrap_or_else(|| "hello_probe_not_run".to_string());

    // Helper: decide how a TLS-1.2-only extension observation renders.
    let tls12_ext = |probed: Option<bool>, ext_label: &str| -> ObservationBool {
        if hello_ok {
            match hello_version {
                Some(0x0303) => ObservationBool::probe(probed.unwrap_or(false)),
                Some(other) => ObservationBool::not_applicable(&format!(
                    "hello_probe_negotiated_0x{other:04x}_not_tls12"
                )),
                None => ObservationBool::not_probed("hello_version_unknown"),
            }
        } else if char_tls13 {
            ObservationBool::not_applicable(&format!("tls13_has_no_{ext_label}"))
        } else {
            ObservationBool::not_probed(&format!("hello_probe_failed:{hello_fail_reason}"))
        }
    };

    let ems = tls12_ext(hello.and_then(|h| h.ems), "ems_extension");
    let secure_renegotiation =
        tls12_ext(hello.and_then(|h| h.secure_renegotiation), "renegotiation");
    let encrypt_then_mac = tls12_ext(
        hello.and_then(|h| h.encrypt_then_mac),
        "encrypt_then_mac_extension",
    );

    // Heartbeat extension is defined for both TLS 1.2 and 1.3 (RFC 6520),
    // though rarely enabled. Emit probe observation regardless of version.
    let heartbeat_present = if hello_ok {
        ObservationBool::probe(hello.and_then(|h| h.heartbeat_present).unwrap_or(false))
    } else {
        ObservationBool::not_probed(&format!("hello_probe_failed:{hello_fail_reason}"))
    };

    // compression_offered: whatever the byte probe observed. Empty when the
    // probe didn't succeed (consumers read `method` on other fields to know).
    let compression_offered: Vec<String> = hello
        .and_then(|h| h.compression_selected.clone())
        .map(|c| vec![c])
        .unwrap_or_default();

    let ocsp_stapling = match &results.negotiated {
        Some(n) => OcspStapling {
            stapled: Some(n.ocsp_stapled),
            method: Method::ConnectionState,
            reason: None,
            response_length: n.ocsp_response_len as u64,
        },
        None => OcspStapling {
            stapled: None,
            method: Method::NotProbed,
            reason: Some("characterization_handshake_failed".to_string()),
            response_length: 0,
        },
    };

    // SCT delivery paths. Embedded (cert extension) is counted in PR 6
    // via CertificateInfo.embedded_scts. ext_path comes from the hello
    // probe. OCSP-stapled SCTs aren't parsed in v1.0.
    let mut delivery_paths: Vec<String> = Vec::new();
    let embedded_scts_total: u32 = results
        .certificate_chain
        .first()
        .map(|c| c.embedded_scts)
        .unwrap_or(0);
    if embedded_scts_total > 0 {
        delivery_paths.push("x509_extension".to_string());
    }
    if hello.map(|h| h.sct_via_tls_extension).unwrap_or(false) {
        delivery_paths.push("tls_extension".to_string());
    }

    TlsExtensions {
        ems,
        secure_renegotiation,
        ocsp_stapling,
        sct: SctObservation {
            delivery_paths,
            count: embedded_scts_total,
        },
        alpn_offered: results.alpn_offered.clone(),
        encrypt_then_mac,
        heartbeat_present,
        heartbeat_echoes_oversized_payload: match results.heartbeat_echoes_oversized_payload {
            Some(v) => ObservationBool::probe(v),
            None => ObservationBool::not_probed("heartbeat_probe_inconclusive"),
        },
        compression_offered,
    }
}

fn build_certificates(chain: &[CertificateInfo]) -> Certificates {
    let facts: Vec<CertificateFacts> = chain.iter().map(cert_to_facts).collect();
    Certificates {
        leaf: facts.first().cloned(),
        chain: facts.clone(),
        chain_length: facts.len(),
    }
}

fn cert_to_facts(c: &CertificateInfo) -> CertificateFacts {
    let public_key = PublicKey {
        algorithm: c.public_key_algorithm.clone(),
        size_bits: c.public_key_size,
        curve: c.ecc_curve_name.clone(),
    };
    CertificateFacts {
        subject_cn: extract_cn(&c.subject),
        subject_dn: c.subject.clone(),
        san: c.san.clone(),
        issuer_cn: extract_cn(&c.issuer),
        issuer_dn: c.issuer.clone(),
        serial: c.serial_number.clone(),
        not_before: c.not_before,
        not_after: c.not_after,
        validity_days: (c.not_after - c.not_before).num_days(),
        signature_algorithm_oid: c.signature_algorithm_oid.clone(),
        signature_algorithm_name: c.signature_algorithm.clone(),
        is_pqc_signature: c.is_pqc_signature,
        public_key,
        embedded_scts: c.embedded_scts,
        fingerprint_sha256: c.fingerprint_sha256.clone(),
        fingerprint_sha1: c.fingerprint_sha1.clone(),
    }
}

fn extract_cn(dn: &str) -> Option<String> {
    // Minimal CN extractor. x509-parser's Display produces comma-separated RDNs;
    // full RFC 4514 unescaping lands in PR 6 alongside OID inspection.
    for rdn in dn.split(',') {
        let rdn = rdn.trim();
        if let Some(v) = rdn.strip_prefix("CN=") {
            return Some(v.to_string());
        }
    }
    None
}

fn build_sni_behavior(results: &ScanResults) -> SniBehavior {
    match &results.sni_behavior {
        Some(r) => {
            use crate::scanner::sni::SniBehaviorOutcome;
            let method = match r.outcome {
                SniBehaviorOutcome::SameCert | SniBehaviorOutcome::DifferentCert => Method::Probe,
                SniBehaviorOutcome::Rejected => Method::Probe,
                SniBehaviorOutcome::Error => Method::Error,
            };
            SniBehavior {
                omitted_probe: Some(r.outcome.as_str().to_string()),
                method,
                reason: r.reason.clone(),
            }
        }
        None => SniBehavior {
            omitted_probe: None,
            method: Method::NotProbed,
            reason: Some("sni_probe_did_not_run".to_string()),
        },
    }
}

fn build_validation(results: &ScanResults) -> Validation {
    let v = &results.validation;
    Validation {
        chain_valid_to_webpki_roots: match v.chain_valid_to_webpki_roots {
            Some(b) => ObservationBool::probe(b),
            None => ObservationBool::not_probed("characterization_handshake_failed"),
        },
        name_matches_sni: match v.name_matches_sni {
            Some(b) => ObservationBool::probe(b),
            None => ObservationBool::not_probed("characterization_handshake_failed"),
        },
        validation_error: v.validation_error.clone(),
    }
}

/// Parse rustls/aws-lc-rs/native-tls versions from Cargo.toml at compile time.
/// Moved from main.rs to keep capability-building self-contained.
fn parse_dependency_versions() -> (String, String, String) {
    let cargo_toml = include_str!("../../Cargo.toml");
    let mut rustls_version = "unknown".to_string();
    let mut native_tls_version = "unknown".to_string();
    for line in cargo_toml.lines() {
        let line = line.trim();
        if line.starts_with("rustls = {") {
            if let Some(pos) = line.find("version = \"") {
                let start = pos + 11;
                if let Some(end) = line[start..].find('"') {
                    rustls_version = line[start..start + end].to_string();
                }
            }
        }
        if line.starts_with("native-tls = \"") {
            if let Some(start) = line.find('"') {
                let start = start + 1;
                if let Some(end) = line[start..].find('"') {
                    native_tls_version = line[start..start + end].to_string();
                }
            }
        }
    }
    // aws-lc-rs is transitive via rustls's aws_lc_rs feature; we don't get a
    // dedicated version string without parsing Cargo.lock. Leave as a sentinel
    // for PR 2; PR 13 can read Cargo.lock during release builds.
    (rustls_version, "bundled".to_string(), native_tls_version)
}

pub fn print_json(results: &ScanResults, ctx: &JsonEmitContext) -> Result<(), ScannerError> {
    let scan_result = build_scan_result(results, ctx);
    println!("{}", serde_json::to_string(&scan_result)?);
    Ok(())
}

pub fn print_json_pretty(results: &ScanResults, ctx: &JsonEmitContext) -> Result<(), ScannerError> {
    let scan_result = build_scan_result(results, ctx);
    println!("{}", serde_json::to_string_pretty(&scan_result)?);
    Ok(())
}

pub fn write_json(
    results: &ScanResults,
    ctx: &JsonEmitContext,
    path: &str,
) -> Result<(), ScannerError> {
    use std::io::Write;
    let scan_result = build_scan_result(results, ctx);
    let json = serde_json::to_string_pretty(&scan_result)?;
    let mut file = std::fs::File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}
