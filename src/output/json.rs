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
        validation: build_validation_placeholder(),
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
        negotiated: build_negotiated_placeholder(results),
        cipher_suites: build_cipher_suites(results),
        groups: build_groups(&results.key_exchange_groups),
        extensions: build_extensions(results),
        downgrade_signaling: DowngradeSignaling {
            fallback_scsv_accepted: match results.fallback_scsv_accepted {
                Some(v) => ObservationBool::probe(v),
                None => ObservationBool::not_probed("scsv_heuristic_inconclusive"),
            },
        },
        sni_behavior: SniBehavior {
            omitted_probe: None,
            method: Method::NotProbed,
            reason: Some("pending_pr_9".to_string()),
        },
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

fn build_negotiated_placeholder(results: &ScanResults) -> Option<TlsNegotiated> {
    // Until PR 5 surfaces rustls connection state, the only field we can fill
    // is `cipher_suite` from the "preferred" pick — a best-effort hint.
    results.preferred_cipher.as_ref().map(|c| TlsNegotiated {
        version: c.protocol_version.as_str().to_string(),
        cipher_suite: Some(c.iana_name.clone()),
        group: None,
        signature_scheme: None,
        alpn: None,
    })
}

fn build_cipher_suites(results: &ScanResults) -> TlsCipherSuites {
    let (tls12, tls13): (Vec<_>, Vec<_>) = results
        .cipher_suites
        .iter()
        .filter(|c| c.supported)
        .partition(|c| c.cipher.protocol_version == TlsVersion::Tls12);
    let to_entry = |c: &crate::model::cipher::CipherSuiteResult| CipherSuiteEntry {
        name: c.cipher.iana_name.clone(),
        iana_code: format!("0x{:04X}", c.cipher.id),
        method: Method::NotProbed,
        reason: Some("pending_pr_7_per_cipher_probes".to_string()),
    };
    TlsCipherSuites {
        tls1_2: tls12.iter().map(|c| to_entry(c)).collect(),
        tls1_3: tls13.iter().map(|c| to_entry(c)).collect(),
        server_enforces_order: ObservationBool::not_probed("pending_pr_7"),
    }
}

fn build_groups(groups: &[crate::scanner::KeyExchangeGroup]) -> BTreeMap<String, GroupObservation> {
    let mut map = BTreeMap::new();
    for g in groups {
        // Until PR 8 wires real per-group probes, surface the hardcoded list
        // as `not_probed` — NOT `supported: true/false`. Absence-of-probe is
        // never evidence of absence-of-support.
        map.insert(
            g.name.clone(),
            GroupObservation::not_probed("pending_pr_8_per_group_probes"),
        );
    }
    map
}

fn build_extensions(results: &ScanResults) -> TlsExtensions {
    let reneg = &results.tls_renegotiation;
    TlsExtensions {
        ems: ObservationBool::not_probed("pending_pr_5_connection_state"),
        secure_renegotiation: match reneg.secure_renegotiation {
            Some(v) => ObservationBool::probe(v),
            None => ObservationBool::not_probed("no_modern_tls_connection_established"),
        },
        ocsp_stapling: OcspStapling {
            stapled: None,
            method: Method::NotProbed,
            reason: Some("pending_pr_5_connection_state".to_string()),
            response_length: 0,
        },
        sct: SctObservation {
            delivery_paths: Vec::new(),
            count: 0,
        },
        alpn_offered: Vec::new(),
        encrypt_then_mac: ObservationBool::not_probed("pending_pr_9_byte_parsing"),
        heartbeat_present: ObservationBool::not_probed("pending_pr_9_byte_parsing"),
        heartbeat_echoes_oversized_payload: match results.heartbeat_echoes_oversized_payload {
            Some(v) => ObservationBool::probe(v),
            None => ObservationBool::not_probed("heartbeat_probe_inconclusive"),
        },
        compression_offered: Vec::new(),
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
    let (public_key, curve) = (
        PublicKey {
            algorithm: c.public_key_algorithm.clone(),
            size_bits: c.public_key_size,
            curve: c.ecc_curve_name.clone(),
        },
        c.ecc_curve_name.clone(),
    );
    let _ = curve;
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
        signature_algorithm_oid: String::new(),
        signature_algorithm_name: c.signature_algorithm.clone(),
        is_pqc_signature: false, // populated in PR 6
        public_key,
        embedded_scts: 0, // populated in PR 6
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

fn build_validation_placeholder() -> Validation {
    Validation {
        chain_valid_to_webpki_roots: ObservationBool::not_probed("pending_pr_6_webpki_validation"),
        name_matches_sni: ObservationBool::not_probed("pending_pr_6_name_match"),
        validation_error: None,
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
