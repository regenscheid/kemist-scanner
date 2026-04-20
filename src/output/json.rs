//! JSON emission for schema v1.
//!
//! Converts internal `ScanResults` (probe data, unchanged since PR 1) into the
//! canonical `ScanResult` shape defined in [`crate::model::scan_result`] and
//! emits it. This conversion layer is the authoritative mapping from "what the
//! scanner measured" to "what the JSON contract says."

use chrono::{DateTime, Utc};

use crate::model::cert::CertificateInfo;
use crate::model::errors::ScannerError;
use crate::model::protocol::TlsVersion;
use crate::model::scan_result::{
    Capabilities, CertificateFacts, Certificates, CipherSuiteEntry, ClientAuthRequestEntry,
    DhParametersObservation, DowngradeSignaling, GroupObservation, Hsts, Http, Method,
    ObservationBool, OcspStapling, PublicKey, RenegotiationBehavior, ScanMetadata, ScanResult,
    Scanner as ScannerMeta, SctObservation, SecurityTxt, SkeSigObservation, SniBehavior, Tls,
    TlsCipherSuites, TlsExtensions, TlsGroups, TlsNegotiated, TlsVersionsOffered, Validation,
    VersionOffered, SCHEMA_VERSION,
};
#[cfg(feature = "legacy-probes")]
use crate::model::scan_result::{ClientAuthCaDn, ClientAuthOidFilter};
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
    /// Emit raw OCSP response bytes as hex alongside the parsed
    /// `content`. Gated by the `--include-ocsp-raw` CLI flag so most
    /// scans produce compact output.
    pub include_ocsp_raw: bool,
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
        tls: build_tls(results, ctx),
        certificates: build_certificates(&results.certificate_chain),
        validation: build_validation(results),
        http: build_http(results),
        raw_handshakes: None,
        errors: results.scan_errors.clone(),
    }
}

fn build_http(results: &ScanResults) -> Option<Http> {
    let obs = results.http_observations.as_ref()?;
    // Only emit the top-level `http` block when checks were actually run.
    // Consumers read `http.enabled` as the authoritative gate — a missing
    // block means the HTTP feature was compiled out or left disabled.
    if !obs.enabled {
        return None;
    }
    Some(Http {
        enabled: true,
        hsts: obs.hsts.as_ref().map(|h| Hsts {
            header_present: h.header_present,
            raw_value: h.raw_value.clone(),
            max_age: h.max_age,
            include_subdomains: h.include_subdomains,
            preload: h.preload,
        }),
        preload_list_status: obs.preload_list_status.clone(),
        security_txt: obs.security_txt.as_ref().map(|s| SecurityTxt {
            present: s.present,
            url: s.url.clone(),
            content_type: s.content_type.clone(),
            body: s.body.clone(),
        }),
    })
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

fn build_tls(results: &ScanResults, ctx: &JsonEmitContext) -> Tls {
    Tls {
        versions_offered: build_versions_offered(&results.protocol_support),
        negotiated: build_negotiated_from_state(results),
        cipher_suites: build_cipher_suites(results),
        groups: build_groups(results),
        extensions: build_extensions(results, ctx),
        downgrade_signaling: DowngradeSignaling {
            // Deprecated-in-place for v1: always renders null with a
            // supersession reason, regardless of the (now-deleted)
            // heuristic. See docs/OUTPUT_SCHEMA.md deprecation note.
            fallback_scsv_accepted: ObservationBool::not_probed(
                "superseded_by_fallback_scsv_enforced",
            ),
            fallback_scsv_enforced: build_fallback_scsv_enforced(results),
            tls13_downgrade_sentinel: results
                .hello_observed
                .as_ref()
                .and_then(|h| h.tls13_downgrade_sentinel.clone()),
        },
        sni_behavior: build_sni_behavior(results),
        dh_parameters: build_dh_parameters(results),
        server_key_exchange_signatures: build_ske_sigs(results),
        renegotiation_behavior: build_renegotiation_behavior(results),
        client_auth_request: build_client_auth_request(results),
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
    // One canonical place for every probed cipher suite, partitioned by
    // TLS version. aws-lc-rs modern probes land in tls1_2/tls1_3;
    // OpenSSL legacy probes land in tls1_0/tls1_1/tls1_2 (all tagged
    // with `provider` so consumers who care about backend attribution
    // can filter).
    let mut tls1_0 = Vec::new();
    let mut tls1_1 = Vec::new();
    let mut tls1_2 = Vec::new();
    let mut tls1_3 = Vec::new();

    // aws-lc-rs modern probes.
    let server_enforces_order = if let Some(probes) = &results.cipher_probes {
        for r in &probes.results {
            use crate::scanner::ciphers::ProbeOutcome;
            let (supported, method, reason) = match &r.outcome {
                ProbeOutcome::Supported => (Some(true), Method::Probe, None),
                ProbeOutcome::NotSupported => (Some(false), Method::Probe, None),
                ProbeOutcome::Error(e) => (None, Method::Error, Some(e.clone())),
            };
            let entry = CipherSuiteEntry {
                name: r.name.clone(),
                iana_code: format!("0x{:04X}", r.iana_code),
                supported,
                method,
                reason,
                openssl_name: None,
                provider: Some("aws_lc_rs".to_string()),
            };
            match r.version {
                TlsVersion::Tls12 => tls1_2.push(entry),
                TlsVersion::Tls13 => tls1_3.push(entry),
                _ => {}
            }
        }
        match probes.server_enforces_order {
            Some(v) => ObservationBool::probe(v),
            None => match &probes.order_probe_error {
                Some(e) => ObservationBool::error(e),
                None => ObservationBool::not_probed("order_probe_inconclusive"),
            },
        }
    } else {
        ObservationBool::not_probed("cipher_probes_did_not_run")
    };

    // OpenSSL legacy probes. Feature-gated — entirely absent when
    // `legacy-probes` is compiled off, leaving just aws-lc-rs entries.
    merge_openssl_cipher_probes(results, &mut tls1_0, &mut tls1_1, &mut tls1_2);

    TlsCipherSuites {
        tls1_0,
        tls1_1,
        tls1_2,
        tls1_3,
        server_enforces_order,
    }
}

fn merge_openssl_cipher_probes(
    results: &ScanResults,
    tls1_0: &mut Vec<CipherSuiteEntry>,
    tls1_1: &mut Vec<CipherSuiteEntry>,
    tls1_2: &mut Vec<CipherSuiteEntry>,
) {
    #[cfg(feature = "legacy-probes")]
    {
        use crate::scanner::openssl::ciphers::LegacyProbeOutcome;
        let Some(obs) = results.openssl_observations.as_ref() else {
            return;
        };
        let Some(probes) = obs.cipher_probes.as_ref() else {
            return;
        };
        for r in &probes.results {
            let (supported, method, reason) = match &r.outcome {
                LegacyProbeOutcome::Supported => (Some(true), Method::Probe, None),
                LegacyProbeOutcome::NotSupported => (Some(false), Method::Probe, None),
                LegacyProbeOutcome::Error(e) => (None, Method::Error, Some(e.clone())),
            };
            let entry = CipherSuiteEntry {
                name: r.name.clone(),
                iana_code: format!("0x{:04X}", r.iana_code),
                supported,
                method,
                reason,
                openssl_name: Some(r.openssl_name.clone()),
                provider: Some("openssl".to_string()),
            };
            match r.version {
                TlsVersion::Tls10 => tls1_0.push(entry),
                TlsVersion::Tls11 => tls1_1.push(entry),
                TlsVersion::Tls12 => tls1_2.push(entry),
                _ => {}
            }
        }
    }
    #[cfg(not(feature = "legacy-probes"))]
    {
        let _ = (results, tls1_0, tls1_1, tls1_2);
    }
}

fn build_groups(results: &ScanResults) -> TlsGroups {
    // All observations live under one roof, partitioned by TLS version.
    // aws-lc-rs probes are TLS 1.3-only. OpenSSL FFDHE probes produce
    // per-version outcomes that split across tls1_2 and tls1_3.
    let mut out = TlsGroups::default();

    if let Some(probes) = &results.group_probes {
        for r in &probes.results {
            use crate::scanner::groups::GroupProbeOutcome;
            let obs = match &r.outcome {
                GroupProbeOutcome::Supported => GroupObservation {
                    supported: Some(true),
                    method: Method::Probe,
                    reason: None,
                    iana_code: None,
                    provider: Some("aws_lc_rs".to_string()),
                },
                GroupProbeOutcome::NotSupported => GroupObservation {
                    supported: Some(false),
                    method: Method::Probe,
                    reason: None,
                    iana_code: None,
                    provider: Some("aws_lc_rs".to_string()),
                },
                GroupProbeOutcome::Error(ctx) => GroupObservation {
                    supported: None,
                    method: Method::Error,
                    reason: Some(ctx.clone()),
                    iana_code: None,
                    provider: Some("aws_lc_rs".to_string()),
                },
                GroupProbeOutcome::NotProbed(reason) => {
                    let mut o = GroupObservation::not_probed(reason.as_str());
                    o.provider = Some("aws_lc_rs".to_string());
                    o
                }
            };
            // src/scanner/groups.rs is TLS 1.3-only by design, so every
            // entry lands in tls1_3.
            out.tls1_3.insert(r.name.clone(), obs);
        }
    }

    merge_openssl_ffdhe(results, &mut out);
    out
}

fn merge_openssl_ffdhe(results: &ScanResults, out: &mut TlsGroups) {
    #[cfg(feature = "legacy-probes")]
    {
        use crate::scanner::openssl::ffdhe::FfdheOutcome;
        let Some(obs) = results.openssl_observations.as_ref() else {
            return;
        };
        let Some(probes) = obs.ffdhe_probes.as_ref() else {
            return;
        };
        let to_obs = |o: &FfdheOutcome, iana: &str| match o {
            FfdheOutcome::Supported => GroupObservation {
                supported: Some(true),
                method: Method::Probe,
                reason: None,
                iana_code: Some(iana.to_string()),
                provider: Some("openssl".to_string()),
            },
            FfdheOutcome::NotSupported => GroupObservation {
                supported: Some(false),
                method: Method::Probe,
                reason: None,
                iana_code: Some(iana.to_string()),
                provider: Some("openssl".to_string()),
            },
            FfdheOutcome::IgnoredGroupReturnedCustomPrime => GroupObservation {
                supported: Some(false),
                method: Method::Probe,
                reason: Some("server_ignored_group_offer_returned_custom_prime".to_string()),
                iana_code: Some(iana.to_string()),
                provider: Some("openssl".to_string()),
            },
            FfdheOutcome::Error(e) => GroupObservation {
                supported: None,
                method: Method::Error,
                reason: Some(e.clone()),
                iana_code: Some(iana.to_string()),
                provider: Some("openssl".to_string()),
            },
            FfdheOutcome::NotProbed(r) => GroupObservation {
                supported: None,
                method: Method::NotProbed,
                reason: Some(r.clone()),
                iana_code: Some(iana.to_string()),
                provider: Some("openssl".to_string()),
            },
        };
        for r in &probes.results {
            let iana = format!("0x{:04X}", r.iana_code);
            out.tls1_2
                .insert(r.group_name.clone(), to_obs(&r.tls12_outcome, &iana));
            out.tls1_3
                .insert(r.group_name.clone(), to_obs(&r.tls13_outcome, &iana));
        }
    }
    #[cfg(not(feature = "legacy-probes"))]
    {
        let _ = (results, out);
    }
}

fn build_extensions(results: &ScanResults, ctx: &JsonEmitContext) -> TlsExtensions {
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

    let ocsp_stapling = build_ocsp_stapling(results, ctx);

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

    let truncated_hmac = tls12_ext(
        hello.and_then(|h| h.truncated_hmac),
        "truncated_hmac_extension",
    );
    let npn = tls12_ext(hello.and_then(|h| h.npn), "npn_extension");
    let supported_point_formats_echoed = hello
        .map(|h| h.supported_point_formats_echoed.clone())
        .unwrap_or_default();
    let max_fragment_length = hello.and_then(|h| h.max_fragment_length.clone());
    let (record_size_limit, compress_certificate_algorithms) = build_tls13_ee_observations(results);

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
        truncated_hmac,
        npn,
        supported_point_formats_echoed,
        max_fragment_length,
        record_size_limit,
        compress_certificate_algorithms,
    }
}

/// Build the [`OcspStapling`] slot from the characterization
/// handshake's captured OCSP bytes. Populates:
///
/// - `stapled` — whether any bytes were captured
/// - `response_length` — byte count
/// - `content` — parsed [`OcspResponseContent`] (RFC 6960 §4.2) via
///   [`crate::model::ocsp_response::parse`]
/// - `delivery_path` — `"tls1_3"` if TLS 1.3 was negotiated,
///   `"tls1_2"` otherwise, `None` when the handshake didn't complete
/// - `raw_hex` — hex of the bytes, only when `ctx.include_ocsp_raw`
///   is set
///
/// When the handshake failed entirely we emit a `NotProbed` shape
/// with a reason so consumers can distinguish "scanner never got a
/// staple" from "server didn't send one."
fn build_ocsp_stapling(results: &ScanResults, ctx: &JsonEmitContext) -> OcspStapling {
    use crate::model::ocsp_response;

    let Some(negotiated) = &results.negotiated else {
        return OcspStapling {
            stapled: None,
            method: Method::NotProbed,
            reason: Some("characterization_handshake_failed".to_string()),
            response_length: 0,
            content: None,
            delivery_path: None,
            raw_hex: None,
        };
    };

    let delivery_path = match negotiated.version {
        Some(crate::model::protocol::TlsVersion::Tls13) => Some("tls1_3".to_string()),
        Some(_) => Some("tls1_2".to_string()),
        None => None,
    };

    // Parse the captured bytes. Parse errors land in `reason` so
    // consumers see why `content` is absent rather than silently
    // dropping the observation.
    let (content, parse_reason) = match negotiated.ocsp_response_bytes.as_deref() {
        Some(bytes) if !bytes.is_empty() => match ocsp_response::parse(bytes) {
            Ok(c) => (Some(c), None),
            Err(e) => (None, Some(format!("ocsp_parse_failed:{e}"))),
        },
        _ => (None, None),
    };

    let raw_hex = if ctx.include_ocsp_raw {
        negotiated.ocsp_response_bytes.as_ref().map(hex::encode)
    } else {
        None
    };

    OcspStapling {
        stapled: Some(negotiated.ocsp_stapled),
        method: Method::ConnectionState,
        reason: parse_reason,
        response_length: negotiated.ocsp_response_len as u64,
        content,
        delivery_path,
        raw_hex,
    }
}

/// Pull TLS 1.3 EncryptedExtensions observations from the OpenSSL probe
/// subsystem. Returns `(None, [])` when `legacy-probes` is disabled or
/// the probe didn't produce a parseable message — the fields are
/// optional in the schema, so "absent" correctly means "not observed."
fn build_tls13_ee_observations(results: &ScanResults) -> (Option<u16>, Vec<String>) {
    #[cfg(feature = "legacy-probes")]
    {
        let Some(obs) = results.openssl_observations.as_ref() else {
            return (None, Vec::new());
        };
        let Some(ee) = obs.tls13_extensions.as_ref() else {
            return (None, Vec::new());
        };
        if !ee.parsed {
            return (None, Vec::new());
        }
        (
            ee.record_size_limit,
            ee.compress_certificate_algorithms.clone(),
        )
    }
    #[cfg(not(feature = "legacy-probes"))]
    {
        let _ = results;
        (None, Vec::new())
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
        extensions: c.extensions.clone(),
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

// ---------------------------------------------------------------------
// OpenSSL legacy-probe output builders. Each reads
// `results.openssl_observations` (when the `legacy-probes` feature is on)
// and emits the corresponding schema section. With the feature off, every
// builder returns an empty / not-probed default so the schema shape stays
// stable.
// ---------------------------------------------------------------------

fn build_fallback_scsv_enforced(results: &ScanResults) -> ObservationBool {
    #[cfg(feature = "legacy-probes")]
    {
        let Some(obs) = results.openssl_observations.as_ref() else {
            return ObservationBool::not_probed("feature_disabled");
        };
        let Some(scsv) = obs.fallback_scsv.as_ref() else {
            return ObservationBool::not_probed("feature_disabled");
        };
        match scsv.enforced {
            Some(true) => ObservationBool {
                value: Some(true),
                method: Method::Probe,
                reason: Some(scsv.reason.clone()),
            },
            Some(false) => ObservationBool {
                value: Some(false),
                method: Method::Probe,
                reason: Some(scsv.reason.clone()),
            },
            None => ObservationBool {
                value: None,
                method: Method::Error,
                reason: Some(scsv.reason.clone()),
            },
        }
    }
    #[cfg(not(feature = "legacy-probes"))]
    {
        let _ = results;
        ObservationBool::not_probed("feature_disabled")
    }
}

fn build_dh_parameters(results: &ScanResults) -> Vec<DhParametersObservation> {
    #[cfg(feature = "legacy-probes")]
    {
        let Some(obs) = results.openssl_observations.as_ref() else {
            return Vec::new();
        };
        let Some(probes) = obs.cipher_probes.as_ref() else {
            return Vec::new();
        };
        probes
            .results
            .iter()
            .filter_map(|r| {
                let snap = r.dh_snapshot.as_ref()?;
                Some(DhParametersObservation {
                    cipher_suite: r.name.clone(),
                    prime_bits: snap.prime_bits,
                    classification: snap.classification.as_schema_str().to_string(),
                    generator: snap.generator,
                    prime_sha256: snap.prime_sha256_hex(),
                    prime_raw_hex: None,
                    method: Method::Probe,
                    reason: None,
                })
            })
            .collect()
    }
    #[cfg(not(feature = "legacy-probes"))]
    {
        let _ = results;
        Vec::new()
    }
}

fn build_ske_sigs(results: &ScanResults) -> Vec<SkeSigObservation> {
    #[cfg(feature = "legacy-probes")]
    {
        let Some(obs) = results.openssl_observations.as_ref() else {
            return Vec::new();
        };
        let Some(probes) = obs.cipher_probes.as_ref() else {
            return Vec::new();
        };
        probes
            .results
            .iter()
            .filter_map(|r| {
                let sig = r.ske_sig.as_ref()?;
                Some(SkeSigObservation {
                    cipher_suite: r.name.clone(),
                    signature_algorithm: sig.clone(),
                    method: Method::Probe,
                    reason: None,
                })
            })
            .collect()
    }
    #[cfg(not(feature = "legacy-probes"))]
    {
        let _ = results;
        Vec::new()
    }
}

fn build_renegotiation_behavior(results: &ScanResults) -> RenegotiationBehavior {
    #[cfg(feature = "legacy-probes")]
    {
        use crate::scanner::openssl::renegotiation::RenegotiationVerdict;
        let Some(obs) = results.openssl_observations.as_ref() else {
            return feature_disabled_reneg();
        };
        let Some(ro) = obs.renegotiation.as_ref() else {
            return feature_disabled_reneg();
        };
        let (verdict, method) = match &ro.client_initiated_verdict {
            RenegotiationVerdict::ClientInitiatedAccepted => {
                (Some("accepted".to_string()), Method::Probe)
            }
            RenegotiationVerdict::ClientInitiatedRejected => {
                (Some("rejected".to_string()), Method::Probe)
            }
            RenegotiationVerdict::NotAttempted => {
                (Some("not_attempted".to_string()), Method::NotApplicable)
            }
            RenegotiationVerdict::Error(_) => (Some("error".to_string()), Method::Error),
        };
        RenegotiationBehavior {
            client_initiated_verdict: verdict,
            method,
            reason: ro.reason.clone(),
        }
    }
    #[cfg(not(feature = "legacy-probes"))]
    {
        let _ = results;
        feature_disabled_reneg()
    }
}

fn feature_disabled_reneg() -> RenegotiationBehavior {
    RenegotiationBehavior {
        client_initiated_verdict: None,
        method: Method::NotProbed,
        reason: Some("feature_disabled".to_string()),
    }
}

fn build_client_auth_request(results: &ScanResults) -> Option<ClientAuthRequestEntry> {
    #[cfg(feature = "legacy-probes")]
    {
        let obs = results.openssl_observations.as_ref()?;
        let ca = obs.client_auth.as_ref()?;
        Some(ClientAuthRequestEntry {
            requested: ca.requested,
            certificate_types: ca.certificate_types.clone(),
            signature_algorithms: ca.signature_algorithms.clone(),
            ca_distinguished_names: ca
                .ca_distinguished_names
                .iter()
                .map(|d| ClientAuthCaDn {
                    raw_der_b64: d.raw_der_b64.clone(),
                    common_name: d.common_name.clone(),
                    organization: d.organization.clone(),
                })
                .collect(),
            oid_filters: ca
                .oid_filters
                .iter()
                .map(|f| ClientAuthOidFilter {
                    oid: f.oid.clone(),
                    values_b64: f.values_b64.clone(),
                })
                .collect(),
            alert_on_empty_cert: ca.alert_on_empty_cert.clone(),
            method: Method::Probe,
            reason: None,
        })
    }
    #[cfg(not(feature = "legacy-probes"))]
    {
        let _ = results;
        None
    }
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
