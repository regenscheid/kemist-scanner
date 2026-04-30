//! JSON emission for schema v1.
//!
//! Converts internal `ScanResults` (probe data) into the
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
        certificates: build_certificates(results),
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
        preload_list_source: obs.preload_list_source.clone(),
        security_txt: obs.security_txt.as_ref().map(|s| {
            use crate::model::scan_result::SecurityTxtParsedOutput;
            SecurityTxt {
                present: s.present,
                url: s.url.clone(),
                content_type: s.content_type.clone(),
                body: s.body.clone(),
                parsed: s.parsed.as_ref().map(|p| SecurityTxtParsedOutput {
                    contact: p.contact.clone(),
                    expires: p.expires.clone(),
                    encryption: p.encryption.clone(),
                    preferred_languages: p.preferred_languages.clone(),
                    canonical: p.canonical.clone(),
                    policy: p.policy.clone(),
                    hiring: p.hiring.clone(),
                    acknowledgments: p.acknowledgments.clone(),
                    pgp_signed: p.pgp_signed,
                }),
            }
        }),
        security_headers: obs.security_headers.as_ref().map(|h| {
            use crate::model::scan_result::{CookieFlagsOutput, SecurityHeadersOutput};
            SecurityHeadersOutput {
                content_security_policy: h.content_security_policy.clone(),
                content_security_policy_report_only: h.content_security_policy_report_only.clone(),
                x_frame_options: h.x_frame_options.clone(),
                x_content_type_options: h.x_content_type_options.clone(),
                referrer_policy: h.referrer_policy.clone(),
                permissions_policy: h.permissions_policy.clone(),
                cross_origin_opener_policy: h.cross_origin_opener_policy.clone(),
                cross_origin_embedder_policy: h.cross_origin_embedder_policy.clone(),
                cross_origin_resource_policy: h.cross_origin_resource_policy.clone(),
                reporting_endpoints: h.reporting_endpoints.clone(),
                set_cookies: h
                    .set_cookies
                    .iter()
                    .map(|c| CookieFlagsOutput {
                        name: c.name.clone(),
                        secure: c.secure,
                        http_only: c.http_only,
                        same_site: c.same_site.clone(),
                    })
                    .collect(),
            }
        }),
        redirect_chain: obs.redirect_chain.as_ref().map(|hops| {
            use crate::model::scan_result::RedirectHopOutput;
            hops.iter()
                .map(|h| RedirectHopOutput {
                    url: h.url.clone(),
                    status: h.status,
                    location: h.location.clone(),
                })
                .collect()
        }),
    })
}

fn build_capabilities(ctx: &JsonEmitContext) -> Capabilities {
    // Versions parsed from Cargo.toml at compile time. Best-effort — downstream
    // consumers should not depend on the exact format of these strings.
    let (rustls_version, aws_lc_rs_version) = parse_dependency_versions();

    // Merged probe inventory across every backend present in this build.
    // The per-backend `provider: "aws_lc_rs" | "openssl"` tag on each
    // `tls.cipher_suites.*` / `tls.groups.*` entry identifies which
    // backend ran each probe; this summary is the flat union.
    let mut probed_cipher_suites: Vec<String> = Vec::new();
    let mut probed_kx_groups: Vec<String> = Vec::new();
    for inv in crate::scanner::backends::all_inventories() {
        for name in inv.cipher_names {
            if !probed_cipher_suites.contains(&name) {
                probed_cipher_suites.push(name);
            }
        }
        for name in inv.group_names {
            if !probed_kx_groups.contains(&name) {
                probed_kx_groups.push(name);
            }
        }
    }

    Capabilities {
        enabled_features: ctx.enabled_features.clone(),
        rustls_version,
        aws_lc_rs_version,
        openssl_version: openssl_version(),
        probed_cipher_suites,
        probed_kx_groups,
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
        behavioral_probes: build_behavioral_probes(results),
        downgrade_signaling: DowngradeSignaling {
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
        session_resumption: build_session_resumption(results),
        signature_algorithm_policy_probe: build_sigalg_policy(results),
        client_auth_request: build_client_auth_request(results),
        channel_binding: build_channel_binding(results),
        alpn_probe: build_alpn_probe(results),
    }
}

/// Build the per-ALPN probe matrix. Maps each
/// [`crate::scanner::backends::rustls::alpn_matrix::AlpnProbeOutcome`] onto the
/// `{supported, method, reason}` envelope used throughout the schema.
fn build_alpn_probe(results: &ScanResults) -> Vec<crate::model::scan_result::AlpnProbeEntry> {
    use crate::model::scan_result::AlpnProbeEntry;
    use crate::scanner::backends::rustls::alpn_matrix::AlpnProbeOutcome;

    let Some(matrix) = results.alpn_matrix.as_ref() else {
        return Vec::new();
    };
    matrix
        .results
        .iter()
        .map(|r| match &r.outcome {
            AlpnProbeOutcome::Supported => AlpnProbeEntry {
                protocol: r.protocol.clone(),
                supported: Some(true),
                method: Method::Probe,
                reason: None,
            },
            AlpnProbeOutcome::NotSupported { reason } => AlpnProbeEntry {
                protocol: r.protocol.clone(),
                supported: Some(false),
                method: Method::Probe,
                reason: Some(reason.clone()),
            },
            AlpnProbeOutcome::Error { reason } => AlpnProbeEntry {
                protocol: r.protocol.clone(),
                supported: None,
                method: Method::Error,
                reason: Some(reason.clone()),
            },
        })
        .collect()
}

/// Build the [`ChannelBinding`] slot from fields captured during the
/// characterization handshake. `tls-exporter` populates only on TLS
/// 1.3; `tls-server-end-point` populates whenever a leaf cert was
/// delivered. Both fall through to `NotProbed` when the
/// characterization handshake did not complete.
fn build_channel_binding(results: &ScanResults) -> crate::model::scan_result::ChannelBinding {
    use crate::model::scan_result::{ChannelBinding, ChannelBindingValue, Method};

    let negotiated = results.negotiated.as_ref();
    let version = negotiated.and_then(|n| n.version);

    let tls_exporter = match negotiated.and_then(|n| n.channel_binding_tls_exporter.clone()) {
        Some(hex) => ChannelBindingValue {
            value: Some(hex),
            method: Method::Probe,
            reason: None,
        },
        None => {
            let (method, reason) = match version {
                Some(TlsVersion::Tls13) => (
                    Method::Error,
                    Some("export_keying_material_failed".to_string()),
                ),
                Some(_) => (
                    Method::NotApplicable,
                    Some("not_defined_for_tls12".to_string()),
                ),
                None => (
                    Method::NotProbed,
                    Some("characterization_handshake_failed".to_string()),
                ),
            };
            ChannelBindingValue {
                value: None,
                method,
                reason,
            }
        }
    };

    let tls_server_end_point =
        match negotiated.and_then(|n| n.channel_binding_server_end_point.clone()) {
            Some(hex) => ChannelBindingValue {
                value: Some(hex),
                method: Method::Probe,
                reason: None,
            },
            None => ChannelBindingValue {
                value: None,
                method: Method::NotProbed,
                reason: Some("no_leaf_certificate".to_string()),
            },
        };

    ChannelBinding {
        tls_exporter,
        tls_server_end_point,
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
    // OpenSSL legacy probes land in ssl3/tls1_0/tls1_1/tls1_2;
    // SSLv2 cipher specs echoed back in the raw-socket SERVER-HELLO
    // land in ssl2. All entries carry `provider` so consumers who
    // care about backend attribution can filter.
    let mut ssl3 = Vec::new();
    let mut tls1_0 = Vec::new();
    let mut tls1_1 = Vec::new();
    let mut tls1_2 = Vec::new();
    let mut tls1_3 = Vec::new();

    // aws-lc-rs modern probes.
    let server_enforces_order = if let Some(probes) = &results.cipher_probes {
        for r in &probes.results {
            use crate::scanner::backends::HandshakeOutcome;
            let (supported, method, reason) = match &r.outcome {
                HandshakeOutcome::Supported => (Some(true), Method::Probe, None),
                HandshakeOutcome::NotSupported => (Some(false), Method::Probe, None),
                HandshakeOutcome::WireRejected { reason } => {
                    (Some(false), Method::Probe, Some(reason.clone()))
                }
                HandshakeOutcome::Error(e) => (None, Method::Error, Some(e.clone())),
                HandshakeOutcome::NotProbed(_)
                | HandshakeOutcome::IgnoredGroupReturnedDifferentPrime { .. } => unreachable!(
                    "aws-lc-rs cipher probe never constructs NotProbed or \
                     IgnoredGroupReturnedDifferentPrime variants"
                ),
            };
            let entry = CipherSuiteEntry {
                classification: crate::model::cipher_classification::classify(&r.name),
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
    merge_openssl_cipher_probes(results, &mut ssl3, &mut tls1_0, &mut tls1_1, &mut tls1_2);

    // SSLv2 SERVER-HELLO cipher specs (raw-socket probe). Populated
    // only on servers that still answer SSLv2 — effectively zero
    // today. Each entry is `supported: Some(true)` because SSLv2's
    // SERVER-HELLO explicitly lists accepted ciphers from our offer.
    let ssl2 = build_sslv2_cipher_entries(results);

    TlsCipherSuites {
        ssl2,
        ssl3,
        tls1_0,
        tls1_1,
        tls1_2,
        tls1_3,
        server_enforces_order,
    }
}

fn build_sslv2_cipher_entries(results: &ScanResults) -> Vec<CipherSuiteEntry> {
    let Some(obs) = results.sslv2_observation.as_ref() else {
        return Vec::new();
    };
    obs.ciphers_observed
        .iter()
        .map(|c| CipherSuiteEntry {
            classification: crate::model::cipher_classification::CipherClassification::Other,
            name: c.name.clone(),
            iana_code: format!("0x{:06X}", c.code),
            supported: Some(true),
            method: Method::Probe,
            reason: None,
            openssl_name: None,
            provider: Some("raw_socket".to_string()),
        })
        .collect()
}

fn merge_openssl_cipher_probes(
    results: &ScanResults,
    ssl3: &mut Vec<CipherSuiteEntry>,
    tls1_0: &mut Vec<CipherSuiteEntry>,
    tls1_1: &mut Vec<CipherSuiteEntry>,
    tls1_2: &mut Vec<CipherSuiteEntry>,
) {
    #[cfg(feature = "legacy-probes")]
    {
        use crate::scanner::backends::HandshakeOutcome;
        let Some(obs) = results.openssl_observations.as_ref() else {
            return;
        };
        let Some(probes) = obs.cipher_probes.as_ref() else {
            return;
        };
        for r in &probes.results {
            let (supported, method, reason) = match &r.outcome {
                HandshakeOutcome::Supported => (Some(true), Method::Probe, None),
                HandshakeOutcome::NotSupported => (Some(false), Method::Probe, None),
                // Wire-level rejection with attribution — emitted by
                // raw-socket cipher probes (`raw::static_dh`) when the
                // server tore the connection down with a TCP RST after
                // our ClientHello. Verdict-equivalent to NotSupported;
                // the reason records *how* the server rejected so
                // dashboards can distinguish "server RST'd" from a
                // vanilla `handshake_failure` alert.
                HandshakeOutcome::WireRejected { reason } => {
                    (Some(false), Method::Probe, Some(reason.clone()))
                }
                HandshakeOutcome::Error(e) => (None, Method::Error, Some(e.clone())),
                // OpenSSL cipher probes emit `NotProbed` when the
                // cipher name isn't recognized by the local OpenSSL
                // build (e.g. static-DH/ECDH suites dropped in
                // OpenSSL 3.x). Surface as `method: not_probed` with
                // the deterministic reason so downstream consumers
                // can tell "never attempted" from "attempted and
                // rejected."
                HandshakeOutcome::NotProbed(reason) => {
                    (None, Method::NotProbed, Some(reason.clone()))
                }
                HandshakeOutcome::IgnoredGroupReturnedDifferentPrime { .. } => unreachable!(
                    "OpenSSL cipher probe never constructs \
                     IgnoredGroupReturnedDifferentPrime variant — that's \
                     FFDHE-specific"
                ),
            };
            let entry = CipherSuiteEntry {
                classification: crate::model::cipher_classification::classify(&r.name),
                name: r.name.clone(),
                iana_code: format!("0x{:04X}", r.iana_code),
                supported,
                method,
                reason,
                openssl_name: Some(r.openssl_name.clone()),
                provider: Some("openssl".to_string()),
            };
            match r.version {
                TlsVersion::Ssl3 => ssl3.push(entry),
                TlsVersion::Tls10 => tls1_0.push(entry),
                TlsVersion::Tls11 => tls1_1.push(entry),
                TlsVersion::Tls12 => tls1_2.push(entry),
                _ => {}
            }
        }
    }
    #[cfg(not(feature = "legacy-probes"))]
    {
        let _ = (results, ssl3, tls1_0, tls1_1, tls1_2);
    }
}

fn build_groups(results: &ScanResults) -> TlsGroups {
    // All observations live under one roof, partitioned by TLS version.
    // aws-lc-rs probes are TLS 1.3-only. OpenSSL FFDHE probes produce
    // per-version outcomes that split across tls1_2 and tls1_3.
    let mut out = TlsGroups::default();

    if let Some(probes) = &results.group_probes {
        for r in &probes.results {
            use crate::scanner::backends::HandshakeOutcome;
            // iana_code mirrors what the OpenSSL branch emits: probe
            // name → codepoint lookup. `iana_code_for` returns None
            // only for names outside TARGET_GROUPS; the rustls probe
            // only emits names from that table, so the fallback
            // branch is defensive.
            let iana_code = crate::scanner::backends::rustls::groups::iana_code_for(&r.name)
                .map(|code| format!("0x{code:04X}"));
            let obs = match &r.outcome {
                HandshakeOutcome::Supported => GroupObservation {
                    supported: Some(true),
                    method: Method::Probe,
                    reason: None,
                    iana_code: iana_code.clone(),
                    provider: Some("aws_lc_rs".to_string()),
                    returned_group: None,
                    returned_prime_bits: None,
                },
                HandshakeOutcome::NotSupported => GroupObservation {
                    supported: Some(false),
                    method: Method::Probe,
                    reason: None,
                    iana_code: iana_code.clone(),
                    provider: Some("aws_lc_rs".to_string()),
                    returned_group: None,
                    returned_prime_bits: None,
                },
                HandshakeOutcome::Error(ctx) => GroupObservation {
                    supported: None,
                    method: Method::Error,
                    reason: Some(ctx.clone()),
                    iana_code: iana_code.clone(),
                    provider: Some("aws_lc_rs".to_string()),
                    returned_group: None,
                    returned_prime_bits: None,
                },
                HandshakeOutcome::NotProbed(reason) => {
                    let mut o = GroupObservation::not_probed(reason.as_str());
                    o.provider = Some("aws_lc_rs".to_string());
                    o.iana_code = iana_code.clone();
                    o
                }
                HandshakeOutcome::IgnoredGroupReturnedDifferentPrime { .. }
                | HandshakeOutcome::WireRejected { .. } => unreachable!(
                    "rustls group probe never constructs \
                     IgnoredGroupReturnedDifferentPrime or WireRejected — \
                     FFDHE cross-check is OpenSSL-only and WireRejected is \
                     emitted only by raw-socket cipher probes"
                ),
            };
            // Route by the version tag on the result. Classical ECDHE
            // curves get probed at both TLS 1.2 and TLS 1.3 (two
            // entries in `probes.results`); ML-KEM and hybrids are
            // TLS 1.3 only.
            match r.version {
                TlsVersion::Tls12 => {
                    out.tls1_2.insert(r.name.clone(), obs);
                }
                TlsVersion::Tls13 => {
                    out.tls1_3.insert(r.name.clone(), obs);
                }
                _ => {}
            }
        }
    }

    merge_openssl_kx_groups(results, &mut out);
    out
}

fn merge_openssl_kx_groups(results: &ScanResults, out: &mut TlsGroups) {
    #[cfg(feature = "legacy-probes")]
    {
        use crate::scanner::backends::HandshakeOutcome;
        let Some(obs) = results.openssl_observations.as_ref() else {
            return;
        };
        let Some(probes) = obs.kx_group_probes.as_ref() else {
            return;
        };

        // Cross-codepoint coherence: a server that completes a TLS 1.2
        // DHE handshake but returns a prime different from the FFDHE
        // codepoint we offered has demonstrably not honored
        // `supported_groups`. When that evidence exists, downgrade
        // every FFDHE TLS 1.2 row — including rows whose returned
        // prime "matched" the codepoint, since the match is also
        // consistent with the server returning its static prime
        // regardless of offer (the fs.bbg.gov pattern: an RFC 7919
        // prime configured as the static `ssl_dhparam`). Per-row
        // `returned_group` + `returned_prime_bits` preserve the
        // observed evidence even after the verdict flips. TLS 1.3
        // FFDHE rows are wire-confirmed via `key_share` and not
        // subject to the downgrade.
        let host_ignores_supported_groups = probes.results.iter().any(|r| {
            ffdhe_bits_for_codepoint(r.iana_code).is_some()
                && matches!(
                    r.tls12_outcome,
                    HandshakeOutcome::IgnoredGroupReturnedDifferentPrime { .. }
                )
        });

        let to_obs = |o: &HandshakeOutcome,
                      iana: &str,
                      ffdhe_self_bits: Option<u32>,
                      ffdhe_self_group: Option<&str>|
         -> Option<GroupObservation> {
            Some(match o {
                HandshakeOutcome::Supported => {
                    match (host_ignores_supported_groups, ffdhe_self_group, ffdhe_self_bits) {
                        // FFDHE TLS 1.2 self-match downgraded by
                        // cross-codepoint evidence. The server
                        // returned the codepoint's expected prime, so
                        // that is what we record as returned_group.
                        (true, Some(self_group), Some(self_bits)) => GroupObservation {
                            supported: Some(false),
                            method: Method::Probe,
                            reason: Some(
                                "server_does_not_honor_supported_groups".to_string(),
                            ),
                            iana_code: Some(iana.to_string()),
                            provider: Some("openssl".to_string()),
                            returned_group: Some(self_group.to_string()),
                            returned_prime_bits: Some(self_bits),
                        },
                        _ => GroupObservation {
                            supported: Some(true),
                            method: Method::Probe,
                            reason: None,
                            iana_code: Some(iana.to_string()),
                            provider: Some("openssl".to_string()),
                            returned_group: None,
                            returned_prime_bits: None,
                        },
                    }
                }
                HandshakeOutcome::NotSupported => GroupObservation {
                    supported: Some(false),
                    method: Method::Probe,
                    reason: None,
                    iana_code: Some(iana.to_string()),
                    provider: Some("openssl".to_string()),
                    returned_group: None,
                    returned_prime_bits: None,
                },
                HandshakeOutcome::IgnoredGroupReturnedDifferentPrime {
                    returned_group,
                    returned_prime_bits,
                } => GroupObservation {
                    supported: Some(false),
                    method: Method::Probe,
                    reason: Some("server_does_not_honor_supported_groups".to_string()),
                    iana_code: Some(iana.to_string()),
                    provider: Some("openssl".to_string()),
                    returned_group: Some(returned_group.clone()),
                    returned_prime_bits: Some(*returned_prime_bits),
                },
                HandshakeOutcome::Error(e) => GroupObservation {
                    supported: None,
                    method: Method::Error,
                    reason: Some(e.clone()),
                    iana_code: Some(iana.to_string()),
                    provider: Some("openssl".to_string()),
                    returned_group: None,
                    returned_prime_bits: None,
                },
                // A "TLS 1.2 not applicable" cell for a non-FFDHE group
                // would just clutter the output — suppress it.
                HandshakeOutcome::NotProbed(r) if r == "tls12_not_applicable" => return None,
                HandshakeOutcome::NotProbed(r) => GroupObservation {
                    supported: None,
                    method: Method::NotProbed,
                    reason: Some(r.clone()),
                    iana_code: Some(iana.to_string()),
                    provider: Some("openssl".to_string()),
                    returned_group: None,
                    returned_prime_bits: None,
                },
                HandshakeOutcome::WireRejected { .. } => unreachable!(
                    "OpenSSL kx_groups probe never constructs \
                     WireRejected — that variant is emitted only by \
                     raw-socket cipher probes (`raw::static_dh`)"
                ),
            })
        };
        // aws-lc-rs-first override discipline: a real aws-lc-rs probe
        // result (`method: Probe`) wins; only overwrite slots aws-lc-rs
        // reported as `not_probed`.
        let should_override = |existing: Option<&GroupObservation>| -> bool {
            match existing {
                None => true,
                Some(o) => matches!(o.method, Method::NotProbed),
            }
        };
        for r in &probes.results {
            let iana = format!("0x{:04X}", r.iana_code);
            // Only TLS 1.2 FFDHE rows are subject to the downgrade —
            // the row's own group classification + bit length describe
            // what the server returned when it matched its own offer.
            let ffdhe_self_bits = ffdhe_bits_for_codepoint(r.iana_code);
            let ffdhe_self_group = ffdhe_self_bits.map(|_| r.group_name.as_str());
            if let Some(o) = to_obs(&r.tls12_outcome, &iana, ffdhe_self_bits, ffdhe_self_group) {
                if should_override(out.tls1_2.get(&r.group_name)) {
                    out.tls1_2.insert(r.group_name.clone(), o);
                }
            }
            if let Some(o) = to_obs(&r.tls13_outcome, &iana, None, None) {
                if should_override(out.tls1_3.get(&r.group_name)) {
                    out.tls1_3.insert(r.group_name.clone(), o);
                }
            }
        }
    }
    #[cfg(not(feature = "legacy-probes"))]
    {
        let _ = (results, out);
    }
}

/// Map an FFDHE IANA codepoint (RFC 7919 §5) to its prime bit length.
/// Returns `None` for any non-FFDHE codepoint, which doubles as the
/// FFDHE-or-not predicate used by the cross-codepoint coherence pass.
#[cfg(feature = "legacy-probes")]
fn ffdhe_bits_for_codepoint(code: u16) -> Option<u32> {
    match code {
        0x0100 => Some(2048),
        0x0101 => Some(3072),
        0x0102 => Some(4096),
        0x0103 => Some(6144),
        0x0104 => Some(8192),
        _ => None,
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

    let ocsp_stapling = build_ocsp_stapling(results, ctx);

    // SCT delivery paths. Embedded (cert extension) is counted via
    // CertificateInfo.embedded_scts. ext_path comes from the hello
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
    let delegated_credentials = build_delegated_credentials(results);

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
        truncated_hmac,
        npn,
        supported_point_formats_echoed,
        max_fragment_length,
        record_size_limit,
        compress_certificate_algorithms,
        delegated_credentials,
    }
}

/// Build `tls.behavioral_probes`: vulnerability probes (Heartbleed,
/// ephemeral reuse, ROBOT) plus ClientHello-body / ServerHello-variant
/// signals that aren't TLS extensions per the RFC framework. Schema
/// v2.0 split these out of `tls.extensions`.
fn build_behavioral_probes(results: &ScanResults) -> crate::model::scan_result::BehavioralProbes {
    use crate::model::scan_result::BehavioralProbes;

    let hello = results.hello_observed.as_ref();
    let hello_ok = hello.map(|h| h.server_hello_parsed).unwrap_or(false);
    let hello_fail_reason = hello
        .and_then(|h| h.error.clone())
        .unwrap_or_else(|| "hello_probe_not_run".to_string());

    // ClientHello/ServerHello body field — `compression_methods`
    // (RFC 5246 §7.4.1.3), not an extension. Empty when the byte
    // probe didn't succeed.
    let compression_offered: Vec<String> = hello
        .and_then(|h| h.compression_selected.clone())
        .map(|c| vec![c])
        .unwrap_or_default();

    // RFC 8701 GREASE echo. `true` = server echoed an unknown
    // extension (protocol violation); `false` = server correctly
    // ignored our GREASE offer. `not_probed` when the byte-level
    // hello probe didn't parse a ServerHello.
    let grease_echoed = if hello_ok {
        ObservationBool::probe(hello.and_then(|h| h.grease_echoed).unwrap_or(false))
    } else {
        ObservationBool::not_probed(&format!("hello_probe_failed:{hello_fail_reason}"))
    };

    // RFC 8446 §4.1.3 HelloRetryRequest observation. Populated by a
    // separate probe that sends a TLS 1.3 ClientHello with an empty
    // `key_share`. `None` on the struct means the probe never ran
    // (shouldn't happen in practice since `scan()` always invokes it).
    //
    // Cross-reference: HRR is a TLS 1.3 mechanism. If the protocol
    // probe pass affirmatively reports TLS 1.3 as not supported on
    // this host, the HRR question is `not_applicable` — there is no
    // TLS 1.3 handshake on this host for HRR to occur in. We still
    // surface the underlying probe error in the reason so consumers
    // who care about *why* HRR couldn't be measured (e.g. a peer-RST
    // pattern that signals an aggressive TLS 1.3 rejection) retain
    // that signal. Only an *affirmative* TLS-1.3-not-supported probe
    // gates the downgrade — when the version probe itself failed
    // (`error` set, `supported` unknown), the legacy `not_probed`
    // path stands so we don't quietly bury a real measurement
    // failure.
    let tls13_affirmatively_unsupported = results
        .protocol_support
        .iter()
        .find(|p| p.version == TlsVersion::Tls13)
        .map(|p| !p.supported && p.error.is_none())
        .unwrap_or(false);

    let hello_retry_request = match results.hrr_observed.as_ref() {
        Some(hrr) => match hrr.hrr_observed {
            Some(v) => ObservationBool::probe(v),
            None if tls13_affirmatively_unsupported => {
                let reason = match hrr.error.as_deref() {
                    Some(e) => format!("tls13_not_supported_on_host:{e}"),
                    None => "tls13_not_supported_on_host".to_string(),
                };
                ObservationBool::not_applicable(&reason)
            }
            None => ObservationBool::not_probed(
                hrr.error.as_deref().unwrap_or("hrr_probe_inconclusive"),
            ),
        },
        None if tls13_affirmatively_unsupported => {
            ObservationBool::not_applicable("tls13_not_supported_on_host")
        }
        None => ObservationBool::not_probed("hrr_probe_not_run"),
    };

    let heartbeat_echoes_oversized_payload = match results.heartbeat_echoes_oversized_payload {
        Some(v) => ObservationBool::probe(v),
        None => ObservationBool::not_probed("heartbeat_probe_inconclusive"),
    };

    BehavioralProbes {
        heartbeat_echoes_oversized_payload,
        compression_offered,
        grease_echoed,
        hello_retry_request,
        ephemeral_key_reuse: build_ephemeral_key_reuse(results),
        bleichenbacher_oracle_probe: build_bleichenbacher_oracle_probe(results),
    }
}

/// Merge the ROBOT probe observation from
/// `OpensslObservations.bleichenbacher_oracle_probe`. Feature-off
/// builds emit a stable `feature_disabled` skeleton.
fn build_bleichenbacher_oracle_probe(
    results: &ScanResults,
) -> crate::model::scan_result::BleichenbacherOracleProbe {
    use crate::model::scan_result::{BleichenbacherOracleProbe, Method};

    #[cfg(feature = "legacy-probes")]
    {
        if let Some(obs) = results.openssl_observations.as_ref() {
            if let Some(rb) = obs.bleichenbacher_oracle_probe.as_ref() {
                return rb.clone();
            }
        }
    }
    let _ = results;
    BleichenbacherOracleProbe {
        rsa_kex_suite_probed: None,
        method: Method::NotProbed,
        reason: Some("feature_disabled".to_string()),
        per_variant: Vec::new(),
    }
}

/// Merge the ephemeral-key-reuse observation from
/// `OpensslObservations.ephemeral_key_reuse`. Builds a
/// `feature_disabled` skeleton on non-legacy-probes builds so the
/// output shape stays stable across feature matrices.
fn build_ephemeral_key_reuse(
    results: &ScanResults,
) -> crate::model::scan_result::EphemeralKeyReuseObservation {
    use crate::model::scan_result::EphemeralKeyReuseObservation;

    #[cfg(feature = "legacy-probes")]
    {
        if let Some(obs) = results.openssl_observations.as_ref() {
            if let Some(ekr) = obs.ephemeral_key_reuse.as_ref() {
                return ekr.clone();
            }
        }
    }
    let _ = results;
    EphemeralKeyReuseObservation {
        dhe_public_reused_across_connections: ObservationBool::not_probed("feature_disabled"),
        ecdhe_public_reused_across_connections: ObservationBool::not_probed("feature_disabled"),
        dhe_suite_probed: None,
        ecdhe_suite_probed: None,
    }
}

/// Pull the TLS 1.3 DC detail fields (valid_time,
/// expected_cert_verify_algorithm) out of the feature-gated
/// observation path. Returns `None` under non-legacy-probes builds
/// so the caller's merge logic stays feature-agnostic.
#[cfg(feature = "legacy-probes")]
fn tls13_delegated_credential_facts(results: &ScanResults) -> Option<(u32, String)> {
    let dc = results
        .openssl_observations
        .as_ref()?
        .tls13_extensions
        .as_ref()?
        .delegated_credential
        .as_ref()?;
    Some((
        dc.valid_time_seconds,
        dc.expected_cert_verify_algorithm.clone(),
    ))
}
#[cfg(not(feature = "legacy-probes"))]
fn tls13_delegated_credential_facts(_results: &ScanResults) -> Option<(u32, String)> {
    None
}

/// Merge the TLS 1.2 SH presence signal (from `hello.rs`) with the
/// TLS 1.3 CertificateEntry parse (from `openssl/tls13_extensions.rs`)
/// into a single [`DelegatedCredentialsObservation`]. TLS 1.3 takes
/// precedence when both paths observe DC; the TLS 1.2 path only
/// carries presence, the TLS 1.3 path carries `valid_time` +
/// `expected_cert_verify_algorithm`.
fn build_delegated_credentials(
    results: &ScanResults,
) -> crate::model::scan_result::DelegatedCredentialsObservation {
    use crate::model::scan_result::DelegatedCredentialsObservation;

    let tls12_seen = results
        .hello_observed
        .as_ref()
        .and_then(|h| h.delegated_credential_advertised_in_sh)
        .unwrap_or(false);

    let tls13_dc = tls13_delegated_credential_facts(results);

    match (tls13_dc, tls12_seen) {
        (Some((valid_time, scheme)), _) => DelegatedCredentialsObservation {
            value: ObservationBool::probe(true),
            valid_time_seconds: Some(valid_time),
            expected_cert_verify_algorithm: Some(scheme),
            delivery_path: Some("tls1_3_certificate_entry".to_string()),
        },
        (None, true) => DelegatedCredentialsObservation {
            value: ObservationBool::probe(true),
            valid_time_seconds: None,
            expected_cert_verify_algorithm: None,
            delivery_path: Some("tls1_2_server_hello".to_string()),
        },
        (None, false) => {
            // Neither path saw DC. Distinguish "probed, not observed"
            // (hello probe parsed a SH) from "never probed" (hello
            // probe failed and no legacy-probes handshake reached
            // Certificate either).
            let hello_ok = results
                .hello_observed
                .as_ref()
                .map(|h| h.server_hello_parsed)
                .unwrap_or(false);
            if hello_ok {
                DelegatedCredentialsObservation {
                    value: ObservationBool::probe(false),
                    valid_time_seconds: None,
                    expected_cert_verify_algorithm: None,
                    delivery_path: None,
                }
            } else {
                DelegatedCredentialsObservation {
                    value: ObservationBool::not_probed("no_dc_observed_on_either_path"),
                    valid_time_seconds: None,
                    expected_cert_verify_algorithm: None,
                    delivery_path: None,
                }
            }
        }
    }
}

#[cfg(feature = "http-checks")]
fn build_crl_fetch(results: &ScanResults) -> Vec<crate::model::scan_result::CrlFetchEntry> {
    use crate::model::scan_result::CrlFetchEntry;
    let Some(out) = results.crl_fetch.as_ref() else {
        return Vec::new();
    };
    out.results
        .iter()
        .map(|r| CrlFetchEntry {
            url: r.url.clone(),
            http_status: r.http_status,
            this_update: r.this_update.clone(),
            next_update: r.next_update.clone(),
            crl_issuer: r.crl_issuer.clone(),
            revoked_cert_count: r.revoked_cert_count,
            leaf_revoked: r.leaf_revoked,
            revocation_time: r.revocation_time.clone(),
            revocation_reason: r.revocation_reason.clone(),
            error: r.error.clone(),
        })
        .collect()
}

#[cfg(not(feature = "http-checks"))]
fn build_crl_fetch(_results: &ScanResults) -> Vec<crate::model::scan_result::CrlFetchEntry> {
    Vec::new()
}

/// Render the OCSP-over-HTTP fallback entries from
/// `results.ocsp_http_fetch`. Parses each raw response body via the
/// shared OCSP parser ([`crate::model::ocsp_response::parse`]) so
/// the `content` shape matches what stapled OCSP renders as.
#[cfg(all(feature = "http-checks", feature = "legacy-probes"))]
fn build_ocsp_http_fallback(
    results: &ScanResults,
) -> Vec<crate::model::scan_result::OcspHttpFallbackEntry> {
    use crate::model::scan_result::OcspHttpFallbackEntry;

    let Some(fetch) = results.ocsp_http_fetch.as_ref() else {
        return Vec::new();
    };
    fetch
        .results
        .iter()
        .map(|r| {
            let (content, parse_err) = match r.response_der.as_ref() {
                Some(bytes) => match crate::model::ocsp_response::parse(bytes) {
                    Ok(c) => (Some(c), None),
                    Err(e) => (None, Some(format!("response_parse_failed:{e}"))),
                },
                None => (None, None),
            };
            OcspHttpFallbackEntry {
                url: r.url.clone(),
                http_status: r.http_status,
                content,
                response_length: r.response_der.as_ref().map(|b| b.len()).unwrap_or(0),
                error: r.error.clone().or(parse_err),
            }
        })
        .collect()
}

#[cfg(not(all(feature = "http-checks", feature = "legacy-probes")))]
fn build_ocsp_http_fallback(
    _results: &ScanResults,
) -> Vec<crate::model::scan_result::OcspHttpFallbackEntry> {
    Vec::new()
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

fn build_certificates(results: &ScanResults) -> Certificates {
    let chain = &results.certificate_chain;
    let mut facts: Vec<CertificateFacts> = chain.iter().map(cert_to_facts).collect();
    // Attach revocation observations to the leaf only. Intermediate-
    // cert revocation checking is a future workstream; non-leaf
    // entries keep `revocation: None`, which is skipped in JSON.
    if let Some(leaf_facts) = facts.first_mut() {
        let rev = build_cert_revocation(results);
        if rev.ocsp_http_fallback.is_empty() && rev.crl_fetch.is_empty() {
            leaf_facts.revocation = None;
        } else {
            leaf_facts.revocation = Some(rev);
        }
    }
    Certificates {
        leaf: facts.first().cloned(),
        chain: facts.clone(),
        chain_length: facts.len(),
    }
}

/// Assemble the leaf's out-of-band revocation observations:
/// OCSP-over-HTTP fetches + CRL fetches. Empty values render as
/// `None` on `CertificateFacts.revocation`.
fn build_cert_revocation(results: &ScanResults) -> crate::model::scan_result::CertRevocation {
    crate::model::scan_result::CertRevocation {
        ocsp_http_fallback: build_ocsp_http_fallback(results),
        crl_fetch: build_crl_fetch(results),
    }
}

fn cert_to_facts(c: &CertificateInfo) -> CertificateFacts {
    let public_key = PublicKey {
        algorithm: c.public_key_algorithm.clone(),
        size_bits: c.public_key_size,
        curve: c.ecc_curve_name.clone(),
        curve_oid: c.ecc_curve_oid.clone(),
        rsa_exponent: c.rsa_exponent,
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
        signature_algorithm_structured: c.signature_algorithm_structured.clone(),
        pqc_signature_family: c.pqc_signature_family.clone(),
        public_key,
        embedded_scts: c.embedded_scts,
        fingerprint_sha256: c.fingerprint_sha256.clone(),
        fingerprint_sha1: c.fingerprint_sha1.clone(),
        wire_position: c.wire_position,
        extensions: c.extensions.clone(),
        revocation: None,
    }
}

fn extract_cn(dn: &str) -> Option<String> {
    // Minimal CN extractor. x509-parser's Display produces comma-separated RDNs;
    // full RFC 4514 unescaping can land later alongside OID inspection.
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
            use crate::scanner::backends::rustls::sni::SniBehaviorOutcome;
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

    // Helper: map Option<bool> from a store slot to an
    // ObservationBool. `None` at this layer means the probe couldn't
    // run — either the characterization handshake failed, or the
    // trust store was empty (placeholder PEM / empty override). The
    // `per_store_validation_errors` map carries the specific reason;
    // we surface it in the ObservationBool's `reason` when present.
    let to_obs = |store_name: &str, slot: Option<bool>| -> ObservationBool {
        match slot {
            Some(b) => ObservationBool::probe(b),
            None => {
                let reason = v
                    .per_store_validation_errors
                    .get(store_name)
                    .cloned()
                    .unwrap_or_else(|| "characterization_handshake_failed".to_string());
                ObservationBool::not_probed(&reason)
            }
        }
    };

    let custom_roots: std::collections::BTreeMap<String, ObservationBool> = v
        .chain_valid_to_custom_roots
        .iter()
        .map(|(name, slot)| (name.clone(), to_obs(name, *slot)))
        .collect();

    Validation {
        chain_valid_to_webpki_roots: to_obs("webpki-roots", v.chain_valid_to_webpki_roots),
        chain_valid_to_microsoft_roots: to_obs("microsoft", v.chain_valid_to_microsoft_roots),
        chain_valid_to_apple_roots: to_obs("apple", v.chain_valid_to_apple_roots),
        chain_valid_to_us_fpki_common_roots: to_obs(
            "us-fpki-common",
            v.chain_valid_to_us_fpki_common_roots,
        ),
        chain_valid_to_us_dod_roots: to_obs("us-dod", v.chain_valid_to_us_dod_roots),
        chain_valid_to_custom_roots: custom_roots,
        name_matches_sni: match v.name_matches_sni {
            Some(b) => ObservationBool::probe(b),
            None => ObservationBool::not_probed("characterization_handshake_failed"),
        },
        validation_error: v.validation_error.clone(),
        per_store_validation_errors: v.per_store_validation_errors.clone(),
        trust_store_sources: v.trust_store_sources.clone(),
        trust_store_bundle_metadata: v
            .trust_store_bundle_metadata
            .iter()
            .map(|(name, meta)| {
                (
                    name.clone(),
                    crate::model::scan_result::TrustStoreBundleMetadata {
                        source: meta.source.clone(),
                        fetched_at: meta.fetched_at.clone(),
                        sha256: meta.sha256.clone(),
                        entry_count: meta.entry_count,
                        upstream_version: meta.upstream_version.clone(),
                    },
                )
            })
            .collect(),
    }
}

/// Parse rustls + openssl-src pinned versions from Cargo.toml at compile
/// time. Moved from main.rs to keep capability-building self-contained.
fn parse_dependency_versions() -> (String, String) {
    let cargo_toml = include_str!("../../Cargo.toml");
    let mut rustls_version = "unknown".to_string();
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
    }
    // aws-lc-rs is transitive via rustls's aws_lc_rs feature; we don't
    // get a dedicated version string without parsing Cargo.lock. Leave
    // as a `"bundled"` sentinel — a future release-time build step
    // could read Cargo.lock and substitute the real pinned version.
    (rustls_version, "bundled".to_string())
}

/// Pinned OpenSSL version shipped by the `legacy-probes` feature.
/// Sourced from `openssl-src = "=300.5.5"` in Cargo.toml. Returns
/// `"not_shipped"` when the feature is compiled out so downstream
/// consumers can tell legacy-probes-on vs off at a glance.
fn openssl_version() -> String {
    #[cfg(feature = "legacy-probes")]
    {
        let cargo_toml = include_str!("../../Cargo.toml");
        for line in cargo_toml.lines() {
            let line = line.trim();
            // `openssl-src = { version = "=300.5.5", ... }` — the
            // `=` prefix is an exact-version requirement; strip it so
            // consumers see a clean version number.
            if line.starts_with("openssl-src = {") {
                if let Some(pos) = line.find("version = \"") {
                    let start = pos + 11;
                    if let Some(end) = line[start..].find('"') {
                        let raw = &line[start..start + end];
                        return raw.trim_start_matches('=').to_string();
                    }
                }
            }
        }
        "unknown".to_string()
    }
    #[cfg(not(feature = "legacy-probes"))]
    {
        "not_shipped".to_string()
    }
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

fn build_session_resumption(results: &ScanResults) -> crate::model::scan_result::SessionResumption {
    use crate::model::scan_result::{Method, ObservationBool};

    #[cfg(feature = "legacy-probes")]
    let mut sr = {
        if let Some(obs) = results.openssl_observations.as_ref() {
            if let Some(sr) = obs.session_resumption.as_ref() {
                sr.clone()
            } else {
                feature_disabled_session_resumption()
            }
        } else {
            feature_disabled_session_resumption()
        }
    };
    #[cfg(not(feature = "legacy-probes"))]
    let mut sr = feature_disabled_session_resumption();

    // Cross-reference: TLS 1.3 PSK resumption + 0-RTT are TLS 1.3
    // mechanisms. If the protocol probe affirmatively reports TLS 1.3
    // as not supported on this host, the rustls resumption probe will
    // have failed with `ServerTlsVersionIsDisabledByOurConfig` (or
    // similar) on handshake #1 — surface the slot as
    // `not_applicable` rather than `not_probed`, preserving the
    // original probe error in the reason for forensic continuity.
    // Only an *affirmative* TLS-1.3-not-supported signal triggers the
    // downgrade; if the version probe itself failed (`error` set,
    // `supported` indeterminate), the original reason stands so we
    // don't quietly bury a real measurement failure.
    let tls13_affirmatively_unsupported = results
        .protocol_support
        .iter()
        .find(|p| p.version == TlsVersion::Tls13)
        .map(|p| !p.supported && p.error.is_none())
        .unwrap_or(false);
    if tls13_affirmatively_unsupported {
        for slot in [
            &mut sr.tls1_3.psk_resumption_accepted,
            &mut sr.tls1_3.early_data_accepted,
        ] {
            if matches!(slot.method, Method::NotProbed | Method::Error) {
                let new_reason = match slot.reason.as_deref() {
                    Some(r) => format!("tls13_not_supported_on_host:{r}"),
                    None => "tls13_not_supported_on_host".to_string(),
                };
                *slot = ObservationBool::not_applicable(&new_reason);
            }
        }
    }

    let _ = (results, &sr);
    sr
}

fn feature_disabled_session_resumption() -> crate::model::scan_result::SessionResumption {
    use crate::model::scan_result::{
        ObservationBool, SessionResumption, Tls12Resumption, Tls13Resumption,
    };
    SessionResumption {
        tls1_2: Tls12Resumption {
            session_ticket_issued: ObservationBool::not_probed("feature_disabled"),
            ticket_lifetime_hint_secs: None,
            session_id_issued: ObservationBool::not_probed("feature_disabled"),
            ticket_rotated_across_connections: ObservationBool::not_probed("feature_disabled"),
            session_ticket_resumption_accepted: ObservationBool::not_probed("feature_disabled"),
            session_id_resumption_accepted: ObservationBool::not_probed("feature_disabled"),
        },
        tls1_3: Tls13Resumption {
            new_session_ticket_count: None,
            ticket_lifetime_secs: Vec::new(),
            psk_resumption_accepted: ObservationBool::not_probed("feature_disabled"),
            early_data_accepted: ObservationBool::not_probed("feature_disabled"),
        },
    }
}

fn build_sigalg_policy(
    results: &ScanResults,
) -> crate::model::scan_result::SignatureAlgorithmPolicyProbe {
    use crate::model::scan_result::{
        ConstrainedProbeResult, Method, SigalgOutcome, SignatureAlgorithmPolicyProbe,
    };

    #[cfg(feature = "legacy-probes")]
    {
        if let Some(obs) = results.openssl_observations.as_ref() {
            if let Some(sap) = obs.sigalg_policy.as_ref() {
                return sap.clone();
            }
        }
    }
    let _ = results;
    // feature_disabled fallback — stable shape with every slot
    // resolving to the same not_probed reason.
    let slot = || ConstrainedProbeResult {
        outcome: SigalgOutcome::NotProbed,
        selected_sigalg: None,
        alert: None,
        method: Method::NotProbed,
        reason: Some("feature_disabled".to_string()),
        leaf_fingerprint_sha256: None,
        leaf_subject_dn: None,
    };
    SignatureAlgorithmPolicyProbe {
        sha256_plus_only: slot(),
        ecdsa_only: slot(),
        rsa_pss_only: slot(),
        rsa_pkcs1_only: slot(),
        eddsa_only: slot(),
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
