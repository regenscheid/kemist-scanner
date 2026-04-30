//! Human-readable terminal renderer for schema-v1 `ScanResult` records.
//!
//! Downstream rule engines consume the  JSON output; this view is for
//! interactive debugging of single scans.
//!
//! ## Glyph legend
//! - `+` supported / true
//! - `-` not supported / false
//! - `?` not probed, not applicable, or probe errored
//!
//! Color only fires when stdout is a TTY — the `colored` crate auto-detects
//! via `CARGO_TERM_COLOR`/isatty. `--no-color` turns it off entirely.

use colored::Colorize;

use crate::model::scan_result::{
    CipherSuiteEntry, ClientAuthRequestEntry, DhParametersObservation, GroupObservation, Method,
    ObservationBool, RenegotiationBehavior, ScanResult, SkeSigObservation, TlsExtensions,
};

/// Render one scan record to stdout. Compact (~50 lines).
pub fn render(r: &ScanResult) {
    render_header(r);
    println!();
    render_versions(r);
    println!();
    render_negotiated(r);
    println!();
    render_cipher_suites(r);
    println!();
    render_groups(r);
    println!();
    render_legacy_probes(r);
    render_certificates(r);
    println!();
    render_validation(r);
    println!();
    render_extensions(r);
    println!();
    render_behavioral_probes(r);
    println!();
    render_sni_behavior(r);
    if let Some(http) = &r.http {
        if http.enabled {
            println!();
            render_http(r);
        }
    }
    println!();
    render_errors(r);
}

fn render_header(r: &ScanResult) {
    println!("{}", "kemist scan".bold().cyan());
    kv("target", &r.scan.target);
    if let Some(ip) = &r.scan.resolved_ip {
        kv("resolved_ip", ip);
    }
    kv("sni_sent", &r.scan.sni_sent);
    kv("duration_ms", &r.scan.duration_ms.to_string());
    kv("schema_version", &r.schema_version);
}

fn render_versions(r: &ScanResult) {
    section("TLS versions offered");
    let v = &r.tls.versions_offered;
    print_version(
        "SSL 2.0",
        v.ssl2.offered,
        &v.ssl2.method,
        v.ssl2.reason.as_deref(),
    );
    print_version(
        "SSL 3.0",
        v.ssl3.offered,
        &v.ssl3.method,
        v.ssl3.reason.as_deref(),
    );
    print_version(
        "TLS 1.0",
        v.tls1_0.offered,
        &v.tls1_0.method,
        v.tls1_0.reason.as_deref(),
    );
    print_version(
        "TLS 1.1",
        v.tls1_1.offered,
        &v.tls1_1.method,
        v.tls1_1.reason.as_deref(),
    );
    print_version(
        "TLS 1.2",
        v.tls1_2.offered,
        &v.tls1_2.method,
        v.tls1_2.reason.as_deref(),
    );
    print_version(
        "TLS 1.3",
        v.tls1_3.offered,
        &v.tls1_3.method,
        v.tls1_3.reason.as_deref(),
    );
}

fn render_negotiated(r: &ScanResult) {
    section("Negotiated");
    match &r.tls.negotiated {
        Some(n) => {
            kv("version", &n.version);
            if let Some(s) = &n.cipher_suite {
                kv("cipher_suite", s);
            }
            if let Some(g) = &n.group {
                // PQC groups get cyan to stand out visually.
                if is_pqc_group(g) {
                    println!("  {:<22} {}", "kx_group:", g.cyan().bold());
                } else {
                    kv("kx_group", g);
                }
            }
            if let Some(ss) = &n.signature_scheme {
                kv("sig_scheme", ss);
            }
            if let Some(a) = &n.alpn {
                kv("alpn", a);
            }
        }
        None => println!(
            "    {}",
            "(characterization handshake did not complete)".dimmed()
        ),
    }
}

fn render_cipher_suites(r: &ScanResult) {
    section("Cipher suites (probed)");
    let cs = &r.tls.cipher_suites;
    // Print newest → oldest so the "normal" modern suites show at the
    // top and legacy findings fall below where they're less likely to
    // distract on a clean scan.
    let mut any = false;
    for (label, arr) in [
        ("TLS 1.3", &cs.tls1_3),
        ("TLS 1.2", &cs.tls1_2),
        ("TLS 1.1", &cs.tls1_1),
        ("TLS 1.0", &cs.tls1_0),
    ] {
        if arr.is_empty() {
            continue;
        }
        any = true;
        println!("  {}:", label.bold());
        for e in arr {
            print_cipher_entry(e);
        }
    }
    if !any {
        println!("    {}", "(no cipher suites probed)".dimmed());
    }
    // server_enforces_order
    let label = "server_enforces_order:";
    match (
        cs.server_enforces_order.value,
        &cs.server_enforces_order.method,
    ) {
        (Some(true), _) => println!("  {} {}", label, "true".green()),
        (Some(false), _) => println!("  {} {}", label, "false".dimmed()),
        (None, m) => println!(
            "  {} {} [{}]",
            label,
            "—".yellow(),
            method_label(m).yellow()
        ),
    }
}

fn render_groups(r: &ScanResult) {
    section("Key exchange groups");
    let g = &r.tls.groups;
    if g.tls1_2.is_empty() && g.tls1_3.is_empty() {
        println!("    {}", "(no groups probed)".dimmed());
        return;
    }
    // TLS 1.3 first — aws-lc-rs modern groups + FFDHE 1.3 outcomes.
    if !g.tls1_3.is_empty() {
        println!("  {}:", "TLS 1.3".bold());
        for (name, obs) in &g.tls1_3 {
            print_group(name, obs);
        }
    }
    // TLS 1.2 — FFDHE only. This is where the FFDHE cross-check
    // finding (`server_does_not_honor_supported_groups`)
    // surfaces, handled inside print_group.
    if !g.tls1_2.is_empty() {
        println!("  {}:", "TLS 1.2".bold());
        for (name, obs) in &g.tls1_2 {
            print_group(name, obs);
        }
    }
}

fn render_certificates(r: &ScanResult) {
    section("Certificate (leaf)");
    let Some(leaf) = &r.certificates.leaf else {
        println!("    {}", "(no cert chain captured)".dimmed());
        return;
    };
    if let Some(cn) = &leaf.subject_cn {
        kv("subject_cn", cn);
    }
    if !leaf.san.is_empty() {
        let san = leaf.san.join(", ");
        // Trim long SAN lists for readability.
        let s = if san.len() > 100 {
            format!("{}… ({} entries)", &san[..100], leaf.san.len())
        } else {
            san
        };
        kv("san", &s);
    }
    if let Some(cn) = &leaf.issuer_cn {
        kv("issuer_cn", cn);
    }
    let sig_line = match &leaf.pqc_signature_family {
        Some(family) => format!(
            "{} ({})  {} ({})",
            leaf.signature_algorithm_name,
            leaf.signature_algorithm_oid,
            "PQC".cyan().bold(),
            family
        ),
        None => format!(
            "{} ({})",
            leaf.signature_algorithm_name, leaf.signature_algorithm_oid
        ),
    };
    kv("signature", &sig_line);
    let pk = &leaf.public_key;
    let pk_line = match &pk.curve {
        Some(c) => format!("{} {}b ({})", pk.algorithm, pk.size_bits, c),
        None => format!("{} {}b", pk.algorithm, pk.size_bits),
    };
    kv("public_key", &pk_line);
    kv(
        "validity",
        &format!(
            "{} → {} ({} days)",
            leaf.not_before.format("%Y-%m-%d"),
            leaf.not_after.format("%Y-%m-%d"),
            leaf.validity_days
        ),
    );
    kv("chain_length", &r.certificates.chain_length.to_string());
    kv("embedded_scts", &leaf.embedded_scts.to_string());
    render_cert_extensions(&leaf.extensions);
}

fn render_cert_extensions(ext: &crate::model::cert_extensions::CertExtensions) {
    if let Some(bc) = &ext.basic_constraints {
        let line = match bc.path_len_constraint {
            Some(n) => format!("ca={} path_len={}", bc.ca, n),
            None => format!("ca={}", bc.ca),
        };
        kv("basic_constraints", &line);
    }
    if let Some(ku) = &ext.key_usage {
        if !ku.bits.is_empty() {
            kv("key_usage", &ku.bits.join(", "));
        }
    }
    if let Some(eku) = &ext.extended_key_usage {
        if !eku.oids.is_empty() {
            kv("extended_key_usage", &eku.oids.join(", "));
        }
    }
    if let Some(ski) = &ext.subject_key_identifier {
        kv("subject_key_identifier", ski);
    }
    if let Some(aki) = &ext.authority_key_identifier {
        kv("authority_key_identifier", aki);
    }
    if let Some(aia) = &ext.authority_information_access {
        if !aia.ocsp.is_empty() {
            kv("aia_ocsp", &aia.ocsp.join(", "));
        }
        if !aia.ca_issuers.is_empty() {
            kv("aia_ca_issuers", &aia.ca_issuers.join(", "));
        }
    }
    if let Some(crl) = &ext.crl_distribution_points {
        if !crl.urls.is_empty() {
            kv("crl_distribution_points", &crl.urls.join(", "));
        }
    }
    if let Some(nc) = &ext.name_constraints {
        if !nc.permitted_subtrees.is_empty() {
            kv(
                "name_constraints_permitted",
                &nc.permitted_subtrees.join(", "),
            );
        }
        if !nc.excluded_subtrees.is_empty() {
            kv(
                "name_constraints_excluded",
                &nc.excluded_subtrees.join(", "),
            );
        }
    }
    if let Some(cp) = &ext.certificate_policies {
        if !cp.oids.is_empty() {
            kv("certificate_policies", &cp.oids.join(", "));
        }
    }
    if let Some(ms) = ext.must_staple {
        kv("must_staple", &ms.to_string());
    }
    if !ext.scts.is_empty() {
        kv("scts", &format!("{} entries", ext.scts.len()));
    }
}

fn render_validation(r: &ScanResult) {
    section("Validation");
    print_obs_bool(
        "chain_valid_to_webpki_roots",
        &r.validation.chain_valid_to_webpki_roots,
    );
    print_obs_bool("name_matches_sni", &r.validation.name_matches_sni);
    if let Some(e) = &r.validation.validation_error {
        kv("validation_error", e);
    }
}

fn render_extensions(r: &ScanResult) {
    section("Extensions");
    let ext: &TlsExtensions = &r.tls.extensions;
    print_obs_bool("ems", &ext.ems);
    print_obs_bool("encrypt_then_mac", &ext.encrypt_then_mac);
    print_obs_bool("heartbeat_present", &ext.heartbeat_present);
    print_obs_bool("secure_renegotiation", &ext.secure_renegotiation);
    // ocsp_stapling is a struct, not Observation<bool> — render inline.
    let ocsp = &ext.ocsp_stapling;
    match (ocsp.stapled, &ocsp.method) {
        (Some(true), _) => {
            let delivery = ocsp.delivery_path.as_deref().unwrap_or("?");
            println!(
                "  {:<22} {} ({} bytes, {})",
                "ocsp_stapling:",
                "true".green(),
                ocsp.response_length,
                delivery
            );
            if let Some(c) = &ocsp.content {
                let status = c.cert_status.as_deref().unwrap_or("?");
                let status_colored = match status {
                    "good" => "good".green().to_string(),
                    "revoked" => "revoked".red().bold().to_string(),
                    "unknown" => "unknown".yellow().to_string(),
                    other => other.to_string(),
                };
                println!(
                    "  {:<22} {} / cert_status={}",
                    "", c.response_status, status_colored
                );
                if let (Some(this), Some(next)) = (&c.this_update, &c.next_update) {
                    println!(
                        "  {:<22} thisUpdate={} nextUpdate={}",
                        "",
                        this.format("%Y-%m-%d %H:%M"),
                        next.format("%Y-%m-%d %H:%M")
                    );
                }
                if let Some(reason) = &c.revocation_reason {
                    println!("  {:<22} revocation_reason={}", "", reason.red());
                }
            } else if let Some(reason) = &ocsp.reason {
                println!("  {:<22} ({})", "", reason.yellow());
            }
        }
        (Some(false), _) => println!("  {:<22} {}", "ocsp_stapling:", "false".dimmed()),
        (None, m) => println!(
            "  {:<22} {} [{}]",
            "ocsp_stapling:",
            "—".yellow(),
            method_label(m).yellow()
        ),
    }
    if !ext.alpn_offered.is_empty() {
        kv("alpn_offered", &ext.alpn_offered.join(", "));
    }
    if !ext.sct.delivery_paths.is_empty() {
        kv(
            "sct",
            &format!(
                "{} (count={})",
                ext.sct.delivery_paths.join(", "),
                ext.sct.count
            ),
        );
    }
    print_obs_bool("truncated_hmac", &ext.truncated_hmac);
    print_obs_bool("npn", &ext.npn);
    if !ext.supported_point_formats_echoed.is_empty() {
        kv(
            "supported_point_formats_echoed",
            &ext.supported_point_formats_echoed.join(", "),
        );
    }
    if let Some(v) = &ext.max_fragment_length {
        kv("max_fragment_length", v);
    }
    if let Some(v) = ext.record_size_limit {
        kv("record_size_limit", &v.to_string());
    }
    if !ext.compress_certificate_algorithms.is_empty() {
        kv(
            "compress_certificate",
            &ext.compress_certificate_algorithms.join(", "),
        );
    }
    if let Some(s) = &r.tls.downgrade_signaling.tls13_downgrade_sentinel {
        let colored = match s.as_str() {
            "tls12" => "tls12".yellow().to_string(),
            "lte_tls11" => "lte_tls11".red().to_string(),
            _ => s.dimmed().to_string(),
        };
        println!("  {:<22} {}", "tls13_downgrade_sentinel:", colored);
    }
}

/// Render `tls.behavioral_probes` — vulnerability probes plus
/// non-extension handshake-time observations. Schema v2.0 split this
/// out of `tls.extensions` because none of these are TLS extensions
/// in the RFC 5246 §7.4.1.4 / RFC 8446 §4.2 sense.
fn render_behavioral_probes(r: &ScanResult) {
    let bp = &r.tls.behavioral_probes;
    section("Behavioral probes");
    print_obs_bool(
        "heartbleed_echo",
        &bp.heartbeat_echoes_oversized_payload,
    );
    if !bp.compression_offered.is_empty() {
        kv("compression_methods", &bp.compression_offered.join(", "));
    }
    print_obs_bool("grease_echoed", &bp.grease_echoed);
    print_obs_bool("hello_retry_request", &bp.hello_retry_request);
    // ephemeral_key_reuse + bleichenbacher_oracle_probe are
    // structured observations rather than ObservationBool — they
    // already render through `render_legacy_probes` and the JSON
    // output. Surface a one-line summary here so a reader of the
    // text output sees them grouped under the right banner.
    let dhe = &bp.ephemeral_key_reuse.dhe_public_reused_across_connections;
    let ecdhe = &bp
        .ephemeral_key_reuse
        .ecdhe_public_reused_across_connections;
    print_obs_bool("dhe_ephemeral_reuse", dhe);
    print_obs_bool("ecdhe_ephemeral_reuse", ecdhe);
    let robot_method = method_label(&bp.bleichenbacher_oracle_probe.method);
    println!(
        "  {:<22} {}",
        "robot_probe:",
        robot_method.to_string().yellow()
    );
}

/// Render the OpenSSL-backed probe sections that don't fold into
/// `cipher_suites` or `groups` — DH parameters, SKE signatures, SCSV,
/// renegotiation, CertificateRequest. Each subsection is gated on "did
/// we actually learn something?" so the text output stays compact when
/// `legacy-probes` is disabled or the target rejects everything cleanly.
fn render_legacy_probes(r: &ScanResult) {
    let tls = &r.tls;

    let scsv = &tls.downgrade_signaling.fallback_scsv_enforced;
    let has_scsv_signal = scsv.value.is_some() || scsv.method != Method::NotProbed;

    let anything = !tls.dh_parameters.is_empty()
        || !tls.server_key_exchange_signatures.is_empty()
        || tls.client_auth_request.is_some()
        || tls
            .renegotiation_behavior
            .client_initiated_verdict
            .is_some()
        || has_scsv_signal
        || matches!(
            tls.session_resumption.tls1_2.session_ticket_issued.method,
            Method::Probe | Method::ConnectionState
        )
        || [
            &tls.signature_algorithm_policy_probe.sha256_plus_only,
            &tls.signature_algorithm_policy_probe.ecdsa_only,
            &tls.signature_algorithm_policy_probe.rsa_pss_only,
            &tls.signature_algorithm_policy_probe.rsa_pkcs1_only,
        ]
        .iter()
        .any(|r| matches!(r.method, Method::Probe));
    if !anything {
        return;
    }

    render_dh_parameters(&tls.dh_parameters);
    render_ske_signatures(&tls.server_key_exchange_signatures);
    render_downgrade_signaling(scsv);
    render_renegotiation_behavior(&tls.renegotiation_behavior);
    render_client_auth_request(tls.client_auth_request.as_ref());
    render_session_resumption(&tls.session_resumption);
    render_sigalg_policy(&tls.signature_algorithm_policy_probe);
}

fn render_sigalg_policy(p: &crate::model::scan_result::SignatureAlgorithmPolicyProbe) {
    use crate::model::scan_result::SigalgOutcome;
    let has_signal = [
        &p.sha256_plus_only,
        &p.ecdsa_only,
        &p.rsa_pss_only,
        &p.rsa_pkcs1_only,
    ]
    .iter()
    .any(|r| matches!(r.method, Method::Probe));
    if !has_signal {
        return;
    }
    section("Signature-algorithm policy probe");
    for (label, r) in [
        ("sha256_plus_only", &p.sha256_plus_only),
        ("ecdsa_only", &p.ecdsa_only),
        ("rsa_pss_only", &p.rsa_pss_only),
        ("rsa_pkcs1_only", &p.rsa_pkcs1_only),
    ] {
        let outcome_str = match r.outcome {
            SigalgOutcome::HandshakeComplete => "complete".green().to_string(),
            SigalgOutcome::HandshakeFailure => "handshake_failure".yellow().to_string(),
            SigalgOutcome::ConnectionClosed => "connection_closed".yellow().to_string(),
            SigalgOutcome::OtherAlert => "other_alert".yellow().to_string(),
            SigalgOutcome::NotProbed => "not_probed".dimmed().to_string(),
        };
        let suffix = match (&r.selected_sigalg, &r.alert) {
            (Some(s), _) => format!(" → {s}"),
            (None, Some(a)) => format!(" ({a})"),
            (None, None) => match &r.reason {
                Some(reason) => format!(" ({reason})"),
                None => String::new(),
            },
        };
        println!("  {:<22} {}{}", format!("{label}:"), outcome_str, suffix);
    }
}

fn render_session_resumption(sr: &crate::model::scan_result::SessionResumption) {
    // Only render when at least one slot has a probed observation —
    // keeps the text output compact when the probe is feature-
    // disabled or the handshake never completed.
    let tls12_has_signal = matches!(
        sr.tls1_2.session_ticket_issued.method,
        Method::Probe | Method::ConnectionState
    );
    if !tls12_has_signal {
        return;
    }
    section("Session resumption");
    print_obs_bool(
        "tls1_2.session_ticket_issued",
        &sr.tls1_2.session_ticket_issued,
    );
    if let Some(secs) = sr.tls1_2.ticket_lifetime_hint_secs {
        kv("tls1_2.ticket_lifetime_hint_secs", &secs.to_string());
    }
    print_obs_bool("tls1_2.session_id_issued", &sr.tls1_2.session_id_issued);
    print_obs_bool(
        "tls1_2.ticket_rotated_across_connections",
        &sr.tls1_2.ticket_rotated_across_connections,
    );
    print_obs_bool(
        "tls1_2.session_ticket_resumption_accepted",
        &sr.tls1_2.session_ticket_resumption_accepted,
    );
    print_obs_bool(
        "tls1_2.session_id_resumption_accepted",
        &sr.tls1_2.session_id_resumption_accepted,
    );
}

fn render_dh_parameters(entries: &[DhParametersObservation]) {
    if entries.is_empty() {
        return;
    }
    section("DH parameters (observed)");
    for e in entries {
        // Color by prime size: <2048 is Logjam territory; anything
        // larger is fine on size alone. Custom classification
        // (regardless of size) gets flagged because unknown-provenance
        // primes are the Logjam precomputation target.
        let size_style = if e.prime_bits < 2048 {
            format!("{}-bit", e.prime_bits).red().bold()
        } else {
            format!("{}-bit", e.prime_bits).normal()
        };
        let class_style = if e.classification == "custom" {
            e.classification.yellow()
        } else {
            e.classification.green()
        };
        println!(
            "    {} via {}: g={} sha256={}…{}",
            size_style,
            class_style,
            e.generator,
            &e.prime_sha256[..8],
            format!("  [{}]", e.cipher_suite).dimmed()
        );
    }
    println!();
}

fn render_ske_signatures(sigs: &[SkeSigObservation]) {
    if sigs.is_empty() {
        return;
    }
    section("Server-key-exchange signatures");
    for s in sigs {
        // SHA-1 or MD5 in a production TLS 1.2 SKE is a weak-sig
        // finding — highlight. Everything else is informational.
        let style =
            if s.signature_algorithm.ends_with("_sha1") || s.signature_algorithm.contains("md5") {
                s.signature_algorithm.yellow().bold()
            } else {
                s.signature_algorithm.normal()
            };
        println!("    {:<32} ({})", style, s.cipher_suite.dimmed());
    }
    println!();
}

fn render_downgrade_signaling(scsv: &ObservationBool) {
    section("Downgrade signaling");
    // Reason-string flag set when the server rejected the downgraded
    // handshake with handshake_failure instead of the RFC 7507-mandated
    // inappropriate_fallback alert. Effective protection; non-compliant
    // wording. Worth surfacing so an eyeball can see the caveat without
    // dropping into the JSON output.
    let non_compliant = scsv
        .reason
        .as_deref()
        .map(|r| r.starts_with("rejected_via_non_mandated_alert:"))
        .unwrap_or(false);
    let line = match (scsv.value, &scsv.method) {
        (Some(true), _) if non_compliant => format!(
            "{} {}",
            "enforced".green(),
            "(via handshake_failure — not RFC-compliant alert)".yellow()
        ),
        (Some(true), _) => format!("{} {}", "enforced".green(), "(TLS_FALLBACK_SCSV)".dimmed()),
        (Some(false), _) => format!(
            "{} {}",
            "NOT enforced".red().bold(),
            "(server accepted downgrade)".dimmed()
        ),
        (None, m) => format!(
            "{} [{}]{}",
            "—".yellow(),
            method_label(m).yellow(),
            scsv.reason
                .as_deref()
                .map(|r| format!(": {}", r.dimmed()))
                .unwrap_or_default()
        ),
    };
    println!("  fallback_scsv: {}", line);
    println!();
}

fn render_renegotiation_behavior(r: &RenegotiationBehavior) {
    // Deliberately omit when the verdict is `None` and no reason is set —
    // that's the "nothing to report" state.
    if r.client_initiated_verdict.is_none() && r.reason.is_none() {
        return;
    }
    section("Client-initiated renegotiation");
    let verdict_style = match r.client_initiated_verdict.as_deref() {
        Some("rejected") => "rejected".green(),
        Some("not_attempted") => "not_attempted".dimmed(),
        Some("accepted") => "accepted".yellow().bold(),
        Some("error") => "error".yellow(),
        Some(other) => other.normal(),
        None => "—".yellow(),
    };
    let tail = r
        .reason
        .as_deref()
        .map(|s| format!("  [{}]", s.dimmed()))
        .unwrap_or_default();
    println!("  verdict: {}{}", verdict_style, tail);
    println!();
}

fn render_client_auth_request(ca: Option<&ClientAuthRequestEntry>) {
    let Some(ca) = ca else { return };
    if !ca.requested {
        return;
    }
    section("Client-auth request (CertificateRequest observed)");
    if !ca.signature_algorithms.is_empty() {
        kv("sig_algs", &ca.signature_algorithms.join(", "));
    }
    if !ca.certificate_types.is_empty() {
        let bytes: Vec<String> = ca
            .certificate_types
            .iter()
            .map(|b| format!("0x{b:02X}"))
            .collect();
        kv("cert_types", &bytes.join(", "));
    }
    for dn in &ca.ca_distinguished_names {
        let ident = match (&dn.common_name, &dn.organization) {
            (Some(cn), Some(o)) => format!("CN={cn}, O={o}"),
            (Some(cn), None) => format!("CN={cn}"),
            (None, Some(o)) => format!("O={o}"),
            (None, None) => format!("(DER {} bytes)", dn.raw_der_b64.len() / 2),
        };
        println!("    CA: {}", ident);
    }
    if !ca.oid_filters.is_empty() {
        kv("oid_filters", &format!("{} entries", ca.oid_filters.len()));
    }
    if let Some(alert) = &ca.alert_on_empty_cert {
        kv("on_empty_cert", &format!("{} (required mTLS)", alert));
    } else {
        kv("on_empty_cert", "accepted (optional mTLS)");
    }
    println!();
}

fn render_sni_behavior(r: &ScanResult) {
    section("SNI behavior (omitted probe)");
    let sni = &r.tls.sni_behavior;
    match (&sni.omitted_probe, &sni.method) {
        (Some(s), _) => {
            let colored = match s.as_str() {
                "same_cert" => s.normal(),
                "different_cert" => s.cyan(),
                "rejected" => s.yellow(),
                "error" => s.yellow(),
                _ => s.normal(),
            };
            // A rejected/error probe is much more useful with the reason
            // attached: "server required SNI" reads very differently
            // from "TCP reset mid-probe".
            let tail = sni
                .reason
                .as_deref()
                .filter(|_| matches!(s.as_str(), "rejected" | "error"))
                .map(|r| format!("  [{}]", r.dimmed()))
                .unwrap_or_default();
            println!("  {}{}", colored, tail);
        }
        (None, m) => println!("  {} [{}]", "—".yellow(), method_label(m).yellow()),
    }
}

fn render_http(r: &ScanResult) {
    section("HTTP (enabled)");
    let Some(http) = &r.http else { return };
    if let Some(hsts) = &http.hsts {
        if hsts.header_present {
            let mut parts = Vec::new();
            if let Some(m) = hsts.max_age {
                parts.push(format!("max-age={m}"));
            }
            if hsts.include_subdomains == Some(true) {
                parts.push("includeSubDomains".to_string());
            }
            if hsts.preload == Some(true) {
                parts.push("preload".to_string());
            }
            kv("hsts", &parts.join(", "));
        } else {
            kv("hsts", "not present");
        }
    }
    if let Some(s) = &http.preload_list_status {
        kv("preload_list", s);
    }
    if let Some(stxt) = &http.security_txt {
        if stxt.present {
            let ct = stxt.content_type.as_deref().unwrap_or("?");
            let blen = stxt.body.as_ref().map(|b| b.len()).unwrap_or(0);
            kv("security_txt", &format!("present ({ct}, {blen} bytes)"));
        } else {
            kv("security_txt", "not present");
        }
    }
}

fn render_errors(r: &ScanResult) {
    if r.errors.is_empty() {
        println!("{} 0", "Errors:".bold());
        return;
    }
    println!("{} {}", "Errors:".bold().yellow(), r.errors.len());
    for e in &r.errors {
        println!("  - [{}] {}", e.category.yellow(), e.context);
    }
}

// ── helpers ────────────────────────────────────────────────────────

fn section(title: &str) {
    println!("{}", title.bold().cyan());
}

fn kv(key: &str, value: &str) {
    println!("  {:<22} {}", format!("{key}:"), value);
}

fn print_version(label: &str, offered: Option<bool>, method: &Method, reason: Option<&str>) {
    let prefix = "  ";
    let method_str = method_label(method);
    match offered {
        Some(true) => println!("{prefix}{:<10} {}", label, "yes".green()),
        Some(false) => println!("{prefix}{:<10} {}", label, "no".dimmed()),
        None => match reason {
            Some(r) => println!(
                "{prefix}{:<10} {} [{}: {}]",
                label,
                "—".yellow(),
                method_str.yellow(),
                r.dimmed()
            ),
            None => println!(
                "{prefix}{:<10} {} [{}]",
                label,
                "—".yellow(),
                method_str.yellow()
            ),
        },
    }
}

fn print_obs_bool(label: &str, o: &ObservationBool) {
    let label_cell = format!("{label}:");
    match (o.value, &o.method) {
        (Some(true), _) => println!("  {:<22} {}", label_cell, "true".green()),
        (Some(false), _) => println!("  {:<22} {}", label_cell, "false".dimmed()),
        (None, m) => match &o.reason {
            Some(r) => println!(
                "  {:<22} {} [{}: {}]",
                label_cell,
                "—".yellow(),
                method_label(m).yellow(),
                r.dimmed()
            ),
            None => println!(
                "  {:<22} {} [{}]",
                label_cell,
                "—".yellow(),
                method_label(m).yellow()
            ),
        },
    }
}

fn print_cipher_entry(e: &CipherSuiteEntry) {
    // Supported-but-weak suites (RC4, NULL, anon-DH, etc.) are the
    // interesting finding even though the observation is technically
    // positive. Upgrade to yellow+bold for attention. Keyed on name
    // substrings so both aws-lc-rs and OpenSSL entries get the same
    // treatment.
    let weak = is_weak_cipher_name(&e.name);
    let (glyph, name_style) = match (e.supported, &e.method) {
        (Some(true), _) if weak => ("+", e.name.yellow().bold()),
        (Some(true), _) => ("+", e.name.green()),
        (Some(false), _) => ("-", e.name.dimmed()),
        (None, _) => ("?", e.name.yellow()),
    };
    // OpenSSL short name (e.g. "AES128-SHA") is useful for manual
    // reproduction — render it in parentheses when present.
    let ossl_suffix = e
        .openssl_name
        .as_deref()
        .map(|s| format!("  ({})", s.dimmed()))
        .unwrap_or_default();
    let tail = match (&e.method, &e.reason) {
        (Method::Error, Some(r)) => format!("  [{}]", r.dimmed()),
        (Method::NotProbed, Some(r)) => format!("  [{}]", r.dimmed()),
        _ => String::new(),
    };
    println!(
        "    {} {:<48} {}{}{}",
        glyph, name_style, e.iana_code, ossl_suffix, tail
    );
}

/// Name-substring heuristic for "this suite is a weak-crypto finding."
/// Matches both IANA (`TLS_RSA_WITH_RC4_128_SHA`) and OpenSSL short
/// names (`RC4-SHA`). Only affects text-view color; JSON stays neutral.
fn is_weak_cipher_name(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    n.contains("RC4")
        || n.contains("NULL")
        || n.contains("_DES_")
        || n.contains("-DES-")
        || n.contains("3DES")
        || n.contains("DES-CBC3")
        || n.contains("_ANON_")
        || n.contains("ADH-")
        || n.contains("AECDH")
        || n.contains("EXPORT")
        || n.starts_with("EXP-")
        || n.contains("IDEA")
        || n.contains("_MD5")
}

fn print_group(name: &str, obs: &GroupObservation) {
    // Misconfig finding carried in the reason string for TLS 1.2 FFDHE
    // entries where cross-codepoint coherence determined the server
    // doesn't honor `supported_groups`. Surface with a red `!` glyph +
    // yellow callout so a reader doesn't parse it as "merely not
    // supported."
    let ignored_offer = obs
        .reason
        .as_deref()
        .map(|r| r == "server_does_not_honor_supported_groups")
        .unwrap_or(false);

    let (glyph, name_style) = match (obs.supported, &obs.method, ignored_offer) {
        (_, _, true) => ("!", name.red().bold()),
        (Some(true), _, _) => {
            if is_pqc_group(name) {
                ("+", name.cyan().bold())
            } else {
                ("+", name.green())
            }
        }
        (Some(false), _, _) => ("-", name.dimmed()),
        (None, _, _) => ("?", name.yellow()),
    };

    // IANA codepoint — prefer what the observation itself carries
    // (populated for OpenSSL FFDHE entries), else look up from the
    // aws-lc-rs probe table for modern groups.
    let code = obs.iana_code.clone().unwrap_or_else(|| {
        crate::scanner::backends::rustls::groups::iana_code_for(name)
            .map(|c| format!("0x{c:04X}"))
            .unwrap_or_else(|| "0x????".to_string())
    });

    let tail = if ignored_offer {
        // Render returned-prime evidence inline: "server returned
        // ffdhe2048" or "server returned custom (1024 bits)" so the
        // reader sees both the verdict and the substituted prime
        // without consulting the JSON.
        let returned = match (&obs.returned_group, obs.returned_prime_bits) {
            (Some(g), Some(bits)) if g == "custom" => format!("custom ({bits}-bit)"),
            (Some(g), _) => g.clone(),
            (None, _) => String::new(),
        };
        if returned.is_empty() {
            format!("  [{}]", "server_ignores_supported_groups".yellow())
        } else {
            format!(
                "  [{}: {}]",
                "server_ignores_supported_groups".yellow(),
                format!("returned {}", returned).dimmed()
            )
        }
    } else {
        match (&obs.method, &obs.reason) {
            (Method::NotProbed, Some(r)) => {
                format!("  [{}: {}]", "not_probed".yellow(), r.dimmed())
            }
            (Method::Error, Some(r)) => format!("  [{}: {}]", "error".yellow(), r.dimmed()),
            _ => String::new(),
        }
    };
    println!("    {} {:<30} {}{}", glyph, name_style, code, tail);
}

fn method_label(m: &Method) -> &'static str {
    match m {
        Method::Probe => "probe",
        Method::NotProbed => "not_probed",
        Method::NotApplicable => "not_applicable",
        Method::Error => "error",
        Method::ConnectionState => "connection_state",
    }
}

/// Rough-and-ready PQC group detection — any name containing "MLKEM" or
/// "KYBER" is treated as a PQC (hybrid or standalone) group for
/// coloring purposes. Not used for any decision, just visual cue.
fn is_pqc_group(name: &str) -> bool {
    let upper = name.to_uppercase();
    upper.contains("MLKEM") || upper.contains("KYBER")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pqc_group_detection() {
        assert!(is_pqc_group("X25519MLKEM768"));
        assert!(is_pqc_group("mlkem1024"));
        assert!(!is_pqc_group("X25519"));
        assert!(!is_pqc_group("secp256r1"));
    }

    #[test]
    fn method_labels_cover_all_variants() {
        assert_eq!(method_label(&Method::Probe), "probe");
        assert_eq!(method_label(&Method::NotProbed), "not_probed");
        assert_eq!(method_label(&Method::NotApplicable), "not_applicable");
        assert_eq!(method_label(&Method::Error), "error");
        assert_eq!(method_label(&Method::ConnectionState), "connection_state");
    }
}
