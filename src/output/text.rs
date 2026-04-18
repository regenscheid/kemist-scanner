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
    CipherSuiteEntry, GroupObservation, Method, ObservationBool, ScanResult, TlsExtensions,
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
    render_certificates(r);
    println!();
    render_validation(r);
    println!();
    render_extensions(r);
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
    if !cs.tls1_3.is_empty() {
        println!("  {}:", "TLS 1.3".bold());
        for e in &cs.tls1_3 {
            print_cipher_entry(e);
        }
    }
    if !cs.tls1_2.is_empty() {
        println!("  {}:", "TLS 1.2".bold());
        for e in &cs.tls1_2 {
            print_cipher_entry(e);
        }
    }
    if cs.tls1_2.is_empty() && cs.tls1_3.is_empty() {
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
    if r.tls.groups.is_empty() {
        println!("    {}", "(no groups probed)".dimmed());
        return;
    }
    for (name, obs) in &r.tls.groups {
        print_group(name, obs);
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
    let sig_line = if leaf.is_pqc_signature {
        format!(
            "{} ({})  {}",
            leaf.signature_algorithm_name,
            leaf.signature_algorithm_oid,
            "PQC".cyan().bold()
        )
    } else {
        format!(
            "{} ({})",
            leaf.signature_algorithm_name, leaf.signature_algorithm_oid
        )
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
        (Some(true), _) => println!(
            "  {:<22} {} ({} bytes)",
            "ocsp_stapling:",
            "true".green(),
            ocsp.response_length
        ),
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
    if !ext.compression_offered.is_empty() {
        kv("compression", &ext.compression_offered.join(", "));
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
}

fn render_sni_behavior(r: &ScanResult) {
    section("SNI behavior (omitted probe)");
    match (
        &r.tls.sni_behavior.omitted_probe,
        &r.tls.sni_behavior.method,
    ) {
        (Some(s), _) => {
            let colored = match s.as_str() {
                "same_cert" => s.normal(),
                "different_cert" => s.cyan(),
                "rejected" => s.yellow(),
                "error" => s.yellow(),
                _ => s.normal(),
            };
            println!("  {}", colored);
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
    let (glyph, name_style) = match (e.supported, &e.method) {
        (Some(true), _) => ("+", e.name.green()),
        (Some(false), _) => ("-", e.name.dimmed()),
        (None, _) => ("?", e.name.yellow()),
    };
    let tail = match (&e.method, &e.reason) {
        (Method::Error, Some(r)) => format!("  [{}]", r.dimmed()),
        (Method::NotProbed, Some(r)) => format!("  [{}]", r.dimmed()),
        _ => String::new(),
    };
    println!("    {} {:<48} {}{}", glyph, name_style, e.iana_code, tail);
}

fn print_group(name: &str, obs: &GroupObservation) {
    let (glyph, name_style) = match (obs.supported, &obs.method) {
        (Some(true), _) => {
            if is_pqc_group(name) {
                ("+", name.cyan().bold())
            } else {
                ("+", name.green())
            }
        }
        (Some(false), _) => ("-", name.dimmed()),
        (None, _) => ("?", name.yellow()),
    };
    // IANA codepoint ties every line to a concrete identifier, mirroring
    // how cipher suites render. Keeps probed lines from looking empty.
    let code = match crate::scanner::groups::iana_code_for(name) {
        Some(c) => format!("0x{c:04X}"),
        None => "0x????".to_string(),
    };
    let tail = match (&obs.method, &obs.reason) {
        (Method::NotProbed, Some(r)) => {
            format!("  [{}: {}]", "not_probed".yellow(), r.dimmed())
        }
        (Method::Error, Some(r)) => format!("  [{}: {}]", "error".yellow(), r.dimmed()),
        _ => String::new(),
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
        assert!(is_pqc_group("X25519Kyber768Draft00"));
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
