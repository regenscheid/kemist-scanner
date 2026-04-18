pub mod json;

use clap::ValueEnum;
use colored::*;

use crate::model::errors::ScannerError;
use crate::model::protocol::TlsVersion;
use crate::scanner::ScanResults;

pub use json::JsonEmitContext;

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum OutputFormat {
    Text,
    Json,
    JsonPretty,
}

pub fn print_text_results(results: &ScanResults) {
    println!("{}", "SSL/TLS Scan Results".bold().underline());
    println!();

    // Target information
    println!("{}:", "Target".bold());
    println!("  Host: {}", results.hostname);
    println!("  IP: {}", results.target);
    println!("  Port: {}", results.port);
    println!();

    // Protocol support
    println!("{}:", "Supported Protocols".bold());
    for protocol in &results.protocol_support {
        let status = if protocol.supported {
            if protocol.version.is_secure() {
                "YES".green()
            } else if protocol.version.is_deprecated() {
                "YES".yellow()
            } else {
                "YES".red()
            }
        } else {
            "NO".normal()
        };

        println!("  {:<10} {}", protocol.version.as_str(), status);

        if let Some(error) = &protocol.error {
            if protocol.supported {
                println!("    {}", error.dimmed());
            }
        }
    }
    println!();

    // TLS Fallback SCSV
    if let Some(fallback_scsv) = results.fallback_scsv_accepted {
        println!("{}:", "TLS Fallback SCSV".bold());
        let status = if fallback_scsv {
            "Supported".green()
        } else {
            "Not Supported".red()
        };
        println!("  {}", status);

        if fallback_scsv {
            println!(
                "  {}",
                "✓ Server protects against downgrade attacks".dimmed()
            );
        } else {
            println!(
                "  {}",
                "⚠ Server may be vulnerable to downgrade attacks"
                    .yellow()
                    .dimmed()
            );
        }
        println!();
    }

    // TLS renegotiation
    println!("{}:", "TLS renegotiation".bold());

    // Secure renegotiation (RFC 5746)
    if let Some(secure_renego) = results.tls_renegotiation.secure_renegotiation {
        let status = if secure_renego {
            "Supported".green()
        } else {
            "Not Supported".red()
        };
        println!("  Secure renegotiation (RFC 5746): {}", status);

        if !secure_renego {
            println!(
                "    {}",
                "⚠ Server may be vulnerable to renegotiation attacks"
                    .yellow()
                    .dimmed()
            );
        }
    } else {
        println!("  Secure renegotiation (RFC 5746): {}", "Unknown".yellow());
    }

    // TLS compression offered
    if let Some(compression) = results.tls_renegotiation.compression_supported {
        let status = if compression {
            "Enabled".red()
        } else {
            "Disabled".green()
        };
        println!("  TLS compression: {}", status);

        if compression {
            println!(
                "    {}",
                "⚠ Server vulnerable to CRIME attack (CVE-2012-4929)"
                    .red()
                    .dimmed()
            );
        } else {
            println!("    {}", "✓ Server not vulnerable to CRIME attack".dimmed());
        }
    } else {
        println!("  TLS compression: {}", "Unknown".yellow());
    }

    println!();

    // Heartbleed vulnerability
    if let Some(heartbleed) = results.heartbeat_echoes_oversized_payload {
        println!("{}:", "Heartbleed (CVE-2014-0160)".bold());
        let status = if heartbleed {
            "VULNERABLE".red().bold()
        } else {
            "Not Vulnerable".green()
        };
        println!("  {}", status);

        if heartbleed {
            println!(
                "    {}",
                "⚠ CRITICAL: Server is vulnerable to Heartbleed attack!"
                    .red()
                    .bold()
            );
            println!(
                "    {}",
                "⚠ Private keys, passwords, and sensitive data may be leaked"
                    .red()
                    .dimmed()
            );
            println!("    {}", "⚠ Immediate patching required!".red().dimmed());
        } else {
            println!(
                "    {}",
                "✓ Server is protected against Heartbleed attacks".dimmed()
            );
        }
        println!();
    }

    // Preferred cipher
    if let Some(preferred) = &results.preferred_cipher {
        println!("{}:", "Preferred Cipher".bold());
        println!("  {}", preferred.format_plain());
        println!();
    }

    // Cipher suites
    if !results.cipher_suites.is_empty() {
        println!("{}:", "Supported Cipher Suites".bold());
        println!("  (Preferred cipher marked with {})", "*".yellow());
        println!();

        // Group by protocol version
        let mut by_version: std::collections::HashMap<TlsVersion, Vec<_>> =
            std::collections::HashMap::new();

        for result in &results.cipher_suites {
            if result.supported {
                by_version
                    .entry(result.cipher.protocol_version)
                    .or_insert_with(Vec::new)
                    .push(result);
            }
        }

        for version in &[
            TlsVersion::Tls13,
            TlsVersion::Tls12,
            TlsVersion::Tls11,
            TlsVersion::Tls10,
            TlsVersion::Ssl3,
            TlsVersion::Ssl2,
        ] {
            if let Some(ciphers) = by_version.get(version) {
                println!("  {}:", version.as_str().bold());
                for cipher_result in ciphers {
                    let prefix = if cipher_result.preferred { "*" } else { " " };
                    println!(
                        "  {} {}",
                        prefix.yellow(),
                        cipher_result.cipher.format_plain()
                    );
                }
                println!();
            }
        }
    }

    // Server Key Exchange Groups
    if !results.key_exchange_groups.is_empty() {
        println!("{}:", "Server Key Exchange Group(s)".bold());
        println!();

        // Separate classical and post-quantum groups
        let classical_groups: Vec<_> = results
            .key_exchange_groups
            .iter()
            .filter(|g| !g.post_quantum && g.supported)
            .collect();
        let pq_groups: Vec<_> = results
            .key_exchange_groups
            .iter()
            .filter(|g| g.post_quantum && g.supported)
            .collect();

        if !classical_groups.is_empty() {
            println!("  {}:", "Classical Groups".bold());
            for group in classical_groups {
                let status = if group.negotiated {
                    format!("{} (negotiated)", "✓".green())
                } else {
                    "✓".green().to_string()
                };
                println!("    {:<20} {}", group.name, status);
            }
            println!();
        }

        if !pq_groups.is_empty() {
            println!("  {}:", "Post-Quantum Groups".bold());
            for group in pq_groups {
                let status = if group.negotiated {
                    format!("{} (negotiated)", "✓".green())
                } else {
                    "✓".green().to_string()
                };
                let name_colored = if group.name.contains("MLKEM") {
                    group.name.cyan().bold()
                } else {
                    group.name.normal()
                };
                println!("    {:<20} {}", name_colored, status);
            }
            println!();
        }
    }

    // Certificate information
    if !results.certificate_chain.is_empty() {
        println!();
        println!("{}:", "Certificate Information".bold());
        println!();

        for (i, cert) in results.certificate_chain.iter().enumerate() {
            // Certificate header with chain position
            let cert_type = if i == 0 { "Server" } else { "Intermediate" };
            println!(
                "  {}:",
                format!("{} Certificate (#{} in chain)", cert_type, i + 1).underline()
            );
            println!();

            // Basic Information section
            println!("    {}:", "Basic Information".bold());
            println!("      Subject:             {}", cert.subject);
            println!("      Issuer:              {}", cert.issuer);

            // Alternative Names
            if !cert.san.is_empty() {
                println!("      Alternative Names:");
                for san in &cert.san {
                    println!("        - {}", san);
                }
            }
            println!();

            // Key Information section
            println!("    {}:", "Public Key Information".bold());
            if let Some(curve_name) = &cert.ecc_curve_name {
                println!(
                    "      Algorithm:           {} ({})",
                    cert.public_key_algorithm, curve_name
                );
                if let Some(strength) = cert.ecc_key_strength {
                    println!("      Key Strength:        {} bits", strength);
                }
            } else {
                println!("      Algorithm:           {}", cert.public_key_algorithm);
                println!("      Key Size:            {} bits", cert.public_key_size);
            }

            // Signature Algorithm
            println!("      Signature Algorithm: {}", cert.signature_algorithm);
            println!();

            // Validity Period section
            println!("    {}:", "Validity Period".bold());
            println!(
                "      Not Before:          {}",
                cert.not_before.format("%Y-%m-%d %H:%M:%S UTC")
            );
            println!(
                "      Not After:           {}",
                cert.not_after.format("%Y-%m-%d %H:%M:%S UTC")
            );

            // Calculate days remaining
            let now = chrono::Utc::now();
            if cert.not_after > now {
                let days_remaining = (cert.not_after - now).num_days();
                let status = if days_remaining < 30 {
                    format!("{} days remaining", days_remaining).red()
                } else if days_remaining < 90 {
                    format!("{} days remaining", days_remaining).yellow()
                } else {
                    format!("{} days remaining", days_remaining).green()
                };
                println!("      Status:              {}", status);
            } else {
                println!("      Status:              {}", "EXPIRED".red().bold());
            }
            println!();

            // Technical Details section
            println!("    {}:", "Technical Details".bold());
            println!("      Serial Number:       {}", cert.serial_number);

            // Fingerprints
            println!("      SHA256 Fingerprint:  {}", cert.fingerprint_sha256);
            println!(
                "      SHA1 Fingerprint:    {}",
                cert.fingerprint_sha1.dimmed()
            );

            // Factual notes
            let notes = cert.factual_notes();
            if !notes.is_empty() {
                println!();
                println!("    {}:", "Notes".bold());
                for note in notes {
                    println!("      - {}", note.dimmed());
                }
            }

            // Add spacing between certificates
            if i < results.certificate_chain.len() - 1 {
                println!();
                println!("  {}", "─".repeat(60).dimmed());
                println!();
            }
        }
        println!();
    }

    // Summary
    print_summary(results);
}

pub fn print_json_results(
    results: &ScanResults,
    ctx: &JsonEmitContext,
    pretty: bool,
) -> Result<(), ScannerError> {
    if pretty {
        json::print_json_pretty(results, ctx)
    } else {
        json::print_json(results, ctx)
    }
}

pub fn save_results(
    results: &ScanResults,
    ctx: &JsonEmitContext,
    path: &str,
    format: OutputFormat,
) -> Result<(), ScannerError> {
    match format {
        OutputFormat::Text => {
            // Text is TTY-only for now; dump the canonical JSON to disk instead
            // of a debug-formatted dump. PR 12 will add a real text formatter.
            json::write_json(results, ctx, path)
        }
        OutputFormat::Json | OutputFormat::JsonPretty => json::write_json(results, ctx, path),
    }
}

fn print_summary(results: &ScanResults) {
    println!("{}", "Summary".bold().underline());

    let mut warnings = Vec::new();
    let mut good = Vec::new();

    // Check protocol support
    for protocol in &results.protocol_support {
        if protocol.supported {
            if protocol.version.is_deprecated() {
                warnings.push(format!("{} is enabled (deprecated)", protocol.version));
            } else if protocol.version.is_secure() {
                good.push(format!("{} is enabled", protocol.version));
            }
        }
    }

    // Collect factual notes from certificates
    for cert in &results.certificate_chain {
        let notes = cert.factual_notes();
        warnings.extend(notes);
    }

    // Surface heartbeat oversized-payload echo observation
    if let Some(true) = results.heartbeat_echoes_oversized_payload {
        warnings.push("Heartbeat extension echoed oversized payload".to_string());
    }

    // Print summary
    if !good.is_empty() {
        println!("\n{}:", "Good".green().bold());
        for item in &good {
            println!("  ✓ {}", item.green());
        }
    }

    if !warnings.is_empty() {
        println!("\n{}:", "Warnings".yellow().bold());
        for warning in &warnings {
            println!("  ⚠ {}", warning.yellow());
        }
    }

    if warnings.is_empty() && !good.is_empty() {
        println!("\n{}", "No additional notes.".dimmed());
    }
}
