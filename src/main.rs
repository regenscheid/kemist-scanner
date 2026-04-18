use anyhow::Result;
use clap::Parser;
use colored::*;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tracing::info;

use kemist::{model, output, scanner};
use output::OutputFormat;
use scanner::SslScanner;

/// kemist — TLS + PQC observation scanner
#[derive(Parser, Debug)]
#[command(name = "kemist")]
#[command(version)]
#[command(about = "TLS + PQC observation scanner", long_about = None)]
struct Args {
    /// Target to scan (hostname:port, hostname, or IP:port). Default port is 443
    target: String,

    /// Output format
    #[arg(short = 'f', long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Show certificate details
    #[arg(long)]
    show_certificate: bool,

    /// Show failed cipher tests
    #[arg(long)]
    show_failed: bool,

    /// Disable colored output
    #[arg(long)]
    no_color: bool,

    /// Disable cipher suite testing
    #[arg(long)]
    no_ciphersuites: bool,

    /// Test only specific TLS version
    #[arg(long, value_parser = parse_tls_version)]
    tls_version: Option<model::protocol::TlsVersion>,

    /// Connection timeout in seconds
    #[arg(long, default_value_t = 5)]
    timeout: u64,

    /// Use IPv4 only
    #[arg(long)]
    ipv4: bool,

    /// Use IPv6 only
    #[arg(long)]
    ipv6: bool,

    /// Server name for SNI
    #[arg(long)]
    sni_name: Option<String>,

    /// Output file for results
    #[arg(short, long)]
    output: Option<String>,

    /// Enable verbose logging
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn enabled_cargo_features() -> Vec<String> {
    // Hardcoded for PR 2 — PR 13 replaces with build-time feature inspection.
    // Today kemist has no cargo features defined.
    Vec::new()
}

fn parse_tls_version(s: &str) -> Result<model::protocol::TlsVersion, String> {
    use model::protocol::TlsVersion;
    match s.to_lowercase().as_str() {
        "ssl2" | "sslv2" => Ok(TlsVersion::Ssl2),
        "ssl3" | "sslv3" => Ok(TlsVersion::Ssl3),
        "tls1" | "tls1.0" | "tlsv1" | "tlsv1.0" | "1.0" => Ok(TlsVersion::Tls10),
        "tls1.1" | "tlsv1.1" | "1.1" => Ok(TlsVersion::Tls11),
        "tls1.2" | "tlsv1.2" | "1.2" => Ok(TlsVersion::Tls12),
        "tls1.3" | "tlsv1.3" | "1.3" => Ok(TlsVersion::Tls13),
        _ => Err(format!("Unknown TLS version: {}", s)),
    }
}

fn parse_target(target: &str, default_port: u16) -> (String, u16) {
    if let Some(colon_pos) = target.rfind(':') {
        // Check if this is a port separator (not part of IPv6 address)
        if target.starts_with('[') && target.contains(']') {
            // IPv6 format like [::1]:443
            if let Some(bracket_end) = target.find(']') {
                if colon_pos > bracket_end {
                    // Port specified after IPv6 address
                    let host = &target[..colon_pos];
                    if let Ok(port) = target[colon_pos + 1..].parse::<u16>() {
                        return (host.to_string(), port);
                    }
                }
            }
        } else if !target.contains("::") || target.matches(':').count() == 1 {
            // IPv4 or hostname with port, or single-colon IPv6
            if let Ok(port) = target[colon_pos + 1..].parse::<u16>() {
                let host = &target[..colon_pos];
                return (host.to_string(), port);
            }
        }
    }

    // No port specified or failed to parse
    (target.to_string(), default_port)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Install crypto provider for rustls
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

    // Initialize logging
    let log_level = match args.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    tracing_subscriber::fmt()
        .with_env_filter(format!("kemist={}", log_level))
        .init();

    // Disable colors if requested
    if args.no_color {
        colored::control::set_override(false);
    }

    // Print banner and version info (only for text output)
    if args.format == OutputFormat::Text {
        println!("{}", "kemist — TLS + PQC observation scanner".bold().cyan());
        println!("{}", "======================================".cyan());

        // Print rustls and native-tls version info
        let tls_version_info = get_tls_version_info();
        println!("{} {}", "Powered by:".dimmed(), tls_version_info.green());
        println!();
    }

    // Parse target (hostname:port or just hostname)
    let (hostname, port) = parse_target(&args.target, 443);

    // Resolve target
    let target_addr = resolve_target(&hostname, port, args.ipv4, args.ipv6).await?;

    info!("Scanning target: {}", target_addr);
    if args.format == OutputFormat::Text {
        println!(
            "Testing SSL/TLS on {}:{}",
            args.sni_name.as_ref().unwrap_or(&hostname),
            port
        );
        println!();
    }

    let sni_sent = args.sni_name.clone().unwrap_or_else(|| hostname.clone());

    // Create scanner configuration
    let config = scanner::ScanConfig {
        target: target_addr,
        hostname: sni_sent.clone(),
        timeout: Duration::from_secs(args.timeout),
        _show_certificate: args.show_certificate,
        _show_failed: args.show_failed,
        no_ciphersuites: args.no_ciphersuites,
        tls_version: args.tls_version,
    };

    // Perform scan (with wall-clock bookends for schema v1 scan.duration_ms)
    let scanner = SslScanner::new(config);
    let started_at = chrono::Utc::now();
    let results = scanner.scan().await?;
    let completed_at = chrono::Utc::now();

    let emit_ctx = output::JsonEmitContext {
        host: hostname.clone(),
        port,
        sni_sent,
        resolved_ip: Some(target_addr.ip().to_string()),
        started_at,
        completed_at,
        enabled_features: enabled_cargo_features(),
        config_paths: vec![],
    };

    // Output results
    match args.format {
        OutputFormat::Text => output::print_text_results(&results),
        OutputFormat::Json => output::print_json_results(&results, &emit_ctx, false)?,
        OutputFormat::JsonPretty => output::print_json_results(&results, &emit_ctx, true)?,
    }

    // Save to file if requested
    if let Some(output_file) = args.output {
        output::save_results(&results, &emit_ctx, &output_file, args.format)?;
        println!("\nResults saved to: {}", output_file);
    }

    Ok(())
}

async fn resolve_target(
    target: &str,
    port: u16,
    ipv4_only: bool,
    ipv6_only: bool,
) -> Result<SocketAddr> {
    use hickory_resolver::TokioAsyncResolver;

    // Try to parse as IP address first
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }

    // Resolve hostname
    let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
    let response = resolver.lookup_ip(target).await?;

    let ips: Vec<IpAddr> = response.iter().collect();

    let ip = if ipv4_only {
        ips.into_iter()
            .find(|ip| ip.is_ipv4())
            .ok_or_else(|| anyhow::anyhow!("No IPv4 address found for {}", target))?
    } else if ipv6_only {
        ips.into_iter()
            .find(|ip| ip.is_ipv6())
            .ok_or_else(|| anyhow::anyhow!("No IPv6 address found for {}", target))?
    } else {
        ips.into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No IP address found for {}", target))?
    };

    Ok(SocketAddr::new(ip, port))
}

/// Get rustls and native-tls version information
fn get_tls_version_info() -> String {
    let kemist_version = env!("CARGO_PKG_VERSION");

    // Parse Cargo.toml to get dependency versions
    let (rustls_version, crypto_info, native_tls_version) = parse_dependency_versions();

    format!(
        "rustls {} + {} | native-tls {} | kemist v{}",
        rustls_version, crypto_info, native_tls_version, kemist_version
    )
}

/// Parse dependency versions from Cargo.toml
fn parse_dependency_versions() -> (String, String, String) {
    // Include Cargo.toml content at compile time
    let cargo_toml = include_str!("../Cargo.toml");

    let mut rustls_version = "unknown".to_string();
    let mut native_tls_version = "unknown".to_string();
    let mut has_post_quantum = false;

    // Parse dependency versions from Cargo.toml
    for line in cargo_toml.lines() {
        let line = line.trim();
        if line.starts_with("rustls = {") {
            // Parse `rustls = { version = "0.23", ... }` format
            if let Some(version_pos) = line.find("version = \"") {
                let version_start = version_pos + 11; // length of 'version = "'
                if let Some(version_end) = line[version_start..].find('"') {
                    rustls_version = line[version_start..version_start + version_end].to_string();
                }
            }
        }
        if line.starts_with("native-tls = \"") {
            // Parse `native-tls = "0.2"` format
            if let Some(version_start) = line.find('"') {
                let version_start = version_start + 1;
                if let Some(version_end) = line[version_start..].find('"') {
                    native_tls_version =
                        line[version_start..version_start + version_end].to_string();
                }
            }
        }
        // Check for post-quantum features
        if line.contains("prefer-post-quantum") {
            has_post_quantum = true;
        }
    }

    // Detect crypto provider and post-quantum support
    let crypto_info = if has_post_quantum {
        "aws-lc-rs (post-quantum)".to_string()
    } else {
        "aws-lc-rs".to_string()
    };

    (rustls_version, crypto_info, native_tls_version)
}
