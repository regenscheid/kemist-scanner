//! kemist CLI — thin wrapper over the public [`kemist::Scanner`] API.
//!
//! Responsibilities: parse flags + target inputs, construct a `Scanner`,
//! route emitted `ScanResult` records through the chosen output path.
//! All scanning logic lives in the library so other binaries can reuse it.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use kemist::{Scanner, ScannerConfig, ScannerError, Target};

/// kemist — TLS + PQC observation scanner
#[derive(Parser, Debug)]
#[command(name = "kemist")]
#[command(version)]
#[command(about = "TLS + PQC observation scanner", long_about = None)]
struct Args {
    /// Target to scan (repeatable). Syntax: `host[:port][#sni=alt.example.com]`.
    /// Default port is 443.
    #[arg(long = "target", value_name = "HOST[:PORT][#sni=NAME]")]
    targets: Vec<String>,

    /// Read newline-delimited targets from a file.
    #[arg(long, value_name = "PATH")]
    targets_file: Option<PathBuf>,

    /// Read newline-delimited targets from stdin.
    #[arg(long)]
    targets_stdin: bool,

    /// Maximum concurrent targets.
    #[arg(long, default_value_t = 10)]
    concurrency: usize,

    /// Minimum delay between probes to the same target (milliseconds).
    #[arg(long, default_value_t = 100)]
    per_target_delay: u64,

    /// TCP connect timeout (seconds).
    #[arg(long, default_value_t = 10)]
    connect_timeout: u64,

    /// TLS handshake timeout (seconds).
    #[arg(long, default_value_t = 15)]
    handshake_timeout: u64,

    /// Hard ceiling on total wall-clock time per target, including retries (seconds).
    #[arg(long, default_value_t = 60)]
    total_timeout: u64,

    /// Retry attempts on transient network errors (0 disables).
    #[arg(long, default_value_t = 2)]
    retries: u32,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Write NDJSON stream (one record per line) to a file instead of stdout.
    /// Requires `--format json`.
    #[arg(long, value_name = "PATH")]
    output_file: Option<PathBuf>,

    /// Write one pretty-printed JSON file per target into this directory.
    /// Requires `--format json-pretty`. Filename: `<sanitized_host>_<unix>.json`.
    #[arg(long, value_name = "PATH")]
    output_dir: Option<PathBuf>,

    /// Disable colored output.
    #[arg(long)]
    no_color: bool,

    /// Restrict probes to a single TLS version.
    #[arg(long, value_parser = parse_tls_version)]
    tls_version: Option<kemist::model::protocol::TlsVersion>,

    /// Use IPv4 only for DNS resolution.
    #[arg(long)]
    ipv4: bool,

    /// Use IPv6 only for DNS resolution.
    #[arg(long)]
    ipv6: bool,

    /// Fire HTTP-layer observations (HSTS, security.txt, preload list)
    /// after TLS probes complete. Requires the `http-checks` cargo
    /// feature (default on).
    #[arg(long)]
    enable_http_checks: bool,

    /// Identifier URL appended to the User-Agent when HTTP checks fire:
    /// `kemist/<ver> (+<url>)`. Lets server operators trace requests
    /// back to a kemist scan — set to a contact/repo URL. Ignored
    /// without --enable-http-checks.
    #[arg(long, value_name = "URL")]
    user_agent_info_url: Option<String>,

    /// Increase logging verbosity (-v info, -vv debug, -vvv trace).
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum, PartialEq)]
enum OutputFormat {
    Text,
    Json,
    JsonPretty,
}

fn parse_tls_version(s: &str) -> std::result::Result<kemist::model::protocol::TlsVersion, String> {
    use kemist::model::protocol::TlsVersion;
    match s.to_lowercase().as_str() {
        "ssl2" | "sslv2" => Ok(TlsVersion::Ssl2),
        "ssl3" | "sslv3" => Ok(TlsVersion::Ssl3),
        "tls1" | "tls1.0" | "tlsv1" | "tlsv1.0" | "1.0" => Ok(TlsVersion::Tls10),
        "tls1.1" | "tlsv1.1" | "1.1" => Ok(TlsVersion::Tls11),
        "tls1.2" | "tlsv1.2" | "1.2" => Ok(TlsVersion::Tls12),
        "tls1.3" | "tlsv1.3" | "1.3" => Ok(TlsVersion::Tls13),
        _ => Err(format!("Unknown TLS version: {s}")),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kemist: {e:#}");
            ExitCode::from(1)
        }
    }
}

async fn run() -> Result<()> {
    let args = Args::parse();

    if args.no_color {
        colored::control::set_override(false);
    }

    install_logging(args.verbose);

    // Install rustls crypto provider (must happen before any TLS op).
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    // Collect targets from all three input sources.
    let targets = collect_targets(&args)?;
    if targets.is_empty() {
        anyhow::bail!("no targets specified — use --target, --targets-file, or --targets-stdin");
    }

    validate_output_routing(&args)?;

    let user_agent_info_url = match (args.enable_http_checks, args.user_agent_info_url.clone()) {
        (true, Some(u)) => u,
        (true, None) => {
            // Default to the project URL. Operators who run kemist against
            // targets they don't own should set --user-agent-info-url to
            // their own contact address so site operators can reach them.
            "https://www.kemist-tls.net".to_string()
        }
        (false, _) => "https://www.kemist-tls.net".to_string(),
    };

    let scanner = Scanner::new(ScannerConfig {
        concurrency: args.concurrency.max(1),
        per_target_delay: Duration::from_millis(args.per_target_delay),
        connect_timeout: Duration::from_secs(args.connect_timeout),
        handshake_timeout: Duration::from_secs(args.handshake_timeout),
        total_timeout: Duration::from_secs(args.total_timeout),
        retries: args.retries,
        tls_version_filter: args.tls_version,
        ipv4_only: args.ipv4,
        ipv6_only: args.ipv6,
        enabled_features: enabled_cargo_features(),
        config_paths: vec![],
        enable_http_checks: args.enable_http_checks,
        user_agent_info_url,
    });

    let results = scanner.scan_many(targets).await;

    emit(&args, &results)?;

    Ok(())
}

fn install_logging(verbose: u8) {
    let level = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(format!("kemist={level}"))
        .init();
}

fn enabled_cargo_features() -> Vec<String> {
    // No cargo features defined on kemist today. PR 13 will replace this
    // with a build-time feature inspection macro.
    Vec::new()
}

/// Collect targets from `--target`, `--targets-file`, and `--targets-stdin`.
/// Duplicates are preserved — callers who want dedupe should do it upstream.
fn collect_targets(args: &Args) -> Result<Vec<Target>> {
    let mut raw: Vec<String> = Vec::new();

    raw.extend(args.targets.iter().cloned());

    if let Some(path) = &args.targets_file {
        let file = std::fs::File::open(path)
            .with_context(|| format!("open targets file: {}", path.display()))?;
        for line in io::BufReader::new(file).lines() {
            let line = line.with_context(|| format!("read targets file: {}", path.display()))?;
            let t = line.trim();
            if !t.is_empty() && !t.starts_with('#') {
                raw.push(t.to_string());
            }
        }
    }

    if args.targets_stdin {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            let line = line.context("read targets from stdin")?;
            let t = line.trim();
            if !t.is_empty() && !t.starts_with('#') {
                raw.push(t.to_string());
            }
        }
    }

    let mut parsed = Vec::with_capacity(raw.len());
    for r in raw {
        parsed.push(
            Target::parse(&r)
                .map_err(|e: ScannerError| anyhow::anyhow!("invalid target '{r}': {e}"))?,
        );
    }
    Ok(parsed)
}

fn validate_output_routing(args: &Args) -> Result<()> {
    if args.output_file.is_some() && args.format != OutputFormat::Json {
        anyhow::bail!("--output-file requires --format json");
    }
    if args.output_dir.is_some() && args.format != OutputFormat::JsonPretty {
        anyhow::bail!("--output-dir requires --format json-pretty");
    }
    if args.output_file.is_some() && args.output_dir.is_some() {
        anyhow::bail!("--output-file and --output-dir are mutually exclusive");
    }
    Ok(())
}

fn emit(args: &Args, results: &[kemist::ScanResult]) -> Result<()> {
    match args.format {
        OutputFormat::Text => emit_text(results),
        OutputFormat::Json => emit_ndjson(args, results),
        OutputFormat::JsonPretty => emit_pretty(args, results),
    }
}

fn emit_text(results: &[kemist::ScanResult]) -> Result<()> {
    // PR 12 rewrites the text output against schema-v1. Until then, render
    // a compact summary so interactive single-target scans stay usable.
    for (i, r) in results.iter().enumerate() {
        if i > 0 {
            println!();
            println!("{}", "─".repeat(60));
            println!();
        }
        print_text_summary(r);
    }
    Ok(())
}

fn print_text_summary(r: &kemist::ScanResult) {
    use colored::Colorize;
    println!("{}", "kemist scan".bold().cyan());
    println!("  target:      {}", r.scan.target);
    if let Some(ip) = &r.scan.resolved_ip {
        println!("  resolved_ip: {ip}");
    }
    println!("  sni_sent:    {}", r.scan.sni_sent);
    println!("  duration_ms: {}", r.scan.duration_ms);
    if let Some(neg) = &r.tls.negotiated {
        println!(
            "  negotiated:  version={} suite={}",
            neg.version,
            neg.cipher_suite.as_deref().unwrap_or("-")
        );
    }
    println!("  cert chain:  {}", r.certificates.chain_length);
    println!("  errors:      {}", r.errors.len());
    for e in &r.errors {
        println!("    - [{}] {}", e.category.yellow(), e.context);
    }
}

fn emit_ndjson(args: &Args, results: &[kemist::ScanResult]) -> Result<()> {
    let mut writer: Box<dyn Write> = match &args.output_file {
        Some(path) => Box::new(
            std::fs::File::create(path)
                .with_context(|| format!("create output file: {}", path.display()))?,
        ),
        None => Box::new(io::stdout().lock()),
    };
    for r in results {
        serde_json::to_writer(&mut writer, r).context("serialize NDJSON record")?;
        writer.write_all(b"\n").context("write NDJSON delimiter")?;
    }
    writer.flush().context("flush output")?;
    Ok(())
}

fn emit_pretty(args: &Args, results: &[kemist::ScanResult]) -> Result<()> {
    match &args.output_dir {
        Some(dir) => {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("create output dir: {}", dir.display()))?;
            for r in results {
                let filename = per_target_filename(r);
                let path = dir.join(filename);
                let json = serde_json::to_string_pretty(r).context("serialize pretty record")?;
                std::fs::write(&path, json).with_context(|| format!("write {}", path.display()))?;
            }
            Ok(())
        }
        None => {
            // Single-target convenience: pretty-print to stdout.
            let stdout = io::stdout();
            let mut w = stdout.lock();
            for (i, r) in results.iter().enumerate() {
                if i > 0 {
                    writeln!(w).ok();
                }
                let json = serde_json::to_string_pretty(r).context("serialize pretty record")?;
                writeln!(w, "{json}").context("write pretty record")?;
            }
            Ok(())
        }
    }
}

fn per_target_filename(r: &kemist::ScanResult) -> String {
    let host = &r.scan.host;
    let port = r.scan.port;
    let ts = r.scan.started_at.timestamp();
    // Sanitize host for filesystem use: keep [a-zA-Z0-9.-_], replace others with '_'.
    let sanitized: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || ".-_".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("{sanitized}_{port}_{ts}.json")
}
