//! Integration tests for the public `Scanner` API.
//!
//! - Public `Scanner::scan` / `scan_many` are the stable surface.
//! - Per-target DNS failure produces a schema-valid record with a populated
//!   `errors` array rather than aborting the batch.
//! - Output order of `scan_many` is not guaranteed (`buffer_unordered`), so
//!   tests sort by `scan.target` before asserting.

use std::time::Duration;

use kemist::{Scanner, ScannerConfig, Target};

fn install_crypto_once() {
    use std::sync::OnceLock;
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

fn fast_config() -> ScannerConfig {
    ScannerConfig {
        concurrency: 4,
        per_target_delay: Duration::from_millis(0),
        connect_timeout: Duration::from_millis(500),
        handshake_timeout: Duration::from_millis(500),
        total_timeout: Duration::from_secs(5),
        retries: 0,
        ..ScannerConfig::default()
    }
}

#[tokio::test]
async fn dns_failure_produces_schema_valid_record_not_panic() {
    install_crypto_once();
    // A name that definitely won't resolve.
    let target = Target::parse("no-such-host.kemist-test.invalid").unwrap();
    let scanner = Scanner::new(fast_config());
    let result = scanner.scan(target).await;

    assert_eq!(result.schema_version, "2.1.0");
    assert!(!result.errors.is_empty());
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.category == "dns_resolution_failed"),
        "expected dns_resolution_failed in errors, got: {:?}",
        result
            .errors
            .iter()
            .map(|e| &e.category)
            .collect::<Vec<_>>()
    );
    assert_eq!(result.certificates.chain_length, 0);
    assert_eq!(result.scan.host, "no-such-host.kemist-test.invalid");
}

#[tokio::test]
async fn scan_many_bounded_concurrency_never_aborts() {
    install_crypto_once();
    // Three unresolvable targets — each produces its own record.
    let targets = vec![
        Target::parse("no-such-a.kemist-test.invalid").unwrap(),
        Target::parse("no-such-b.kemist-test.invalid").unwrap(),
        Target::parse("no-such-c.kemist-test.invalid").unwrap(),
    ];

    let scanner = Scanner::new(fast_config());
    let mut results = scanner.scan_many(targets).await;

    assert_eq!(results.len(), 3);
    results.sort_by(|a, b| a.scan.host.cmp(&b.scan.host));
    for r in &results {
        assert_eq!(r.schema_version, "2.1.0");
        assert!(!r.errors.is_empty());
    }
    assert!(results[0].scan.host.contains("no-such-a"));
    assert!(results[1].scan.host.contains("no-such-b"));
    assert!(results[2].scan.host.contains("no-such-c"));
}

#[tokio::test]
async fn scan_many_empty_input_returns_empty_vec() {
    install_crypto_once();
    let scanner = Scanner::new(fast_config());
    let results = scanner.scan_many(vec![]).await;
    assert!(results.is_empty());
}

#[tokio::test]
async fn sni_override_reported_in_output() {
    install_crypto_once();
    let target = Target::parse("no-such.kemist-test.invalid#sni=alt.example.com").unwrap();
    let scanner = Scanner::new(fast_config());
    let result = scanner.scan(target).await;

    assert_eq!(result.scan.host, "no-such.kemist-test.invalid");
    assert_eq!(result.scan.sni_sent, "alt.example.com");
}
