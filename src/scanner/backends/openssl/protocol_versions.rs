//! SSLv3 / TLS 1.0 / TLS 1.1 protocol-version probes (OpenSSL path).
//!
//! Replaces the `native-tls`-backed path at
//! `src/scanner/legacy.rs:28-95` when the `legacy-probes` feature is on.
//! SSLv3 requires the already-loaded legacy provider (`ensure_legacy_providers`)
//! plus `set_security_level(0)` plus a permissive cipher list. TLS 1.0
//! and 1.1 work with the default provider + seclevel 0.
//!
//! SSLv2 is NOT handled here — OpenSSL 3.x dropped SSLv2 entirely. The
//! raw-socket `test_sslv2` in `src/scanner/legacy.rs` remains the only
//! SSLv2 path.

use std::net::SocketAddr;
use std::time::Duration;

use openssl::ssl::{HandshakeError, Ssl, SslContext, SslMethod, SslVerifyMode, SslVersion};
use tracing::info;

use crate::model::errors::ScannerError;
use crate::model::protocol::{ProtocolSupport, TlsVersion};
use crate::scanner::openssl::{alerts, ensure_legacy_providers};

/// Probe a specific legacy protocol version against the target.
///
/// Returns the same `ProtocolSupport` shape as the rustls path — so the
/// outer dispatch in `src/scanner/mod.rs` can swap backends by cargo
/// feature without reshaping `ScanResults.protocol_support`.
pub async fn probe_protocol(
    target: SocketAddr,
    hostname: &str,
    version: TlsVersion,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> ProtocolSupport {
    info!("OpenSSL legacy protocol probe for {:?}", version);

    if let Err(e) = ensure_legacy_providers() {
        return ProtocolSupport {
            version,
            supported: false,
            error: Some(format!("openssl_provider_load:{}", e.category)),
        };
    }

    let hostname_owned = hostname.to_string();
    tokio::task::spawn_blocking(move || {
        probe_blocking(
            target,
            &hostname_owned,
            version,
            connect_timeout,
            handshake_timeout,
        )
    })
    .await
    .unwrap_or_else(|e| ProtocolSupport {
        version,
        supported: false,
        error: Some(format!("spawn_blocking_panic:{e}")),
    })
}

fn probe_blocking(
    target: SocketAddr,
    hostname: &str,
    version: TlsVersion,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> ProtocolSupport {
    let Some(ossl_version) = tls_version_to_ossl(version) else {
        return ProtocolSupport {
            version,
            supported: false,
            error: Some(format!("out_of_scope_for_openssl:{version:?}")),
        };
    };

    let tcp = match std::net::TcpStream::connect_timeout(&target, connect_timeout) {
        Ok(s) => s,
        Err(e) => {
            return ProtocolSupport {
                version,
                supported: false,
                error: Some(ScannerError::from_io("legacy tcp connect", e).category),
            };
        }
    };
    let _ = tcp.set_read_timeout(Some(handshake_timeout));
    let _ = tcp.set_write_timeout(Some(handshake_timeout));

    let ctx = match build_context(ossl_version) {
        Ok(c) => c,
        Err(stack) => {
            return ProtocolSupport {
                version,
                supported: false,
                error: Some(format!("openssl_ctx_build:{stack}")),
            };
        }
    };

    let mut ssl = match Ssl::new(&ctx) {
        Ok(s) => s,
        Err(stack) => {
            return ProtocolSupport {
                version,
                supported: false,
                error: Some(format!("openssl_ssl_new:{stack}")),
            };
        }
    };
    let _ = ssl.set_hostname(hostname);

    match ssl.connect(tcp) {
        Ok(_stream) => ProtocolSupport {
            version,
            supported: true,
            error: None,
        },
        Err(HandshakeError::Failure(mid)) => {
            let se = alerts::classify_openssl_error("legacy handshake", mid.error());
            ProtocolSupport {
                version,
                supported: false,
                error: Some(se.category),
            }
        }
        Err(HandshakeError::SetupFailure(stack)) => ProtocolSupport {
            version,
            supported: false,
            error: Some(format!("openssl_setup:{stack}")),
        },
        Err(HandshakeError::WouldBlock(_)) => ProtocolSupport {
            version,
            supported: false,
            error: Some("openssl_would_block".to_string()),
        },
    }
}

fn build_context(ossl_version: SslVersion) -> Result<SslContext, openssl::error::ErrorStack> {
    let mut builder = SslContext::builder(SslMethod::tls_client())?;
    builder.set_min_proto_version(Some(ossl_version))?;
    builder.set_max_proto_version(Some(ossl_version))?;
    builder.set_security_level(0);
    // SSLv3 requires the legacy provider to be loaded AND a permissive
    // cipher list — modern @SECLEVEL=0 alone isn't enough. TLS 1.0/1.1
    // are OK with the default cipher list + SECLEVEL=0, but setting an
    // explicit list doesn't hurt them.
    builder.set_cipher_list("ALL:@SECLEVEL=0")?;
    builder.set_verify(SslVerifyMode::NONE);
    Ok(builder.build())
}

/// Restrict to the three versions this probe covers. TLS 1.2/1.3 are
/// handled by the rustls path at `src/scanner/mod.rs::test_rustls_protocol`;
/// SSLv2 by `src/scanner/legacy.rs::test_sslv2`.
fn tls_version_to_ossl(v: TlsVersion) -> Option<SslVersion> {
    match v {
        TlsVersion::Ssl3 => Some(SslVersion::SSL3),
        TlsVersion::Tls10 => Some(SslVersion::TLS1),
        TlsVersion::Tls11 => Some(SslVersion::TLS1_1),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_version_to_ossl_restricts_to_d8_scope() {
        assert_eq!(
            tls_version_to_ossl(TlsVersion::Ssl3),
            Some(SslVersion::SSL3)
        );
        assert_eq!(
            tls_version_to_ossl(TlsVersion::Tls10),
            Some(SslVersion::TLS1)
        );
        assert_eq!(
            tls_version_to_ossl(TlsVersion::Tls11),
            Some(SslVersion::TLS1_1)
        );
        // Out of scope — the rustls path owns these.
        assert_eq!(tls_version_to_ossl(TlsVersion::Tls12), None);
        assert_eq!(tls_version_to_ossl(TlsVersion::Tls13), None);
        // SSLv2 is raw-socket territory.
        assert_eq!(tls_version_to_ossl(TlsVersion::Ssl2), None);
    }
}
