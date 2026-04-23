//! OCSP-over-HTTP fallback probe (RFC 6960 §A.1).
//!
//! The rustls characterization handshake captures any stapled OCSP
//! response the server delivered during the TLS record flight
//! (`CertificateStatus` in TLS 1.2 / `status_request` in TLS 1.3
//! EncryptedExtensions). Servers that don't staple leave the probe
//! with no revocation signal — even though the cert's AIA extension
//! advertises an `OCSP` URI the client *could* query directly.
//!
//! This module fills the gap: when the scanner has a leaf + issuer
//! cert AND the leaf's AIA lists one or more OCSP URLs AND
//! `--enable-revocation-fetch` is set, fetch each URL via HTTP POST
//! and surface the response alongside whatever staple was captured.
//!
//! ## Why openssl::ocsp
//! Building an `OCSPRequest` (ASN.1 SEQUENCE of SEQUENCE of CertIDs)
//! from scratch is ~150 lines of DER encoding. The `openssl` crate
//! already in kemist's dep tree (vendored via `openssl-src`) exposes
//! `OcspRequest::new()` + `OcspCertId::from_cert(digest, subject,
//! issuer)` + `to_der()` — feature-gate shared with the other
//! OpenSSL-backed probes so this module lives under the same
//! `legacy-probes` umbrella.
//!
//! ## Feature gating
//! Requires both `legacy-probes` (for `openssl::ocsp`) and
//! `http-checks` (for `reqwest`). Both are default-on; under
//! `--no-default-features`, the top-level wiring emits a
//! `method: not_probed, reason: "feature_disabled"` envelope.
//!
//! ## Non-goals
//! - **OCSP response signature validation.** The parsed `content`
//!   field downstream carries the response's `signature_algorithm`
//!   + `responder_id` — rule engines that want to verify can do so
//!   against a responder trust chain they control. kemist is a
//!   sensor; signature cryptographic validation is a verdict-layer
//!   concern.
//! - **Request nonce (RFC 6960 §4.4.1).** Adds a request-reply
//!   binding, but many production responders reject nonced
//!   requests (pre-computed responses). We elide it for
//!   compatibility — the observation is "what did the responder
//!   say about this serial," not "did the responder sign a fresh
//!   reply to our challenge."
//! - **Issuer discovery via AIA `caIssuers`.** We use the chain the
//!   server delivered; if the intermediate isn't present in the
//!   chain, the probe reports `missing_issuer_cert`. A future
//!   workstream can fetch + follow the `caIssuers` URL to recover
//!   the intermediate.

#![cfg(all(feature = "http-checks", feature = "legacy-probes"))]

use std::time::Duration;

use openssl::hash::MessageDigest;
use openssl::ocsp::{OcspCertId, OcspRequest};
use openssl::x509::X509;

/// One OCSP-over-HTTP fetch attempt.
#[derive(Debug, Clone)]
pub struct OcspHttpFetch {
    /// URL that was fetched (AIA `OCSP` access description).
    pub url: String,
    /// HTTP response status code from the POST. `None` when the
    /// request didn't complete (DNS / TCP / TLS / timeout).
    pub http_status: Option<u16>,
    /// Raw OCSP response bytes (application/ocsp-response body).
    /// `None` on transport failure or non-2xx status. Passed to
    /// [`crate::model::ocsp_response::parse`] by the output builder
    /// to produce the same `content` shape as stapled OCSP.
    pub response_der: Option<Vec<u8>>,
    /// Category string when the probe failed — transport error,
    /// HTTP error status, malformed response, etc.
    pub error: Option<String>,
}

/// Aggregate output — one entry per AIA OCSP URL attempted.
#[derive(Debug, Clone, Default)]
pub struct OcspHttpFetchOutput {
    pub results: Vec<OcspHttpFetch>,
}

/// Drive the OCSP-over-HTTP probe. Builds a single OCSPRequest
/// containing a CertID for the leaf (digest SHA-1 per RFC 6960
/// §4.1.1 — the default most responders expect), POSTs that
/// request to every AIA OCSP URL in turn, and returns one result
/// per URL. Never errors — transport / protocol failures resolve
/// to per-URL `error` strings.
///
/// `leaf_der` and `issuer_der` must be the DER-encoded
/// SubjectPublicKeyInfo certificates from the chain the server
/// delivered; they're parsed into `X509` for CertID construction.
pub async fn probe_ocsp_http(
    leaf_der: &[u8],
    issuer_der: &[u8],
    aia_ocsp_urls: &[String],
    overall_timeout: Duration,
) -> OcspHttpFetchOutput {
    let mut out = OcspHttpFetchOutput::default();
    if aia_ocsp_urls.is_empty() {
        return out;
    }

    // Parse leaf + issuer into X509 handles. Failures here are
    // single-URL-agnostic — surface once across all attempts.
    let leaf = match X509::from_der(leaf_der) {
        Ok(c) => c,
        Err(e) => {
            for url in aia_ocsp_urls {
                out.results.push(OcspHttpFetch {
                    url: url.clone(),
                    http_status: None,
                    response_der: None,
                    error: Some(format!("leaf_parse_failed:{e}")),
                });
            }
            return out;
        }
    };
    let issuer = match X509::from_der(issuer_der) {
        Ok(c) => c,
        Err(e) => {
            for url in aia_ocsp_urls {
                out.results.push(OcspHttpFetch {
                    url: url.clone(),
                    http_status: None,
                    response_der: None,
                    error: Some(format!("issuer_parse_failed:{e}")),
                });
            }
            return out;
        }
    };

    // Build the OCSPRequest once — same bytes POSTed to every URL.
    let request_der = match build_ocsp_request_der(&leaf, &issuer) {
        Ok(d) => d,
        Err(e) => {
            for url in aia_ocsp_urls {
                out.results.push(OcspHttpFetch {
                    url: url.clone(),
                    http_status: None,
                    response_der: None,
                    error: Some(format!("ocsp_request_build:{e}")),
                });
            }
            return out;
        }
    };

    let client = match reqwest::Client::builder()
        .timeout(overall_timeout)
        .user_agent(format!("kemist-ocsp/{}", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            for url in aia_ocsp_urls {
                out.results.push(OcspHttpFetch {
                    url: url.clone(),
                    http_status: None,
                    response_der: None,
                    error: Some(format!("http_client_build:{e}")),
                });
            }
            return out;
        }
    };

    for url in aia_ocsp_urls {
        out.results
            .push(fetch_one(&client, url, &request_der).await);
    }
    out
}

/// Build the OCSPRequest DER bytes for `leaf` signed under `issuer`.
/// Uses SHA-1 for the CertID hash — the legacy default every
/// responder accepts (RFC 6960 §A.2 explicitly calls out SHA-1 as
/// the interoperable choice). SHA-256 CertIDs would be preferable
/// cryptographically but are frequently rejected by production
/// responders expecting SHA-1.
fn build_ocsp_request_der(
    leaf: &X509,
    issuer: &X509,
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let cert_id = OcspCertId::from_cert(MessageDigest::sha1(), leaf, issuer)?;
    let mut req = OcspRequest::new()?;
    req.add_id(cert_id)?;
    req.to_der()
}

async fn fetch_one(client: &reqwest::Client, url: &str, request_der: &[u8]) -> OcspHttpFetch {
    let resp = match client
        .post(url)
        .header("Content-Type", "application/ocsp-request")
        .header("Accept", "application/ocsp-response")
        .body(request_der.to_vec())
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return OcspHttpFetch {
                url: url.to_string(),
                http_status: None,
                response_der: None,
                error: Some(format!("post_failed:{e}")),
            };
        }
    };

    let http_status = resp.status().as_u16();
    if !resp.status().is_success() {
        return OcspHttpFetch {
            url: url.to_string(),
            http_status: Some(http_status),
            response_der: None,
            error: Some(format!("http_status_{http_status}")),
        };
    }

    // Body cap — OCSP responses are typically <10 KB; anything
    // larger is either a misbehaving responder or a compressed
    // bundle we don't want to blindly load into memory.
    let body = match resp.bytes().await {
        Ok(b) if b.len() > 256 * 1024 => {
            return OcspHttpFetch {
                url: url.to_string(),
                http_status: Some(http_status),
                response_der: None,
                error: Some(format!("response_exceeds_size_cap:{}", b.len())),
            };
        }
        Ok(b) => b.to_vec(),
        Err(e) => {
            return OcspHttpFetch {
                url: url.to_string(),
                http_status: Some(http_status),
                response_der: None,
                error: Some(format!("body_read:{e}")),
            };
        }
    };

    OcspHttpFetch {
        url: url.to_string(),
        http_status: Some(http_status),
        response_der: Some(body),
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_url_list_returns_empty_output() {
        let out = probe_ocsp_http(&[], &[], &[], Duration::from_secs(1)).await;
        assert!(out.results.is_empty());
    }

    #[tokio::test]
    async fn bad_leaf_der_surfaces_per_url_error() {
        let out = probe_ocsp_http(
            b"not-a-cert",
            b"not-a-cert",
            &["http://ocsp.example.com".to_string()],
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(out.results.len(), 1);
        assert!(out.results[0]
            .error
            .as_ref()
            .unwrap()
            .contains("leaf_parse_failed"));
    }

    #[tokio::test]
    async fn bad_issuer_der_surfaces_per_url_error() {
        // Use a real cert for leaf so the leaf parse succeeds, then
        // a bogus issuer blob to hit the second error path.
        //
        // x509-parser generates a valid self-signed cert we can
        // borrow at runtime via openssl's X509Builder — saves us
        // committing a test fixture. Falls back gracefully if the
        // builder path fails (CI smoke catches it).
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509NameBuilder, X509};
        let rsa = Rsa::generate(2048).expect("rsa gen");
        let pkey = PKey::from_rsa(rsa).expect("pkey");
        let mut name = X509NameBuilder::new().expect("name builder");
        name.append_entry_by_text("CN", "kemist-test").expect("cn");
        let name = name.build();
        let mut builder = X509::builder().expect("x509 builder");
        builder.set_version(2).expect("version");
        builder.set_subject_name(&name).expect("subject");
        builder.set_issuer_name(&name).expect("issuer");
        builder.set_pubkey(&pkey).expect("pubkey");
        builder
            .set_not_before(&Asn1Time::days_from_now(0).expect("nb"))
            .expect("set nb");
        builder
            .set_not_after(&Asn1Time::days_from_now(30).expect("na"))
            .expect("set na");
        builder.sign(&pkey, MessageDigest::sha256()).expect("sign");
        let leaf = builder.build();
        let leaf_der = leaf.to_der().expect("leaf der");

        let out = probe_ocsp_http(
            &leaf_der,
            b"not-an-issuer-cert",
            &["http://ocsp.example.com".to_string()],
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(out.results.len(), 1);
        assert!(out.results[0]
            .error
            .as_ref()
            .unwrap()
            .contains("issuer_parse_failed"));
    }
}
