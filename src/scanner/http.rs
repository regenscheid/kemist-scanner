//! HTTP-layer observations.
//!
//! These are not TLS probes — they run over a successfully negotiated
//! TLS connection and record HTTP-side security signals:
//!
//! - `Strict-Transport-Security` header (HSTS, RFC 6797)
//! - `/.well-known/security.txt` presence + body (RFC 9116)
//! - HSTS preload list inclusion (Chromium snapshot)
//!
//! Gated behind cargo feature `http-checks` (default on) so
//! `--no-default-features` builds produce a pure-TLS scanner.
//!
//! ## Runtime opt-in
//! Even when the feature is compiled in, the CLI must pass
//! `--enable-http-checks` to actually fire HTTP requests. This keeps
//! batch scans TLS-only by default and avoids surprising anyone
//! watching their own server logs.
//!
//! ## Preload list snapshot
//! The hardcoded list below covers a small set of well-known preloaded
//! domains for demonstration. A future workstream could bundle a full
//! Chromium `transport_security_state_static.json` snapshot as a
//! compile-time data file. Until then the observation is correct for
//! listed entries and a conservative `null` for everything else.

use std::time::Duration;

#[derive(Debug, Clone, Default)]
pub struct HttpObservations {
    /// True when `--enable-http-checks` was set and probes were attempted.
    /// When `false`, consumers should treat every nested field as
    /// `not_probed` regardless of its value.
    pub enabled: bool,
    pub hsts: Option<HstsObservation>,
    /// `"included"`, `"not_included"`, or `None` when the lookup was skipped.
    pub preload_list_status: Option<String>,
    pub security_txt: Option<SecurityTxtObservation>,
    /// Populated when a probe step errored — a breadcrumb for debugging.
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct HstsObservation {
    pub header_present: bool,
    pub raw_value: Option<String>,
    pub max_age: Option<u64>,
    pub include_subdomains: Option<bool>,
    pub preload: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct SecurityTxtObservation {
    pub present: bool,
    pub url: Option<String>,
    pub content_type: Option<String>,
    pub body: Option<String>,
}

/// Small, conservative HSTS preload subset covering common test targets.
/// Each entry is `(domain, include_subdomains)`. Domain match is exact
/// plus, when `include_subdomains: true`, any subdomain also matches.
///
/// This is a stub — a future workstream can replace with a full
/// Chromium `transport_security_state_static.json` snapshot bundled
/// at build time.
const PRELOAD_LIST: &[(&str, bool)] = &[
    ("github.com", true),
    ("www.github.com", true),
    ("paypal.com", true),
    ("www.paypal.com", true),
    ("reddit.com", true),
    ("twitter.com", true),
    ("mozilla.org", true),
    ("wikipedia.org", true),
    ("cisa.gov", true),
    ("gov.uk", true),
    ("example.com", true),
    ("cloudflare.com", false),
];

/// Resolve preload status for `host`. Returns `"included"` when the host
/// matches an entry (exact or via subdomain include), else `"not_included"`.
pub fn preload_list_status(host: &str) -> &'static str {
    let needle = host.to_ascii_lowercase();
    for (entry, include_sub) in PRELOAD_LIST {
        if entry.eq_ignore_ascii_case(&needle) {
            return "included";
        }
        if *include_sub && needle.ends_with(&format!(".{entry}")) {
            return "included";
        }
    }
    "not_included"
}

/// Parse an HSTS header value (RFC 6797 §6.1). Missing directives leave
/// their fields as `None`/`false`. Malformed directives (bad max-age) make
/// the relevant field `None` but don't reject the whole header.
pub fn parse_hsts(value: &str) -> HstsObservation {
    let mut obs = HstsObservation {
        header_present: true,
        raw_value: Some(value.to_string()),
        ..Default::default()
    };

    for directive in value.split(';') {
        let d = directive.trim();
        let lower = d.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("max-age=") {
            // RFC 6797 allows a quoted value. Strip quotes if present.
            let val = rest.trim().trim_matches('"');
            if let Ok(n) = val.parse::<u64>() {
                obs.max_age = Some(n);
            }
        } else if lower == "includesubdomains" {
            obs.include_subdomains = Some(true);
        } else if lower == "preload" {
            obs.preload = Some(true);
        }
    }

    obs
}

#[cfg(feature = "http-checks")]
pub async fn probe_http(
    host: &str,
    port: u16,
    enable: bool,
    user_agent_info_url: &str,
    overall_timeout: Duration,
) -> HttpObservations {
    if !enable {
        return HttpObservations::default();
    }

    let mut out = HttpObservations {
        enabled: true,
        preload_list_status: Some(preload_list_status(host).to_string()),
        ..Default::default()
    };

    let ua = format!(
        "{}/{} (+{})",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        user_agent_info_url
    );

    let client = match reqwest::Client::builder()
        .user_agent(ua)
        .timeout(overall_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            out.errors.push(format!("client_build:{e}"));
            return out;
        }
    };

    // Base URL for HTTPS. Omit default :443 so the Host header is clean.
    let base = if port == 443 {
        format!("https://{host}")
    } else {
        format!("https://{host}:{port}")
    };

    // ── HSTS via HEAD / ───────────────────────────────────────────────
    let hsts_url = format!("{base}/");
    match client.head(&hsts_url).send().await {
        Ok(resp) => match resp.headers().get("strict-transport-security") {
            Some(v) => match v.to_str() {
                Ok(s) => out.hsts = Some(parse_hsts(s)),
                Err(_) => {
                    out.errors.push("hsts_header_non_utf8".to_string());
                    out.hsts = Some(HstsObservation::default());
                }
            },
            None => out.hsts = Some(HstsObservation::default()),
        },
        Err(e) => out.errors.push(format!("hsts_request:{e}")),
    }

    // ── security.txt via GET /.well-known/security.txt ────────────────
    let sec_url = format!("{base}/.well-known/security.txt");
    match client.get(&sec_url).send().await {
        Ok(resp) => {
            let status = resp.status();
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            if status.is_success() {
                match resp.text().await {
                    Ok(body) => {
                        out.security_txt = Some(SecurityTxtObservation {
                            present: true,
                            url: Some(sec_url),
                            content_type,
                            body: Some(body),
                        });
                    }
                    Err(e) => {
                        out.errors.push(format!("security_txt_body:{e}"));
                        out.security_txt = Some(SecurityTxtObservation {
                            present: false,
                            url: Some(sec_url),
                            content_type,
                            body: None,
                        });
                    }
                }
            } else {
                out.security_txt = Some(SecurityTxtObservation {
                    present: false,
                    url: Some(sec_url),
                    content_type,
                    body: None,
                });
            }
        }
        Err(e) => {
            out.errors.push(format!("security_txt_request:{e}"));
            out.security_txt = Some(SecurityTxtObservation::default());
        }
    }

    out
}

#[cfg(not(feature = "http-checks"))]
pub async fn probe_http(
    host: &str,
    _port: u16,
    enable: bool,
    _user_agent_info_url: &str,
    _overall_timeout: Duration,
) -> HttpObservations {
    // Build without the `http-checks` feature: preload-list lookup still
    // works (it's a static table), HSTS/security.txt stay unprobed.
    let mut out = HttpObservations {
        enabled: false,
        ..Default::default()
    };
    if enable {
        out.preload_list_status = Some(preload_list_status(host).to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_hsts_header() {
        let obs = parse_hsts("max-age=31536000; includeSubDomains; preload");
        assert!(obs.header_present);
        assert_eq!(obs.max_age, Some(31_536_000));
        assert_eq!(obs.include_subdomains, Some(true));
        assert_eq!(obs.preload, Some(true));
    }

    #[test]
    fn parses_minimal_hsts_header() {
        let obs = parse_hsts("max-age=0");
        assert_eq!(obs.max_age, Some(0));
        assert_eq!(obs.include_subdomains, None);
        assert_eq!(obs.preload, None);
    }

    #[test]
    fn hsts_parse_is_case_insensitive() {
        let obs = parse_hsts("MAX-AGE=86400; INCLUDESUBDOMAINS");
        assert_eq!(obs.max_age, Some(86_400));
        assert_eq!(obs.include_subdomains, Some(true));
    }

    #[test]
    fn hsts_ignores_unknown_directives() {
        let obs = parse_hsts("max-age=3600; foobar; includeSubDomains");
        assert_eq!(obs.max_age, Some(3_600));
        assert_eq!(obs.include_subdomains, Some(true));
    }

    #[test]
    fn hsts_handles_quoted_max_age() {
        // RFC 6797 §6.1 allows quoted directive values.
        let obs = parse_hsts("max-age=\"3600\"");
        assert_eq!(obs.max_age, Some(3_600));
    }

    #[test]
    fn preload_exact_match() {
        assert_eq!(preload_list_status("github.com"), "included");
        assert_eq!(preload_list_status("GITHUB.COM"), "included");
    }

    #[test]
    fn preload_subdomain_match_when_include_subdomains() {
        assert_eq!(preload_list_status("api.github.com"), "included");
        assert_eq!(preload_list_status("sub.api.github.com"), "included");
    }

    #[test]
    fn preload_no_subdomain_match_when_parent_excludes() {
        // cloudflare.com entry has include_sub=false in the stub list
        assert_eq!(preload_list_status("cloudflare.com"), "included");
        assert_eq!(preload_list_status("api.cloudflare.com"), "not_included");
    }

    #[test]
    fn preload_unknown_host() {
        assert_eq!(
            preload_list_status("not-preloaded.example.net"),
            "not_included"
        );
    }
}
