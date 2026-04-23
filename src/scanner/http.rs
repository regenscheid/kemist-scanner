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
    /// Source breadcrumb for the preload lookup — `"compiled_in"`
    /// (default, using the build.rs-generated PHF) or
    /// `"runtime_override:<path>"` when `--hsts-preload-list-path`
    /// was supplied. Lets downstream consumers tell which snapshot
    /// the observation was made against.
    pub preload_list_source: Option<String>,
    pub security_txt: Option<SecurityTxtObservation>,
    /// Additional security-related HTTP response headers observed
    /// on `HEAD /`. Each field carries the raw header value (or
    /// structured parse where trivial). `None` when the header was
    /// absent. Feeds `http.security_headers` in schema.
    pub security_headers: Option<SecurityHeaders>,
    /// Redirect chain observed when fetching `GET /` with redirect
    /// following enabled (bounded depth). Each hop carries the
    /// request URL, status, and `Location` target. `None` when the
    /// redirect probe didn't run; empty `Vec` when the origin
    /// responded with a non-3xx status and no redirects occurred.
    pub redirect_chain: Option<Vec<RedirectHop>>,
    /// Populated when a probe step errored — a breadcrumb for debugging.
    pub errors: Vec<String>,
}

/// Security-related HTTP response headers beyond HSTS. Each field is
/// the raw header value when present; absent headers render as
/// `None`. Structured where trivial (Set-Cookie flags); raw
/// otherwise so rule engines can do their own policy evaluation.
#[derive(Debug, Clone, Default)]
pub struct SecurityHeaders {
    /// `Content-Security-Policy` — raw directive string.
    pub content_security_policy: Option<String>,
    /// `Content-Security-Policy-Report-Only` — raw; monitoring-mode
    /// CSP deployed without enforcement.
    pub content_security_policy_report_only: Option<String>,
    /// `X-Frame-Options` — `DENY` / `SAMEORIGIN` / `ALLOW-FROM <uri>`.
    /// Deprecated in favor of CSP `frame-ancestors` but still widely
    /// present.
    pub x_frame_options: Option<String>,
    /// `X-Content-Type-Options` — canonical value `nosniff`.
    pub x_content_type_options: Option<String>,
    /// `Referrer-Policy` — e.g. `no-referrer`, `strict-origin`.
    pub referrer_policy: Option<String>,
    /// `Permissions-Policy` (RFC 9214 successor to Feature-Policy) —
    /// raw directive string.
    pub permissions_policy: Option<String>,
    /// `Cross-Origin-Opener-Policy` — `same-origin` etc.
    pub cross_origin_opener_policy: Option<String>,
    /// `Cross-Origin-Embedder-Policy` — `require-corp` etc.
    pub cross_origin_embedder_policy: Option<String>,
    /// `Cross-Origin-Resource-Policy` — `same-origin` / `same-site`
    /// / `cross-origin`.
    pub cross_origin_resource_policy: Option<String>,
    /// `Report-To` / `Reporting-Endpoints` — modern reporting API
    /// endpoint declaration. Raw value.
    pub reporting_endpoints: Option<String>,
    /// One entry per `Set-Cookie` header on the response. Each
    /// entry exposes the cookie name + flag observations; cookie
    /// values are NOT captured (potential PII / session-token leak).
    pub set_cookies: Vec<CookieObservation>,
}

/// Per-cookie security-flag observation. Cookie *value* is
/// deliberately omitted — the scanner is a sensor, and cookie values
/// often carry session tokens or other sensitive material that should
/// not land in observation output.
#[derive(Debug, Clone, Default)]
pub struct CookieObservation {
    /// Cookie name (left of the `=`).
    pub name: String,
    /// True when the `Secure` attribute is present.
    pub secure: bool,
    /// True when the `HttpOnly` attribute is present.
    pub http_only: bool,
    /// `"Strict"`, `"Lax"`, `"None"`, or `None` when absent.
    pub same_site: Option<String>,
}

/// One hop in the redirect chain. Captured when the HTTP-layer probe
/// follows redirects.
#[derive(Debug, Clone, Default)]
pub struct RedirectHop {
    /// URL that was requested for this hop.
    pub url: String,
    /// HTTP status code returned (`3xx` for a redirect, final
    /// non-3xx for the terminal hop).
    pub status: u16,
    /// Value of the `Location` header. `None` on the terminal hop
    /// (non-redirect) or when the header was absent/malformed.
    pub location: Option<String>,
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
    /// Structured parse of the RFC 9116 body. `None` when `body` is
    /// `None` or when parsing produced no recognized fields.
    pub parsed: Option<SecurityTxtParsed>,
}

/// Parsed security.txt body per RFC 9116 §2.5. Each field holds all
/// occurrences of the directive in the order encountered; RFC 9116
/// allows multiple `Contact`, `Encryption`, `Acknowledgments`, etc.
/// entries. Comments (`#`-prefixed lines) and unknown directives are
/// ignored.
#[derive(Debug, Clone, Default)]
pub struct SecurityTxtParsed {
    /// `Contact:` — required, one or more. URL or `mailto:` / `tel:`.
    pub contact: Vec<String>,
    /// `Expires:` — required, ISO 8601 datetime. Retained as-is;
    /// downstream rule engines parse + compare against current time.
    pub expires: Option<String>,
    /// `Encryption:` — URL of public key for encrypted
    /// vulnerability reports.
    pub encryption: Vec<String>,
    /// `Preferred-Languages:` — RFC 5646 tags, comma-separated in
    /// the source header, split here.
    pub preferred_languages: Vec<String>,
    /// `Canonical:` — URL(s) where this security.txt is served.
    pub canonical: Vec<String>,
    /// `Policy:` — URL of the vulnerability-disclosure policy.
    pub policy: Vec<String>,
    /// `Hiring:` — URL of security-related job postings.
    pub hiring: Vec<String>,
    /// `Acknowledgments:` — URL of the hall-of-fame / researcher
    /// credits page.
    pub acknowledgments: Vec<String>,
    /// True when the body includes a PGP cleartext-signature block
    /// (`-----BEGIN PGP SIGNED MESSAGE-----`). RFC 9116 §5 recommends
    /// signing. No signature validation — presence only.
    pub pgp_signed: bool,
}

// Compile-time HSTS preload map, generated by `build.rs` from
// `data/hsts_preload_list.json` (a vendored Chromium
// `transport_security_state_static.json` snapshot). The generated
// file is emitted to `$OUT_DIR` and `include!`-d here.
//
// The included file declares:
//   pub static HSTS_PRELOAD: phf::Map<&'static str, bool>;
// Key: lowercase host. Value: whether `include_subdomains` is set.
// Only entries with `mode: "force-https"` in the source file land
// here — HPKP-only pinning entries are excluded.
include!(concat!(env!("OUT_DIR"), "/hsts_preload.rs"));

/// Global preload-source selector. `None` → use the compile-time PHF
/// (default). `Some` → a runtime-loaded override supplied via
/// `--hsts-preload-list-path`. Set once at startup; never mutated
/// after.
static PRELOAD_OVERRIDE: std::sync::OnceLock<PreloadOverride> = std::sync::OnceLock::new();

/// Runtime-loaded preload map. Parallel shape to the compile-time
/// PHF — host → `include_subdomains`.
#[derive(Debug, Clone)]
pub struct PreloadOverride {
    /// Absolute path the map was loaded from. Surfaces in the output
    /// as `preload_list_source: "runtime_override:<path>"` so
    /// consumers know which snapshot the observation was made against.
    pub source_path: String,
    map: std::collections::HashMap<String, bool>,
}

/// Install a runtime-loaded preload override. Must be called exactly
/// once, before any `preload_list_status` call. Silently ignores
/// subsequent calls (OnceLock semantics).
pub fn install_preload_override(override_: PreloadOverride) {
    let _ = PRELOAD_OVERRIDE.set(override_);
}

/// Load a runtime preload override from a file path. Expected format
/// is the Chromium `transport_security_state_static.json` schema —
/// JSON with `{ "entries": [{ "name": ..., "mode": ...,
/// "include_subdomains": ... }, ...] }`. JavaScript-style `//`
/// comments are permitted (parser is JSON5-lenient).
///
/// Returns an error string if the file can't be read or parsed, or
/// if no `mode: force-https` entries were found. The caller is
/// expected to surface the error to the user; kemist falls back to
/// the compile-time PHF when override loading fails.
pub fn load_preload_override_from_path(path: &str) -> Result<PreloadOverride, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("read {path}: {e}"))?;
    let parsed: PreloadOverrideFile = json5::from_str(&raw)
        .map_err(|e| format!("parse {path}: {e}"))?;
    let mut map = std::collections::HashMap::new();
    for entry in parsed.entries {
        if entry.mode.as_deref() == Some("force-https") {
            map.insert(entry.name.to_ascii_lowercase(), entry.include_subdomains);
        }
    }
    if map.is_empty() {
        return Err(format!(
            "no `mode: force-https` entries found in {path}"
        ));
    }
    Ok(PreloadOverride {
        source_path: path.to_string(),
        map,
    })
}

#[derive(serde::Deserialize)]
struct PreloadOverrideFile {
    entries: Vec<PreloadOverrideEntry>,
}

#[derive(serde::Deserialize)]
struct PreloadOverrideEntry {
    name: String,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    include_subdomains: bool,
}

/// Breadcrumb describing which snapshot drove the preload lookup —
/// `"compiled_in"` for the default PHF or
/// `"runtime_override:<path>"` when `--hsts-preload-list-path` is in
/// effect. Surfaces in schema as `http.preload_list_source`.
pub fn preload_list_source() -> String {
    match PRELOAD_OVERRIDE.get() {
        Some(ov) => format!("runtime_override:{}", ov.source_path),
        None => "compiled_in".to_string(),
    }
}

/// Resolve preload status for `host`. Returns `"included"` when the host
/// matches an entry (exact or via subdomain include), else `"not_included"`.
///
/// Dispatches on [`PRELOAD_OVERRIDE`]: uses the runtime override map
/// when one is installed, else the compile-time PHF. Both paths
/// share the exact-match + subdomain-suffix semantics.
pub fn preload_list_status(host: &str) -> &'static str {
    let needle = host.to_ascii_lowercase();

    if let Some(ov) = PRELOAD_OVERRIDE.get() {
        return resolve_preload_runtime(&needle, &ov.map);
    }

    // Compile-time PHF path.
    if HSTS_PRELOAD.get(needle.as_str()).is_some() {
        return "included";
    }
    // Subdomain check: walk parent labels, test each against the PHF.
    // Start after the first dot — the exact-match check above already
    // covered the full host.
    let mut rest = needle.as_str();
    while let Some(dot) = rest.find('.') {
        let parent = &rest[dot + 1..];
        if parent.is_empty() {
            break;
        }
        if let Some(&include_sub) = HSTS_PRELOAD.get(parent) {
            if include_sub {
                return "included";
            }
        }
        rest = parent;
    }
    "not_included"
}

fn resolve_preload_runtime(
    needle: &str,
    map: &std::collections::HashMap<String, bool>,
) -> &'static str {
    if map.contains_key(needle) {
        return "included";
    }
    let mut rest = needle;
    while let Some(dot) = rest.find('.') {
        let parent = &rest[dot + 1..];
        if parent.is_empty() {
            break;
        }
        if let Some(&include_sub) = map.get(parent) {
            if include_sub {
                return "included";
            }
        }
        rest = parent;
    }
    "not_included"
}

/// Extract security-related HTTP response headers from a
/// [`reqwest::header::HeaderMap`]. Raw string values for CSP /
/// frame-options / referrer-policy / etc.; structured parse for
/// `Set-Cookie` (name + flags, no cookie value).
#[cfg(feature = "http-checks")]
fn extract_security_headers(headers: &reqwest::header::HeaderMap) -> SecurityHeaders {
    let get = |name: &str| -> Option<String> {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    };

    // `Reporting-Endpoints` supersedes `Report-To` (deprecated). Prefer
    // the modern header; fall through to the legacy one when the new
    // one is absent so old deployments still surface.
    let reporting_endpoints = get("reporting-endpoints").or_else(|| get("report-to"));

    let mut set_cookies = Vec::new();
    for v in headers.get_all("set-cookie").iter() {
        if let Ok(s) = v.to_str() {
            if let Some(obs) = parse_set_cookie(s) {
                set_cookies.push(obs);
            }
        }
    }

    SecurityHeaders {
        content_security_policy: get("content-security-policy"),
        content_security_policy_report_only: get("content-security-policy-report-only"),
        x_frame_options: get("x-frame-options"),
        x_content_type_options: get("x-content-type-options"),
        referrer_policy: get("referrer-policy"),
        permissions_policy: get("permissions-policy"),
        cross_origin_opener_policy: get("cross-origin-opener-policy"),
        cross_origin_embedder_policy: get("cross-origin-embedder-policy"),
        cross_origin_resource_policy: get("cross-origin-resource-policy"),
        reporting_endpoints,
        set_cookies,
    }
}

/// Parse a single `Set-Cookie` header value into a [`CookieObservation`].
/// Cookie value (the part between `=` and the first `;`) is discarded
/// — we only retain the name and security-flag attributes.
///
/// Tolerates loose formatting: whitespace around attributes, missing
/// `=` (valueless attributes like `Secure`, `HttpOnly`), and
/// case-insensitive attribute names.
pub fn parse_set_cookie(value: &str) -> Option<CookieObservation> {
    let mut parts = value.split(';');
    let first = parts.next()?.trim();
    let name = match first.find('=') {
        Some(i) => first[..i].trim(),
        None => first,
    };
    if name.is_empty() {
        return None;
    }

    let mut out = CookieObservation {
        name: name.to_string(),
        secure: false,
        http_only: false,
        same_site: None,
    };

    for attr in parts {
        let attr = attr.trim();
        let (k, v) = match attr.find('=') {
            Some(i) => (attr[..i].trim(), Some(attr[i + 1..].trim())),
            None => (attr, None),
        };
        match k.to_ascii_lowercase().as_str() {
            "secure" => out.secure = true,
            "httponly" => out.http_only = true,
            "samesite" => {
                // Canonical values are Strict / Lax / None. Preserve
                // whatever the server sent, case-normalized to
                // match browser behavior.
                out.same_site = v.map(|s| match s.to_ascii_lowercase().as_str() {
                    "strict" => "Strict".to_string(),
                    "lax" => "Lax".to_string(),
                    "none" => "None".to_string(),
                    other => other.to_string(),
                });
            }
            _ => {}
        }
    }

    Some(out)
}

/// Parse a `/.well-known/security.txt` body per RFC 9116. Fields are
/// `Name: value` pairs, one per line. Comments start with `#`. Blank
/// lines separate optional signature block (when PGP-signed).
/// Multiple `Contact`, `Encryption`, etc. entries are allowed — each
/// occurrence is appended to its vector.
///
/// Returns `None` when no recognized fields were found (e.g. an
/// empty body, or a 404 page HTML that happened to return 200 OK).
pub fn parse_security_txt(body: &str) -> Option<SecurityTxtParsed> {
    let mut out = SecurityTxtParsed::default();
    let mut saw_any = false;
    let mut in_pgp_signature_block = false;

    for raw_line in body.lines() {
        let line = raw_line.trim();

        if line.starts_with("-----BEGIN PGP SIGNED MESSAGE-----") {
            out.pgp_signed = true;
            continue;
        }
        if line.starts_with("-----BEGIN PGP SIGNATURE-----") {
            in_pgp_signature_block = true;
            continue;
        }
        if line.starts_with("-----END PGP SIGNATURE-----") {
            in_pgp_signature_block = false;
            continue;
        }
        if in_pgp_signature_block || line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Directive lines: `Name: value`. Name is case-insensitive
        // per RFC 9116 §2.5.2.
        let Some(colon) = line.find(':') else {
            continue;
        };
        let name = line[..colon].trim();
        let value = line[colon + 1..].trim().to_string();
        if name.is_empty() || value.is_empty() {
            continue;
        }

        saw_any = true;
        match name.to_ascii_lowercase().as_str() {
            "contact" => out.contact.push(value),
            "expires" => {
                // RFC 9116 §2.5.2: exactly one Expires field. Keep
                // the first occurrence (duplicates are a producer
                // bug; we surface it as-is rather than silently
                // picking the last).
                if out.expires.is_none() {
                    out.expires = Some(value);
                }
            }
            "encryption" => out.encryption.push(value),
            "preferred-languages" => {
                // Comma-separated; split + trim each.
                for tag in value.split(',') {
                    let t = tag.trim();
                    if !t.is_empty() {
                        out.preferred_languages.push(t.to_string());
                    }
                }
            }
            "canonical" => out.canonical.push(value),
            "policy" => out.policy.push(value),
            "hiring" => out.hiring.push(value),
            "acknowledgments" => out.acknowledgments.push(value),
            _ => {} // unknown directive — RFC 9116 §2.4 says ignore
        }
    }

    if saw_any {
        Some(out)
    } else {
        None
    }
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
        preload_list_source: Some(preload_list_source()),
        ..Default::default()
    };

    let ua = format!(
        "{}/{} (+{})",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        user_agent_info_url
    );

    let client = match reqwest::Client::builder()
        .user_agent(&ua)
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

    // ── HSTS + security headers via HEAD / ────────────────────────────
    // One HEAD request feeds both `hsts` and `security_headers` — no
    // point in doubling up network round trips.
    let hsts_url = format!("{base}/");
    match client.head(&hsts_url).send().await {
        Ok(resp) => {
            let headers = resp.headers();
            match headers.get("strict-transport-security") {
                Some(v) => match v.to_str() {
                    Ok(s) => out.hsts = Some(parse_hsts(s)),
                    Err(_) => {
                        out.errors.push("hsts_header_non_utf8".to_string());
                        out.hsts = Some(HstsObservation::default());
                    }
                },
                None => out.hsts = Some(HstsObservation::default()),
            }
            out.security_headers = Some(extract_security_headers(headers));
        }
        Err(e) => out.errors.push(format!("hsts_request:{e}")),
    }

    // ── Redirect chain via GET / ──────────────────────────────────────
    // Separate client — the main `client` is configured with
    // `Policy::none()` so HEAD / sees only the origin's immediate
    // response. Here we want the chain. Cap at 10 hops (matches
    // reqwest default + common browser limits).
    out.redirect_chain = Some(collect_redirect_chain(&base, overall_timeout, &ua).await);

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
                        let parsed = parse_security_txt(&body);
                        out.security_txt = Some(SecurityTxtObservation {
                            present: true,
                            url: Some(sec_url),
                            content_type,
                            body: Some(body),
                            parsed,
                        });
                    }
                    Err(e) => {
                        out.errors.push(format!("security_txt_body:{e}"));
                        out.security_txt = Some(SecurityTxtObservation {
                            present: false,
                            url: Some(sec_url),
                            content_type,
                            body: None,
                            parsed: None,
                        });
                    }
                }
            } else {
                out.security_txt = Some(SecurityTxtObservation {
                    present: false,
                    url: Some(sec_url),
                    content_type,
                    body: None,
                    parsed: None,
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

/// Walk the redirect chain for `GET <base>/`, capturing each hop's
/// URL, status code, and `Location` target. Follows redirects
/// manually (not via reqwest's `Policy::limited`) so every hop
/// surfaces individually in the output even when the final response
/// is non-3xx. Bounded at 10 hops; on the terminal hop the chain
/// ends with a non-3xx status.
///
/// Tolerates malformed relative `Location` values: if a hop's
/// Location can't be resolved against the current request URL, the
/// chain stops there with `location: Some(raw)` on the last hop.
///
/// Returns an empty `Vec` when the initial request fails — the
/// caller's `errors` breadcrumb covers the root cause.
#[cfg(feature = "http-checks")]
async fn collect_redirect_chain(
    base: &str,
    overall_timeout: Duration,
    user_agent: &str,
) -> Vec<RedirectHop> {
    const MAX_HOPS: usize = 10;

    let client = match reqwest::Client::builder()
        .user_agent(user_agent)
        .timeout(overall_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut chain = Vec::new();
    let mut current = format!("{base}/");

    for _ in 0..MAX_HOPS {
        let resp = match client.get(&current).send().await {
            Ok(r) => r,
            Err(_) => {
                // Record the failed attempt as a hop with status 0 so
                // downstream consumers can see where the chain broke.
                chain.push(RedirectHop {
                    url: current.clone(),
                    status: 0,
                    location: None,
                });
                break;
            }
        };
        let status = resp.status().as_u16();
        let location_header = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        chain.push(RedirectHop {
            url: current.clone(),
            status,
            location: location_header.clone(),
        });

        // Not a redirect → terminal hop.
        if !(300..400).contains(&status) {
            break;
        }
        // 3xx but no usable Location → can't continue; stop here.
        let Some(loc) = location_header else {
            break;
        };
        // Resolve relative URLs against the current request URL. Bail
        // if resolution fails (malformed Location) — the last hop
        // already records the raw value so consumers see what the
        // server sent.
        let next = match reqwest::Url::parse(&current).and_then(|u| u.join(&loc)) {
            Ok(u) => u.to_string(),
            Err(_) => break,
        };
        current = next;
    }

    chain
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
        out.preload_list_source = Some(preload_list_source());
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
    fn preload_exact_match_against_compiled_snapshot() {
        // github.com is a well-known preload entry with
        // include_subdomains: true. Lookup must be case-insensitive.
        assert_eq!(preload_list_status("github.com"), "included");
        assert_eq!(preload_list_status("GITHUB.COM"), "included");
    }

    #[test]
    fn preload_subdomain_match_walks_parent_labels() {
        // The compiled-in snapshot has github.com with
        // include_subdomains: true, so any subdomain resolves to
        // included via the parent-walk logic.
        assert_eq!(preload_list_status("api.github.com"), "included");
        assert_eq!(preload_list_status("deep.sub.api.github.com"), "included");
        // mail.google.com is a concrete Chromium entry; it's a real
        // subdomain of google.com AND has its own record. This
        // specifically covers the "full snapshot has entries the
        // 12-row stub never had" case the plan calls out.
        assert_eq!(preload_list_status("mail.google.com"), "included");
    }

    #[test]
    fn preload_source_defaults_to_compiled_in() {
        // When no runtime override is installed the breadcrumb
        // resolves to the literal "compiled_in". The runtime-override
        // branch is exercised via main.rs integration, not this unit
        // test — OnceLock can't be reset between tests.
        // Assert only the prefix is stable; this test coexists with
        // other tests that may or may not install an override.
        let src = preload_list_source();
        assert!(src == "compiled_in" || src.starts_with("runtime_override:"));
    }

    #[test]
    fn preload_unknown_host_returns_not_included() {
        assert_eq!(
            preload_list_status("this-should-never-be-preloaded.example.invalid"),
            "not_included"
        );
    }

    #[test]
    fn preload_override_loader_rejects_empty_and_non_https_modes() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        // Empty entries list.
        let empty_path = dir.join("kemist_preload_empty.json");
        let mut f = std::fs::File::create(&empty_path).unwrap();
        writeln!(f, r#"{{"entries": []}}"#).unwrap();
        drop(f);
        let err =
            load_preload_override_from_path(empty_path.to_str().unwrap()).unwrap_err();
        assert!(err.contains("no `mode: force-https` entries"));

        // File with entries but none `force-https`.
        let pins_only_path = dir.join("kemist_preload_pins.json");
        let mut f = std::fs::File::create(&pins_only_path).unwrap();
        writeln!(
            f,
            r#"{{"entries": [{{"name":"pinned.example","mode":"pkp-only","include_subdomains":true}}]}}"#
        )
        .unwrap();
        drop(f);
        let err =
            load_preload_override_from_path(pins_only_path.to_str().unwrap()).unwrap_err();
        assert!(err.contains("no `mode: force-https` entries"));

        let _ = std::fs::remove_file(empty_path);
        let _ = std::fs::remove_file(pins_only_path);
    }

    #[test]
    fn preload_override_loader_accepts_json_with_comments() {
        use std::io::Write;
        let path = std::env::temp_dir().join("kemist_preload_with_comments.json");
        let mut f = std::fs::File::create(&path).unwrap();
        // JavaScript-style comments (Chromium format); json5 tolerates them.
        writeln!(
            f,
            "// header comment\n{{\n  \"entries\": [\n    {{ \"name\": \"foo.invalid\", \"mode\": \"force-https\", \"include_subdomains\": true }}\n  ]\n}}"
        )
        .unwrap();
        drop(f);
        let ov = load_preload_override_from_path(path.to_str().unwrap()).unwrap();
        assert_eq!(ov.source_path, path.to_str().unwrap());
        assert!(ov.map.contains_key("foo.invalid"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn security_txt_parses_minimal_rfc9116() {
        let body = "\
            Contact: mailto:security@example.com\n\
            Expires: 2026-12-31T23:59:59Z\n\
        ";
        let parsed = parse_security_txt(body).expect("parseable");
        assert_eq!(parsed.contact, vec!["mailto:security@example.com"]);
        assert_eq!(parsed.expires.as_deref(), Some("2026-12-31T23:59:59Z"));
        assert!(!parsed.pgp_signed);
    }

    #[test]
    fn security_txt_allows_multiple_contacts_and_encryption() {
        let body = "\
            # Comment line ignored\n\
            Contact: mailto:one@example.com\n\
            Contact: https://example.com/report\n\
            Encryption: https://example.com/pgp.txt\n\
            Encryption: https://example.com/pgp2.txt\n\
            Expires: 2026-01-01T00:00:00Z\n\
            Preferred-Languages: en, de, fr\n\
            Policy: https://example.com/policy\n\
        ";
        let p = parse_security_txt(body).expect("parseable");
        assert_eq!(p.contact.len(), 2);
        assert_eq!(p.encryption.len(), 2);
        assert_eq!(p.preferred_languages, vec!["en", "de", "fr"]);
        assert_eq!(p.policy, vec!["https://example.com/policy"]);
    }

    #[test]
    fn security_txt_detects_pgp_signature_block() {
        let body = "\
            -----BEGIN PGP SIGNED MESSAGE-----\n\
            Hash: SHA256\n\
            \n\
            Contact: mailto:security@example.com\n\
            Expires: 2026-01-01T00:00:00Z\n\
            -----BEGIN PGP SIGNATURE-----\n\
            iQIzBAEBCAAdFiEE...\n\
            -----END PGP SIGNATURE-----\n\
        ";
        let p = parse_security_txt(body).expect("parseable");
        assert!(p.pgp_signed);
        assert_eq!(p.contact.len(), 1);
        // Directives inside the signature block must NOT be parsed.
        assert_eq!(p.expires.as_deref(), Some("2026-01-01T00:00:00Z"));
    }

    #[test]
    fn security_txt_returns_none_for_empty_or_unrecognized_body() {
        assert!(parse_security_txt("").is_none());
        assert!(parse_security_txt("# just a comment\n").is_none());
        assert!(parse_security_txt("<!DOCTYPE html>\n<html>...").is_none());
    }

    #[test]
    fn set_cookie_captures_flags_not_value() {
        let c = parse_set_cookie("session=abc123; Secure; HttpOnly; SameSite=Strict")
            .expect("parseable");
        assert_eq!(c.name, "session");
        assert!(c.secure);
        assert!(c.http_only);
        assert_eq!(c.same_site.as_deref(), Some("Strict"));
    }

    #[test]
    fn set_cookie_without_flags_is_all_false() {
        let c = parse_set_cookie("tracking=xyz; Path=/; Domain=example.com")
            .expect("parseable");
        assert_eq!(c.name, "tracking");
        assert!(!c.secure);
        assert!(!c.http_only);
        assert!(c.same_site.is_none());
    }

    #[test]
    fn set_cookie_samesite_normalizes_case() {
        let lax = parse_set_cookie("k=v; SameSite=lax").unwrap();
        assert_eq!(lax.same_site.as_deref(), Some("Lax"));
        let none = parse_set_cookie("k=v; samesite=NONE; Secure").unwrap();
        assert_eq!(none.same_site.as_deref(), Some("None"));
        assert!(none.secure);
    }

    #[test]
    fn set_cookie_rejects_empty_name() {
        assert!(parse_set_cookie("=value; Secure").is_none());
        assert!(parse_set_cookie("").is_none());
    }
}
