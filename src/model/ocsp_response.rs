//! OCSP response content parsing (RFC 6960 §4.2).
//!
//! Pure parser — no TLS backend dependency. Consumes the raw OCSP
//! response bytes captured by the rustls handshake
//! (`StateCollector::ocsp_response`) and produces a structured
//! [`OcspResponseContent`] for the schema.
//!
//! Scope: parse the subset of BasicOCSPResponse fields that downstream
//! rule engines commonly consult (cert_status, this/next/producedAt
//! timestamps, responder identification, signature algorithm). Signature
//! validation is **not** performed — kemist records what the responder
//! said, not whether it was entitled to say it; chain-verification
//! belongs in a separate observation.
//!
//! The parser is tolerant of trailing bytes and unknown extension OIDs
//! — we populate what we recognize and leave the rest silent. Unknown
//! `responseType` OIDs (anything other than `id-pkix-ocsp-basic`)
//! result in `response_status` populated but no signed content
//! decoded.
//!
//! References:
//! - RFC 6960 §4.2 — OCSPResponse / BasicOCSPResponse ASN.1
//! - RFC 5280 §5.3.1 — CRLReason codepoints (used in revoked responses)

use chrono::{DateTime, Utc};
use der_parser::asn1_rs::{Any, Class, FromDer, GeneralizedTime, Tag};
use serde::{Deserialize, Serialize};

/// Parsed content of a stapled OCSP response.
///
/// Every field is optional except [`response_status`] — even a
/// `response_status` of `"malformedRequest"` or similar carries
/// signal, so we always emit the outer container as soon as we get a
/// parseable status byte.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OcspResponseContent {
    /// RFC 6960 §4.2.1 OCSPResponseStatus:
    /// `successful`, `malformedRequest`, `internalError`, `tryLater`,
    /// `sigRequired`, `unauthorized`, or `unknown_<n>` for
    /// unrecognized codes.
    pub response_status: String,

    /// SignatureAlgorithm OID (dotted-decimal) from the
    /// BasicOCSPResponse. `None` when the response is not a
    /// successful BasicOCSPResponse.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_algorithm_oid: Option<String>,

    /// Responder identified by Distinguished Name (ResponderID byName).
    /// Best-effort DN string; not canonicalized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub responder_id_by_name: Option<String>,

    /// Responder identified by key hash (ResponderID byKey) —
    /// lower-case hex of the SHA-1 over the responder's public key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub responder_id_by_key: Option<String>,

    /// When the responder produced the response (RFC 3339).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub produced_at: Option<DateTime<Utc>>,

    /// Number of SingleResponse entries — usually 1 for a TLS staple.
    pub single_responses_count: u32,

    /// First SingleResponse's cert_status. One of: `"good"`,
    /// `"revoked"`, `"unknown"`. `None` when no SingleResponse was
    /// parseable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_status: Option<String>,

    /// RevokedInfo.revocationTime — only populated when
    /// `cert_status == "revoked"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_time: Option<DateTime<Utc>>,

    /// RevokedInfo.revocationReason — canonical RFC 5280 §5.3.1 name
    /// (e.g. `"keyCompromise"`, `"unspecified"`), or
    /// `"crl_reason_<n>"` for unrecognized codes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<String>,

    /// SingleResponse.thisUpdate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub this_update: Option<DateTime<Utc>>,

    /// SingleResponse.nextUpdate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_update: Option<DateTime<Utc>>,

    /// CertID fields from the first SingleResponse.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_id: Option<OcspCertId>,
}

/// CertID identifies which certificate the status applies to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcspCertId {
    /// Hash algorithm OID used for the name / key hashes.
    pub hash_algorithm_oid: String,
    /// Lower-case hex of the issuer's subject DN hash.
    pub issuer_name_hash_hex: String,
    /// Lower-case hex of the issuer's public key hash.
    pub issuer_key_hash_hex: String,
    /// Serial number of the target certificate, lower-case hex
    /// (big-endian, unsigned).
    pub serial_number_hex: String,
}

/// Errors this parser surfaces. Consumers don't inspect the specific
/// variant; they just render the `Display` form for diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum OcspParseError {
    #[error("truncated or malformed DER: {0}")]
    BadDer(String),
    #[error("unexpected tag: expected {expected}, got {got}")]
    UnexpectedTag { expected: String, got: String },
    #[error("response_status byte missing")]
    NoStatus,
    #[error("BasicOCSPResponse contents not parseable")]
    BadBasicResponse,
}

const OID_ID_PKIX_OCSP_BASIC: &str = "1.3.6.1.5.5.7.48.1.1";

/// Parse a raw OCSP response.
///
/// Populates as much as the DER cleanly supports; fields that
/// aren't present or can't be parsed stay `None`. A top-level parse
/// error returns `Err`; partial success returns `Ok` with best-effort
/// fields.
pub fn parse(bytes: &[u8]) -> Result<OcspResponseContent, OcspParseError> {
    let (_, outer) = Any::from_der(bytes).map_err(|e| OcspParseError::BadDer(format!("{e}")))?;
    if outer.class() != Class::Universal || outer.tag() != Tag::Sequence {
        return Err(OcspParseError::UnexpectedTag {
            expected: "SEQUENCE (OCSPResponse)".to_string(),
            got: format!("{:?}/{:?}", outer.class(), outer.tag()),
        });
    }

    let inner = outer.data;
    // First child: responseStatus (ENUMERATED, universal tag 0x0a).
    let (rest, status_any) = Any::from_der(inner).map_err(|_| OcspParseError::NoStatus)?;
    if status_any.tag() != Tag::Enumerated || status_any.data.is_empty() {
        return Err(OcspParseError::NoStatus);
    }
    let status_byte = status_any.data[0];

    let mut out = OcspResponseContent {
        response_status: response_status_name(status_byte),
        ..Default::default()
    };

    // Second (optional) child: [0] EXPLICIT ResponseBytes.
    if rest.is_empty() {
        return Ok(out);
    }
    let (_, response_bytes_any) = match Any::from_der(rest) {
        Ok(v) => v,
        Err(_) => return Ok(out),
    };
    // [0] EXPLICIT means context-specific class, tag 0. The wrapped
    // ResponseBytes SEQUENCE is inside `.data`.
    if response_bytes_any.class() != Class::ContextSpecific {
        return Ok(out);
    }
    let (_, rb_seq) = match Any::from_der(response_bytes_any.data) {
        Ok(v) => v,
        Err(_) => return Ok(out),
    };
    if rb_seq.tag() != Tag::Sequence {
        return Ok(out);
    }

    // ResponseBytes: responseType OID, response OCTET STRING.
    let rb = rb_seq.data;
    let (rest_rb, oid_any) = match Any::from_der(rb) {
        Ok(v) => v,
        Err(_) => return Ok(out),
    };
    let (_, resp_oct) = match Any::from_der(rest_rb) {
        Ok(v) => v,
        Err(_) => return Ok(out),
    };
    // `oid_any.data` is the OID BODY (tag/length already stripped by
    // `Any::from_der`). asn1_rs's `Oid::from_der` expects full DER
    // (tag+length+body) — rather than reconstruct, we decode the body
    // directly into dotted-decimal form.
    let resp_oid = oid_body_to_dotted(oid_any.data);
    if resp_oid != OID_ID_PKIX_OCSP_BASIC {
        // Unknown responseType — we only know how to parse basic OCSP.
        return Ok(out);
    }
    if resp_oct.tag() != Tag::OctetString {
        return Ok(out);
    }

    // The OCTET STRING contains a DER-encoded BasicOCSPResponse.
    // On a partial-fill error, the `response_status` we already set
    // survives upstream along with the parse error.
    parse_basic_ocsp(resp_oct.data, &mut out)?;
    Ok(out)
}

/// Parse BasicOCSPResponse into `out`. Any field that can't be
/// parsed is left at its default.
fn parse_basic_ocsp(bytes: &[u8], out: &mut OcspResponseContent) -> Result<(), OcspParseError> {
    let (_, basic_seq) = Any::from_der(bytes).map_err(|_| OcspParseError::BadBasicResponse)?;
    if basic_seq.tag() != Tag::Sequence {
        return Err(OcspParseError::BadBasicResponse);
    }

    let body = basic_seq.data;
    // tbsResponseData (SEQUENCE)
    let (rest, tbs_any) = Any::from_der(body).map_err(|_| OcspParseError::BadBasicResponse)?;
    if tbs_any.tag() != Tag::Sequence {
        return Err(OcspParseError::BadBasicResponse);
    }
    parse_tbs_response_data(tbs_any.data, out);

    // signatureAlgorithm (AlgorithmIdentifier SEQUENCE { OID, params })
    if let Ok((_, sig_alg_any)) = Any::from_der(rest) {
        if sig_alg_any.tag() == Tag::Sequence {
            if let Ok((_, alg_oid_any)) = Any::from_der(sig_alg_any.data) {
                out.signature_algorithm_oid = Some(oid_body_to_dotted(alg_oid_any.data));
            }
        }
    }

    Ok(())
}

/// Parse ResponseData (the `tbsResponseData` inner of BasicOCSPResponse).
fn parse_tbs_response_data(bytes: &[u8], out: &mut OcspResponseContent) {
    let mut cursor = bytes;

    // Optional [0] EXPLICIT version — skip if present.
    if let Ok((rest, any)) = Any::from_der(cursor) {
        if any.class() == Class::ContextSpecific && any.tag().0 == 0 {
            cursor = rest;
        }
    }

    // responderID CHOICE [1] Name | [2] KeyHash
    if let Ok((rest, any)) = Any::from_der(cursor) {
        if any.class() == Class::ContextSpecific {
            match any.tag().0 {
                1 => {
                    // [1] EXPLICIT Name — best-effort stringification of
                    // the inner SEQUENCE OF RDN.
                    out.responder_id_by_name = Some(render_name(any.data));
                }
                2 => {
                    // [2] EXPLICIT KeyHash — inside is OCTET STRING.
                    if let Ok((_, octet)) = Any::from_der(any.data) {
                        if octet.tag() == Tag::OctetString {
                            out.responder_id_by_key = Some(hex::encode(octet.data));
                        } else {
                            // Some encoders use IMPLICIT tagging; treat data directly.
                            out.responder_id_by_key = Some(hex::encode(any.data));
                        }
                    }
                }
                _ => {}
            }
            cursor = rest;
        }
    }

    // producedAt (GeneralizedTime)
    if let Ok((rest, any)) = Any::from_der(cursor) {
        if any.tag() == Tag::GeneralizedTime {
            if let Ok((_, gt)) =
                GeneralizedTime::from_der(&raw_der_for(any.class(), any.tag(), any.data))
            {
                out.produced_at = generalized_time_to_chrono(&gt);
            } else {
                out.produced_at = parse_generalized_time_bytes(any.data);
            }
            cursor = rest;
        }
    }

    // responses SEQUENCE OF SingleResponse
    if let Ok((_, seq_any)) = Any::from_der(cursor) {
        if seq_any.tag() == Tag::Sequence {
            let mut single_cursor = seq_any.data;
            let mut first = true;
            while let Ok((rest, sr)) = Any::from_der(single_cursor) {
                if sr.tag() != Tag::Sequence {
                    break;
                }
                if first {
                    parse_single_response(sr.data, out);
                    first = false;
                }
                out.single_responses_count += 1;
                single_cursor = rest;
                if single_cursor.is_empty() {
                    break;
                }
            }
        }
    }
}

/// Parse the first SingleResponse, populating cert-level fields.
fn parse_single_response(bytes: &[u8], out: &mut OcspResponseContent) {
    let (rest, cert_id_any) = match Any::from_der(bytes) {
        Ok(v) => v,
        Err(_) => return,
    };
    if cert_id_any.tag() == Tag::Sequence {
        out.cert_id = parse_cert_id(cert_id_any.data);
    }

    let (rest, status_any) = match Any::from_der(rest) {
        Ok(v) => v,
        Err(_) => return,
    };
    // CertStatus is a CHOICE with IMPLICIT tags:
    //   [0] IMPLICIT NULL  = good
    //   [1] IMPLICIT SEQUENCE (RevokedInfo) = revoked
    //   [2] IMPLICIT SEQUENCE OR NULL = unknown
    if status_any.class() == Class::ContextSpecific {
        match status_any.tag().0 {
            0 => out.cert_status = Some("good".to_string()),
            1 => {
                out.cert_status = Some("revoked".to_string());
                parse_revoked_info(status_any.data, out);
            }
            2 => out.cert_status = Some("unknown".to_string()),
            _ => {}
        }
    }

    // thisUpdate (GeneralizedTime)
    let (rest, this_any) = match Any::from_der(rest) {
        Ok(v) => v,
        Err(_) => return,
    };
    if this_any.tag() == Tag::GeneralizedTime {
        out.this_update = parse_generalized_time_bytes(this_any.data);
    }

    // [0] EXPLICIT nextUpdate (optional)
    if let Ok((_, next_any)) = Any::from_der(rest) {
        if next_any.class() == Class::ContextSpecific && next_any.tag().0 == 0 {
            if let Ok((_, gt_any)) = Any::from_der(next_any.data) {
                if gt_any.tag() == Tag::GeneralizedTime {
                    out.next_update = parse_generalized_time_bytes(gt_any.data);
                }
            }
        }
    }
}

/// Parse RevokedInfo { revocationTime, [0] EXPLICIT crlReason OPTIONAL }.
fn parse_revoked_info(bytes: &[u8], out: &mut OcspResponseContent) {
    let (rest, time_any) = match Any::from_der(bytes) {
        Ok(v) => v,
        Err(_) => return,
    };
    if time_any.tag() == Tag::GeneralizedTime {
        out.revocation_time = parse_generalized_time_bytes(time_any.data);
    }
    if let Ok((_, reason_any)) = Any::from_der(rest) {
        if reason_any.class() == Class::ContextSpecific && reason_any.tag().0 == 0 {
            if let Ok((_, inner)) = Any::from_der(reason_any.data) {
                if inner.tag() == Tag::Enumerated {
                    if let Some(&code) = inner.data.first() {
                        out.revocation_reason = Some(crl_reason_name(code));
                    }
                }
            }
        }
    }
}

fn parse_cert_id(bytes: &[u8]) -> Option<OcspCertId> {
    // CertID: hashAlgorithm AlgorithmIdentifier, issuerNameHash OCTET
    // STRING, issuerKeyHash OCTET STRING, serialNumber INTEGER.
    let (rest, alg_any) = Any::from_der(bytes).ok()?;
    if alg_any.tag() != Tag::Sequence {
        return None;
    }
    let (_, alg_oid_any) = Any::from_der(alg_any.data).ok()?;
    let hash_algorithm_oid = oid_body_to_dotted(alg_oid_any.data);

    let (rest, name_hash) = match Any::from_der(rest) {
        Ok(v) => v,
        Err(_) => return None,
    };
    if name_hash.tag() != Tag::OctetString {
        return None;
    }
    let issuer_name_hash_hex = hex::encode(name_hash.data);

    let (rest, key_hash) = match Any::from_der(rest) {
        Ok(v) => v,
        Err(_) => return None,
    };
    if key_hash.tag() != Tag::OctetString {
        return None;
    }
    let issuer_key_hash_hex = hex::encode(key_hash.data);

    let (_, serial_any) = match Any::from_der(rest) {
        Ok(v) => v,
        Err(_) => return None,
    };
    if serial_any.tag() != Tag::Integer {
        return None;
    }
    // INTEGER data is raw twos-complement bytes. For display, strip a
    // leading 0x00 sign byte.
    let serial_bytes = if serial_any.data.first() == Some(&0x00) && serial_any.data.len() > 1 {
        &serial_any.data[1..]
    } else {
        serial_any.data
    };
    let serial_number_hex = hex::encode(serial_bytes);

    Some(OcspCertId {
        hash_algorithm_oid,
        issuer_name_hash_hex,
        issuer_key_hash_hex,
        serial_number_hex,
    })
}

fn raw_der_for(class: Class, tag: Tag, data: &[u8]) -> Vec<u8> {
    // Reconstruct a minimal DER encoding so sub-parsers that expect
    // header+body can consume it. Only supports short-form lengths;
    // OCSP timestamps fit comfortably.
    let class_bits = match class {
        Class::Universal => 0x00,
        Class::Application => 0x40,
        Class::ContextSpecific => 0x80,
        Class::Private => 0xc0,
    };
    let tag_byte = class_bits | (tag.0 as u8 & 0x1f);
    let mut out = Vec::with_capacity(2 + data.len());
    out.push(tag_byte);
    if data.len() < 0x80 {
        out.push(data.len() as u8);
    } else {
        // Long form — punt to two-byte length.
        out.push(0x82);
        out.push((data.len() >> 8) as u8);
        out.push(data.len() as u8);
    }
    out.extend_from_slice(data);
    out
}

fn generalized_time_to_chrono(gt: &GeneralizedTime) -> Option<DateTime<Utc>> {
    let utc = gt.utc_datetime().ok()?;
    DateTime::from_timestamp(utc.unix_timestamp(), 0)
}

/// Fallback GeneralizedTime parser — walks the raw bytes when
/// asn1-rs's typed parser rejects edge cases. Expects
/// `YYYYMMDDHHMMSS[.fff...]Z` per RFC 5280 §4.1.2.5.2.
fn parse_generalized_time_bytes(bytes: &[u8]) -> Option<DateTime<Utc>> {
    let s = std::str::from_utf8(bytes).ok()?.trim_end_matches('Z');
    // Strip optional fractional seconds — chrono's format handling
    // doesn't uniformly accept variable digits without explicit format.
    let (s, _frac) = s.split_once('.').unwrap_or((s, ""));
    if s.len() < 14 {
        return None;
    }
    let year: i32 = s.get(0..4)?.parse().ok()?;
    let month: u32 = s.get(4..6)?.parse().ok()?;
    let day: u32 = s.get(6..8)?.parse().ok()?;
    let hour: u32 = s.get(8..10)?.parse().ok()?;
    let minute: u32 = s.get(10..12)?.parse().ok()?;
    let second: u32 = s.get(12..14)?.parse().ok()?;
    chrono::NaiveDate::from_ymd_opt(year, month, day)?
        .and_hms_opt(hour, minute, second)
        .map(|ndt| ndt.and_utc())
}

/// Best-effort rendering of the Name inside [1] byName. The inner
/// structure is `RDNSequence` — for our purposes we stringify any
/// PrintableString / Utf8String we find, comma-joined.
fn render_name(bytes: &[u8]) -> String {
    let mut out = String::new();
    let Ok((_, seq)) = Any::from_der(bytes) else {
        return "<unparseable>".to_string();
    };
    let mut cursor = seq.data;
    while let Ok((rest, rdn_any)) = Any::from_der(cursor) {
        if let Ok((_, atv_set)) = Any::from_der(rdn_any.data) {
            if let Ok((_, atv)) = Any::from_der(atv_set.data) {
                let (rest_inner, _oid_any) = match Any::from_der(atv.data) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                if let Ok((_, value_any)) = Any::from_der(rest_inner) {
                    if let Ok(s) = std::str::from_utf8(value_any.data) {
                        if !out.is_empty() {
                            out.push(',');
                        }
                        out.push_str(s);
                    }
                }
            }
        }
        cursor = rest;
        if cursor.is_empty() {
            break;
        }
    }
    if out.is_empty() {
        "<empty>".to_string()
    } else {
        out
    }
}

/// Decode an OID body (BER contents, without the tag/length header)
/// into its dotted-decimal representation. Matches the canonical X.690
/// §8.19 encoding: first byte carries `40*X + Y` for the first two
/// subidentifiers (X ∈ {0,1,2}), remaining subidentifiers are
/// base-128 with a continuation bit.
fn oid_body_to_dotted(body: &[u8]) -> String {
    if body.is_empty() {
        return String::new();
    }
    let first = body[0];
    let (x, y) = if first >= 80 {
        (2u64, u64::from(first) - 80)
    } else {
        (u64::from(first / 40), u64::from(first % 40))
    };
    let mut parts: Vec<String> = vec![x.to_string(), y.to_string()];
    let mut acc: u64 = 0;
    for &b in &body[1..] {
        acc = (acc << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            parts.push(acc.to_string());
            acc = 0;
        }
    }
    parts.join(".")
}

fn response_status_name(code: u8) -> String {
    match code {
        0 => "successful".to_string(),
        1 => "malformedRequest".to_string(),
        2 => "internalError".to_string(),
        3 => "tryLater".to_string(),
        // 4 is undefined per RFC 6960.
        5 => "sigRequired".to_string(),
        6 => "unauthorized".to_string(),
        other => format!("unknown_{other}"),
    }
}

/// RFC 5280 §5.3.1 CRLReason codepoints.
fn crl_reason_name(code: u8) -> String {
    match code {
        0 => "unspecified".to_string(),
        1 => "keyCompromise".to_string(),
        2 => "cACompromise".to_string(),
        3 => "affiliationChanged".to_string(),
        4 => "superseded".to_string(),
        5 => "cessationOfOperation".to_string(),
        6 => "certificateHold".to_string(),
        8 => "removeFromCRL".to_string(),
        9 => "privilegeWithdrawn".to_string(),
        10 => "aACompromise".to_string(),
        other => format!("crl_reason_{other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_status_name_maps_rfc_codepoints() {
        assert_eq!(response_status_name(0), "successful");
        assert_eq!(response_status_name(1), "malformedRequest");
        assert_eq!(response_status_name(2), "internalError");
        assert_eq!(response_status_name(3), "tryLater");
        assert_eq!(response_status_name(5), "sigRequired");
        assert_eq!(response_status_name(6), "unauthorized");
        assert_eq!(response_status_name(42), "unknown_42");
    }

    #[test]
    fn crl_reason_name_maps_common_codes() {
        assert_eq!(crl_reason_name(0), "unspecified");
        assert_eq!(crl_reason_name(1), "keyCompromise");
        assert_eq!(crl_reason_name(4), "superseded");
        assert_eq!(crl_reason_name(11), "crl_reason_11");
    }

    #[test]
    fn parse_generalized_time_bytes_handles_standard_and_fractional() {
        let t = parse_generalized_time_bytes(b"20260420123456Z").expect("parse");
        assert_eq!(t.to_rfc3339(), "2026-04-20T12:34:56+00:00");
        let t = parse_generalized_time_bytes(b"20260420123456.789Z").expect("parse frac");
        assert_eq!(t.to_rfc3339(), "2026-04-20T12:34:56+00:00");
    }

    /// Synthesize a tiny successful OCSPResponse with no responseBytes
    /// and verify we still emit the status string.
    #[test]
    fn parse_status_only_response() {
        // SEQUENCE { ENUMERATED(0) } — responseStatus = successful.
        let der = &[0x30, 0x03, 0x0a, 0x01, 0x00];
        let out = parse(der).expect("parses");
        assert_eq!(out.response_status, "successful");
        assert_eq!(out.single_responses_count, 0);
        assert_eq!(out.cert_status, None);
    }

    #[test]
    fn parse_rejects_non_sequence_outer() {
        let der = &[0x0a, 0x01, 0x00]; // bare ENUMERATED
        assert!(parse(der).is_err());
    }

    #[test]
    fn parse_truncated_returns_err() {
        assert!(parse(&[]).is_err());
    }
}
