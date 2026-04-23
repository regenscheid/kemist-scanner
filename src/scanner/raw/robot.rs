//! Bleichenbacher / ROBOT differential probe.
//!
//! For each of five malformed PKCS#1 v1.5 ciphertexts, runs a fresh
//! TLS 1.2 handshake up through the server's `ServerHelloDone`,
//! extracts the leaf's RSA public key, RSA-encrypts a deliberately
//! malformed PreMasterSecret block, then sends
//! `ClientKeyExchange + ChangeCipherSpec + Finished-placeholder` and
//! classifies the server's response: alert category, TCP reset,
//! timeout, graceful close, or unexpected plaintext. The probe never
//! derives session keys correctly — the Finished placeholder is bytes
//! that won't pass the server's MAC check under any PMS. The
//! differential signal is in **how** the server rejects across the
//! five variants.
//!
//! The scanner records the 5-entry `per_variant` list. It never
//! renders an "oracle detected" boolean and never calls the target
//! "vulnerable" — downstream rule engines compare the variants.
//!
//! ## Variants (Hanno Böck test vector set, adapted)
//!
//! | Variant | Ciphertext shape |
//! |---|---|
//! | `correctly_formatted_pkcs1` | `0x00 0x02 <8+ non-zero padding> 0x00 <client_version=0x0303> <46 random>` (RFC 8017 EME-PKCS1-v1_5, legal) |
//! | `invalid_0x00_02_prefix` | First two bytes `0x00 0x17` instead of `0x00 0x02` |
//! | `invalid_version_0x00_02_byte_swap` | Prefix `0x02 0x00` (bytes transposed) |
//! | `null_separator_missing` | Padding terminator byte `0x00` replaced with a non-zero byte — no null separator |
//! | `wrong_tls_version_in_pms` | Legal PKCS#1 v1.5 envelope, but the `client_version` field inside the PMS is `0x0302` (TLS 1.1) instead of the offered `0x0303` |
//!
//! ## Gate
//!
//! The probe is driven from the outer scanner after the OpenSSL
//! cipher enumeration. It only runs when at least one `TLS_RSA_*`
//! suite was observed supported; otherwise the observation lands as
//! `method: "not_probed", reason: "no_rsa_kex_suite_supported"` and
//! `per_variant` is empty.
//!
//! ## Non-goals
//!
//! - No "vulnerable" boolean.
//! - No timing-signal interpretation beyond the per-variant
//!   `elapsed_ms`.
//! - No attempt to recover the server's RSA private key.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use openssl::pkey::Public;
use openssl::rand::rand_bytes;
use openssl::rsa::{Padding, Rsa};
use openssl::x509::X509;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::info;

use crate::model::scan_result::{BleichenbacherOracleProbe, Method, RobotVariantObservation};

/// TLS_RSA_WITH_AES_128_CBC_SHA — the suite the probe pins its
/// ClientHello to. CBC-SHA1 over RSA-kex is the classical ROBOT
/// target: stable record-layer shape, widely-still-implemented on
/// legacy-configured servers.
const CIPHER_SUITE_RSA_AES128_CBC_SHA: u16 = 0x002F;
const RSA_KEX_SUITE_NAME: &str = "TLS_RSA_WITH_AES_128_CBC_SHA";

/// Record content types (RFC 5246 §A.1).
const CT_CHANGE_CIPHER_SPEC: u8 = 0x14;
const CT_ALERT: u8 = 0x15;
const CT_HANDSHAKE: u8 = 0x16;

/// Handshake message types (RFC 5246 §A.4).
const HS_SERVER_HELLO: u8 = 0x02;
const HS_CERTIFICATE: u8 = 0x0B;
const HS_SERVER_HELLO_DONE: u8 = 0x0E;
const HS_CLIENT_KEY_EXCHANGE: u8 = 0x10;

/// Five-entry variant table. Order is stable; downstream rule
/// engines key on the `variant` string.
const VARIANTS: &[VariantKind] = &[
    VariantKind::CorrectlyFormattedPkcs1,
    VariantKind::Invalid0002Prefix,
    VariantKind::InvalidVersion0002ByteSwap,
    VariantKind::NullSeparatorMissing,
    VariantKind::WrongTlsVersionInPms,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VariantKind {
    CorrectlyFormattedPkcs1,
    Invalid0002Prefix,
    InvalidVersion0002ByteSwap,
    NullSeparatorMissing,
    WrongTlsVersionInPms,
}

impl VariantKind {
    fn name(self) -> &'static str {
        match self {
            Self::CorrectlyFormattedPkcs1 => "correctly_formatted_pkcs1",
            Self::Invalid0002Prefix => "invalid_0x00_02_prefix",
            Self::InvalidVersion0002ByteSwap => "invalid_version_0x00_02_byte_swap",
            Self::NullSeparatorMissing => "null_separator_missing",
            Self::WrongTlsVersionInPms => "wrong_tls_version_in_pms",
        }
    }
}

/// Outer entry point. `rsa_kex_supported` indicates whether an
/// earlier probe observed a `TLS_RSA_*` suite at `Supported`;
/// `false` skips the probe with the canonical reason string.
pub async fn probe(
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    rsa_kex_supported: bool,
) -> BleichenbacherOracleProbe {
    info!("ROBOT differential probe");

    if !rsa_kex_supported {
        return BleichenbacherOracleProbe {
            rsa_kex_suite_probed: None,
            method: Method::NotProbed,
            reason: Some("no_rsa_kex_suite_supported".to_string()),
            per_variant: Vec::new(),
        };
    }

    let mut per_variant = Vec::with_capacity(VARIANTS.len());
    for v in VARIANTS {
        let result = run_variant(
            *v,
            target,
            hostname,
            connect_timeout,
            handshake_timeout,
        )
        .await;
        per_variant.push(result);
    }

    BleichenbacherOracleProbe {
        rsa_kex_suite_probed: Some(RSA_KEX_SUITE_NAME.to_string()),
        method: Method::Probe,
        reason: None,
        per_variant,
    }
}

async fn run_variant(
    variant: VariantKind,
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> RobotVariantObservation {
    let start = Instant::now();
    let outcome = drive_variant(variant, target, hostname, connect_timeout, handshake_timeout).await;
    let elapsed_ms = start.elapsed().as_millis() as u64;

    match outcome {
        Outcome::Alert(cat) => RobotVariantObservation {
            variant: variant.name().to_string(),
            alert_category: Some(cat),
            tcp_reset: false,
            elapsed_ms,
            other_outcome: None,
        },
        Outcome::TcpReset => RobotVariantObservation {
            variant: variant.name().to_string(),
            alert_category: None,
            tcp_reset: true,
            elapsed_ms,
            other_outcome: None,
        },
        Outcome::Timeout => RobotVariantObservation {
            variant: variant.name().to_string(),
            alert_category: None,
            tcp_reset: false,
            elapsed_ms,
            other_outcome: Some("timeout".to_string()),
        },
        Outcome::GracefulClose => RobotVariantObservation {
            variant: variant.name().to_string(),
            alert_category: None,
            tcp_reset: false,
            elapsed_ms,
            other_outcome: Some("graceful_close".to_string()),
        },
        Outcome::UnexpectedPlaintext(s) => RobotVariantObservation {
            variant: variant.name().to_string(),
            alert_category: None,
            tcp_reset: false,
            elapsed_ms,
            other_outcome: Some(format!("unexpected_plaintext:{s}")),
        },
        Outcome::SetupError(s) => RobotVariantObservation {
            variant: variant.name().to_string(),
            alert_category: None,
            tcp_reset: false,
            elapsed_ms,
            other_outcome: Some(format!("setup_error:{s}")),
        },
    }
}

#[derive(Debug)]
enum Outcome {
    Alert(String),
    TcpReset,
    Timeout,
    GracefulClose,
    UnexpectedPlaintext(String),
    SetupError(String),
}

async fn drive_variant(
    variant: VariantKind,
    target: SocketAddr,
    hostname: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> Outcome {
    let mut stream = match timeout(connect_timeout, TcpStream::connect(&target)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Outcome::SetupError(format!("tcp_connect:{e}")),
        Err(_) => return Outcome::SetupError("tcp_connect_timeout".to_string()),
    };

    let (client_random, hello) = build_client_hello(hostname);
    if let Err(e) = stream.write_all(&hello).await {
        return Outcome::SetupError(format!("clienthello_send:{e}"));
    }

    // Read TLS records until we see ServerHelloDone (or hit an alert
    // or EOF). Aggregate the Certificate message body for RSA pubkey
    // extraction.
    let mut aggregated = Vec::new();
    let deadline = Instant::now() + handshake_timeout;
    let cert_msg: Option<Vec<u8>>;
    let mut saw_server_hello = false;

    loop {
        if Instant::now() >= deadline {
            return Outcome::SetupError("server_flight_timeout".to_string());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let mut buf = [0u8; 4096];
        let n = match timeout(remaining, stream.read(&mut buf)).await {
            Ok(Ok(0)) => {
                if !saw_server_hello {
                    return Outcome::GracefulClose;
                }
                return Outcome::SetupError("eof_before_server_hello_done".to_string());
            }
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                return Outcome::SetupError(format!("read_server_flight:{e}"));
            }
            Err(_) => return Outcome::SetupError("server_flight_timeout".to_string()),
        };
        aggregated.extend_from_slice(&buf[..n]);

        // Walk records accumulated so far. We don't remove consumed
        // bytes — we re-scan from the start each pass until
        // ServerHelloDone appears or an alert lands.
        match scan_server_flight(&aggregated) {
            ScanResult::Alert(cat) => return Outcome::Alert(cat),
            ScanResult::NeedMore => continue,
            ScanResult::Done {
                cert_message,
                server_hello_seen,
            } => {
                cert_msg = cert_message;
                saw_server_hello = server_hello_seen;
                break;
            }
            ScanResult::UnexpectedContentType(ct) => {
                return Outcome::UnexpectedPlaintext(format!("content_type_0x{ct:02x}"));
            }
        }
    }

    let _ = saw_server_hello;
    let Some(cert_msg) = cert_msg else {
        return Outcome::SetupError("no_certificate_message".to_string());
    };
    let leaf_der = match extract_leaf_der(&cert_msg) {
        Some(d) => d,
        None => return Outcome::SetupError("certificate_list_parse_failed".to_string()),
    };
    let rsa = match rsa_from_leaf_der(&leaf_der) {
        Ok(k) => k,
        Err(s) => return Outcome::SetupError(format!("rsa_from_leaf:{s}")),
    };
    let modulus_bytes = rsa.size() as usize;

    // Build the PKCS#1 v1.5 plaintext for this variant, encrypt
    // (Padding::NONE so we control every byte), and wrap in CKE +
    // CCS + Finished-placeholder records.
    let plaintext = build_variant_plaintext(variant, modulus_bytes);
    let mut ciphertext = vec![0u8; modulus_bytes];
    if let Err(e) = rsa.public_encrypt(&plaintext, &mut ciphertext, Padding::NONE) {
        return Outcome::SetupError(format!("rsa_public_encrypt:{e}"));
    }
    let _ = client_random; // client_random only matters if we were deriving keys; not needed here.

    let cke_record = build_cke_record(&ciphertext);
    let ccs_record = build_ccs_record();
    let finished_placeholder = build_finished_placeholder();

    // Send all three records back-to-back.
    if let Err(e) = stream.write_all(&cke_record).await {
        return classify_post_cke_io_err(e);
    }
    if let Err(e) = stream.write_all(&ccs_record).await {
        return classify_post_cke_io_err(e);
    }
    if let Err(e) = stream.write_all(&finished_placeholder).await {
        return classify_post_cke_io_err(e);
    }

    // Now classify the server's response. Give it up to
    // handshake_timeout to send something (alert, FIN, or RST).
    classify_server_response(&mut stream, handshake_timeout).await
}

fn classify_post_cke_io_err(e: std::io::Error) -> Outcome {
    if e.kind() == std::io::ErrorKind::ConnectionReset {
        Outcome::TcpReset
    } else if e.kind() == std::io::ErrorKind::BrokenPipe {
        // Peer closed mid-write — treat as graceful close; downstream
        // sees `graceful_close` and differentiates from alert.
        Outcome::GracefulClose
    } else {
        Outcome::SetupError(format!("post_cke_write:{e}"))
    }
}

async fn classify_server_response(
    stream: &mut TcpStream,
    wait_for: Duration,
) -> Outcome {
    let mut buf = [0u8; 4096];
    match timeout(wait_for, stream.read(&mut buf)).await {
        Ok(Ok(0)) => Outcome::GracefulClose,
        Ok(Ok(n)) => {
            let data = &buf[..n];
            if data.len() < 5 {
                return Outcome::UnexpectedPlaintext(format!("truncated_reply:{}b", data.len()));
            }
            match data[0] {
                CT_ALERT => {
                    if data.len() >= 7 {
                        let desc = data[6];
                        Outcome::Alert(alert_category_for(desc))
                    } else {
                        Outcome::Alert("tls_alert_truncated".to_string())
                    }
                }
                CT_HANDSHAKE => Outcome::UnexpectedPlaintext("handshake_record".to_string()),
                other => {
                    Outcome::UnexpectedPlaintext(format!("content_type_0x{other:02x}"))
                }
            }
        }
        Ok(Err(e)) => {
            if e.kind() == std::io::ErrorKind::ConnectionReset {
                Outcome::TcpReset
            } else {
                Outcome::SetupError(format!("read_post_cke:{e}"))
            }
        }
        Err(_) => Outcome::Timeout,
    }
}

/// Render a TLS alert description byte as `tls_alert_<name>`.
/// Unknown codes render as `tls_alert_0xNN`. Same taxonomy as
/// `scanner::backends::openssl::alerts`.
fn alert_category_for(desc: u8) -> String {
    match desc {
        0 => "tls_alert_close_notify".to_string(),
        10 => "tls_alert_unexpected_message".to_string(),
        20 => "tls_alert_bad_record_mac".to_string(),
        21 => "tls_alert_decryption_failed".to_string(),
        22 => "tls_alert_record_overflow".to_string(),
        30 => "tls_alert_decompression_failure".to_string(),
        40 => "tls_alert_handshake_failure".to_string(),
        41 => "tls_alert_no_certificate".to_string(),
        42 => "tls_alert_bad_certificate".to_string(),
        43 => "tls_alert_unsupported_certificate".to_string(),
        44 => "tls_alert_certificate_revoked".to_string(),
        45 => "tls_alert_certificate_expired".to_string(),
        46 => "tls_alert_certificate_unknown".to_string(),
        47 => "tls_alert_illegal_parameter".to_string(),
        48 => "tls_alert_unknown_ca".to_string(),
        49 => "tls_alert_access_denied".to_string(),
        50 => "tls_alert_decode_error".to_string(),
        51 => "tls_alert_decrypt_error".to_string(),
        70 => "tls_alert_protocol_version".to_string(),
        71 => "tls_alert_insufficient_security".to_string(),
        80 => "tls_alert_internal_error".to_string(),
        86 => "tls_alert_inappropriate_fallback".to_string(),
        90 => "tls_alert_user_canceled".to_string(),
        100 => "tls_alert_no_renegotiation".to_string(),
        109 => "tls_alert_missing_extension".to_string(),
        110 => "tls_alert_unsupported_extension".to_string(),
        112 => "tls_alert_unrecognized_name".to_string(),
        113 => "tls_alert_bad_certificate_status_response".to_string(),
        115 => "tls_alert_unknown_psk_identity".to_string(),
        116 => "tls_alert_certificate_required".to_string(),
        120 => "tls_alert_no_application_protocol".to_string(),
        other => format!("tls_alert_0x{other:02x}"),
    }
}

enum ScanResult {
    NeedMore,
    Alert(String),
    Done {
        cert_message: Option<Vec<u8>>,
        server_hello_seen: bool,
    },
    UnexpectedContentType(u8),
}

/// Scan the accumulated server-flight bytes for records. Returns
/// once we see ServerHelloDone, an alert, or an unexpected content
/// type.
fn scan_server_flight(bytes: &[u8]) -> ScanResult {
    let mut i = 0usize;
    let mut cert_message: Option<Vec<u8>> = None;
    let mut server_hello_seen = false;

    while i + 5 <= bytes.len() {
        let ct = bytes[i];
        let rec_len = u16::from_be_bytes([bytes[i + 3], bytes[i + 4]]) as usize;
        let rec_end = i + 5 + rec_len;
        if rec_end > bytes.len() {
            return ScanResult::NeedMore;
        }
        let rec_body = &bytes[i + 5..rec_end];
        match ct {
            CT_ALERT => {
                if rec_body.len() >= 2 {
                    return ScanResult::Alert(alert_category_for(rec_body[1]));
                }
                return ScanResult::Alert("tls_alert_truncated".to_string());
            }
            CT_HANDSHAKE => {
                // A record may contain multiple handshake messages;
                // walk the handshake header chain within rec_body.
                let mut j = 0usize;
                while j + 4 <= rec_body.len() {
                    let hs_type = rec_body[j];
                    let hs_len = ((rec_body[j + 1] as usize) << 16)
                        | ((rec_body[j + 2] as usize) << 8)
                        | (rec_body[j + 3] as usize);
                    let hs_end = j + 4 + hs_len;
                    if hs_end > rec_body.len() {
                        break;
                    }
                    match hs_type {
                        HS_SERVER_HELLO => {
                            server_hello_seen = true;
                        }
                        HS_CERTIFICATE => {
                            cert_message = Some(rec_body[j..hs_end].to_vec());
                        }
                        HS_SERVER_HELLO_DONE => {
                            return ScanResult::Done {
                                cert_message,
                                server_hello_seen,
                            };
                        }
                        _ => {}
                    }
                    j = hs_end;
                }
            }
            CT_CHANGE_CIPHER_SPEC => {
                // Unexpected at this point — server shouldn't send
                // CCS before ServerHelloDone in TLS 1.2.
                return ScanResult::UnexpectedContentType(ct);
            }
            _ => return ScanResult::UnexpectedContentType(ct),
        }
        i = rec_end;
    }
    ScanResult::NeedMore
}

/// Extract the leaf DER from a Certificate handshake message body.
/// Layout (RFC 5246 §7.4.2):
///   msg_type(1) + hs_len(3) + cert_list_len(3) + [ cert_len(3) + cert_der ]+
fn extract_leaf_der(cert_msg: &[u8]) -> Option<Vec<u8>> {
    if cert_msg.len() < 4 + 3 + 3 {
        return None;
    }
    let cert_list_len =
        ((cert_msg[4] as usize) << 16) | ((cert_msg[5] as usize) << 8) | (cert_msg[6] as usize);
    let list_start = 7;
    if list_start + cert_list_len > cert_msg.len() {
        return None;
    }
    // First entry in the list is the leaf.
    if cert_list_len < 3 {
        return None;
    }
    let cert_len = ((cert_msg[list_start] as usize) << 16)
        | ((cert_msg[list_start + 1] as usize) << 8)
        | (cert_msg[list_start + 2] as usize);
    let leaf_start = list_start + 3;
    let leaf_end = leaf_start + cert_len;
    if leaf_end > cert_msg.len() {
        return None;
    }
    Some(cert_msg[leaf_start..leaf_end].to_vec())
}

fn rsa_from_leaf_der(leaf_der: &[u8]) -> Result<Rsa<Public>, String> {
    let cert = X509::from_der(leaf_der).map_err(|e| format!("x509_parse:{e}"))?;
    let pkey = cert
        .public_key()
        .map_err(|e| format!("x509_pubkey:{e}"))?;
    let rsa = pkey
        .rsa()
        .map_err(|_| "leaf_pubkey_not_rsa".to_string())?;
    Ok(rsa)
}

/// Build a `modulus_bytes`-long plaintext to feed to
/// `RSA_public_encrypt(Padding::NONE)`. `modulus_bytes` is typically
/// 256 (RSA-2048) or 384 (RSA-3072).
fn build_variant_plaintext(variant: VariantKind, modulus_bytes: usize) -> Vec<u8> {
    // The 48-byte PreMasterSecret (RFC 5246 §7.4.7.1): 2-byte
    // client_version + 46-byte random.
    const PMS_LEN: usize = 48;
    let mut pms = [0u8; PMS_LEN];
    pms[0] = 0x03;
    pms[1] = 0x03; // TLS 1.2 — what we offered in ClientHello
    let _ = rand_bytes(&mut pms[2..]);

    // Start with a well-formed EME-PKCS1-v1_5 envelope filling the
    // whole modulus:
    //   0x00 0x02 <PS: non-zero, modulus_bytes-PMS_LEN-3 bytes> 0x00 <pms>
    let ps_len = modulus_bytes
        .checked_sub(PMS_LEN + 3)
        .expect("modulus too small for PKCS#1 v1.5 envelope");
    let mut padding = vec![0u8; ps_len];
    // Fill with non-zero random bytes (RFC 8017 §7.2.1).
    for b in padding.iter_mut() {
        loop {
            let mut one = [0u8];
            let _ = rand_bytes(&mut one);
            if one[0] != 0 {
                *b = one[0];
                break;
            }
        }
    }

    let mut out = Vec::with_capacity(modulus_bytes);
    out.push(0x00);
    out.push(0x02);
    out.extend_from_slice(&padding);
    out.push(0x00);
    out.extend_from_slice(&pms);

    match variant {
        VariantKind::CorrectlyFormattedPkcs1 => {
            // No mutation — the envelope above is already legal.
        }
        VariantKind::Invalid0002Prefix => {
            out[1] = 0x17; // second byte no longer 0x02
        }
        VariantKind::InvalidVersion0002ByteSwap => {
            out[0] = 0x02;
            out[1] = 0x00;
        }
        VariantKind::NullSeparatorMissing => {
            // The 0x00 terminator sits at index (ps_len + 2) in the
            // full plaintext. Replace with a non-zero byte.
            let sep_idx = 2 + ps_len;
            out[sep_idx] = 0xFF;
        }
        VariantKind::WrongTlsVersionInPms => {
            // `client_version` field within the PMS is the first two
            // bytes after the separator.
            let pms_start = 3 + ps_len;
            out[pms_start] = 0x03;
            out[pms_start + 1] = 0x02; // TLS 1.1 instead of 1.2
        }
    }

    debug_assert_eq!(out.len(), modulus_bytes);
    out
}

/// Build the ClientKeyExchange record wrapping the RSA ciphertext.
/// Layout: record(5) + handshake(4) + encrypted_pms_len(2) + ciphertext.
fn build_cke_record(ciphertext: &[u8]) -> Vec<u8> {
    let hs_body_len = 2 + ciphertext.len(); // uint16 length prefix + ciphertext
    let mut hs = Vec::with_capacity(4 + hs_body_len);
    hs.push(HS_CLIENT_KEY_EXCHANGE);
    hs.push(((hs_body_len >> 16) & 0xff) as u8);
    hs.push(((hs_body_len >> 8) & 0xff) as u8);
    hs.push((hs_body_len & 0xff) as u8);
    hs.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
    hs.extend_from_slice(ciphertext);

    let mut rec = Vec::with_capacity(5 + hs.len());
    rec.push(CT_HANDSHAKE);
    rec.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// ChangeCipherSpec record: content_type + version + length(1) + value(0x01).
fn build_ccs_record() -> Vec<u8> {
    vec![CT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01]
}

/// Finished-placeholder record. Under CBC, a real Finished record
/// would be: 16-byte IV + AES-CBC(MAC(plaintext)). We emit 16 + 48
/// bytes of zeros inside a handshake record — right content type,
/// plausible length for TLS_RSA_WITH_AES_128_CBC_SHA, guaranteed
/// MAC failure regardless of the PMS the server derived. The
/// differential signal across variants comes from whether the
/// server rejected earlier (at CKE) or at the MAC check here.
fn build_finished_placeholder() -> Vec<u8> {
    // TLS_RSA_WITH_AES_128_CBC_SHA: explicit IV(16) + ciphertext
    // aligned to block(16). Finished handshake plaintext is 16
    // bytes (type + length + 12-byte verify_data) + 20-byte SHA-1
    // MAC + PKCS#7 padding to block boundary = 48 ciphertext bytes.
    let body_len = 16 + 48;
    let mut rec = Vec::with_capacity(5 + body_len);
    rec.push(CT_HANDSHAKE);
    rec.extend_from_slice(&[0x03, 0x03]);
    rec.extend_from_slice(&(body_len as u16).to_be_bytes());
    rec.resize(rec.len() + body_len, 0x00);
    rec
}

/// Minimal TLS 1.2 ClientHello pinning cipher suite
/// `TLS_RSA_WITH_AES_128_CBC_SHA`. Compatibility extensions present
/// so CDNs don't drop the connection as unparseable.
fn build_client_hello(hostname: &str) -> ([u8; 32], Vec<u8>) {
    let mut client_random = [0u8; 32];
    let _ = rand_bytes(&mut client_random);

    let mut exts: Vec<u8> = Vec::new();

    // SNI
    let host = hostname.as_bytes();
    let mut sni_body = Vec::with_capacity(host.len() + 5);
    sni_body.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
    sni_body.push(0x00); // name_type = host_name
    sni_body.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni_body.extend_from_slice(host);
    exts.extend_from_slice(&0x0000u16.to_be_bytes());
    exts.extend_from_slice(&(sni_body.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sni_body);

    // signature_algorithms (ext 13) — common RSA/ECDSA schemes. We
    // offer the canonical modern set; doesn't affect the ROBOT
    // observation since the server signs with RSA-kex and we don't
    // verify.
    let sigalgs: [u8; 20] = [
        0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08,
        0x06, 0x06, 0x01, 0x02, 0x01,
    ];
    exts.extend_from_slice(&0x000du16.to_be_bytes());
    exts.extend_from_slice(&(sigalgs.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sigalgs);

    // supported_versions (ext 43) pinned to TLS 1.2 — we can't
    // probe TLS 1.3 for an RSA-kex oracle, and TLS 1.3 doesn't
    // offer ext-0x0022-tier suites anyway.
    exts.extend_from_slice(&0x002bu16.to_be_bytes());
    exts.extend_from_slice(&3u16.to_be_bytes());
    exts.push(0x02);
    exts.push(0x03);
    exts.push(0x03);

    // cipher_suites: pinned TLS_RSA_WITH_AES_128_CBC_SHA + SCSV.
    let cipher_suites: [u8; 4] = [
        (CIPHER_SUITE_RSA_AES128_CBC_SHA >> 8) as u8,
        (CIPHER_SUITE_RSA_AES128_CBC_SHA & 0xff) as u8,
        0x00,
        0xff,
    ];

    let mut hello = Vec::new();
    hello.extend_from_slice(&[0x03, 0x03]); // client_version = TLS 1.2
    hello.extend_from_slice(&client_random);
    hello.push(0x00); // session_id length
    hello.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
    hello.extend_from_slice(&cipher_suites);
    hello.push(0x01); // compression_methods length
    hello.push(0x00); // null compression
    hello.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    hello.extend_from_slice(&exts);

    let mut handshake = Vec::with_capacity(hello.len() + 4);
    handshake.push(0x01); // ClientHello
    let len = hello.len();
    handshake.push((len >> 16) as u8);
    handshake.push((len >> 8) as u8);
    handshake.push(len as u8);
    handshake.extend_from_slice(&hello);

    let mut record = Vec::with_capacity(handshake.len() + 5);
    record.push(CT_HANDSHAKE);
    record.extend_from_slice(&[0x03, 0x01]); // record layer version = TLS 1.0 (max-compat)
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    (client_random, record)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOD_BYTES: usize = 256; // RSA-2048

    #[test]
    fn variants_covers_five_canonical_cases() {
        assert_eq!(VARIANTS.len(), 5);
        let names: Vec<&str> = VARIANTS.iter().map(|v| v.name()).collect();
        assert_eq!(
            names,
            vec![
                "correctly_formatted_pkcs1",
                "invalid_0x00_02_prefix",
                "invalid_version_0x00_02_byte_swap",
                "null_separator_missing",
                "wrong_tls_version_in_pms",
            ]
        );
    }

    #[test]
    fn correct_pkcs1_variant_has_canonical_prefix_and_separator() {
        let p = build_variant_plaintext(VariantKind::CorrectlyFormattedPkcs1, MOD_BYTES);
        assert_eq!(p.len(), MOD_BYTES);
        assert_eq!(p[0], 0x00);
        assert_eq!(p[1], 0x02);
        // Padding bytes (indices 2..MOD_BYTES-49) must all be non-zero.
        for (idx, &b) in p[2..MOD_BYTES - 49].iter().enumerate() {
            assert_ne!(b, 0x00, "padding byte {idx} was zero");
        }
        // Separator at MOD_BYTES-49 = 0x00.
        assert_eq!(p[MOD_BYTES - 49], 0x00);
        // PMS client_version = 0x0303 (TLS 1.2).
        assert_eq!(p[MOD_BYTES - 48], 0x03);
        assert_eq!(p[MOD_BYTES - 47], 0x03);
    }

    #[test]
    fn invalid_0x00_02_prefix_variant_has_wrong_second_byte() {
        let p = build_variant_plaintext(VariantKind::Invalid0002Prefix, MOD_BYTES);
        assert_eq!(p[0], 0x00);
        assert_eq!(p[1], 0x17);
    }

    #[test]
    fn byte_swap_variant_has_transposed_prefix() {
        let p = build_variant_plaintext(VariantKind::InvalidVersion0002ByteSwap, MOD_BYTES);
        assert_eq!(p[0], 0x02);
        assert_eq!(p[1], 0x00);
    }

    #[test]
    fn null_separator_missing_variant_replaces_separator() {
        let p = build_variant_plaintext(VariantKind::NullSeparatorMissing, MOD_BYTES);
        // Separator slot was overwritten — no zero byte between
        // padding and PMS.
        assert_eq!(p[MOD_BYTES - 49], 0xFF);
    }

    #[test]
    fn wrong_tls_version_in_pms_variant_flips_pms_version() {
        let p = build_variant_plaintext(VariantKind::WrongTlsVersionInPms, MOD_BYTES);
        // Envelope still legal.
        assert_eq!(p[0], 0x00);
        assert_eq!(p[1], 0x02);
        assert_eq!(p[MOD_BYTES - 49], 0x00);
        // PMS client_version = 0x0302.
        assert_eq!(p[MOD_BYTES - 48], 0x03);
        assert_eq!(p[MOD_BYTES - 47], 0x02);
    }

    #[test]
    fn alert_category_maps_known_descriptions() {
        assert_eq!(alert_category_for(20), "tls_alert_bad_record_mac");
        assert_eq!(alert_category_for(40), "tls_alert_handshake_failure");
        assert_eq!(alert_category_for(50), "tls_alert_decode_error");
        assert_eq!(alert_category_for(51), "tls_alert_decrypt_error");
        assert_eq!(alert_category_for(70), "tls_alert_protocol_version");
    }

    #[test]
    fn alert_category_unknown_renders_hex() {
        assert_eq!(alert_category_for(0xAB), "tls_alert_0xab");
    }

    #[test]
    fn ccs_record_shape() {
        let ccs = build_ccs_record();
        assert_eq!(ccs, vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    }

    #[test]
    fn cke_record_shape_wraps_ciphertext() {
        let ct = vec![0xAA; 256];
        let rec = build_cke_record(&ct);
        assert_eq!(rec[0], CT_HANDSHAKE);
        assert_eq!(&rec[1..3], &[0x03, 0x03]);
        let rec_len = u16::from_be_bytes([rec[3], rec[4]]) as usize;
        assert_eq!(rec_len, rec.len() - 5);
        assert_eq!(rec[5], HS_CLIENT_KEY_EXCHANGE);
        let ct_len = u16::from_be_bytes([rec[9], rec[10]]) as usize;
        assert_eq!(ct_len, 256);
    }

    #[test]
    fn client_hello_framing_valid() {
        let (_, ch) = build_client_hello("example.com");
        assert_eq!(ch[0], CT_HANDSHAKE);
        let rec_len = u16::from_be_bytes([ch[3], ch[4]]) as usize;
        assert_eq!(rec_len, ch.len() - 5);
        assert_eq!(ch[5], 0x01); // ClientHello
        // Cipher suite 0x002F should appear somewhere in the record.
        let mut found = false;
        for w in ch.windows(4) {
            if w[0] == 0x00 && w[1] == 0x2f && w[2] == 0x00 && w[3] == 0xff {
                found = true;
                break;
            }
        }
        assert!(found, "cipher suite 0x002F + SCSV must appear in ClientHello");
    }

    #[test]
    fn extract_leaf_from_well_formed_cert_message() {
        let leaf: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let cert_len = leaf.len();
        let list_len = 3 + cert_len;
        let mut msg = Vec::new();
        msg.push(HS_CERTIFICATE);
        let hs_len = 3 + list_len; // list_len(3) + list bytes
        msg.push(((hs_len >> 16) & 0xff) as u8);
        msg.push(((hs_len >> 8) & 0xff) as u8);
        msg.push((hs_len & 0xff) as u8);
        msg.push(((list_len >> 16) & 0xff) as u8);
        msg.push(((list_len >> 8) & 0xff) as u8);
        msg.push((list_len & 0xff) as u8);
        msg.push(((cert_len >> 16) & 0xff) as u8);
        msg.push(((cert_len >> 8) & 0xff) as u8);
        msg.push((cert_len & 0xff) as u8);
        msg.extend_from_slice(&leaf);

        let parsed = extract_leaf_der(&msg).expect("leaf extracted");
        assert_eq!(parsed, leaf);
    }

    #[test]
    fn extract_leaf_handles_truncated_list() {
        // Truncated: claims list_len=100 but body is empty.
        let mut msg = Vec::new();
        msg.push(HS_CERTIFICATE);
        msg.extend_from_slice(&[0x00, 0x00, 0x03]);
        msg.extend_from_slice(&[0x00, 0x00, 0x64]);
        assert!(extract_leaf_der(&msg).is_none());
    }
}
