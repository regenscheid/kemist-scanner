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

use openssl::hash::{Hasher, MessageDigest};
use openssl::pkey::{PKey, Public};
use openssl::rand::rand_bytes;
use openssl::rsa::{Padding, Rsa};
use openssl::sign::Signer;
use openssl::symm::{Cipher, Crypter, Mode};
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
const HS_FINISHED: u8 = 0x14;

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

    let (client_random, hello_record, client_hello_hs) = build_client_hello(hostname);
    if let Err(e) = stream.write_all(&hello_record).await {
        return Outcome::SetupError(format!("clienthello_send:{e}"));
    }

    // Transcript accumulator for the Finished hash. ClientHello
    // (handshake layer only) goes in first; server messages are
    // appended inside scan_server_flight's Done branch; CKE goes in
    // last before we compute the hash.
    let mut transcript: Vec<u8> = Vec::new();
    transcript.extend_from_slice(&client_hello_hs);

    let mut aggregated = Vec::new();
    let deadline = Instant::now() + handshake_timeout;
    let cert_msg: Option<Vec<u8>>;
    let server_random: [u8; 32];

    loop {
        if Instant::now() >= deadline {
            return Outcome::SetupError("server_flight_timeout".to_string());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let mut buf = [0u8; 4096];
        let n = match timeout(remaining, stream.read(&mut buf)).await {
            Ok(Ok(0)) => {
                if aggregated.is_empty() {
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

        match scan_server_flight(&aggregated) {
            ScanResult::Alert(cat) => return Outcome::Alert(cat),
            ScanResult::NeedMore => continue,
            ScanResult::Done {
                cert_message,
                server_random: sr,
                server_handshake_transcript,
            } => {
                cert_msg = cert_message;
                match sr {
                    Some(r) => server_random = r,
                    None => return Outcome::SetupError("server_hello_random_unparsed".to_string()),
                }
                transcript.extend_from_slice(&server_handshake_transcript);
                break;
            }
            ScanResult::UnexpectedContentType(ct) => {
                return Outcome::UnexpectedPlaintext(format!("content_type_0x{ct:02x}"));
            }
        }
    }

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
    if modulus_bytes < 64 {
        // EME-PKCS1-v1_5 requires at least 11 padding bytes + 3
        // framing bytes + PMS(48) = 62 bytes minimum. Anything
        // smaller isn't a realistic server and we'd build invalid
        // bytes below.
        return Outcome::SetupError(format!("rsa_modulus_too_small:{modulus_bytes}"));
    }

    let payload = build_variant_payload(variant, modulus_bytes);
    let mut ciphertext = vec![0u8; modulus_bytes];
    if let Err(e) = rsa.public_encrypt(&payload.full_plaintext, &mut ciphertext, Padding::NONE) {
        return Outcome::SetupError(format!("rsa_public_encrypt:{e}"));
    }

    let (cke_record, cke_hs) = build_cke_record(&ciphertext);
    transcript.extend_from_slice(&cke_hs);

    // Derive session keys from the variant's intended PMS.
    // For variant 1 (correct), this matches the server's keys
    // exactly — Finished verifies and the server proceeds. For
    // variants 2–5 the server's decryption diverges from ours, so
    // the Finished MAC fails on the server side and we observe the
    // resulting alert.
    let master_secret = derive_master_secret(&payload.pms, &client_random, &server_random);
    let client_keys = derive_client_keys(&master_secret, &client_random, &server_random);
    let finished_record = build_finished_record(
        &master_secret,
        &client_keys.mac_key,
        &client_keys.enc_key,
        &transcript,
    );

    let ccs_record = build_ccs_record();
    if let Err(e) = stream.write_all(&cke_record).await {
        return classify_post_cke_io_err(e);
    }
    if let Err(e) = stream.write_all(&ccs_record).await {
        return classify_post_cke_io_err(e);
    }
    if let Err(e) = stream.write_all(&finished_record).await {
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
        server_random: Option<[u8; 32]>,
        /// Concatenated handshake-layer bytes (with 4-byte hs
        /// headers, without record-layer framing) for every server
        /// handshake message seen up to and including
        /// ServerHelloDone. Fed into the Finished transcript hash.
        server_handshake_transcript: Vec<u8>,
    },
    UnexpectedContentType(u8),
}

/// Scan the accumulated server-flight bytes for records. Returns
/// once we see ServerHelloDone, an alert, or an unexpected content
/// type.
fn scan_server_flight(bytes: &[u8]) -> ScanResult {
    let mut i = 0usize;
    let mut cert_message: Option<Vec<u8>> = None;
    let mut server_random: Option<[u8; 32]> = None;
    let mut transcript: Vec<u8> = Vec::new();

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
                    // Every handshake message goes into the
                    // transcript, in wire order.
                    transcript.extend_from_slice(&rec_body[j..hs_end]);
                    match hs_type {
                        HS_SERVER_HELLO => {
                            // ServerHello body = version(2) +
                            // random(32) + …
                            if hs_end - (j + 4) >= 34 {
                                let r_start = j + 4 + 2;
                                let mut sr = [0u8; 32];
                                sr.copy_from_slice(&rec_body[r_start..r_start + 32]);
                                server_random = Some(sr);
                            }
                        }
                        HS_CERTIFICATE => {
                            cert_message = Some(rec_body[j..hs_end].to_vec());
                        }
                        HS_SERVER_HELLO_DONE => {
                            return ScanResult::Done {
                                cert_message,
                                server_random,
                                server_handshake_transcript: transcript,
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

/// Intended 48-byte PMS the scanner *would* derive keys from on
/// behalf of this variant, plus the full modulus-sized RSA-encryption
/// input. A well-configured server that decrypts the ciphertext to
/// our plaintext extracts exactly `pms` from the last 48 bytes.
struct VariantPayload {
    full_plaintext: Vec<u8>,
    pms: [u8; 48],
}

/// Build a `modulus_bytes`-long plaintext to feed to
/// `RSA_public_encrypt(Padding::NONE)`. `modulus_bytes` is typically
/// 256 (RSA-2048) or 384 (RSA-3072). Also returns the 48-byte PMS
/// so the caller can derive session keys for the correct-variant
/// case (where the server's key derivation matches ours).
fn build_variant_payload(variant: VariantKind, modulus_bytes: usize) -> VariantPayload {
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

    // The PMS a correct server will extract is the last 48 bytes of
    // our plaintext — that's what RFC 5246 §7.4.7.1 unwraps after
    // padding validation. For variants 2–4 (broken padding) the
    // server will substitute a random PMS internally per the
    // Bleichenbacher countermeasure, so our derived keys won't match
    // the server's. For variant 5 (wrong PMS version) compliance
    // varies by implementation. Those are exactly the divergences
    // the per-variant observation surfaces.
    let mut extracted_pms = [0u8; PMS_LEN];
    extracted_pms.copy_from_slice(&out[modulus_bytes - PMS_LEN..]);

    VariantPayload {
        full_plaintext: out,
        pms: extracted_pms,
    }
}

/// Build the ClientKeyExchange record wrapping the RSA ciphertext,
/// returning both the full record (for the wire) and the handshake
/// portion (type + len + body) for the transcript.
fn build_cke_record(ciphertext: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let hs_body_len = 2 + ciphertext.len();
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
    (rec, hs)
}

/// ChangeCipherSpec record: content_type + version + length(1) + value(0x01).
fn build_ccs_record() -> Vec<u8> {
    vec![CT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01]
}

// ───────────────────────── TLS 1.2 cryptographic helpers ─────────────────────────

/// HMAC with a given digest. Thin wrapper over `openssl::sign::Signer`.
fn hmac(md: MessageDigest, key: &[u8], data: &[u8]) -> Vec<u8> {
    let pkey = PKey::hmac(key).expect("PKey::hmac");
    let mut signer = Signer::new(md, &pkey).expect("Signer::new");
    signer.update(data).expect("Signer::update");
    signer.sign_to_vec().expect("Signer::sign_to_vec")
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac(MessageDigest::sha256(), key, data)
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac(MessageDigest::sha1(), key, data)
}

/// TLS 1.2 PRF per RFC 5246 §5 — P_SHA256 of `secret` over
/// `label || seed`, expanded to `out_len` bytes.
///
/// `PRF(secret, label, seed) = P_<hash>(secret, label || seed)`
/// where `P_hash` is the HMAC-based iteration:
/// ```text
/// A(0) = label || seed
/// A(i) = HMAC(secret, A(i-1))
/// P_hash = HMAC(secret, A(1) || label || seed) ||
///          HMAC(secret, A(2) || label || seed) || …
/// ```
fn tls12_prf(secret: &[u8], label: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut label_seed = Vec::with_capacity(label.len() + seed.len());
    label_seed.extend_from_slice(label);
    label_seed.extend_from_slice(seed);

    let mut a = hmac_sha256(secret, &label_seed); // A(1)
    let mut out = Vec::with_capacity(out_len + 32);
    while out.len() < out_len {
        let mut block_input = Vec::with_capacity(a.len() + label_seed.len());
        block_input.extend_from_slice(&a);
        block_input.extend_from_slice(&label_seed);
        out.extend_from_slice(&hmac_sha256(secret, &block_input));
        a = hmac_sha256(secret, &a); // A(n+1)
    }
    out.truncate(out_len);
    out
}

/// Master secret derivation (RFC 5246 §8.1).
fn derive_master_secret(pms: &[u8], client_random: &[u8; 32], server_random: &[u8; 32]) -> Vec<u8> {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    tls12_prf(pms, b"master secret", &seed, 48)
}

/// Client-side write keys for TLS_RSA_WITH_AES_128_CBC_SHA. Key
/// block layout (RFC 5246 §6.3):
/// `client_write_MAC_key(20) || server_write_MAC_key(20) ||
///  client_write_key(16) || server_write_key(16)`.
/// Only the client side is needed for the Finished record.
struct ClientWriteKeys {
    mac_key: [u8; 20],
    enc_key: [u8; 16],
}

fn derive_client_keys(
    master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> ClientWriteKeys {
    // Note the flipped order vs master-secret derivation: key
    // expansion seed is server_random || client_random.
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);
    let block = tls12_prf(master_secret, b"key expansion", &seed, 72);
    let mut mac_key = [0u8; 20];
    mac_key.copy_from_slice(&block[0..20]);
    // Skip server MAC key (20..40). Then:
    let mut enc_key = [0u8; 16];
    enc_key.copy_from_slice(&block[40..56]);
    ClientWriteKeys { mac_key, enc_key }
}

/// Compute `verify_data` for the client's Finished message
/// (RFC 5246 §7.4.9): `PRF(ms, "client finished", SHA-256(handshake))[0..12]`.
fn client_finished_verify_data(master_secret: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
    tls12_prf(master_secret, b"client finished", transcript_hash, 12)
}

/// SHA-256 of a byte slice.
fn sha256(data: &[u8]) -> Vec<u8> {
    let mut h = Hasher::new(MessageDigest::sha256()).expect("Hasher::new");
    h.update(data).expect("hasher.update");
    h.finish().expect("hasher.finish").to_vec()
}

/// Build the plaintext handshake bytes for the client's Finished
/// message: `type(0x14) || length(3) = 12 || verify_data(12)`.
fn build_finished_plaintext(verify_data: &[u8]) -> Vec<u8> {
    debug_assert_eq!(verify_data.len(), 12);
    let mut v = Vec::with_capacity(16);
    v.push(HS_FINISHED);
    v.extend_from_slice(&[0x00, 0x00, 0x0C]);
    v.extend_from_slice(verify_data);
    v
}

/// HMAC-SHA1 MAC over the per-record input per RFC 5246 §6.2.3.1:
/// `seq_num(8) || content_type(1) || version(2) || length(2) || plaintext`.
fn tls12_mac_sha1(
    mac_key: &[u8],
    seq_num: u64,
    content_type: u8,
    version: (u8, u8),
    plaintext: &[u8],
) -> Vec<u8> {
    let mut input = Vec::with_capacity(13 + plaintext.len());
    input.extend_from_slice(&seq_num.to_be_bytes());
    input.push(content_type);
    input.push(version.0);
    input.push(version.1);
    input.extend_from_slice(&(plaintext.len() as u16).to_be_bytes());
    input.extend_from_slice(plaintext);
    hmac_sha1(mac_key, &input)
}

/// AES-128-CBC encrypt with explicit per-record IV (RFC 5246
/// §6.2.3.2) and TLS CBC padding. Input is the
/// `plaintext || MAC` bytes; output is `IV(16) || ciphertext`, ready
/// to land as the fragment of a TLSCiphertext record.
fn aes128_cbc_encrypt_with_tls_padding(enc_key: &[u8], plaintext_with_mac: &[u8]) -> Vec<u8> {
    const BLOCK: usize = 16;
    let pad_len = BLOCK - (plaintext_with_mac.len() % BLOCK); // 1..=16
    let pad_byte = (pad_len - 1) as u8;
    let mut padded = Vec::with_capacity(plaintext_with_mac.len() + pad_len);
    padded.extend_from_slice(plaintext_with_mac);
    padded.extend(std::iter::repeat(pad_byte).take(pad_len));

    let mut iv = [0u8; 16];
    let _ = rand_bytes(&mut iv);

    let mut crypter = Crypter::new(Cipher::aes_128_cbc(), Mode::Encrypt, enc_key, Some(&iv))
        .expect("Crypter::new aes_128_cbc");
    crypter.pad(false);
    let mut ciphertext = vec![0u8; padded.len() + BLOCK];
    let n1 = crypter
        .update(&padded, &mut ciphertext)
        .expect("Crypter::update");
    let n2 = crypter
        .finalize(&mut ciphertext[n1..])
        .expect("Crypter::finalize");
    ciphertext.truncate(n1 + n2);

    let mut out = Vec::with_capacity(BLOCK + ciphertext.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ciphertext);
    out
}

/// Build a fully-framed, crypto-correct Finished record for
/// TLS_RSA_WITH_AES_128_CBC_SHA. `transcript` is the concatenation
/// of all handshake messages sent/received so far (ClientHello,
/// ServerHello, Certificate, ServerHelloDone, ClientKeyExchange),
/// with 4-byte handshake headers but no record-layer framing.
fn build_finished_record(
    master_secret: &[u8],
    mac_key: &[u8],
    enc_key: &[u8],
    transcript: &[u8],
) -> Vec<u8> {
    let th = sha256(transcript);
    let verify_data = client_finished_verify_data(master_secret, &th);
    let plaintext = build_finished_plaintext(&verify_data);
    let mac = tls12_mac_sha1(mac_key, 0, CT_HANDSHAKE, (0x03, 0x03), &plaintext);
    let mut plaintext_with_mac = Vec::with_capacity(plaintext.len() + mac.len());
    plaintext_with_mac.extend_from_slice(&plaintext);
    plaintext_with_mac.extend_from_slice(&mac);
    let fragment = aes128_cbc_encrypt_with_tls_padding(enc_key, &plaintext_with_mac);

    let mut rec = Vec::with_capacity(5 + fragment.len());
    rec.push(CT_HANDSHAKE);
    rec.extend_from_slice(&[0x03, 0x03]);
    rec.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
    rec.extend_from_slice(&fragment);
    rec
}

/// Minimal TLS 1.2 ClientHello pinning cipher suite
/// `TLS_RSA_WITH_AES_128_CBC_SHA`. Compatibility extensions present
/// so CDNs don't drop the connection as unparseable.
/// Build the minimal TLS 1.2 ClientHello record. Returns the 32-byte
/// client_random, the wire-ready record, and the handshake-layer
/// portion (after the 5-byte record header) so the caller can seed
/// the Finished transcript without re-parsing the record.
fn build_client_hello(hostname: &str) -> ([u8; 32], Vec<u8>, Vec<u8>) {
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

    (client_random, record, handshake)
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
        let payload = build_variant_payload(VariantKind::CorrectlyFormattedPkcs1, MOD_BYTES);
        let p = &payload.full_plaintext;
        assert_eq!(p.len(), MOD_BYTES);
        assert_eq!(p[0], 0x00);
        assert_eq!(p[1], 0x02);
        for (idx, &b) in p[2..MOD_BYTES - 49].iter().enumerate() {
            assert_ne!(b, 0x00, "padding byte {idx} was zero");
        }
        assert_eq!(p[MOD_BYTES - 49], 0x00);
        assert_eq!(p[MOD_BYTES - 48], 0x03);
        assert_eq!(p[MOD_BYTES - 47], 0x03);
        // PMS accessor matches last 48 bytes.
        assert_eq!(&payload.pms[..], &p[MOD_BYTES - 48..]);
        // PMS version prefix = 0x0303.
        assert_eq!(payload.pms[0], 0x03);
        assert_eq!(payload.pms[1], 0x03);
    }

    #[test]
    fn invalid_0x00_02_prefix_variant_has_wrong_second_byte() {
        let p = build_variant_payload(VariantKind::Invalid0002Prefix, MOD_BYTES).full_plaintext;
        assert_eq!(p[0], 0x00);
        assert_eq!(p[1], 0x17);
    }

    #[test]
    fn byte_swap_variant_has_transposed_prefix() {
        let p =
            build_variant_payload(VariantKind::InvalidVersion0002ByteSwap, MOD_BYTES).full_plaintext;
        assert_eq!(p[0], 0x02);
        assert_eq!(p[1], 0x00);
    }

    #[test]
    fn null_separator_missing_variant_replaces_separator() {
        let p = build_variant_payload(VariantKind::NullSeparatorMissing, MOD_BYTES).full_plaintext;
        assert_eq!(p[MOD_BYTES - 49], 0xFF);
    }

    #[test]
    fn wrong_tls_version_in_pms_variant_flips_pms_version() {
        let payload = build_variant_payload(VariantKind::WrongTlsVersionInPms, MOD_BYTES);
        let p = &payload.full_plaintext;
        assert_eq!(p[0], 0x00);
        assert_eq!(p[1], 0x02);
        assert_eq!(p[MOD_BYTES - 49], 0x00);
        assert_eq!(p[MOD_BYTES - 48], 0x03);
        assert_eq!(p[MOD_BYTES - 47], 0x02);
        // PMS surfaces the malformed version.
        assert_eq!(payload.pms[0], 0x03);
        assert_eq!(payload.pms[1], 0x02);
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
        let (rec, hs) = build_cke_record(&ct);
        assert_eq!(rec[0], CT_HANDSHAKE);
        assert_eq!(&rec[1..3], &[0x03, 0x03]);
        let rec_len = u16::from_be_bytes([rec[3], rec[4]]) as usize;
        assert_eq!(rec_len, rec.len() - 5);
        assert_eq!(rec[5], HS_CLIENT_KEY_EXCHANGE);
        let ct_len = u16::from_be_bytes([rec[9], rec[10]]) as usize;
        assert_eq!(ct_len, 256);
        // hs slice matches record body after the 5-byte record header.
        assert_eq!(hs, rec[5..]);
    }

    #[test]
    fn client_hello_framing_valid() {
        let (_, ch, _hs) = build_client_hello("example.com");
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
    fn tls12_prf_is_deterministic_and_respects_length() {
        let s = b"secret";
        let out_a = tls12_prf(s, b"label", b"seed", 64);
        let out_b = tls12_prf(s, b"label", b"seed", 64);
        assert_eq!(out_a, out_b);
        assert_eq!(out_a.len(), 64);
    }

    #[test]
    fn tls12_prf_differs_on_different_inputs() {
        let a = tls12_prf(b"k", b"client finished", b"h1", 12);
        let b = tls12_prf(b"k", b"client finished", b"h2", 12);
        assert_ne!(a, b);
    }

    #[test]
    fn derive_master_secret_outputs_48_bytes() {
        let pms = [0x42u8; 48];
        let cr = [0x11u8; 32];
        let sr = [0x22u8; 32];
        let ms = derive_master_secret(&pms, &cr, &sr);
        assert_eq!(ms.len(), 48);
    }

    #[test]
    fn derive_client_keys_extracts_correct_slices() {
        let ms = vec![0x33u8; 48];
        let cr = [0x44u8; 32];
        let sr = [0x55u8; 32];
        let keys = derive_client_keys(&ms, &cr, &sr);
        // Re-derive the full key block and compare.
        let mut seed = Vec::new();
        seed.extend_from_slice(&sr);
        seed.extend_from_slice(&cr);
        let block = tls12_prf(&ms, b"key expansion", &seed, 72);
        assert_eq!(&keys.mac_key[..], &block[0..20]);
        assert_eq!(&keys.enc_key[..], &block[40..56]);
    }

    #[test]
    fn build_finished_plaintext_structure() {
        let vd = [0x77u8; 12];
        let p = build_finished_plaintext(&vd);
        assert_eq!(p.len(), 16);
        assert_eq!(p[0], HS_FINISHED);
        assert_eq!(&p[1..4], &[0x00, 0x00, 0x0C]);
        assert_eq!(&p[4..], &vd[..]);
    }

    #[test]
    fn aes128_cbc_pads_to_block_boundary_and_ivs_differ() {
        let key = [0x00u8; 16];
        // 10-byte plaintext-with-mac → 6 bytes of pad value 5.
        let out_a = aes128_cbc_encrypt_with_tls_padding(&key, &[0xAAu8; 10]);
        let out_b = aes128_cbc_encrypt_with_tls_padding(&key, &[0xAAu8; 10]);
        // 16-byte IV + 16-byte ciphertext block.
        assert_eq!(out_a.len(), 32);
        assert_eq!(out_b.len(), 32);
        // IVs are fresh per record (RFC 5246 §6.2.3.2).
        assert_ne!(&out_a[..16], &out_b[..16]);
    }

    #[test]
    fn aes128_cbc_full_block_of_pad() {
        // When input is already aligned, TLS mandates one full
        // block of padding (pad_len=16, pad_byte=15).
        let key = [0x00u8; 16];
        let out = aes128_cbc_encrypt_with_tls_padding(&key, &[0xCCu8; 16]);
        // 16-byte IV + 32-byte ciphertext (plaintext 16 + pad 16).
        assert_eq!(out.len(), 48);
    }

    #[test]
    fn tls12_mac_sha1_is_20_bytes() {
        let mac = tls12_mac_sha1(&[0u8; 20], 0, CT_HANDSHAKE, (0x03, 0x03), b"hello");
        assert_eq!(mac.len(), 20);
    }

    #[test]
    fn build_finished_record_is_well_framed() {
        let ms = vec![0u8; 48];
        let mac_key = vec![0u8; 20];
        let enc_key = vec![0u8; 16];
        let transcript = b"synthetic transcript";
        let rec = build_finished_record(&ms, &mac_key, &enc_key, transcript);
        assert_eq!(rec[0], CT_HANDSHAKE);
        assert_eq!(&rec[1..3], &[0x03, 0x03]);
        let len = u16::from_be_bytes([rec[3], rec[4]]) as usize;
        assert_eq!(len, rec.len() - 5);
        // Finished plaintext = 16 bytes, MAC = 20 bytes, subtotal 36.
        // Padded to 48 bytes. Fragment = 16 (IV) + 48 = 64.
        assert_eq!(len, 64);
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
