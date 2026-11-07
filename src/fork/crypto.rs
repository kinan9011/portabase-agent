//! Verification primitives for the task channel: pinned RSA public keys (RSASSA-PKCS1-v1_5 / SHA-256, same as the manifest signature) and the
//! per-agent AES-256-GCM payload. No key generation, no signing: the agent only ever verifies and decrypts.
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};

/// Domain separation prefix of the signed bytes (must equal the dashboard's `SIGN_DOMAIN`).
pub const SIGN_DOMAIN: &str = "portabase-fork-task:v1\n";

#[derive(Debug, Clone)]
pub struct Pin {
    pub kid: String,
    /// RSAPublicKey (PKCS#1) DER — what `aws-lc-rs` verifies with.
    pub pkcs1_der: Vec<u8>,
    /// SHA-256 of the SPKI DER, hex (shown at enrolment, logged at start-up).
    pub fingerprint: String,
}

fn read_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *input.first()?;
    let b = *input.get(1)?;
    let (len, hdr) = if b < 0x80 {
        (b as usize, 2)
    } else {
        let n = (b & 0x7f) as usize;
        if n == 0 || n > 4 || input.len() < 2 + n {
            return None;
        }
        let mut l = 0usize;
        for x in &input[2..2 + n] {
            l = (l << 8) | *x as usize;
        }
        (l, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    if input.len() < end {
        return None;
    }
    Some((tag, &input[hdr..end], &input[end..]))
}

const RSA_OID: [u8; 11] = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// SPKI DER → the inner RSAPublicKey DER. Accepts RSA keys only.
fn rsa_public_key_from_spki(spki: &[u8]) -> Option<Vec<u8>> {
    let (tag, body, rest) = read_tlv(spki)?;
    if tag != 0x30 || !rest.is_empty() {
        return None;
    }
    let (t1, alg, after_alg) = read_tlv(body)?;
    if t1 != 0x30 || alg.len() < RSA_OID.len() || alg[..RSA_OID.len()] != RSA_OID {
        return None;
    }
    let (t2, bits, tail) = read_tlv(after_alg)?;
    if t2 != 0x03 || !tail.is_empty() || bits.first() != Some(&0) {
        return None;
    }
    Some(bits[1..].to_vec())
}

/// Parses a `-----BEGIN PUBLIC KEY-----` (SPKI) PEM into a `Pin`. The `kid` the dashboard states must equal the first 12 hex of SHA-256(SPKI DER).
pub fn parse_pin(kid: &str, pem: &str) -> Result<Pin, &'static str> {
    let body: String = pem
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("-----") && !l.is_empty())
        .collect();
    if !pem.contains("BEGIN PUBLIC KEY") {
        return Err("pin is not an SPKI public key PEM");
    }
    let spki = STANDARD.decode(body.as_bytes()).map_err(|_| "pin PEM is not valid base64")?;
    let pkcs1_der = rsa_public_key_from_spki(&spki).ok_or("pin is not an RSA public key")?;
    let fingerprint = hex::encode(Sha256::digest(&spki));
    if kid.len() != 12 || fingerprint[..12] != *kid {
        return Err("pin kid does not match its key");
    }
    Ok(Pin { kid: kid.to_string(), pkcs1_der, fingerprint })
}

pub fn verify_signature(pin: &Pin, envelope_text: &str, signature_b64: &str) -> bool {
    let Ok(sig) = STANDARD.decode(signature_b64.as_bytes()) else { return false };
    if sig.is_empty() {
        return false;
    }
    let mut msg = Vec::with_capacity(SIGN_DOMAIN.len() + envelope_text.len());
    msg.extend_from_slice(SIGN_DOMAIN.as_bytes());
    msg.extend_from_slice(envelope_text.as_bytes());
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &pin.pkcs1_der).verify(&msg, &sig).is_ok()
}

/// base64(nonce(12) ‖ ciphertext ‖ tag(16)) under the agent task key, AAD = `task_id|agent_id|type`.
pub fn decrypt_payload(task_key: &[u8; 32], task_id: &str, agent_id: &str, task_type: &str, b64: &str) -> Option<Vec<u8>> {
    let data = STANDARD.decode(b64.as_bytes()).ok()?;
    if data.len() < 12 + 16 {
        return None;
    }
    let key = Key::<Aes256Gcm>::try_from(task_key.as_slice()).ok()?;
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::try_from(&data[..12]).ok()?;
    let aad = format!("{task_id}|{agent_id}|{task_type}");
    cipher.decrypt(&nonce, Payload { msg: &data[12..], aad: aad.as_bytes() }).ok()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}
