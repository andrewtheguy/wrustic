use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};

pub const PKENC_PREFIX: &str = "pkenc:";

pub fn is_passphrase_encrypted(value: &str) -> bool {
    value.trim_start().starts_with(PKENC_PREFIX)
}

/// Encrypt a single value with ChaCha20-Poly1305. `key` is the 32-byte AEAD
/// key (typically the passphrase-derived config key). Output is single-line:
/// `pkenc:base64(nonce(12) || ciphertext || tag(16))`.
pub fn encrypt_passphrase_value(plaintext: &str, key: &[u8; 32]) -> Result<String> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut blob = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| anyhow!("chacha20poly1305 encrypt: {e}"))?;
    let mut out = Vec::with_capacity(nonce.len() + blob.len());
    out.extend_from_slice(nonce.as_slice());
    out.append(&mut blob);
    Ok(format!("{PKENC_PREFIX}{}", BASE64.encode(&out)))
}

pub fn decrypt_passphrase_value(value: &str, key: &[u8; 32]) -> Result<String> {
    let encoded = value
        .trim()
        .strip_prefix(PKENC_PREFIX)
        .ok_or_else(|| anyhow!("value is not {PKENC_PREFIX}-prefixed"))?;
    let raw = BASE64
        .decode(encoded)
        .context("invalid base64 in pkenc: value")?;
    if raw.len() < 12 + 16 {
        bail!("pkenc: payload too short ({} bytes)", raw.len());
    }
    let (nonce_bytes, ciphertext) = raw.split_at(12);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|e| anyhow!("chacha20poly1305 decrypt: {e}"))?;
    String::from_utf8(plaintext).context("decrypted value is not valid UTF-8")
}

pub struct Cipher {
    key: [u8; 32],
}

impl std::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cipher").finish()
    }
}

impl Cipher {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        encrypt_passphrase_value(plaintext, &self.key)
    }

    pub fn decrypt(&self, value: &str) -> Result<String> {
        if !is_passphrase_encrypted(value) {
            bail!("expected `{PKENC_PREFIX}` value");
        }
        decrypt_passphrase_value(value, &self.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_detection() {
        assert!(is_passphrase_encrypted("pkenc:AAAA"));
        assert!(!is_passphrase_encrypted(""));
        assert!(!is_passphrase_encrypted("plain"));
    }

    #[test]
    fn pkenc_round_trip() {
        let key = [0x42u8; 32];
        let enc = encrypt_passphrase_value("hunter2", &key).unwrap();
        assert!(enc.starts_with(PKENC_PREFIX));
        assert!(!enc.contains('\n'));
        assert_eq!(decrypt_passphrase_value(&enc, &key).unwrap(), "hunter2");
    }

    #[test]
    fn pkenc_wrong_key_fails() {
        let k1 = [0x01u8; 32];
        let k2 = [0x02u8; 32];
        let enc = encrypt_passphrase_value("secret", &k1).unwrap();
        assert!(decrypt_passphrase_value(&enc, &k2).is_err());
    }

    #[test]
    fn pkenc_tampered_fails() {
        let key = [0x33u8; 32];
        let mut enc = encrypt_passphrase_value("data", &key).unwrap();
        let body_start = PKENC_PREFIX.len();
        let bytes = unsafe { enc.as_bytes_mut() };
        let i = body_start + 5;
        bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
        assert!(decrypt_passphrase_value(&enc, &key).is_err());
    }

    #[test]
    fn cipher_dispatch() {
        let cipher = Cipher::new([0x77u8; 32]);
        let enc = cipher.encrypt("payload").unwrap();
        assert!(enc.starts_with(PKENC_PREFIX));
        assert_eq!(cipher.decrypt(&enc).unwrap(), "payload");
        assert!(cipher.decrypt("plain").is_err());
    }
}
