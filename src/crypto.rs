use age::x25519::{Identity, Recipient};
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};

pub const AGEENC_PREFIX: &str = "ageenc:";
pub const PKENC_PREFIX: &str = "pkenc:";

pub fn is_age_encrypted(value: &str) -> bool {
    value.trim_start().starts_with(AGEENC_PREFIX)
}

pub fn is_passphrase_encrypted(value: &str) -> bool {
    value.trim_start().starts_with(PKENC_PREFIX)
}

pub fn encrypt_value(plaintext: &str, recipient: &Recipient) -> Result<String> {
    let ciphertext = age::encrypt(recipient, plaintext.as_bytes())
        .map_err(|e| anyhow!("age encrypt: {e}"))?;
    Ok(format!("{AGEENC_PREFIX}{}", BASE64.encode(&ciphertext)))
}

pub fn decrypt_value(value: &str, identity: &Identity) -> Result<String> {
    let encoded = value
        .trim()
        .strip_prefix(AGEENC_PREFIX)
        .ok_or_else(|| anyhow!("value is not {AGEENC_PREFIX}-prefixed"))?;
    let ciphertext = BASE64
        .decode(encoded)
        .context("invalid base64 in ageenc: value")?;
    let plaintext = age::decrypt(identity, &ciphertext)
        .map_err(|e| anyhow!("age decrypt: {e}"))?;
    String::from_utf8(plaintext).context("decrypted value is not valid UTF-8")
}

/// Encrypt a single value with ChaCha20-Poly1305. `key` is the 32-byte AEAD
/// key (typically the HKDF-derived passkey config key). Output is single-line:
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

/// Dispatch backend for per-value encrypt/decrypt. Constructed once on app
/// boot from either an age identity (default) or a passkey-derived config
/// key (`--experimental-passkey`), then threaded into `config::load` / `save`.
pub enum Cipher {
    Age {
        identity: Identity,
        recipient: Recipient,
    },
    Passphrase {
        key: [u8; 32],
    },
}

// Manual Debug — never print key material. `age::Identity` doesn't implement
// Debug either (by design), so we can't `derive(Debug)`.
impl std::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cipher::Age { recipient, .. } => f
                .debug_struct("Cipher::Age")
                .field("recipient", &recipient.to_string())
                .finish(),
            Cipher::Passphrase { .. } => f.debug_struct("Cipher::Passphrase").finish(),
        }
    }
}

impl Cipher {
    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        match self {
            Cipher::Age { recipient, .. } => encrypt_value(plaintext, recipient),
            Cipher::Passphrase { key } => encrypt_passphrase_value(plaintext, key),
        }
    }

    pub fn decrypt(&self, value: &str) -> Result<String> {
        match self {
            Cipher::Age { identity, .. } => {
                if !is_age_encrypted(value) {
                    bail!("expected `{AGEENC_PREFIX}` value (this config dir is age mode)");
                }
                decrypt_value(value, identity)
            }
            Cipher::Passphrase { key } => {
                if !is_passphrase_encrypted(value) {
                    bail!("expected `{PKENC_PREFIX}` value (this config dir is passphrase mode)");
                }
                decrypt_passphrase_value(value, key)
            }
        }
    }

    /// Stored-value prefix this cipher emits. Used by callers that want to
    /// skip re-encrypting an already-encrypted field.
    pub fn prefix(&self) -> &'static str {
        match self {
            Cipher::Age { .. } => AGEENC_PREFIX,
            Cipher::Passphrase { .. } => PKENC_PREFIX,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let id = Identity::generate();
        let rcpt = id.to_public();
        let enc = encrypt_value("hello world", &rcpt).unwrap();
        assert!(enc.starts_with(AGEENC_PREFIX));
        assert!(!enc.contains('\n'));
        assert_eq!(decrypt_value(&enc, &id).unwrap(), "hello world");
    }

    #[test]
    fn wrong_key_fails() {
        let a = Identity::generate();
        let b = Identity::generate();
        let enc = encrypt_value("x", &a.to_public()).unwrap();
        assert!(decrypt_value(&enc, &b).is_err());
    }

    #[test]
    fn prefix_detection() {
        assert!(is_age_encrypted("ageenc:AAAA"));
        assert!(is_age_encrypted("   ageenc:AAAA"));
        assert!(!is_age_encrypted(""));
        assert!(!is_age_encrypted("plain"));
        assert!(is_passphrase_encrypted("pkenc:AAAA"));
        assert!(!is_passphrase_encrypted("ageenc:AAAA"));
    }

    #[test]
    fn missing_prefix_decrypt_errors() {
        let id = Identity::generate();
        assert!(decrypt_value("plain", &id).is_err());
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
        // Flip a character in the base64 body to corrupt the ciphertext/tag.
        let body_start = PKENC_PREFIX.len();
        let bytes = unsafe { enc.as_bytes_mut() };
        let i = body_start + 5;
        bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
        assert!(decrypt_passphrase_value(&enc, &key).is_err());
    }

    #[test]
    fn cipher_dispatch_age() {
        let id = Identity::generate();
        let rcpt = id.to_public();
        let cipher = Cipher::Age { identity: id, recipient: rcpt };
        let enc = cipher.encrypt("payload").unwrap();
        assert!(enc.starts_with(AGEENC_PREFIX));
        assert_eq!(cipher.decrypt(&enc).unwrap(), "payload");
        // Cross-prefix is rejected with a clear error.
        let bogus = format!("{PKENC_PREFIX}AAAA");
        assert!(cipher.decrypt(&bogus).is_err());
    }

    #[test]
    fn cipher_dispatch_passphrase() {
        let cipher = Cipher::Passphrase { key: [0x77u8; 32] };
        let enc = cipher.encrypt("payload").unwrap();
        assert!(enc.starts_with(PKENC_PREFIX));
        assert_eq!(cipher.decrypt(&enc).unwrap(), "payload");
        let bogus = format!("{AGEENC_PREFIX}AAAA");
        assert!(cipher.decrypt(&bogus).is_err());
    }
}
