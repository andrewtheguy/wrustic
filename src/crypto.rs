use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};

const HEADER: &str = "$WR;1.0;CHACHA20-POLY1305;";
const SIG_PREFIX_LEN: usize = 8;

pub fn is_passphrase_encrypted(value: &str) -> bool {
    value.trim().starts_with(HEADER)
}

fn encrypt_value(
    plaintext: &str,
    key: &[u8; 32],
    instance: &str,
    sig_prefix: &str,
) -> Result<String> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut blob = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| anyhow!("chacha20poly1305 encrypt: {e}"))?;
    let mut out = Vec::with_capacity(nonce.len() + blob.len());
    out.extend_from_slice(nonce.as_slice());
    out.append(&mut blob);
    Ok(format!(
        "{HEADER}{instance};{sig_prefix};{}",
        BASE64.encode(&out)
    ))
}

fn decrypt_value(value: &str, key: &[u8; 32]) -> Result<String> {
    let after_header = value
        .trim()
        .strip_prefix(HEADER)
        .ok_or_else(|| anyhow!("value is not encrypted (missing header)"))?;
    // Skip instance and sig_prefix fields to reach the base64 payload.
    let (_, rest) = after_header
        .split_once(';')
        .ok_or_else(|| anyhow!("malformed encrypted value (missing instance separator)"))?;
    let (_, encoded) = rest
        .split_once(';')
        .ok_or_else(|| anyhow!("malformed encrypted value (missing sig separator)"))?;
    let raw = BASE64
        .decode(encoded)
        .context("invalid base64 in encrypted value")?;
    if raw.len() < 12 + 16 {
        bail!("encrypted payload too short ({} bytes)", raw.len());
    }
    let (nonce_bytes, ciphertext) = raw.split_at(12);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|e| anyhow!("chacha20poly1305 decrypt: {e}"))?;
    String::from_utf8(plaintext).context("decrypted value is not valid UTF-8")
}

fn truncate_sig(instance_sig: &str) -> String {
    instance_sig.chars().take(SIG_PREFIX_LEN).collect()
}

pub struct Cipher {
    key: [u8; 32],
    instance: String,
    sig_prefix: String,
}

impl std::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cipher")
            .field("instance", &self.instance)
            .field("sig_prefix", &self.sig_prefix)
            .finish()
    }
}

impl Cipher {
    pub fn new(key: [u8; 32], instance: String, instance_sig: &str) -> Self {
        Self {
            key,
            instance,
            sig_prefix: truncate_sig(instance_sig),
        }
    }

    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        encrypt_value(plaintext, &self.key, &self.instance, &self.sig_prefix)
    }

    pub fn decrypt(&self, value: &str) -> Result<String> {
        if !is_passphrase_encrypted(value) {
            bail!("expected encrypted value with `{HEADER}` header");
        }
        decrypt_value(value, &self.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_detection() {
        assert!(is_passphrase_encrypted(
            "$WR;1.0;CHACHA20-POLY1305;mysite;abcd1234;AAAA"
        ));
        assert!(!is_passphrase_encrypted(""));
        assert!(!is_passphrase_encrypted("plain"));
    }

    #[test]
    fn round_trip() {
        let key = [0x42u8; 32];
        let enc = encrypt_value("hunter2", &key, "test", "abcd1234").unwrap();
        assert!(enc.starts_with("$WR;1.0;CHACHA20-POLY1305;test;abcd1234;"));
        assert!(!enc.contains('\n'));
        assert_eq!(decrypt_value(&enc, &key).unwrap(), "hunter2");
    }

    #[test]
    fn wrong_key_fails() {
        let k1 = [0x01u8; 32];
        let k2 = [0x02u8; 32];
        let enc = encrypt_value("secret", &k1, "inst", "sig12345").unwrap();
        assert!(decrypt_value(&enc, &k2).is_err());
    }

    #[test]
    fn tampered_fails() {
        let key = [0x33u8; 32];
        let enc = encrypt_value("data", &key, "inst", "sig12345").unwrap();
        let semi_pos = enc.rfind(';').unwrap();
        let mut tampered = enc.clone();
        let bytes = unsafe { tampered.as_bytes_mut() };
        let i = semi_pos + 6;
        bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
        assert!(decrypt_value(&tampered, &key).is_err());
    }

    #[test]
    fn cipher_dispatch() {
        let cipher = Cipher::new([0x77u8; 32], "mysite".into(), "wgMS4JCMUouQ");
        let enc = cipher.encrypt("payload").unwrap();
        assert!(enc.starts_with("$WR;1.0;CHACHA20-POLY1305;mysite;wgMS4JCM;"));
        assert_eq!(cipher.decrypt(&enc).unwrap(), "payload");
        assert!(cipher.decrypt("plain").is_err());
    }

    #[test]
    fn sig_prefix_truncated_to_8_chars() {
        assert_eq!(truncate_sig("wgMS4JCMUouQZRnB4vpscg=="), "wgMS4JCM");
        assert_eq!(truncate_sig("short"), "short");
        assert_eq!(truncate_sig(""), "");
    }
}
