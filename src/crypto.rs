use age::x25519::{Identity, Recipient};
use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

pub const AGEENC_PREFIX: &str = "ageenc:";

pub fn is_age_encrypted(value: &str) -> bool {
    value.trim_start().starts_with(AGEENC_PREFIX)
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
    }

    #[test]
    fn missing_prefix_decrypt_errors() {
        let id = Identity::generate();
        assert!(decrypt_value("plain", &id).is_err());
    }
}
