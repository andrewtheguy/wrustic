use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use age::secrecy::ExposeSecret;
use age::x25519::{Identity, Recipient};
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

use crate::crypto::{decrypt_value, encrypt_value, is_age_encrypted};

const CONFIG_DIR_NAME: &str = "wrustic";
const IDENTITY_FILE: &str = "age.key";
const CONFIG_FILE: &str = "config.toml";
const CONFIG_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy)]
pub enum BackendKind {
    Local,
    Rest,
    S3,
}

impl BackendKind {
    pub fn label(self) -> &'static str {
        match self {
            BackendKind::Local => "Local filesystem",
            BackendKind::Rest => "REST server",
            BackendKind::S3 => "S3 (any S3-compatible endpoint)",
        }
    }
}

/// Profile body — the name is the key in [`Config::profiles`] and is not
/// duplicated inside the variant. The map key is the primary identifier;
/// renaming = remove old key + insert new key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "lowercase")]
pub enum Profile {
    Local {
        password: String,
        local_path: String,
    },
    Rest {
        password: String,
        rest_url: String,
        #[serde(default)]
        rest_user: String,
        #[serde(default)]
        rest_password: String,
    },
    S3 {
        password: String,
        s3_endpoint: String,
        s3_bucket: String,
        s3_region: String,
        #[serde(default)]
        s3_root: String,
        s3_access_key: String,
        s3_secret_key: String,
    },
}

impl Profile {
    pub fn password(&self) -> &str {
        match self {
            Profile::Local { password, .. }
            | Profile::Rest { password, .. }
            | Profile::S3 { password, .. } => password,
        }
    }

    pub fn backend_kind(&self) -> BackendKind {
        match self {
            Profile::Local { .. } => BackendKind::Local,
            Profile::Rest { .. } => BackendKind::Rest,
            Profile::S3 { .. } => BackendKind::S3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub recipient: String,
    pub version: u32,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            recipient: String::new(),
            version: CONFIG_VERSION,
            profiles: BTreeMap::new(),
        }
    }
}

impl Config {
    pub fn has_profile(&self, name: &str) -> bool {
        self.profiles.contains_key(name)
    }

    pub fn profile_at(&self, idx: usize) -> Option<(&String, &Profile)> {
        self.profiles.iter().nth(idx)
    }

    pub fn name_at(&self, idx: usize) -> Option<&String> {
        self.profiles.keys().nth(idx)
    }
}

pub struct Paths {
    pub identity: PathBuf,
    pub config: PathBuf,
}

pub fn paths(override_dir: Option<PathBuf>) -> Result<Paths> {
    let base = match override_dir {
        Some(p) => p,
        None => dirs::config_dir()
            .ok_or_else(|| anyhow!("could not determine config directory"))?
            .join(CONFIG_DIR_NAME),
    };
    Ok(Paths {
        identity: base.join(IDENTITY_FILE),
        config: base.join(CONFIG_FILE),
    })
}

/// Generate a fresh X25519 identity and write it to `path` in the sops-style
/// format (commented public key + recipient hint, then the secret key).
/// File is created with mode 0600. Returns the bech32-encoded public key
/// (`age1…`) so the caller can display it to the user.
pub fn generate_identity(path: &Path) -> Result<String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let identity = Identity::generate();
    let public = identity.to_public();
    let public_str = public.to_string();
    let secret = identity.to_string();

    let body = format!(
        "# created by wrustic\n# public key: {}\n{}\n",
        public_str,
        secret.expose_secret()
    );

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(body.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(public_str)
}

/// Validate that `path` contains a parseable age identity. Returns the
/// derived public key string on success.
pub fn validate_identity(path: &Path) -> Result<String> {
    let identity = parse_identity_from_file(path)?;
    Ok(identity.to_public().to_string())
}

fn parse_identity_from_file(path: &Path) -> Result<Identity> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let secret_lines: Vec<&str> = contents
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("AGE-SECRET-KEY-"))
        .collect();
    match secret_lines.len() {
        0 => bail!("no AGE-SECRET-KEY line found in {}", path.display()),
        1 => Identity::from_str(secret_lines[0])
            .map_err(|e| anyhow!("parsing age identity in {}: {e}", path.display())),
        n => bail!(
            "age.key at {} contains {n} identities, but wrustic requires exactly one",
            path.display()
        ),
    }
}

/// Load the config. If the config file does not exist, returns a default
/// (empty) config without touching disk. The identity must already exist.
pub fn load(paths: &Paths) -> Result<Config> {
    let identity = parse_identity_from_file(&paths.identity)?;

    if !paths.config.exists() {
        return Ok(Config::default());
    }

    let text = fs::read_to_string(&paths.config)
        .with_context(|| format!("reading {}", paths.config.display()))?;
    let mut config: Config = toml::from_str(&text)
        .with_context(|| format!("parsing TOML from {}", paths.config.display()))?;

    let derived = identity.to_public().to_string();
    if config.recipient.is_empty() {
        bail!(
            "{} is missing the `recipient` field (expected `{derived}` matching the identity at {})",
            paths.config.display(),
            paths.identity.display()
        );
    }
    if config.recipient != derived {
        bail!(
            "recipient mismatch: {} has recipient `{}` but the identity at {} derives `{derived}`",
            paths.config.display(),
            config.recipient,
            paths.identity.display()
        );
    }

    if config.version != CONFIG_VERSION {
        bail!(
            "config at {} has version {} but this build of wrustic expects version {} \
             (no migrations are supported — this is a personal tool with no backwards compatibility)",
            paths.config.display(),
            config.version,
            CONFIG_VERSION
        );
    }

    for (name, profile) in &mut config.profiles {
        decrypt_profile_fields(profile, &identity)
            .with_context(|| format!("decrypting profile `{name}`"))?;
    }
    Ok(config)
}

/// Encrypt and write the config atomically. Identity is loaded from the
/// identity file to derive the recipient.
pub fn save(config: &Config, paths: &Paths) -> Result<()> {
    let identity = parse_identity_from_file(&paths.identity)?;
    let recipient: Recipient = identity.to_public();

    let mut on_disk = config.clone();
    on_disk.recipient = recipient.to_string();
    on_disk.version = CONFIG_VERSION;
    for (name, profile) in &mut on_disk.profiles {
        encrypt_profile_fields(profile, &recipient)
            .with_context(|| format!("encrypting profile `{name}`"))?;
    }

    let text = toml::to_string_pretty(&on_disk).context("serializing config to TOML")?;

    if let Some(parent) = paths.config.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    let tmp = paths.config.with_extension("toml.tmp");
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        file.write_all(text.as_bytes())
            .with_context(|| format!("writing {}", tmp.display()))?;
        file.sync_all().ok();
    }
    fs::rename(&tmp, &paths.config)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), paths.config.display()))?;
    Ok(())
}

fn encrypt_field(value: &mut String, recipient: &Recipient) -> Result<()> {
    if value.is_empty() || is_age_encrypted(value) {
        return Ok(());
    }
    *value = encrypt_value(value, recipient)?;
    Ok(())
}

fn decrypt_field(value: &mut String, identity: &Identity) -> Result<()> {
    if value.is_empty() {
        return Ok(());
    }
    if !is_age_encrypted(value) {
        bail!("field is not encrypted (missing `ageenc:` prefix)");
    }
    *value = decrypt_value(value, identity)?;
    Ok(())
}

fn encrypt_profile_fields(profile: &mut Profile, recipient: &Recipient) -> Result<()> {
    match profile {
        Profile::Local { password, .. } => {
            encrypt_field(password, recipient)?;
        }
        Profile::Rest {
            password,
            rest_user,
            rest_password,
            ..
        } => {
            encrypt_field(password, recipient)?;
            encrypt_field(rest_user, recipient)?;
            encrypt_field(rest_password, recipient)?;
        }
        Profile::S3 {
            password,
            s3_access_key,
            s3_secret_key,
            ..
        } => {
            encrypt_field(password, recipient)?;
            encrypt_field(s3_access_key, recipient)?;
            encrypt_field(s3_secret_key, recipient)?;
        }
    }
    Ok(())
}

fn decrypt_profile_fields(profile: &mut Profile, identity: &Identity) -> Result<()> {
    match profile {
        Profile::Local { password, .. } => {
            decrypt_field(password, identity)?;
        }
        Profile::Rest {
            password,
            rest_user,
            rest_password,
            ..
        } => {
            decrypt_field(password, identity)?;
            decrypt_field(rest_user, identity)?;
            decrypt_field(rest_password, identity)?;
        }
        Profile::S3 {
            password,
            s3_access_key,
            s3_secret_key,
            ..
        } => {
            decrypt_field(password, identity)?;
            decrypt_field(s3_access_key, identity)?;
            decrypt_field(s3_secret_key, identity)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_dir(name: &str) -> PathBuf {
        let dir = PathBuf::from("tmp").join(format!("cfgtest-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    fn test_paths(dir: &Path) -> Paths {
        Paths {
            identity: dir.join("age.key"),
            config: dir.join("config.toml"),
        }
    }

    #[test]
    fn round_trip_encrypt_decrypt() -> Result<()> {
        let dir = fresh_dir("rt");
        let paths = test_paths(&dir);

        let pubkey = generate_identity(&paths.identity)?;
        assert!(paths.identity.exists());
        assert!(pubkey.starts_with("age1"), "expected age1 recipient, got {pubkey}");

        assert_eq!(validate_identity(&paths.identity)?, pubkey);

        let empty = load(&paths)?;
        assert_eq!(empty.profiles.len(), 0);
        assert_eq!(empty.version, CONFIG_VERSION);

        let mut profiles = BTreeMap::new();
        profiles.insert(
            "local-a".to_string(),
            Profile::Local {
                password: "pw1".into(),
                local_path: "/var/restic/a".into(),
            },
        );
        profiles.insert(
            "s3-b".to_string(),
            Profile::S3 {
                password: "pw2".into(),
                s3_endpoint: "https://s3.example.com".into(),
                s3_bucket: "buk".into(),
                s3_region: "us-east-1".into(),
                s3_root: "/sub/dir".into(),
                s3_access_key: "AK".into(),
                s3_secret_key: "SK".into(),
            },
        );
        profiles.insert(
            "rest-c".to_string(),
            Profile::Rest {
                password: "pw3".into(),
                rest_url: "https://r.example.com/repo".into(),
                rest_user: String::new(),
                rest_password: String::new(),
            },
        );
        let cfg = Config {
            recipient: String::new(),
            version: CONFIG_VERSION,
            profiles,
        };
        save(&cfg, &paths)?;
        assert!(paths.config.exists());

        let raw = fs::read_to_string(&paths.config)?;
        let parsed: toml::Value = toml::from_str(&raw)?;
        assert_eq!(parsed["recipient"].as_str().unwrap(), pubkey);

        let table = parsed["profiles"].as_table().unwrap();
        assert_eq!(table.len(), 3);
        for (name, profile) in table {
            let profile = profile.as_table().unwrap();
            let password = profile["password"].as_str().unwrap();
            assert!(password.starts_with("ageenc:"), "password should be encrypted: {password}");
            assert!(!password.contains('\n'), "ageenc value must be single-line");
            assert!(!profile.contains_key("name"), "`name` should not be inside profile `{name}`");
            if profile["backend"].as_str().unwrap() == "local" {
                assert!(!profile["local_path"].as_str().unwrap().starts_with("ageenc:"));
            }
        }

        let loaded = load(&paths)?;
        assert_eq!(loaded.profiles.len(), 3);
        assert_eq!(loaded.recipient, pubkey);
        match loaded.profiles.get("local-a") {
            Some(Profile::Local { password, local_path }) => {
                assert_eq!(password, "pw1");
                assert_eq!(local_path, "/var/restic/a");
            }
            other => panic!("expected Local, got {other:?}"),
        }
        match loaded.profiles.get("s3-b") {
            Some(Profile::S3 { s3_root, s3_access_key, s3_secret_key, .. }) => {
                assert_eq!(s3_root, "/sub/dir");
                assert_eq!(s3_access_key, "AK");
                assert_eq!(s3_secret_key, "SK");
            }
            other => panic!("expected S3, got {other:?}"),
        }
        match loaded.profiles.get("rest-c") {
            Some(Profile::Rest { rest_url, .. }) => {
                assert_eq!(rest_url, "https://r.example.com/repo");
            }
            other => panic!("expected Rest, got {other:?}"),
        }

        fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn rest_round_trip_with_split_auth() -> Result<()> {
        let dir = fresh_dir("rest_split");
        let paths = test_paths(&dir);
        generate_identity(&paths.identity)?;

        let mut profiles = BTreeMap::new();
        profiles.insert(
            "rest-auth".to_string(),
            Profile::Rest {
                password: "repo-pw".into(),
                rest_url: "https://r.example.com/repo/".into(),
                rest_user: "andrew".into(),
                rest_password: "hunter2".into(),
            },
        );
        let cfg = Config {
            recipient: String::new(),
            version: CONFIG_VERSION,
            profiles,
        };
        save(&cfg, &paths)?;

        let raw = fs::read_to_string(&paths.config)?;
        let parsed: toml::Value = toml::from_str(&raw)?;
        let rest = &parsed["profiles"]["rest-auth"];
        assert_eq!(rest["rest_url"].as_str().unwrap(), "https://r.example.com/repo/");
        assert!(rest["rest_user"].as_str().unwrap().starts_with("ageenc:"));
        assert!(rest["rest_password"].as_str().unwrap().starts_with("ageenc:"));

        let loaded = load(&paths)?;
        match loaded.profiles.get("rest-auth") {
            Some(Profile::Rest {
                rest_url,
                rest_user,
                rest_password,
                password,
            }) => {
                assert_eq!(rest_url, "https://r.example.com/repo/");
                assert_eq!(rest_user, "andrew");
                assert_eq!(rest_password, "hunter2");
                assert_eq!(password, "repo-pw");
            }
            other => panic!("expected Rest, got {other:?}"),
        }

        fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn recipient_mismatch_is_rejected() -> Result<()> {
        let dir = fresh_dir("rcpt");
        let paths = test_paths(&dir);
        generate_identity(&paths.identity)?;

        let mut profiles = BTreeMap::new();
        profiles.insert(
            "x".to_string(),
            Profile::Local {
                password: "p".into(),
                local_path: "/x".into(),
            },
        );
        let cfg = Config {
            recipient: String::new(),
            version: CONFIG_VERSION,
            profiles,
        };
        save(&cfg, &paths)?;

        // Replace recipient with a syntactically valid but unrelated age1 string.
        let other = Identity::generate().to_public().to_string();
        let raw = fs::read_to_string(&paths.config)?;
        let mut doc: toml::Value = toml::from_str(&raw)?;
        doc["recipient"] = toml::Value::String(other);
        fs::write(&paths.config, toml::to_string_pretty(&doc)?)?;

        let err = load(&paths).expect_err("recipient mismatch should error");
        let msg = format!("{err:#}");
        assert!(msg.contains("recipient"), "error should mention recipient: {msg}");

        fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn multiple_identities_rejected() -> Result<()> {
        let dir = fresh_dir("multi");
        let id_path = dir.join("age.key");

        let a = Identity::generate();
        let b = Identity::generate();
        let body = format!(
            "# id a\n{}\n# id b\n{}\n",
            a.to_string().expose_secret(),
            b.to_string().expose_secret()
        );
        fs::write(&id_path, body)?;

        let err = validate_identity(&id_path).expect_err("two identities should error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("exactly one"),
            "error should mention exactly one: {msg}"
        );

        fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn empty_string_field_not_encrypted() -> Result<()> {
        let dir = fresh_dir("empty");
        let paths = test_paths(&dir);
        generate_identity(&paths.identity)?;

        let mut profiles = BTreeMap::new();
        profiles.insert(
            "anon".to_string(),
            Profile::Rest {
                password: "pw".into(),
                rest_url: "http://localhost:8000/".into(),
                rest_user: String::new(),
                rest_password: String::new(),
            },
        );
        let cfg = Config {
            recipient: String::new(),
            version: CONFIG_VERSION,
            profiles,
        };
        save(&cfg, &paths)?;

        let raw = fs::read_to_string(&paths.config)?;
        let parsed: toml::Value = toml::from_str(&raw)?;
        let rest = &parsed["profiles"]["anon"];
        assert_eq!(rest["rest_user"].as_str().unwrap(), "");
        assert_eq!(rest["rest_password"].as_str().unwrap(), "");

        let loaded = load(&paths)?;
        match loaded.profiles.get("anon") {
            Some(Profile::Rest {
                rest_user,
                rest_password,
                ..
            }) => {
                assert!(rest_user.is_empty());
                assert!(rest_password.is_empty());
            }
            other => panic!("expected Rest, got {other:?}"),
        }

        fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn paths_uses_override_when_provided() -> Result<()> {
        let dir = fresh_dir("override");
        let p = paths(Some(dir.clone()))?;
        assert_eq!(p.identity, dir.join("age.key"));
        assert_eq!(p.config, dir.join("config.toml"));
        fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn load_rejects_unknown_version() -> Result<()> {
        let dir = fresh_dir("ver");
        let paths = test_paths(&dir);
        generate_identity(&paths.identity)?;

        // Save a real config first, then bump the version on disk to one
        // wrustic doesn't know about, and confirm load() refuses it.
        save(&Config::default(), &paths)?;
        let raw = fs::read_to_string(&paths.config)?;
        let mut doc: toml::Value = toml::from_str(&raw)?;
        doc["version"] = toml::Value::Integer((CONFIG_VERSION + 1) as i64);
        fs::write(&paths.config, toml::to_string_pretty(&doc)?)?;

        let err = load(&paths).expect_err("version mismatch should error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("version") && msg.contains(&(CONFIG_VERSION + 1).to_string()),
            "error should mention version mismatch: {msg}"
        );

        fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn missing_identity_errors_cleanly() {
        let dir = fresh_dir("missing");
        let paths = test_paths(&dir);
        let err = load(&paths).expect_err("should fail without identity");
        let msg = format!("{err:#}");
        assert!(msg.contains("age.key"), "error should mention key path: {msg}");
        fs::remove_dir_all(&dir).ok();
    }
}
