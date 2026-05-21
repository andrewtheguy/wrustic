use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use age::secrecy::ExposeSecret;
use age::x25519::{Identity, Recipient};
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

const CONFIG_DIR_NAME: &str = "wrustic";
const IDENTITY_FILE: &str = "age.key";
const CONFIG_FILE: &str = "config.toml.age";
const CONFIG_VERSION: u32 = 1;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "lowercase")]
pub enum Profile {
    Local {
        name: String,
        password: String,
        local_path: String,
    },
    Rest {
        name: String,
        password: String,
        rest_url: String,
    },
    S3 {
        name: String,
        password: String,
        s3_endpoint: String,
        s3_bucket: String,
        s3_region: String,
        s3_access_key: String,
        s3_secret_key: String,
    },
}

impl Profile {
    pub fn name(&self) -> &str {
        match self {
            Profile::Local { name, .. }
            | Profile::Rest { name, .. }
            | Profile::S3 { name, .. } => name,
        }
    }

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
    pub version: u32,
    #[serde(default)]
    pub profiles: Vec<Profile>,
}

impl Default for Config {
    fn default() -> Self {
        Self { version: CONFIG_VERSION, profiles: Vec::new() }
    }
}

impl Config {
    pub fn has_profile(&self, name: &str) -> bool {
        self.profiles.iter().any(|p| p.name() == name)
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
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("AGE-SECRET-KEY-") {
            return Identity::from_str(trimmed)
                .map_err(|e| anyhow!("parsing age identity in {}: {e}", path.display()));
        }
    }
    bail!("no AGE-SECRET-KEY line found in {}", path.display())
}

/// Load the config. If the config file does not exist, returns a default
/// (empty) config without touching disk. The identity must already exist.
pub fn load(paths: &Paths) -> Result<Config> {
    let identity = parse_identity_from_file(&paths.identity)?;

    if !paths.config.exists() {
        return Ok(Config::default());
    }

    let ciphertext = fs::read(&paths.config)
        .with_context(|| format!("reading {}", paths.config.display()))?;
    let plaintext = age::decrypt(&identity, &ciphertext)
        .map_err(|e| anyhow!("decrypting {}: {e}", paths.config.display()))?;
    let text = String::from_utf8(plaintext)
        .context("config file is not valid UTF-8 after decryption")?;
    let config: Config = toml::from_str(&text)
        .with_context(|| format!("parsing TOML from {}", paths.config.display()))?;
    if config.version != CONFIG_VERSION {
        bail!(
            "config at {} has version {} but this build of wrustic expects version {} \
             (no migrations are supported — this is a personal tool with no backwards compatibility)",
            paths.config.display(),
            config.version,
            CONFIG_VERSION
        );
    }
    Ok(config)
}

/// Encrypt and write the config atomically. Identity is loaded from the
/// identity file to derive the recipient.
pub fn save(config: &Config, paths: &Paths) -> Result<()> {
    let identity = parse_identity_from_file(&paths.identity)?;
    let recipient: Recipient = identity.to_public();

    let text = toml::to_string_pretty(config).context("serializing config to TOML")?;
    let armored = age::encrypt_and_armor(&recipient, text.as_bytes())
        .map_err(|e| anyhow!("encrypting config: {e}"))?;

    if let Some(parent) = paths.config.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    let tmp = paths.config.with_extension("age.tmp");
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        file.write_all(armored.as_bytes())
            .with_context(|| format!("writing {}", tmp.display()))?;
        file.sync_all().ok();
    }
    fs::rename(&tmp, &paths.config)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), paths.config.display()))?;
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
            config: dir.join("config.toml.age"),
        }
    }

    #[test]
    fn round_trip_encrypt_decrypt() -> Result<()> {
        let dir = fresh_dir("rt");
        let paths = test_paths(&dir);

        let pubkey = generate_identity(&paths.identity)?;
        assert!(paths.identity.exists());
        assert!(pubkey.starts_with("age1"), "expected age1 recipient, got {pubkey}");

        // round-trip: parsing back yields the same public key
        assert_eq!(validate_identity(&paths.identity)?, pubkey);

        // empty load works before any save
        let empty = load(&paths)?;
        assert_eq!(empty.profiles.len(), 0);
        assert_eq!(empty.version, CONFIG_VERSION);

        let cfg = Config {
            version: CONFIG_VERSION,
            profiles: vec![
                Profile::Local {
                    name: "local-a".into(),
                    password: "pw1".into(),
                    local_path: "/var/restic/a".into(),
                },
                Profile::S3 {
                    name: "s3-b".into(),
                    password: "pw2".into(),
                    s3_endpoint: "https://s3.example.com".into(),
                    s3_bucket: "buk".into(),
                    s3_region: "us-east-1".into(),
                    s3_access_key: "AK".into(),
                    s3_secret_key: "SK".into(),
                },
                Profile::Rest {
                    name: "rest-c".into(),
                    password: "pw3".into(),
                    rest_url: "https://r.example.com/repo".into(),
                },
            ],
        };
        save(&cfg, &paths)?;
        assert!(paths.config.exists());

        // ciphertext must be armored ASCII
        let raw = fs::read_to_string(&paths.config)?;
        assert!(raw.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));

        let loaded = load(&paths)?;
        assert_eq!(loaded.profiles.len(), 3);
        assert_eq!(loaded.profiles[0].name(), "local-a");
        assert_eq!(loaded.profiles[0].password(), "pw1");
        match &loaded.profiles[1] {
            Profile::S3 {
                s3_access_key,
                s3_secret_key,
                ..
            } => {
                assert_eq!(s3_access_key, "AK");
                assert_eq!(s3_secret_key, "SK");
            }
            other => panic!("expected S3, got {other:?}"),
        }
        match &loaded.profiles[2] {
            Profile::Rest { rest_url, .. } => assert_eq!(rest_url, "https://r.example.com/repo"),
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
        assert_eq!(p.config, dir.join("config.toml.age"));
        fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn load_rejects_unknown_version() -> Result<()> {
        let dir = fresh_dir("ver");
        let paths = test_paths(&dir);
        generate_identity(&paths.identity)?;

        // Save a config claiming a future version, then expect load() to refuse it.
        let future = Config {
            version: CONFIG_VERSION + 1,
            profiles: Vec::new(),
        };
        save(&future, &paths)?;

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
