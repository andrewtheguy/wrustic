//! Headless entry points for scripts and scheduled tasks: `env`, `profiles`
//! and `import`. Nothing here starts the TUI or prompts — the passphrase
//! comes from `WRUSTIC_PASSPHRASE` or the OS keychain, and every failure is a
//! plain error on stderr with a non-zero exit.

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

use crate::cli::Command;
use crate::config::{self, Config, Paths, Profile};
use crate::crypto::Cipher;
use crate::passphrase;

/// Overrides the keychain when set. This is the only non-interactive way in
/// for builds without the `keychain` feature (or hosts without a keyring).
pub(crate) const PASSPHRASE_ENV: &str = "WRUSTIC_PASSPHRASE";

pub(crate) fn run(command: Command, paths: Paths, no_keychain: bool) -> Result<()> {
    match command {
        Command::Profiles { json } => run_profiles(&paths, json),
        Command::Env { profile, json } => run_env(&paths, &profile, json, no_keychain),
    }
}

/// Profile names are the plaintext keys of the profiles table, so listing
/// them needs neither the passphrase nor the config lock.
fn run_profiles(paths: &Paths, json: bool) -> Result<()> {
    let config = peek_existing(paths)?;
    let names: Vec<&String> = config.profiles.keys().collect();
    if json {
        println!("{}", serde_json::to_string(&names)?);
    } else {
        for name in names {
            println!("{name}");
        }
    }
    Ok(())
}

fn run_env(paths: &Paths, profile_name: &str, json: bool, no_keychain: bool) -> Result<()> {
    // Read-only, and the config file is replaced atomically on save — no need
    // to contend for the exclusive config lock a running TUI holds.
    let config = unlock(paths, no_keychain)?;
    let Some(profile) = config.profiles.get(profile_name) else {
        let available = config
            .profiles
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        bail!("no profile `{profile_name}` in {} (available: {available})", paths.config.display());
    };
    let vars = env_vars(profile)?;
    if json {
        let map: serde_json::Map<String, serde_json::Value> = vars
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        println!("{}", serde_json::to_string(&map)?);
    } else {
        for (key, value) in vars {
            // KEY=VALUE consumers are line-oriented; a value with a line break
            // would silently truncate a secret. JSON mode carries anything.
            if value.contains('\n') || value.contains('\r') {
                bail!("value of {key} contains a line break — use --json");
            }
            println!("{key}={value}");
        }
    }
    Ok(())
}

/// The environment restic needs for `profile`, in a stable order. Matches
/// what [`crate::restic::run`] sets when wrustic shells out itself, except the
/// repository password rides in `RESTIC_PASSWORD` — the consumer is a script
/// handing the whole map to restic, not our stdin pipe.
fn env_vars(profile: &Profile) -> Result<Vec<(String, String)>> {
    let mut vars = vec![
        ("RESTIC_REPOSITORY".to_string(), crate::restic::repo_url(profile)?),
        ("RESTIC_PASSWORD".to_string(), profile.password().to_string()),
    ];
    if let Profile::S3 {
        s3_access_key,
        s3_secret_key,
        s3_region,
        ..
    } = profile
    {
        vars.push(("AWS_ACCESS_KEY_ID".into(), s3_access_key.clone()));
        vars.push(("AWS_SECRET_ACCESS_KEY".into(), s3_secret_key.clone()));
        if !s3_region.is_empty() {
            vars.push(("AWS_DEFAULT_REGION".into(), s3_region.clone()));
        }
    }
    Ok(vars)
}

fn peek_existing(paths: &Paths) -> Result<Config> {
    config::peek(paths)?.ok_or_else(|| {
        anyhow!(
            "no config found at {} — run the wrustic TUI once to set it up",
            paths.config.display()
        )
    })
}

fn unlock(paths: &Paths, no_keychain: bool) -> Result<Config> {
    let cipher = unlock_cipher(paths, no_keychain)?;
    config::load(paths, &cipher)
}

/// Derive and verify the config key without any prompt. `peek` first so the
/// scrypt cost is only paid when there is actually a passphrase-protected
/// config to unlock.
fn unlock_cipher(paths: &Paths, no_keychain: bool) -> Result<Cipher> {
    let peeked = peek_existing(paths)?;
    let meta = peeked.passphrase.ok_or_else(|| {
        anyhow!(
            "config at {} has no [passphrase] block — finish setup in the TUI first",
            paths.config.display()
        )
    })?;
    let pass = resolve_passphrase(&meta.instance, no_keychain)?;
    let salt = BASE64
        .decode(&meta.salt)
        .context("bad base64 salt in [passphrase]")?;
    let key = passphrase::derive_config_key(&pass, &salt).map_err(|e| anyhow!(e))?;
    if !passphrase::verify_instance_sig(&meta.instance, &key, &meta.instance_sig) {
        bail!(
            "wrong passphrase for instance `{}` (or config.toml was corrupted)",
            meta.instance
        );
    }
    Ok(Cipher::new(key, meta.instance, &meta.instance_sig))
}

fn resolve_passphrase(instance: &str, no_keychain: bool) -> Result<String> {
    if let Ok(pass) = std::env::var(PASSPHRASE_ENV)
        && !pass.is_empty()
    {
        return Ok(pass);
    }
    #[cfg(feature = "keychain")]
    if !no_keychain
        && crate::keychain::init_store()
        && let Some(pass) = crate::keychain::load_passphrase(instance)
    {
        return Ok(pass);
    }
    bail!(
        "no passphrase available for instance `{instance}`: {PASSPHRASE_ENV} is not set and \
         no keychain entry was found (save the passphrase to the keychain from the TUI's \
         unlock screen, or export {PASSPHRASE_ENV})"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rest_profile() -> Profile {
        Profile::Rest {
            password: "repo-pw".into(),
            rest_url: "http://r.example.com:8000/repo".into(),
            rest_user: "andrew".into(),
            rest_password: "hunter2".into(),
        }
    }

    fn s3_profile() -> Profile {
        Profile::S3 {
            password: "pw".into(),
            s3_endpoint: "https://s3.example.com".into(),
            s3_bucket: "buk".into(),
            s3_region: "auto".into(),
            s3_root: "/sub".into(),
            s3_access_key: "AK".into(),
            s3_secret_key: "SK".into(),
        }
    }

    /// The env map is the automation contract scripts parse — repository URL
    /// with REST credentials embedded, and the repo password alongside.
    #[test]
    fn rest_env_vars_embed_rest_credentials() {
        let vars = env_vars(&rest_profile()).expect("env vars");
        assert_eq!(
            vars,
            vec![
                (
                    "RESTIC_REPOSITORY".to_string(),
                    "rest:http://andrew:hunter2@r.example.com:8000/repo".to_string()
                ),
                ("RESTIC_PASSWORD".to_string(), "repo-pw".to_string()),
            ]
        );
    }

    #[test]
    fn s3_env_vars_carry_aws_credentials() {
        let vars = env_vars(&s3_profile()).expect("env vars");
        assert_eq!(
            vars,
            vec![
                (
                    "RESTIC_REPOSITORY".to_string(),
                    "s3:https://s3.example.com/buk/sub".to_string()
                ),
                ("RESTIC_PASSWORD".to_string(), "pw".to_string()),
                ("AWS_ACCESS_KEY_ID".to_string(), "AK".to_string()),
                ("AWS_SECRET_ACCESS_KEY".to_string(), "SK".to_string()),
                ("AWS_DEFAULT_REGION".to_string(), "auto".to_string()),
            ]
        );
    }

}
