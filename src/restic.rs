//! Secure harness for running restic CLI commands.
//!
//! Snapshot delete and unlock are native (src/repo.rs + src/lock.rs), so no
//! TUI flow shells out to restic anymore — this module is kept as the one
//! sanctioned way to trigger the restic commands wrustic deliberately does
//! not reimplement (prune, repair, migrate, dev-flow repo setup). Secrets
//! never touch argv: the master password is piped through the child's stdin
//! (`--password-file /dev/stdin`), the repo URL and any cloud credentials go
//! through env vars.

use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{Result, anyhow};

use crate::config::Profile;

const MIN_MAJOR: u32 = 0;
const MIN_MINOR: u32 = 18;
const MIN_PATCH: u32 = 1;

#[allow(dead_code)] // harness for future flows (prune etc.); not TUI-wired yet
pub(crate) struct ResticInfo;

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum ResticError {
    NotFound,
    TooOld { found: String },
    Unparseable { output: String },
}

impl ResticError {
    #[allow(dead_code)]
    pub(crate) fn user_message(&self) -> String {
        let min = format!("{MIN_MAJOR}.{MIN_MINOR}.{MIN_PATCH}");
        match self {
            ResticError::NotFound => format!(
                "restic not found on PATH. Install restic >= {min} to run restic commands."
            ),
            ResticError::TooOld { found } => format!(
                "restic {found} found on PATH, but >= {min} is required to run restic commands."
            ),
            ResticError::Unparseable { output } => {
                format!("Could not parse restic version output: {output}")
            }
        }
    }
}

#[allow(dead_code)]
pub(crate) fn detect() -> Result<ResticInfo, ResticError> {
    let output = match Command::new("restic").arg("version").output() {
        Ok(o) => o,
        Err(_) => return Err(ResticError::NotFound),
    };
    if !output.status.success() {
        return Err(ResticError::Unparseable {
            output: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    // Format: "restic 0.18.1 compiled with go1.25.1 on linux/amd64"
    let version = stdout
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| ResticError::Unparseable { output: stdout.clone() })?;
    let (major, minor, patch) = parse_version(version)
        .ok_or_else(|| ResticError::Unparseable { output: stdout.clone() })?;
    if (major, minor, patch) < (MIN_MAJOR, MIN_MINOR, MIN_PATCH) {
        return Err(ResticError::TooOld { found: version.to_string() });
    }
    Ok(ResticInfo)
}

fn parse_version(v: &str) -> Option<(u32, u32, u32)> {
    let mut it = v.split('.');
    let major: u32 = it.next()?.parse().ok()?;
    let minor: u32 = it.next()?.parse().ok()?;
    // Patch may carry a suffix like "1-dev"; take the leading digits.
    let patch_raw = it.next()?;
    let patch_digits: String = patch_raw.chars().take_while(|c| c.is_ascii_digit()).collect();
    let patch: u32 = patch_digits.parse().ok()?;
    Some((major, minor, patch))
}

/// Run `restic <args>` for a profile with credentials passed by the safest
/// mechanism each supports, returning restic's stdout. Never put secrets in
/// argv. Master password is piped via the child's stdin
/// (`--password-file /dev/stdin`); the repo URL and any cloud creds go
/// through env vars (override-only — parent env is inherited so PATH, HOME,
/// SSL_CERT_FILE, HTTP_PROXY, etc. still flow through).
#[allow(dead_code)]
pub(crate) fn run(profile: &Profile, args: &[&str]) -> Result<Vec<u8>> {
    let mut cmd = Command::new("restic");
    cmd.arg("--password-file").arg("/dev/stdin");
    cmd.args(args);
    cmd.env("RESTIC_REPOSITORY", repo_url(profile)?);
    match profile {
        Profile::Local { .. } | Profile::Rest { .. } => {}
        Profile::S3 {
            s3_access_key,
            s3_secret_key,
            s3_region,
            ..
        } => {
            cmd.env("AWS_ACCESS_KEY_ID", s3_access_key);
            cmd.env("AWS_SECRET_ACCESS_KEY", s3_secret_key);
            if !s3_region.is_empty() {
                cmd.env("AWS_DEFAULT_REGION", s3_region);
            }
        }
    }
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow!("failed to spawn `restic`: {e}"))?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("failed to open restic stdin"))?;
        stdin
            .write_all(profile.password().as_bytes())
            .map_err(|e| anyhow!("writing password to restic stdin: {e}"))?;
        stdin
            .write_all(b"\n")
            .map_err(|e| anyhow!("writing newline to restic stdin: {e}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| anyhow!("waiting on restic: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(anyhow!(
            "restic exited with status {}: {}",
            output.status,
            if stderr.is_empty() { "(no stderr)" } else { &stderr }
        ));
    }
    Ok(output.stdout)
}

fn repo_url(profile: &Profile) -> Result<String> {
    match profile {
        Profile::Local { local_path, .. } => Ok(local_path.clone()),
        Profile::Rest {
            rest_url,
            rest_user,
            rest_password,
            ..
        } => {
            let mut url = url::Url::parse(rest_url)
                .map_err(|e| anyhow!("parsing REST URL `{rest_url}`: {e}"))?;
            if !rest_user.is_empty() {
                url.set_username(rest_user)
                    .map_err(|_| anyhow!("REST URL `{rest_url}` cannot carry a username"))?;
            }
            if !rest_password.is_empty() {
                url.set_password(Some(rest_password))
                    .map_err(|_| anyhow!("REST URL `{rest_url}` cannot carry a password"))?;
            }
            Ok(format!("rest:{url}"))
        }
        Profile::S3 {
            s3_endpoint,
            s3_bucket,
            s3_root,
            ..
        } => {
            // restic accepts `s3:<endpoint>/<bucket>[/<path>]`. When no
            // endpoint is set, default to AWS by using the bucket-only form;
            // restic's S3 backend reads the region from AWS_DEFAULT_REGION.
            let endpoint = if s3_endpoint.is_empty() {
                "s3.amazonaws.com".to_string()
            } else {
                // Strip scheme + trailing slash so the URL composes cleanly.
                s3_endpoint
                    .trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .trim_end_matches('/')
                    .to_string()
            };
            let root = s3_root.trim_matches('/');
            if root.is_empty() {
                Ok(format!("s3:{endpoint}/{s3_bucket}"))
            } else {
                Ok(format!("s3:{endpoint}/{s3_bucket}/{root}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_version_string() {
        assert_eq!(parse_version("0.18.1"), Some((0, 18, 1)));
        assert_eq!(parse_version("1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("0.18.1-dev"), Some((0, 18, 1)));
        assert_eq!(parse_version("not-a-version"), None);
        assert_eq!(parse_version("0.18"), None);
    }

    #[test]
    fn repo_url_local() {
        let p = Profile::Local {
            password: "pw".into(),
            local_path: "/var/restic/a".into(),
        };
        assert_eq!(repo_url(&p).unwrap(), "/var/restic/a");
    }

    #[test]
    fn repo_url_rest_no_auth() {
        let p = Profile::Rest {
            password: "pw".into(),
            rest_url: "https://r.example.com/repo/".into(),
            rest_user: String::new(),
            rest_password: String::new(),
        };
        assert_eq!(repo_url(&p).unwrap(), "rest:https://r.example.com/repo/");
    }

    #[test]
    fn repo_url_rest_with_auth() {
        let p = Profile::Rest {
            password: "pw".into(),
            rest_url: "https://r.example.com/repo/".into(),
            rest_user: "andrew".into(),
            rest_password: "hunter2".into(),
        };
        assert_eq!(
            repo_url(&p).unwrap(),
            "rest:https://andrew:hunter2@r.example.com/repo/"
        );
    }

    #[test]
    fn repo_url_s3_aws() {
        let p = Profile::S3 {
            password: "pw".into(),
            s3_endpoint: String::new(),
            s3_bucket: "my-bucket".into(),
            s3_region: "us-east-1".into(),
            s3_root: String::new(),
            s3_access_key: "AK".into(),
            s3_secret_key: "SK".into(),
        };
        assert_eq!(repo_url(&p).unwrap(), "s3:s3.amazonaws.com/my-bucket");
    }

    #[test]
    fn repo_url_s3_custom_endpoint_with_root() {
        let p = Profile::S3 {
            password: "pw".into(),
            s3_endpoint: "http://127.0.0.1:8333/".into(),
            s3_bucket: "buk".into(),
            s3_region: "us-east-1".into(),
            s3_root: "/sub/dir/".into(),
            s3_access_key: "AK".into(),
            s3_secret_key: "SK".into(),
        };
        assert_eq!(repo_url(&p).unwrap(), "s3:127.0.0.1:8333/buk/sub/dir");
    }

    // End-to-end: actually shells out to `restic` against a fresh local repo.
    // Marked #[ignore] so it doesn't run unless requested
    // (`cargo test -- --ignored`). Validates the stdin password channel, env
    // var wiring, and a real `prune` — i.e. the full run() pipeline for the
    // kind of command this harness exists for.
    #[test]
    #[ignore]
    fn live_restic_run_snapshots_and_prune() {
        use std::fs;
        use std::path::PathBuf;

        let root = PathBuf::from("tmp").join(format!("restic-it-{}", std::process::id()));
        let repo = root.join("repo");
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("a.txt"), b"hello\n").unwrap();

        let setup = |args: &[&str]| {
            let out = Command::new("restic")
                .args(args)
                .env("RESTIC_REPOSITORY", &repo)
                .env("RESTIC_PASSWORD", "pw")
                .output()
                .expect("running restic");
            assert!(out.status.success(), "restic {args:?} failed: {out:?}");
        };
        setup(&["init"]);
        setup(&["backup", source.to_str().unwrap()]);
        fs::write(source.join("a.txt"), b"hello again\n").unwrap();
        setup(&["backup", source.to_str().unwrap()]);

        let profile = Profile::Local {
            password: "pw".into(),
            local_path: repo.to_string_lossy().into_owned(),
        };

        // List snapshots through the harness (exercises stdin-password path).
        let list = run(&profile, &["snapshots", "--json"]).expect("snapshots");
        let arr: serde_json::Value = serde_json::from_slice(&list).expect("parse list");
        let snaps = arr.as_array().expect("snapshot array");
        assert_eq!(snaps.len(), 2, "expected two snapshots");
        let first = snaps[0]["id"].as_str().expect("snapshot id").to_string();

        // Drop one snapshot, then prune through the harness — the command
        // this module is kept for.
        run(&profile, &["forget", &first]).expect("forget");
        run(&profile, &["prune"]).expect("prune");

        let after = run(&profile, &["snapshots", "--json"]).expect("after-list");
        let arr_after: serde_json::Value = serde_json::from_slice(&after).expect("parse after");
        assert_eq!(arr_after.as_array().map(Vec::len), Some(1));

        fs::remove_dir_all(&root).ok();
    }
}
