//! Secure harness for running restic CLI commands.
//!
//! Snapshot delete and unlock in the TUI are native (src/repo.rs +
//! src/lock.rs), so no TUI flow shells out to restic anymore — this module is
//! kept as the one sanctioned way to trigger the restic commands wrustic
//! deliberately does not reimplement (prune, repair, migrate, dev-flow repo
//! setup). Launch semantics mirror resterm's: secrets never touch argv — the
//! master password is piped through the child's stdin (`--password-file
//! /dev/stdin`), the repo URL and any cloud credentials go through env vars —
//! and restic's on-disk cache is off (`--no-cache`) unless the user opts in
//! with `--restic-cache`, which points restic at a directory private to
//! wrustic.
//!
//! Restic checks the repository lock before any of these commands run, so a
//! leftover lock blocks them with "repository is already locked". Because the
//! blocked process is restic itself, the unstick path is restic's own
//! `unlock` (which removes only provably-stale locks) run through this same
//! harness — not the native stale-lock removal in src/lock.rs, which is for
//! the native write flows. [`run_unsticking_locks`] packages that flow: run,
//! and on a lock error unlock and retry once.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Result, anyhow};
use serde::Deserialize;

use crate::config::Profile;

// The floor is the 0.19 series — the release whose locking protocol and JSON
// output shapes wrustic is built against (docs/locking.md targets restic
// 0.19; restic < 0.19 compatibility is an explicit non-goal).
const MIN_MAJOR: u32 = 0;
const MIN_MINOR: u32 = 19;
const MIN_PATCH: u32 = 0;

/// wrustic's own restic cache directory, or `None` when no per-user cache
/// root can be determined.
///
/// `dirs::cache_dir()` is the per-user, per-platform cache root
/// (`$XDG_CACHE_HOME` or `~/.cache` on Linux). It already sits inside the
/// calling user's own home, and the `wrustic` component keeps it apart from
/// restic's default cache, so wrustic never shares cache state with another
/// restic CLI instance.
fn cache_dir() -> Option<PathBuf> {
    Some(dirs::cache_dir()?.join("wrustic"))
}

/// Whether `--restic-cache` was passed. Off by default: a restic cache costs real
/// disk space — hundreds of megabytes for a large repository — which is not
/// always a trade worth making, so wrustic only keeps one when asked.
static CACHE_ENABLED: AtomicBool = AtomicBool::new(false);

/// Set once from the command line, before any restic call is made.
pub(crate) fn set_cache_enabled(enabled: bool) {
    CACHE_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Add the cache flag every restic invocation carries.
///
/// Default is `--no-cache`. With `--restic-cache`, restic is pointed at
/// [`cache_dir`] instead — and if no per-user cache root can be named,
/// caching stays off rather than falling back to restic's own default, which
/// wrustic must not share with other restic CLI instances.
fn apply_cache_flag(cmd: &mut Command) {
    match cache_dir().filter(|_| CACHE_ENABLED.load(Ordering::Relaxed)) {
        Some(dir) => {
            cmd.arg("--cache-dir").arg(dir);
        }
        None => {
            cmd.arg("--no-cache");
        }
    }
}

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

#[derive(Debug, Deserialize)]
struct VersionDocument {
    version: String,
}

#[allow(dead_code)]
pub(crate) fn detect() -> Result<ResticInfo, ResticError> {
    let mut cmd = Command::new("restic");
    apply_cache_flag(&mut cmd);
    let output = match cmd.arg("version").arg("--json").output() {
        Ok(o) => o,
        Err(_) => return Err(ResticError::NotFound),
    };
    if !output.status.success() {
        return Err(ResticError::Unparseable {
            output: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    // {"message_type":"version","version":"0.19.1","go_version":"go1.26.4",…}
    // A restic old enough not to understand `--json` here lands in
    // `Unparseable`, which is an acceptable message for something that far
    // below the supported floor.
    let parsed: VersionDocument = serde_json::from_str(stdout.trim())
        .map_err(|_| ResticError::Unparseable { output: stdout.clone() })?;
    let (major, minor, patch) = parse_version(&parsed.version)
        .ok_or_else(|| ResticError::Unparseable { output: stdout.clone() })?;
    if !meets_minimum((major, minor, patch)) {
        return Err(ResticError::TooOld { found: parsed.version });
    }
    Ok(ResticInfo)
}

fn meets_minimum(found: (u32, u32, u32)) -> bool {
    found >= (MIN_MAJOR, MIN_MINOR, MIN_PATCH)
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

/// Remove stale repository locks via `restic unlock`. restic only deletes
/// locks it can prove are dead (owning process gone, or old enough that a
/// live owner would have refreshed it) — non-stale locks held by a running
/// process are left in place, which is why restic's own lock error message
/// points at this command. `--json` is passed so any message restic prints is
/// structured rather than prose; the exit status is what we act on.
#[allow(dead_code)]
pub(crate) fn unlock(profile: &Profile) -> Result<()> {
    run(profile, &["unlock", "--json"])?;
    Ok(())
}

/// Run a restic command that takes a repository lock (prune, repair, …),
/// unsticking the repo first when a leftover lock blocks it.
///
/// restic checks the lock before doing any work, so a crashed holder's lock
/// fails the command with "repository is already locked". When that happens
/// this runs `restic unlock` — restic's own stale-lock removal, through the
/// same harness — and retries once. A *live* lock (a running restic or a
/// wrustic native write) is not removed by unlock, so the retry fails with
/// the same lock error and that error is returned for the caller to surface.
#[allow(dead_code)]
pub(crate) fn run_unsticking_locks(profile: &Profile, args: &[&str]) -> Result<Vec<u8>> {
    match run(profile, args) {
        Err(err) if crate::lock::is_lock_error(&format!("{err:#}")) => {
            unlock(profile)?;
            run(profile, args)
        }
        other => other,
    }
}

/// Build a `restic <args>` command for a profile with credentials passed by
/// the safest mechanism each supports. Never put secrets in argv. Master
/// password is piped through an anonymous pipe on the child's stdin
/// (`--password-file /dev/stdin`); the repo URL and any cloud creds go
/// through env vars (override-only — parent env is inherited so PATH, HOME,
/// SSL_CERT_FILE, HTTP_PROXY, etc. still flow through).
///
/// Every command built here also carries the cache flag from
/// [`apply_cache_flag`]: `--no-cache` by default, or `--cache-dir <per-user
/// path>` under `--restic-cache`. Either way wrustic never lets restic use its
/// default on-disk cache, which other restic CLI instances share.
fn command(profile: &Profile, args: &[&str]) -> Result<Command> {
    let mut cmd = Command::new("restic");
    apply_cache_flag(&mut cmd);
    cmd.arg("--password-file").arg("/dev/stdin");
    cmd.args(args);
    // An explicit password file wins over these in restic, but removing them
    // ensures the caller's shell cannot accidentally leak an unrelated secret
    // into the child process.
    cmd.env_remove("RESTIC_PASSWORD");
    cmd.env_remove("RESTIC_PASSWORD_FILE");
    cmd.env_remove("RESTIC_PASSWORD_COMMAND");
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
    cmd.stdin(Stdio::piped());
    Ok(cmd)
}

fn write_password(child: &mut std::process::Child, profile: &Profile) -> Result<()> {
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("failed to open restic stdin"))?;
    stdin
        .write_all(profile.password().as_bytes())
        .map_err(|e| anyhow!("writing password to restic stdin: {e}"))?;
    stdin
        .write_all(b"\n")
        .map_err(|e| anyhow!("writing newline to restic stdin: {e}"))?;
    // Closing the pipe is significant: restic's password-file reader waits
    // for EOF before it can continue.
    drop(stdin);
    Ok(())
}

/// Run `restic <args>` for a profile and return restic's stdout. See
/// [`command`] for how credentials travel.
#[allow(dead_code)]
pub(crate) fn run(profile: &Profile, args: &[&str]) -> Result<Vec<u8>> {
    let mut cmd = command(profile, args)?;
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow!("failed to spawn `restic`: {e}"))?;
    write_password(&mut child, profile)?;
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
            // A scheme-less custom endpoint defaults to https, matching what
            // the native opendal S3 backend does with the same profile field.
            let endpoint = if s3_endpoint.is_empty() {
                "s3.amazonaws.com".to_string()
            } else {
                let endpoint = s3_endpoint.trim_end_matches('/');
                if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
                    endpoint.to_string()
                } else {
                    format!("https://{endpoint}")
                }
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
    fn minimum_is_the_0_19_series() {
        // The whole 0.19 line is accepted, starting at .0 — the release the
        // locking protocol (docs/locking.md) is written against.
        assert!(meets_minimum((0, 19, 0)));
        assert!(meets_minimum((0, 19, 1)));
        assert!(meets_minimum((0, 20, 0)));
        assert!(meets_minimum((1, 0, 0)));
        // Anything before it is refused.
        assert!(!meets_minimum((0, 18, 9)));
        assert!(!meets_minimum((0, 1, 0)));
    }

    #[test]
    fn user_message_quotes_the_minimum() {
        let msg = ResticError::TooOld { found: "0.18.1".into() }.user_message();
        assert!(msg.contains("0.19.0"), "message should name the floor: {msg}");
        assert!(msg.contains("0.18.1"), "message should name what was found: {msg}");
    }

    #[test]
    fn parses_version_string() {
        assert_eq!(parse_version("0.19.1"), Some((0, 19, 1)));
        assert_eq!(parse_version("1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("0.19.1-dev"), Some((0, 19, 1)));
        assert_eq!(parse_version("not-a-version"), None);
        assert_eq!(parse_version("0.19"), None);
    }

    fn test_profile() -> Profile {
        Profile::Local {
            password: "pw".into(),
            local_path: "/var/restic/a".into(),
        }
    }

    fn command_args(profile: &Profile) -> Vec<String> {
        command(profile, &["snapshots", "--json"])
            .unwrap()
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    // Both halves live in one test because the cache switch is process-wide,
    // and Rust runs tests in the same process on parallel threads — as two
    // tests they would race over it.
    #[test]
    fn cache_is_off_by_default_and_opts_in_to_a_private_per_user_directory() {
        let args = command_args(&test_profile());
        let expected: &[&str] = &[
            "--no-cache",
            "--password-file",
            "/dev/stdin",
            "snapshots",
            "--json",
        ];
        assert_eq!(args, expected);
        assert!(
            !args.iter().any(|arg| arg.contains("pw")),
            "the password must never reach argv: {args:?}"
        );

        // No per-user cache root on this machine means there is nothing to opt
        // into, and `--no-cache` above is the whole story.
        let Some(dir) = cache_dir() else { return };
        set_cache_enabled(true);
        let opted_in = command_args(&test_profile());
        set_cache_enabled(false);

        assert!(
            !opted_in.iter().any(|arg| arg == "--no-cache"),
            "opting in must not also disable the cache: {opted_in:?}"
        );
        let passed = opted_in
            .iter()
            .position(|arg| arg == "--cache-dir")
            .and_then(|i| opted_in.get(i + 1))
            .expect("--cache-dir and its path");
        assert_eq!(passed.as_str(), dir.to_string_lossy());
        // The per-user cache root sits inside the calling user's own home,
        // and the `wrustic` leaf keeps this out of restic's own default cache.
        assert!(
            dir.starts_with(dirs::cache_dir().expect("cache root")),
            "{dir:?} must sit under the per-user cache root"
        );
        assert!(dir.ends_with("wrustic"), "{dir:?}");

        // Restored, so the default-path assertions above still hold for any
        // test that runs after this one.
        assert_eq!(command_args(&test_profile()), args);
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
        assert_eq!(
            repo_url(&p).unwrap(),
            "s3:http://127.0.0.1:8333/buk/sub/dir"
        );
    }

    #[test]
    fn repo_url_s3_custom_endpoint_defaults_to_https() {
        let p = Profile::S3 {
            password: "pw".into(),
            s3_endpoint: "garage.example.com/".into(),
            s3_bucket: "buk".into(),
            s3_region: "garage".into(),
            s3_root: String::new(),
            s3_access_key: "AK".into(),
            s3_secret_key: "SK".into(),
        };
        assert_eq!(repo_url(&p).unwrap(), "s3:https://garage.example.com/buk");
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

        let profile = Profile::Local {
            password: "pw".into(),
            local_path: repo.to_string_lossy().into_owned(),
        };
        run(&profile, &["init", "--json"]).expect("init");
        run(&profile, &["backup", source.to_str().unwrap(), "--json"]).expect("backup");
        fs::write(source.join("a.txt"), b"hello again\n").unwrap();
        run(&profile, &["backup", source.to_str().unwrap(), "--json"]).expect("backup 2");

        // List snapshots through the harness (exercises stdin-password path).
        let list = run(&profile, &["snapshots", "--json"]).expect("snapshots");
        let arr: serde_json::Value = serde_json::from_slice(&list).expect("parse list");
        let snaps = arr.as_array().expect("snapshot array");
        assert_eq!(snaps.len(), 2, "expected two snapshots");
        let first = snaps[0]["id"].as_str().expect("snapshot id").to_string();

        // Plant an age-stale lock (well past restic's 30-minute staleness
        // timeout, so restic never PID-probes it — meaning no SIGHUP lands on
        // this test process). Plain `forget` must be blocked by it: restic
        // 0.19 never auto-removes stale locks during acquisition.
        let opened = crate::repo::open_indexed(&profile).expect("open for crypto");
        let crypto = crate::lock::RepoCrypto::from_repo(&opened).expect("crypto");
        let lock_backend = crate::lock::backend_for_profile(&profile).expect("lock backend");
        crate::lock::write_stale_lock_for_tests(lock_backend.as_ref(), &crypto);
        let err = run(&profile, &["forget", &first, "--json"])
            .expect_err("forget should be blocked by the stale lock");
        assert!(
            crate::lock::is_lock_error(&format!("{err:#}")),
            "expected a lock error, got: {err:#}"
        );

        // The unstick flow: same command through run_unsticking_locks must
        // run `restic unlock` (removing the stale lock) and succeed on retry.
        run_unsticking_locks(&profile, &["forget", &first, "--json"])
            .expect("forget after unstick");
        assert_eq!(
            lock_backend.list().expect("list locks").len(),
            0,
            "unlock should have removed the stale lock and forget left none behind"
        );

        // Prune through the harness — the command this module is kept for.
        run_unsticking_locks(&profile, &["prune", "--json"]).expect("prune");

        let after = run(&profile, &["snapshots", "--json"]).expect("after-list");
        let arr_after: serde_json::Value = serde_json::from_slice(&after).expect("parse after");
        assert_eq!(arr_after.as_array().map(Vec::len), Some(1));

        fs::remove_dir_all(&root).ok();
    }
}
