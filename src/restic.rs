//! Secure harness for running restic CLI commands.
//!
//! Snapshot delete and unlock in the TUI are native (src/repo.rs +
//! src/lock.rs); this module is the one sanctioned way to trigger the restic
//! commands wrustic deliberately does not reimplement (prune, repair,
//! migrate, dev-flow repo setup). The TUI's prune flow (`p` on the Snapshots
//! screen) is its first caller, via [`run_unsticking_locks`].
//! Launch semantics mirror resterm's: secrets never touch argv — the
//! master password is piped through the child's stdin (`--password-file
//! /dev/stdin` on Unix; on Windows restic reads its non-terminal stdin
//! directly), the repo URL and any cloud credentials go through env vars —
//! and restic's on-disk cache is off (`--no-cache`) unless the user opts in
//! with `--restic-cache`, which points restic at a directory private to
//! wrustic.
//!
//! Restic checks the repository lock before any of these commands run, so a
//! leftover lock blocks them with "repository is already locked". wrustic
//! speaks the lock protocol natively (src/lock.rs), so
//! [`run_unsticking_locks`] performs restic's own acquisition conflict check
//! *before* spawning: it maps the subcommand to the lock restic takes for it
//! ([`lock_requirement`]), evaluates the repo's lock files natively, and only
//! when blocked runs restic's own `unlock` (which removes only
//! provably-stale locks) through this same harness and re-checks — never the
//! native stale-lock removal in src/lock.rs, which is for the native write
//! flows. restic's in-process check at spawn time remains the authoritative
//! gate.

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

/// Whether `--restic-cache` is on — the prune confirmation screen tells the
/// user which cache mode the run will carry.
pub(crate) fn cache_enabled() -> bool {
    CACHE_ENABLED.load(Ordering::Relaxed)
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

pub(crate) struct ResticInfo;

#[derive(Debug)]
pub(crate) enum ResticError {
    NotFound,
    TooOld { found: String },
    Unparseable { output: String },
}

impl ResticError {
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
pub(crate) fn unlock(profile: &Profile) -> Result<()> {
    run(profile, &["unlock", "--json"])?;
    Ok(())
}

/// The lock restic itself takes for a subcommand — restic 0.19.1's
/// per-command table (docs/locking.md "Per-command lock usage").
#[derive(Debug, PartialEq, Eq)]
enum LockRequirement {
    None,
    NonExclusive,
    Exclusive,
}

/// Map a harness invocation to the lock its restic subcommand will take, so
/// the native pre-check in [`run_unsticking_locks`] applies exactly restic's
/// conflict rules for it. The subcommand is found by scanning the non-flag
/// arguments for a known restic command name — the first non-flag argument
/// alone would be fooled by a flag's *value* (`["--cache-dir", "foo",
/// "prune"]`). A flag value that happens to spell a command name can still
/// match first, which at worst makes the pre-check stricter, and restic's own
/// in-process check stays authoritative either way.
fn lock_requirement(args: &[&str]) -> LockRequirement {
    let mut saw_candidate = false;
    for arg in args.iter().filter(|a| !a.starts_with('-')) {
        saw_candidate = true;
        match *arg {
            // `key add` alone is non-exclusive in restic, but treating all of
            // `key` as exclusive only makes the pre-check stricter, never
            // wrong.
            "forget" | "prune" | "tag" | "key" | "check" | "repair" | "migrate" | "recover"
            | "rewrite" => return LockRequirement::Exclusive,
            "unlock" | "init" | "self-update" | "version" => return LockRequirement::None,
            "backup" | "copy" | "restore" | "mount" | "ls" | "snapshots" | "stats" | "find"
            | "diff" | "dump" | "cat" | "list" => return LockRequirement::NonExclusive,
            _ => {} // a flag's value or a positional (snapshot id, path) — keep looking
        }
    }
    // No recognized command. A non-flag argument means *some* subcommand is
    // being run — assume the weaker non-exclusive lock; flags-only means
    // nothing to lock for.
    if saw_candidate {
        LockRequirement::NonExclusive
    } else {
        LockRequirement::None
    }
}

/// Run a restic command that takes a repository lock (prune, repair, …),
/// unsticking the repo first when a leftover lock would block it.
///
/// This mirrors the lock check restic itself performs before doing any work
/// — the same protocol, evaluated natively (src/lock.rs) against the lock
/// restic takes for this subcommand — so a blocked spawn is known *before*
/// restic runs. When blocked, `restic unlock` — restic's own stale-lock
/// removal, through the same harness — is run and the check repeats. A
/// *live* lock (a running restic or a wrustic native write) is not removed
/// by unlock, so the re-check fails with a lock error carrying the holder's
/// details, returned for the caller to surface. restic re-runs the same
/// check in-process at startup, so a lock appearing in the window between
/// our re-check and the spawn still fails safely inside restic.
#[allow(dead_code)] // the TUI's prune uses the streaming variant; kept for future non-interactive flows (repair, migrate) and exercised by the live test
pub(crate) fn run_unsticking_locks(profile: &Profile, args: &[&str]) -> Result<Vec<u8>> {
    unstick_if_blocked(profile, args)?;
    run(profile, args)
}

/// Tracks the PID of the restic child currently running through this harness
/// so another thread can interrupt it (the TUI's Ctrl+C on the prune screen).
/// 0 means no child is running.
#[derive(Debug, Default)]
pub(crate) struct ChildTracker {
    pid: std::sync::atomic::AtomicU32,
}

impl ChildTracker {
    /// Ask the tracked restic (if any) to stop. Interrupting restic is safe
    /// by design: it never removes data still in use — new packs and indexes
    /// are written before old ones are deleted — so a killed prune only
    /// leaves the remaining work for the next run.
    ///
    /// Unix sends SIGINT, the same signal a terminal Ctrl+C delivers, which
    /// restic catches to clean up and remove its repository lock. Windows has
    /// no cross-process Ctrl+C for a piped child, so the process is
    /// terminated; the lock it leaves behind names a dead PID, which the next
    /// spawn's unstick pre-check removes as stale.
    ///
    /// PID-reuse race: the child can exit between the load and the signal
    /// below. The window is a main-loop tick against the OS not recycling
    /// the PID in that instant — the same exposure every kill-by-PID has.
    pub(crate) fn interrupt(&self) {
        let pid = self.pid.load(Ordering::Relaxed);
        if pid == 0 {
            return;
        }
        #[cfg(unix)]
        unsafe {
            libc::kill(pid as i32, libc::SIGINT);
        }
        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};
            let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
            if !handle.is_null() {
                TerminateProcess(handle, 1);
                CloseHandle(handle);
            }
        }
    }
}

/// [`run_unsticking_locks`] with live output: each stdout line restic prints
/// is appended to `progress` as it arrives (restic reports progress on a
/// pipe too, roughly every 10 s when stdout is not a terminal), the child's
/// PID is registered on `tracker` so it can be interrupted, and the full
/// stdout is still returned at the end.
pub(crate) fn run_unsticking_locks_streaming(
    profile: &Profile,
    args: &[&str],
    tracker: &ChildTracker,
    progress: &std::sync::Mutex<String>,
) -> Result<Vec<u8>> {
    unstick_if_blocked(profile, args)?;
    run_streaming(profile, args, tracker, progress)
}

/// The native pre-spawn lock check shared by both unsticking runners: apply
/// restic's acquisition conflict rules for this subcommand's lock, and when
/// blocked run restic's own `unlock` (stale locks only) and re-check.
fn unstick_if_blocked(profile: &Profile, args: &[&str]) -> Result<()> {
    let exclusive = match lock_requirement(args) {
        LockRequirement::None => return Ok(()),
        LockRequirement::NonExclusive => false,
        LockRequirement::Exclusive => true,
    };
    let (backend, crypto) = crate::repo::lock_context(profile)?;
    if crate::lock::check_blocking_locks(backend.as_ref(), &crypto, exclusive).is_err() {
        unlock(profile)?;
        crate::lock::check_blocking_locks(backend.as_ref(), &crypto, exclusive)?;
    }
    Ok(())
}

/// [`run`], but streaming stdout line-by-line into `progress` and exposing
/// the child on `tracker` for interruption. stderr is drained on a helper
/// thread (so neither pipe can fill up and deadlock the child) and reported
/// on failure exactly like [`run`].
fn run_streaming(
    profile: &Profile,
    args: &[&str],
    tracker: &ChildTracker,
    progress: &std::sync::Mutex<String>,
) -> Result<Vec<u8>> {
    use std::io::{BufRead, BufReader, Read};

    let mut cmd = command(profile, args)?;
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow!("failed to spawn `restic`: {e}"))?;
    tracker.pid.store(child.id(), Ordering::Relaxed);
    let result = (|| {
        if let Err(e) = write_password(&mut child, profile) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
        let stderr = child.stderr.take().ok_or_else(|| anyhow!("restic stderr not piped"))?;
        let stderr_thread = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let mut stderr = stderr;
            let _ = stderr.read_to_end(&mut buf);
            buf
        });
        let stdout = child.stdout.take().ok_or_else(|| anyhow!("restic stdout not piped"))?;
        let mut collected = Vec::new();
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            collected.extend_from_slice(line.as_bytes());
            collected.push(b'\n');
            if let Ok(mut p) = progress.lock() {
                p.push_str(&line);
                p.push('\n');
            }
        }
        let status = child.wait().map_err(|e| anyhow!("waiting on restic: {e}"))?;
        let stderr_buf = stderr_thread.join().unwrap_or_default();
        if !status.success() {
            let stderr = String::from_utf8_lossy(&stderr_buf).trim().to_string();
            return Err(anyhow!(
                "restic exited with status {}: {}",
                status,
                if stderr.is_empty() { "(no stderr)" } else { &stderr }
            ));
        }
        Ok(collected)
    })();
    tracker.pid.store(0, Ordering::Relaxed);
    result
}

/// Build a `restic <args>` command for a profile with credentials passed by
/// the safest mechanism each supports. Never put secrets in argv. Master
/// password is piped through an anonymous pipe on the child's stdin; the repo
/// URL and any cloud creds go through env vars (override-only — parent env is
/// inherited so PATH, HOME, SSL_CERT_FILE, HTTP_PROXY, etc. still flow
/// through).
///
/// Every command built here also carries the cache flag from
/// [`apply_cache_flag`]: `--no-cache` by default, or `--cache-dir <per-user
/// path>` under `--restic-cache`. Either way wrustic never lets restic use its
/// default on-disk cache, which other restic CLI instances share.
fn command(profile: &Profile, args: &[&str]) -> Result<Command> {
    let mut cmd = Command::new("restic");
    apply_cache_flag(&mut cmd);
    // Windows has no `/dev/stdin` path for restic to open. It doesn't need
    // one: when stdin is not a terminal — which it never is here, since
    // `command` always pipes it — restic falls back to reading the password
    // straight off stdin. So the flag is Unix-only and both platforms carry
    // the password over the same anonymous pipe.
    #[cfg(unix)]
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
pub(crate) fn run(profile: &Profile, args: &[&str]) -> Result<Vec<u8>> {
    let mut cmd = command(profile, args)?;
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow!("failed to spawn `restic`: {e}"))?;
    if let Err(e) = write_password(&mut child, profile) {
        // Don't leave a restic waiting forever on a password that will never
        // arrive (or a zombie once it exits). Cleanup failures are swallowed
        // so they can't mask the primary error.
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
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

    #[test]
    fn lock_requirement_matches_restics_per_command_table() {
        use LockRequirement::*;
        // Global flags before the subcommand don't confuse the mapping.
        assert_eq!(lock_requirement(&["--no-cache", "prune", "--json"]), Exclusive);
        for cmd in ["forget", "prune", "tag", "key", "check", "repair", "migrate", "recover", "rewrite"] {
            assert_eq!(lock_requirement(&[cmd, "--json"]), Exclusive, "{cmd}");
        }
        for cmd in ["unlock", "init", "self-update", "version"] {
            assert_eq!(lock_requirement(&[cmd, "--json"]), None, "{cmd}");
        }
        for cmd in ["backup", "copy", "restore", "ls", "snapshots", "stats", "find", "diff", "dump"] {
            assert_eq!(lock_requirement(&[cmd, "--json"]), NonExclusive, "{cmd}");
        }
        // A flag's value must not be mistaken for the subcommand.
        assert_eq!(lock_requirement(&["--cache-dir", "foo", "prune"]), Exclusive);
        assert_eq!(lock_requirement(&["--cache-dir", "foo", "snapshots"]), NonExclusive);
        // Unknown subcommand → the weaker non-exclusive assumption (restic's
        // own check stays authoritative).
        assert_eq!(lock_requirement(&["frobnicate"]), NonExclusive);
        // Flags only (degenerate) → no subcommand, no lock to check.
        assert_eq!(lock_requirement(&["--json"]), None);
    }

    // Unix-only: the assertion needs a child that dies to SIGINT the way
    // restic does; on Windows interrupt() terminates instead, which a live
    // prune would be needed to observe.
    #[cfg(unix)]
    #[test]
    fn child_tracker_interrupt_stops_a_running_child() {
        use std::sync::atomic::Ordering;

        let mut child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let tracker = ChildTracker::default();
        tracker.pid.store(child.id(), Ordering::Relaxed);
        tracker.interrupt();
        let status = child.wait().expect("wait for interrupted child");
        assert!(!status.success(), "SIGINT should have stopped the child");

        // With no tracked PID, interrupt must be a no-op (not signal PID 0 —
        // which would hit our own process group).
        ChildTracker::default().interrupt();
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
        #[cfg(unix)]
        let expected: &[&str] = &[
            "--no-cache",
            "--password-file",
            "/dev/stdin",
            "snapshots",
            "--json",
        ];
        // No `--password-file` on Windows: the password rides restic's
        // non-terminal stdin fallback instead. See `command`.
        #[cfg(windows)]
        let expected: &[&str] = &["--no-cache", "snapshots", "--json"];
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

        // The unstick flow: the native pre-check must detect the block
        // before spawning, run `restic unlock` (removing the stale lock),
        // pass the re-check, and only then spawn forget.
        run_unsticking_locks(&profile, &["forget", &first, "--json"])
            .expect("forget after unstick");
        assert_eq!(
            lock_backend.list().expect("list locks").len(),
            0,
            "unlock should have removed the stale lock and forget left none behind"
        );

        // A *live* lock must not be unstuck: hold a native shared lock (as a
        // concurrent backup would) and the exclusive prune must fail the
        // native re-check — `restic unlock` SIGHUP-probes our PID and keeps
        // the lock because we're alive and ignoring SIGHUP while holding it.
        {
            let _acquire = crate::lock::test_acquire_guard();
            let live = crate::lock::RepoLock::acquire_shared(
                lock_backend.clone(),
                crypto.clone(),
            )
            .expect("shared lock");
            let err = run_unsticking_locks(&profile, &["prune", "--json"])
                .expect_err("prune must stay blocked by a live lock");
            assert!(
                crate::lock::is_lock_error(&format!("{err:#}")),
                "expected a lock error, got: {err:#}"
            );
            assert_eq!(
                lock_backend.list().expect("list locks").len(),
                1,
                "the live lock must survive the unstick attempt"
            );
            drop(live);
        }

        // Prune through the harness — the command this module is kept for.
        // The streaming variant is what the TUI uses: restic's stdout must
        // land in the progress buffer line-by-line and still come back whole.
        let tracker = ChildTracker::default();
        let progress = std::sync::Mutex::new(String::new());
        let out = run_unsticking_locks_streaming(&profile, &["prune"], &tracker, &progress)
            .expect("prune");
        let streamed = progress.into_inner().expect("progress mutex");
        assert!(!streamed.is_empty(), "prune should have streamed progress lines");
        assert_eq!(
            String::from_utf8_lossy(&out),
            streamed,
            "collected stdout and streamed progress must match"
        );

        let after = run(&profile, &["snapshots", "--json"]).expect("after-list");
        let arr_after: serde_json::Value = serde_json::from_slice(&after).expect("parse after");
        assert_eq!(arr_after.as_array().map(Vec::len), Some(1));

        fs::remove_dir_all(&root).ok();
    }
}
