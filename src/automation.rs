//! Headless entry points for scripts and scheduled tasks: `env`, `profiles`
//! and `merge`. Nothing here starts the TUI — the passphrase comes from
//! `WRUSTIC_PASSPHRASE`, the file named by `WRUSTIC_PASSPHRASE_FILE`, or the
//! OS keychain, with a plain hidden-input prompt on the controlling terminal
//! as the interactive fallback. Without a terminal (scheduled tasks, cron)
//! there is no prompt to hang on: every failure is a plain error on stderr
//! with a non-zero exit.

use std::io::IsTerminal;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

use crate::cli::Command;
use crate::config::{self, Config, PassphraseMeta, Paths, Profile};
use crate::crypto::Cipher;
use crate::lock::WriteRetries;
use crate::passphrase;

/// Overrides the keychain when set. Together with [`PASSPHRASE_FILE_ENV`]
/// this is the non-interactive way in for builds without the `keychain`
/// feature (or hosts without a keyring).
pub(crate) const PASSPHRASE_ENV: &str = "WRUSTIC_PASSPHRASE";

/// Path to a file holding the passphrase. Keeps the secret out of the
/// process environment, where anything from `ps -e` to a crash dump can pick
/// it up — a scheduled task can point at a file only its own account reads.
pub(crate) const PASSPHRASE_FILE_ENV: &str = "WRUSTIC_PASSPHRASE_FILE";

pub(crate) fn run(command: Command, paths: Paths, no_keychain: bool) -> Result<()> {
    match command {
        Command::Profiles { json } => run_profiles(&paths, json),
        Command::Env { profile, json } => run_env(&paths, &profile, json, no_keychain),
        Command::Merge { profile, snapshots } => {
            run_merge(&paths, &profile, &snapshots, no_keychain)
        }
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
    let vars = env_vars(profile_named(&config, paths, profile_name)?)?;
    if json {
        let map: serde_json::Map<String, serde_json::Value> = vars
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        println!("{}", serde_json::to_string(&map)?);
    } else {
        print!("{}", render_dotenv(&vars)?);
    }
    Ok(())
}

fn profile_named<'a>(config: &'a Config, paths: &Paths, name: &str) -> Result<&'a Profile> {
    if let Some(profile) = config.profiles.get(name) {
        return Ok(profile);
    }
    if config.profiles.is_empty() {
        bail!(
            "no profile `{name}` in {} — the config has no profiles yet; create one in the TUI",
            paths.config.display()
        );
    }
    let available = config
        .profiles
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    bail!("no profile `{name}` in {} (available: {available})", paths.config.display());
}

/// What `merge` prints on stdout, as one JSON object — the contract scripts
/// parse, so a key is not renamed or dropped lightly.
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
struct MergeReport {
    /// The new snapshot's full id.
    snapshot_id: String,
    /// The full ids of the snapshots merged, in the order they were given.
    sources: Vec<String>,
    /// `repo::MergeOutcome::dropped_node_fields`.
    dropped_node_fields: Vec<String>,
    /// `repo::MergeOutcome::attempt_still_open`.
    late_write_possible: bool,
}

/// The TUI's merge (`M` on the snapshot list) without the TUI: the same
/// `repo::merge_snapshots`, under the same repository lock. Only the config
/// is read here, without its directory lock, so a TUI session may be open —
/// and may itself be working in the repository, which the repository lock
/// settles as it does between any two processes.
fn run_merge(
    paths: &Paths,
    profile_name: &str,
    snapshots: &[String; 2],
    no_keychain: bool,
) -> Result<()> {
    let config = unlock(paths, no_keychain)?;
    let profile = profile_named(&config, paths, profile_name)?;
    let retries = Arc::new(WriteRetries::default());
    stop_on_interrupt(Arc::clone(&retries))?;
    let report = merge(profile, snapshots, &retries)?;
    println!("{}", serde_json::to_string(&report)?);
    // On stderr as well: it is the one outcome that asks something of
    // whoever runs the repository, and a script may read only the id.
    if report.late_write_possible {
        eprintln!(
            "warning: a write the server reported as failed may still be stored later. Until \
             it has had time to finish, put off `restic prune`, `restic forget --prune`, \
             `restic repair index` and deleting the merged snapshot (docs/locking.md)."
        );
    }
    Ok(())
}

fn merge(
    profile: &Profile,
    snapshots: &[String; 2],
    retries: &Arc<WriteRetries>,
) -> Result<MergeReport> {
    let sources = crate::repo::resolve_snapshot_ids(profile, snapshots)?;
    // The merge asks this itself, but only once it holds the lock and has
    // loaded the index.
    if retries.stopped() {
        bail!("the merge was stopped before it began; nothing was written");
    }
    let outcome = crate::repo::merge_snapshots(profile, &sources, retries)?;
    Ok(MergeReport {
        snapshot_id: outcome.snapshot_id,
        sources,
        dropped_node_fields: outcome.dropped_node_fields,
        late_write_possible: outcome.attempt_still_open,
    })
}

/// Makes Ctrl+C and a termination request (SIGINT and SIGTERM on Unix, every
/// console control event on Windows) stop the merge the way Ctrl+C does on
/// the TUI's merging screen, instead of killing the process: killed, it
/// would leave its lock file in the repository and whatever write was under
/// way unaccounted for. Stopped, the merge returns — with an error, unless it
/// was already past its last write — and gives the lock up on the way.
///
/// SIGHUP stays as it was found. The lock module ignores it for as long as a
/// lock is held (restic probes a lock's holder with it), and a merge started
/// under `nohup` is meant to outlive its terminal.
fn stop_on_interrupt(retries: Arc<WriteRetries>) -> Result<()> {
    // `ctrlc` takes SIGHUP along with SIGTERM, so its disposition is read
    // before and put back after.
    #[cfg(unix)]
    let hangup = unsafe {
        let mut found: libc::sigaction = std::mem::zeroed();
        (libc::sigaction(libc::SIGHUP, std::ptr::null(), &mut found) == 0).then_some(found)
    };
    let installed = ctrlc::set_handler(move || {
        if !retries.stopped() {
            eprintln!(
                "Stopping the merge: no new write is begun and no failed one is tried again, \
                 though one already sent may still be stored. It ends when the step under way \
                 returns."
            );
        }
        retries.stop();
    });
    #[cfg(unix)]
    if let Some(found) = hangup {
        unsafe {
            let _ = libc::sigaction(libc::SIGHUP, &found, std::ptr::null_mut());
        }
    }
    installed.context("installing the handler that stops the merge on Ctrl+C")
}

/// KEY=VALUE lines. Line-oriented consumers would silently truncate a secret
/// containing a line break, so such values are refused — JSON mode carries
/// anything.
fn render_dotenv(vars: &[(String, String)]) -> Result<String> {
    let mut out = String::new();
    for (key, value) in vars {
        if value.contains('\n') || value.contains('\r') {
            bail!("value of {key} contains a line break — use --json");
        }
        out.push_str(key);
        out.push('=');
        out.push_str(value);
        out.push('\n');
    }
    Ok(out)
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

/// How many interactive prompts before giving up. Matches the tolerance of a
/// typo without letting a wrapper script that feeds wrong input loop forever.
const PROMPT_ATTEMPTS: u32 = 3;

/// Derive and verify the config key. `peek` first so the scrypt cost is only
/// paid when there is actually a passphrase-protected config to unlock.
fn unlock_cipher(paths: &Paths, no_keychain: bool) -> Result<Cipher> {
    let peeked = peek_existing(paths)?;
    let meta = peeked.passphrase.ok_or_else(|| {
        anyhow!(
            "config at {} has no [passphrase] block — finish setup in the TUI first",
            paths.config.display()
        )
    })?;
    let salt = BASE64
        .decode(&meta.salt)
        .context("bad base64 salt in [passphrase]")?;
    // A wrong *stored* passphrase fails outright instead of falling back to a
    // prompt: prompting would paper over a stale keychain entry or env var
    // that every unattended run is about to trip on.
    if let Some(pass) = stored_passphrase(&meta.instance, no_keychain)? {
        return cipher_from_passphrase(&pass, &salt, &meta);
    }
    if !std::io::stdin().is_terminal() {
        bail!(
            "no passphrase available for instance `{}`: neither {PASSPHRASE_ENV} nor \
             {PASSPHRASE_FILE_ENV} is set, no keychain entry was found, and there is no \
             terminal to prompt on (save the passphrase to the keychain from the TUI's \
             unlock screen, or export {PASSPHRASE_ENV} or {PASSPHRASE_FILE_ENV})",
            meta.instance
        );
    }
    unlock_via_prompts(&meta, &salt, PROMPT_ATTEMPTS, |_| {
        // rpassword prompts on the controlling terminal itself (/dev/tty,
        // CONIN$), not stdout — the prompt stays visible even when a script
        // is capturing the env output.
        rpassword::prompt_password(format!("Passphrase for instance `{}`: ", meta.instance))
            .context("reading passphrase from terminal")
    })
}

/// The interactive fallback: prompt, derive, verify, retry. Takes the reader
/// as a closure so the retry behaviour is testable without a terminal.
fn unlock_via_prompts(
    meta: &PassphraseMeta,
    salt: &[u8],
    attempts: u32,
    mut read_passphrase: impl FnMut(u32) -> Result<String>,
) -> Result<Cipher> {
    for attempt in 1..=attempts {
        let pass = read_passphrase(attempt)?;
        match cipher_from_passphrase(&pass, salt, meta) {
            Ok(cipher) => return Ok(cipher),
            Err(e) if attempt == attempts => return Err(e),
            Err(e) => eprintln!("{e:#}"),
        }
    }
    bail!("no passphrase attempts were made")
}

/// One derive-and-verify. The instance signature check gives a fast "wrong
/// passphrase" answer before any decryption is attempted.
fn cipher_from_passphrase(pass: &str, salt: &[u8], meta: &PassphraseMeta) -> Result<Cipher> {
    let key = passphrase::derive_config_key(pass, salt).map_err(|e| anyhow!(e))?;
    if !passphrase::verify_instance_sig(&meta.instance, &key, &meta.instance_sig) {
        bail!(
            "wrong passphrase for instance `{}` (or config.toml was corrupted)",
            meta.instance
        );
    }
    Ok(Cipher::new(key, meta.instance.clone(), &meta.instance_sig))
}

/// A passphrase from the process environment, with the variable it came from
/// so a caller can name the source in an error. `WRUSTIC_PASSPHRASE` wins
/// over `WRUSTIC_PASSPHRASE_FILE`; a file that cannot be read is an error
/// rather than a fall-through, because the caller named it and quietly
/// unlocking with something else would hide the misconfiguration until the
/// file mattered.
///
/// Shared with the TUI (`App::start_passphrase_flow`), which honours the same
/// two variables on its unlock screen — the environment means the same thing
/// whichever entry point reads it.
pub(crate) fn env_passphrase() -> Result<Option<(&'static str, String)>> {
    if let Ok(pass) = std::env::var(PASSPHRASE_ENV)
        && !pass.is_empty()
    {
        return Ok(Some((PASSPHRASE_ENV, pass)));
    }
    if let Some(path) = std::env::var_os(PASSPHRASE_FILE_ENV)
        && !path.is_empty()
    {
        return read_passphrase_file(path.as_ref()).map(|p| Some((PASSPHRASE_FILE_ENV, p)));
    }
    Ok(None)
}

/// The unattended sources, in override order: environment (variable or file),
/// then keychain. `None` means none of them had anything to offer — not that
/// a passphrase was wrong.
fn stored_passphrase(instance: &str, no_keychain: bool) -> Result<Option<String>> {
    // Only the keychain branch below consumes these; without the feature the
    // bindings would otherwise warn under -D warnings.
    #[cfg(not(feature = "keychain"))]
    let _ = (instance, no_keychain);
    if let Some((_, pass)) = env_passphrase()? {
        return Ok(Some(pass));
    }
    #[cfg(feature = "keychain")]
    if !no_keychain
        && crate::keychain::init_store()
        && let Some(pass) = crate::keychain::load_passphrase(instance)
    {
        return Ok(Some(pass));
    }
    Ok(None)
}

/// The file holds the passphrase and nothing else. Only the trailing line
/// ending is stripped — a passphrase may legitimately start or end with a
/// space, and trimming it would lock the caller out of their own config with
/// a "wrong passphrase" they cannot see.
fn read_passphrase_file(path: &std::path::Path) -> Result<String> {
    let raw = std::fs::read(path)
        .with_context(|| format!("reading {PASSPHRASE_FILE_ENV} ({})", path.display()))?;
    let text = String::from_utf8(raw).with_context(|| {
        format!(
            "{PASSPHRASE_FILE_ENV} ({}) is not valid UTF-8",
            path.display()
        )
    })?;
    let pass = text
        .strip_suffix('\n')
        .map_or(text.as_str(), |t| t.strip_suffix('\r').unwrap_or(t));
    if pass.is_empty() {
        bail!("{PASSPHRASE_FILE_ENV} ({}) is empty", path.display());
    }
    Ok(pass.to_string())
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

    /// Line-oriented consumers would silently truncate a secret containing a
    /// line break, so the KEY=VALUE writer refuses it and points at --json.
    #[test]
    fn dotenv_rejects_line_breaks_and_renders_single_line_values() {
        for bad in ["with\nnewline", "with\rcarriage-return"] {
            let vars = vec![("RESTIC_PASSWORD".to_string(), bad.to_string())];
            let err = render_dotenv(&vars).expect_err("line break must be refused");
            assert!(format!("{err:#}").contains("use --json"), "{err:#}");
        }

        let vars = vec![
            ("RESTIC_REPOSITORY".to_string(), "rest:http://h/repo".to_string()),
            ("RESTIC_PASSWORD".to_string(), "pw=with=equals".to_string()),
        ];
        assert_eq!(
            render_dotenv(&vars).expect("single-line values render"),
            "RESTIC_REPOSITORY=rest:http://h/repo\nRESTIC_PASSWORD=pw=with=equals\n"
        );
    }

    /// Scratch file under the project's tmp/, unique per test and per
    /// process so a parallel run never collides.
    fn passphrase_file(name: &str, contents: &[u8]) -> std::path::PathBuf {
        let dir = std::path::Path::new("tmp").join(format!("pwfile-{}-{}", name, std::process::id()));
        std::fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("passphrase");
        std::fs::write(&path, contents).expect("write passphrase file");
        path
    }

    /// The file is the passphrase verbatim, minus one trailing line ending —
    /// the artefact every editor adds. Interior and leading whitespace is
    /// part of the secret.
    #[test]
    fn passphrase_file_strips_only_the_trailing_line_ending() {
        for (name, contents, want) in [
            ("plain", &b"Right Passphrase 1!"[..], "Right Passphrase 1!"),
            ("lf", &b"Right Passphrase 1!\n"[..], "Right Passphrase 1!"),
            ("crlf", &b"Right Passphrase 1!\r\n"[..], "Right Passphrase 1!"),
            ("spaced", &b" pad ded \n"[..], " pad ded "),
            ("two-lf", &b"pw\n\n"[..], "pw\n"),
        ] {
            let path = passphrase_file(name, contents);
            assert_eq!(
                read_passphrase_file(&path).expect("readable passphrase file"),
                want,
                "case {name}"
            );
            std::fs::remove_dir_all(path.parent().expect("scratch dir")).ok();
        }
    }

    /// A named file that yields nothing is a misconfiguration, not a reason
    /// to unlock with some other source.
    #[test]
    fn passphrase_file_rejects_empty_and_missing_files() {
        let path = passphrase_file("empty", b"\n");
        let err = read_passphrase_file(&path).expect_err("an empty file must be refused");
        assert!(format!("{err:#}").contains("is empty"), "{err:#}");
        std::fs::remove_dir_all(path.parent().expect("scratch dir")).ok();

        let missing = std::path::Path::new("tmp").join("pwfile-does-not-exist");
        let err = read_passphrase_file(&missing).expect_err("a missing file must be refused");
        assert!(format!("{err:#}").contains(PASSPHRASE_FILE_ENV), "{err:#}");
    }

    /// Passphrase metadata whose signature verifies for exactly `pass`.
    fn meta_for(pass: &str, salt: &[u8]) -> PassphraseMeta {
        let instance = "test-instance";
        let key = passphrase::derive_config_key(pass, salt).expect("derive");
        PassphraseMeta {
            instance: instance.into(),
            instance_sig: passphrase::compute_instance_sig(instance, &key),
            salt: BASE64.encode(salt),
        }
    }

    /// The whole point of the prompt loop: a typo costs a retry, not the run.
    #[test]
    fn prompt_unlock_retries_wrong_passphrases_until_one_verifies() {
        let salt = [0x24u8; 32];
        let meta = meta_for("Right Passphrase 1!", &salt);
        let mut seen = Vec::new();
        unlock_via_prompts(&meta, &salt, 3, |attempt| {
            seen.push(attempt);
            Ok(if attempt < 3 {
                "wrong".into()
            } else {
                "Right Passphrase 1!".into()
            })
        })
        .expect("the third attempt verifies");
        assert_eq!(seen, vec![1, 2, 3]);
    }

    #[test]
    fn prompt_unlock_gives_up_after_the_last_wrong_attempt() {
        let salt = [0x25u8; 32];
        let meta = meta_for("Right Passphrase 1!", &salt);
        let mut calls = 0;
        let err = unlock_via_prompts(&meta, &salt, 2, |_| {
            calls += 1;
            Ok("wrong".into())
        })
        .expect_err("a wrong passphrase must not unlock");
        assert_eq!(calls, 2, "exactly the allowed attempts, no more");
        assert!(format!("{err:#}").contains("wrong passphrase"), "{err:#}");
    }

    /// A dead terminal (EOF, closed tty) ends the loop immediately — retrying
    /// a reader that cannot produce input would spin through the attempts.
    #[test]
    fn prompt_unlock_stops_on_a_reader_error() {
        let salt = [0x26u8; 32];
        let meta = meta_for("Right Passphrase 1!", &salt);
        let mut calls = 0;
        let err = unlock_via_prompts(&meta, &salt, 3, |_| {
            calls += 1;
            Err(anyhow!("tty gone"))
        })
        .expect_err("reader failure must propagate");
        assert_eq!(calls, 1);
        assert!(format!("{err:#}").contains("tty gone"), "{err:#}");
    }

    /// The headless merge end to end on a real repository: ids given as a
    /// script would have them — one in full, one cut short as restic prints
    /// it — and the report naming the snapshot that is then in the
    /// repository, under the keys the help text promises.
    #[test]
    fn merge_resolves_short_ids_and_reports_the_new_snapshot() {
        let _guard = crate::lock::test_acquire_guard();
        let fixture = crate::testrepo::TestRepo::init("headless-merge");
        let first = fixture.backup(&[("a.txt", b"a\n")], &[]);
        std::fs::remove_file(fixture.source_path().join("a.txt")).unwrap();
        let second = fixture.backup(&[("b.txt", b"b\n")], &[]);

        let given = [first[..8].to_ascii_uppercase(), second.clone()];
        let report = merge(fixture.profile(), &given, &Default::default()).expect("merge");
        assert_eq!(report.sources, vec![first.clone(), second.clone()]);
        assert!(!report.late_write_possible, "a local write is over when it returns");
        let rows = crate::repo::load_snapshots(fixture.profile()).expect("list snapshots").rows;
        assert_eq!(rows.len(), 3, "the sources are kept");
        assert!(report.snapshot_id != first && report.snapshot_id != second);
        assert!(rows.iter().any(|row| row.id == report.snapshot_id));
        assert_eq!(fixture.lock_count(), 0, "the lock is given up before the report");

        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "snapshot_id": report.snapshot_id,
                "sources": [first, second],
                "dropped_node_fields": report.dropped_node_fields,
                "late_write_possible": false,
            })
        );
    }

    /// A stop that arrives before the merge has begun — during the passphrase
    /// lookup or while short ids are resolved — ends it there: no lock is
    /// taken and nothing is written.
    #[test]
    fn a_merge_stopped_before_it_begins_writes_nothing() {
        let fixture = crate::testrepo::TestRepo::init("headless-merge-stopped");
        let first = fixture.backup(&[("a.txt", b"a\n")], &[]);
        let second = fixture.backup(&[("b.txt", b"b\n")], &[]);
        let before = fixture.fingerprint().expect("fingerprint");

        let retries = Arc::new(WriteRetries::default());
        retries.stop();
        let err = merge(fixture.profile(), &[first, second], &retries)
            .expect_err("a stopped merge must not run");
        assert!(format!("{err:#}").contains("stopped before it began"), "{err:#}");
        assert_eq!(fixture.fingerprint().expect("fingerprint"), before);
        assert_eq!(fixture.lock_count(), 0);
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
