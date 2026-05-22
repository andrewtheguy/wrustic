use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{Result, anyhow};
use serde::Deserialize;

use crate::config::Profile;

const MIN_MAJOR: u32 = 0;
const MIN_MINOR: u32 = 18;
const MIN_PATCH: u32 = 1;

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
                "restic not found on PATH. Install restic >= {min} to delete snapshots."
            ),
            ResticError::TooOld { found } => format!(
                "restic {found} found on PATH, but >= {min} is required to delete snapshots."
            ),
            ResticError::Unparseable { output } => {
                format!("Could not parse restic version output: {output}")
            }
        }
    }
}

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

#[derive(Debug, Deserialize)]
pub(crate) struct SnapshotDetails {
    pub(crate) id: String,
    pub(crate) short_id: Option<String>,
    pub(crate) time: Option<String>,
    pub(crate) hostname: Option<String>,
    pub(crate) username: Option<String>,
    #[serde(default)]
    pub(crate) tags: Vec<String>,
    #[serde(default)]
    pub(crate) paths: Vec<String>,
    pub(crate) parent: Option<String>,
    pub(crate) tree: Option<String>,
    pub(crate) program_version: Option<String>,
    pub(crate) summary: Option<SnapshotSummary>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiffModifier {
    Added,
    Removed,
    Modified,
    TypeChanged,
    Other(char),
}

impl DiffModifier {
    pub(crate) fn parse(s: &str) -> Self {
        match s {
            "+" => DiffModifier::Added,
            "-" => DiffModifier::Removed,
            "M" => DiffModifier::Modified,
            "T" => DiffModifier::TypeChanged,
            // Restic may emit multi-char modifiers (e.g. "MM" for mode+mtime).
            // Keep the first char as the display glyph; anything unrecognised
            // still surfaces to the user instead of being silently dropped.
            _ => DiffModifier::Other(s.chars().next().unwrap_or('?')),
        }
    }

    pub(crate) fn as_char(self) -> char {
        match self {
            DiffModifier::Added => '+',
            DiffModifier::Removed => '-',
            DiffModifier::Modified => 'M',
            DiffModifier::TypeChanged => 'T',
            DiffModifier::Other(c) => c,
        }
    }
}

#[derive(Debug)]
pub(crate) struct DiffChange {
    pub(crate) modifier: DiffModifier,
    pub(crate) path: String,
}

// Flattened view of restic's `statistics` line. Restic emits `added` and
// `removed` as nested objects (`{files, dirs, others, bytes, ...}`) plus a
// top-level `changed_files`. We flatten here so the renderer sees a single
// struct.
#[derive(Debug, Default)]
pub(crate) struct DiffSummary {
    pub(crate) changed_files: u64,
    pub(crate) added_files: u64,
    pub(crate) added_bytes: u64,
    pub(crate) removed_files: u64,
    pub(crate) removed_bytes: u64,
}

#[derive(Debug, Default, Deserialize)]
struct DiffStatsBlock {
    #[serde(default)]
    files: u64,
    #[serde(default)]
    bytes: u64,
}

#[derive(Debug, Default, Deserialize)]
struct DiffStatisticsShim {
    #[serde(default)]
    changed_files: u64,
    #[serde(default)]
    added: DiffStatsBlock,
    #[serde(default)]
    removed: DiffStatsBlock,
}

impl From<DiffStatisticsShim> for DiffSummary {
    fn from(s: DiffStatisticsShim) -> Self {
        DiffSummary {
            changed_files: s.changed_files,
            added_files: s.added.files,
            added_bytes: s.added.bytes,
            removed_files: s.removed.files,
            removed_bytes: s.removed.bytes,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct SnapshotSummary {
    pub(crate) backup_start: Option<String>,
    pub(crate) backup_end: Option<String>,
    pub(crate) total_files_processed: Option<u64>,
    pub(crate) total_bytes_processed: Option<u64>,
    pub(crate) data_added: Option<u64>,
    pub(crate) data_added_packed: Option<u64>,
}

/// `snapshot_id` must be the full 64-char hex hash (enforced — short ids are
/// rejected to avoid prefix ambiguity). Errors if restic returns zero or more
/// than one matching snapshot.
pub(crate) fn snapshot_details_json(
    profile: &Profile,
    snapshot_id: &str,
) -> Result<(SnapshotDetails, String)> {
    ensure_full_snapshot_id(snapshot_id)?;
    let output = spawn(profile, &["snapshots", snapshot_id, "--json"])?;
    let stdout = String::from_utf8_lossy(&output).into_owned();
    let value: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| anyhow!("parsing restic snapshots JSON: {e}\nraw: {stdout}"))?;
    let pretty = serde_json::to_string_pretty(&value)
        .map_err(|e| anyhow!("pretty-printing JSON: {e}"))?;
    let first = match value {
        serde_json::Value::Array(mut arr) => match arr.len() {
            0 => return Err(anyhow!("restic returned no snapshot matching `{snapshot_id}`")),
            1 => arr.remove(0),
            n => {
                return Err(anyhow!(
                    "restic returned {n} snapshots matching `{snapshot_id}`, expected exactly one"
                ));
            }
        },
        _ => return Err(anyhow!("restic snapshots JSON was not an array: {stdout}")),
    };
    let one: SnapshotDetails = serde_json::from_value(first)
        .map_err(|e| anyhow!("converting JSON value to SnapshotDetails: {e}"))?;
    Ok((one, pretty))
}

/// `snapshot_id` must be the full 64-char hex hash (enforced — short ids are
/// rejected to avoid silently forgetting the wrong snapshot when a prefix
/// matches multiple).
pub(crate) fn forget(profile: &Profile, snapshot_id: &str) -> Result<()> {
    ensure_full_snapshot_id(snapshot_id)?;
    spawn(profile, &["forget", snapshot_id])?;
    Ok(())
}

/// Compare two snapshots via `restic diff <first> <second> --json`. Both ids
/// must be the full 64-char hex hash (enforced — see `ensure_full_snapshot_id`).
/// Output is line-delimited JSON; we parse `change` events into `DiffChange`s
/// and the final `statistics` line into `DiffSummary`. Unknown `message_type`s
/// are ignored so a future restic addition doesn't break the call.
pub(crate) fn diff(
    profile: &Profile,
    first: &str,
    second: &str,
) -> Result<(DiffSummary, Vec<DiffChange>)> {
    ensure_full_snapshot_id(first)?;
    ensure_full_snapshot_id(second)?;
    let output = spawn(profile, &["diff", first, second, "--json"])?;
    let stdout = String::from_utf8_lossy(&output);
    parse_diff_lines(&stdout)
}

fn parse_diff_lines(stdout: &str) -> Result<(DiffSummary, Vec<DiffChange>)> {
    let mut changes = Vec::new();
    let mut summary = DiffSummary::default();
    for raw in stdout.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| anyhow!("parsing restic diff JSON line `{line}`: {e}"))?;
        let kind = value.get("message_type").and_then(|v| v.as_str()).unwrap_or("");
        match kind {
            "change" => {
                let path = value
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("restic diff change line missing `path`: {line}"))?
                    .to_string();
                let modifier = value
                    .get("modifier")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("restic diff change line missing `modifier`: {line}"))?;
                changes.push(DiffChange {
                    modifier: DiffModifier::parse(modifier),
                    path,
                });
            }
            "statistics" => {
                let shim: DiffStatisticsShim = serde_json::from_value(value)
                    .map_err(|e| anyhow!("parsing restic diff statistics line: {e}"))?;
                summary = shim.into();
            }
            _ => {}
        }
    }
    Ok((summary, changes))
}

// restic/rustic snapshot ids are SHA-256 hashes — 32 bytes = 64 hex chars
// (either case accepted; hex is case-insensitive). Restic's CLI accepts
// shorter prefixes, but we refuse them so callers can't accidentally act on
// the wrong snapshot if a prefix matches multiple.
fn ensure_full_snapshot_id(id: &str) -> Result<()> {
    if id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(anyhow!(
            "expected a full 64-char hex snapshot id, got `{id}` (length {})",
            id.len()
        ))
    }
}

// Run `restic <args>` with credentials passed by the safest mechanism each
// supports. Never put secrets in argv. Master password is piped via the
// child's stdin (`--password-file /dev/stdin`); the repo URL and any cloud
// creds go through env vars (override-only — parent env is inherited so PATH,
// HOME, SSL_CERT_FILE, HTTP_PROXY, etc. still flow through).
fn spawn(profile: &Profile, args: &[&str]) -> Result<Vec<u8>> {
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

    #[test]
    fn snapshot_details_deserializes() {
        let raw = r#"[{
            "id": "fullid",
            "short_id": "abcd1234",
            "time": "2025-01-01T00:00:00Z",
            "hostname": "host",
            "username": "user",
            "tags": ["weekly"],
            "paths": ["/home"],
            "parent": "parentid",
            "tree": "treeid",
            "program_version": "restic 0.18.1",
            "summary": {
                "backup_start": "2025-01-01T00:00:00Z",
                "backup_end": "2025-01-01T00:00:05Z",
                "total_files_processed": 10,
                "total_bytes_processed": 1024,
                "data_added": 512,
                "data_added_packed": 500
            }
        }]"#;
        let arr: Vec<SnapshotDetails> = serde_json::from_str(raw).unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0].id, "fullid");
        assert_eq!(arr[0].short_id.as_deref(), Some("abcd1234"));
        assert_eq!(arr[0].tags, vec!["weekly"]);
        let sum = arr[0].summary.as_ref().unwrap();
        assert_eq!(sum.total_files_processed, Some(10));
    }

    #[test]
    fn full_snapshot_id_accepts_64_hex() {
        let full = "ceedd62f4a63412571eac929f67931fb9702f31b681387e446e61cae3e039e73";
        assert!(ensure_full_snapshot_id(full).is_ok());
    }

    #[test]
    fn full_snapshot_id_rejects_short_and_nonhex() {
        assert!(ensure_full_snapshot_id("ceedd62f").is_err());
        assert!(ensure_full_snapshot_id("").is_err());
        // 64 chars but not all hex.
        let mut bad = "z".repeat(64);
        assert!(ensure_full_snapshot_id(&bad).is_err());
        // 63 hex chars (just one short).
        bad = "a".repeat(63);
        assert!(ensure_full_snapshot_id(&bad).is_err());
        // 65 hex chars.
        bad = "a".repeat(65);
        assert!(ensure_full_snapshot_id(&bad).is_err());
    }

    #[test]
    fn diff_modifier_parses_known_glyphs() {
        assert_eq!(DiffModifier::parse("+"), DiffModifier::Added);
        assert_eq!(DiffModifier::parse("-"), DiffModifier::Removed);
        assert_eq!(DiffModifier::parse("M"), DiffModifier::Modified);
        assert_eq!(DiffModifier::parse("T"), DiffModifier::TypeChanged);
        assert_eq!(DiffModifier::parse("U"), DiffModifier::Other('U'));
        assert_eq!(DiffModifier::parse(""), DiffModifier::Other('?'));
    }

    #[test]
    fn parses_diff_with_changes_and_statistics() {
        let stdout = r#"{"message_type":"change","path":"/x/a.txt","modifier":"M"}
{"message_type":"change","path":"/x/c.txt","modifier":"+"}
{"message_type":"change","path":"/x/link","modifier":"+"}
{"message_type":"statistics","source_snapshot":"aa","target_snapshot":"bb","changed_files":1,"added":{"files":1,"dirs":0,"others":1,"data_blobs":2,"tree_blobs":4,"bytes":2491},"removed":{"files":0,"dirs":0,"others":0,"data_blobs":1,"tree_blobs":4,"bytes":1814}}
"#;
        let (sum, changes) = parse_diff_lines(stdout).unwrap();
        assert_eq!(changes.len(), 3);
        assert_eq!(changes[0].modifier, DiffModifier::Modified);
        assert_eq!(changes[0].path, "/x/a.txt");
        assert_eq!(changes[1].modifier, DiffModifier::Added);
        assert_eq!(sum.changed_files, 1);
        assert_eq!(sum.added_files, 1);
        assert_eq!(sum.added_bytes, 2491);
        assert_eq!(sum.removed_bytes, 1814);
    }

    #[test]
    fn parses_diff_with_no_statistics_line() {
        let stdout = r#"{"message_type":"change","path":"/only","modifier":"+"}"#;
        let (sum, changes) = parse_diff_lines(stdout).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(sum.changed_files, 0);
        assert_eq!(sum.added_bytes, 0);
    }

    #[test]
    fn parses_empty_diff_output() {
        let (sum, changes) = parse_diff_lines("").unwrap();
        assert!(changes.is_empty());
        assert_eq!(sum.changed_files, 0);
    }

    #[test]
    fn ignores_unknown_message_types() {
        let stdout = r#"{"message_type":"verbose_status","message":"hello"}
{"message_type":"change","path":"/x","modifier":"M"}
"#;
        let (_, changes) = parse_diff_lines(stdout).unwrap();
        assert_eq!(changes.len(), 1);
    }

    #[test]
    fn diff_rejects_short_ids() {
        let profile = Profile::Local {
            password: "pw".into(),
            local_path: "/nonexistent".into(),
        };
        let full = "a".repeat(64);
        // short first id
        assert!(diff(&profile, "abcd1234", &full).is_err());
        // short second id
        assert!(diff(&profile, &full, "abcd1234").is_err());
    }

    #[test]
    fn snapshot_details_tolerates_missing_summary() {
        let raw = r#"[{ "id": "id1", "paths": [], "tags": [] }]"#;
        let arr: Vec<SnapshotDetails> = serde_json::from_str(raw).unwrap();
        assert!(arr[0].summary.is_none());
    }

    // End-to-end: actually shells out to `restic` against a fresh local repo.
    // Marked #[ignore] so it doesn't run unless requested
    // (`cargo test -- --ignored`). Validates the stdin password channel, env
    // var wiring, JSON parsing, and forget — i.e. the full spawn() pipeline.
    #[test]
    #[ignore]
    fn live_restic_delete_round_trip() {
        use std::fs;
        use std::path::PathBuf;

        let root = PathBuf::from("tmp").join(format!("restic-it-{}", std::process::id()));
        let repo = root.join("repo");
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("a.txt"), b"hello\n").unwrap();

        let init = Command::new("restic")
            .arg("init")
            .env("RESTIC_REPOSITORY", &repo)
            .env("RESTIC_PASSWORD", "pw")
            .output()
            .expect("init");
        assert!(init.status.success(), "init failed: {init:?}");

        let backup = Command::new("restic")
            .arg("backup")
            .arg(&source)
            .env("RESTIC_REPOSITORY", &repo)
            .env("RESTIC_PASSWORD", "pw")
            .output()
            .expect("backup");
        assert!(backup.status.success(), "backup failed: {backup:?}");

        let profile = Profile::Local {
            password: "pw".into(),
            local_path: repo.to_string_lossy().into_owned(),
        };

        // List snapshots via restic CLI (also exercises stdin-password path).
        let list = spawn(&profile, &["snapshots", "--json"]).expect("list");
        let arr: Vec<SnapshotDetails> = serde_json::from_slice(&list).expect("parse list");
        assert_eq!(arr.len(), 1, "expected one snapshot");
        let id = arr[0].id.clone();

        // Fetch details for the specific snapshot.
        let (parsed, raw_pretty) = snapshot_details_json(&profile, &id).expect("details");
        assert_eq!(parsed.id, id);
        assert!(raw_pretty.contains(&id), "raw JSON should mention the id");

        // Forget it.
        forget(&profile, &id).expect("forget");

        // Confirm it's gone.
        let after = spawn(&profile, &["snapshots", "--json"]).expect("after-list");
        let arr_after: Vec<SnapshotDetails> = serde_json::from_slice(&after).expect("parse after");
        assert!(arr_after.is_empty(), "snapshot should be deleted");

        fs::remove_dir_all(&root).ok();
    }

    // End-to-end: spawn restic to back up two revisions of a source tree, then
    // call `diff()` and assert the parsed changes line up with what we mutated.
    // Marked #[ignore] so it stays out of the default `cargo test` run.
    #[test]
    #[ignore]
    fn live_restic_diff_two_snapshots() {
        use std::fs;
        use std::path::PathBuf;

        let root = PathBuf::from("tmp").join(format!("restic-it-diff-{}", std::process::id()));
        let repo = root.join("repo");
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("a.txt"), b"v1\n").unwrap();
        fs::write(source.join("stays.txt"), b"unchanged\n").unwrap();

        let init = Command::new("restic")
            .arg("init")
            .env("RESTIC_REPOSITORY", &repo)
            .env("RESTIC_PASSWORD", "pw")
            .output()
            .expect("init");
        assert!(init.status.success(), "init failed: {init:?}");

        let backup1 = Command::new("restic")
            .arg("backup")
            .arg(&source)
            .env("RESTIC_REPOSITORY", &repo)
            .env("RESTIC_PASSWORD", "pw")
            .output()
            .expect("backup1");
        assert!(backup1.status.success(), "backup1 failed: {backup1:?}");

        // Mutate: modify one file, add a new one, remove another.
        fs::write(source.join("a.txt"), b"v2 modified\n").unwrap();
        fs::write(source.join("new.txt"), b"brand new\n").unwrap();
        fs::remove_file(source.join("stays.txt")).unwrap();

        let backup2 = Command::new("restic")
            .arg("backup")
            .arg(&source)
            .env("RESTIC_REPOSITORY", &repo)
            .env("RESTIC_PASSWORD", "pw")
            .output()
            .expect("backup2");
        assert!(backup2.status.success(), "backup2 failed: {backup2:?}");

        let profile = Profile::Local {
            password: "pw".into(),
            local_path: repo.to_string_lossy().into_owned(),
        };

        let list = spawn(&profile, &["snapshots", "--json"]).expect("list");
        let arr: Vec<SnapshotDetails> = serde_json::from_slice(&list).expect("parse list");
        assert_eq!(arr.len(), 2, "expected two snapshots");
        // restic snapshots --json is oldest-first; pick by time order rather
        // than trusting the array index.
        let mut by_time = arr;
        by_time.sort_by(|a, b| a.time.cmp(&b.time));
        let first = by_time[0].id.clone();
        let second = by_time[1].id.clone();

        let (sum, changes) = diff(&profile, &first, &second).expect("diff");
        assert!(
            changes.iter().any(|c| c.modifier == DiffModifier::Modified
                && c.path.ends_with("a.txt")),
            "expected a.txt to appear as Modified, got {changes:?}"
        );
        assert!(
            changes.iter().any(|c| c.modifier == DiffModifier::Added
                && c.path.ends_with("new.txt")),
            "expected new.txt to appear as Added, got {changes:?}"
        );
        assert!(
            changes.iter().any(|c| c.modifier == DiffModifier::Removed
                && c.path.ends_with("stays.txt")),
            "expected stays.txt to appear as Removed, got {changes:?}"
        );
        assert!(sum.added_bytes > 0, "expected some added bytes in summary");

        fs::remove_dir_all(&root).ok();
    }
}
