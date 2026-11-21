use std::collections::BTreeMap;
use std::io::{self, Write};
use std::mem;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use rustic_backend::BackendOptions;
use rustic_core::repofile::{
    BlobType, Node, NodeType, SnapshotFile, SnapshotId, SnapshotSummary,
};
use rustic_core::{
    Credentials, FileType, IndexedFull, IndexedFullStatus, IndexedIdsStatus, Repository,
    RepositoryOptions, RepositoryBackends, TreeId, last_modified_node,
};
use tokio::sync::mpsc;

use crate::config::Profile;
use crate::lock;

/// A repository's snapshots, newest first, and the id of the repository
/// they came from.
pub(crate) struct SnapshotList {
    /// The repository's own id (its config file's), the same whichever
    /// profile, URL or path reaches it.
    pub(crate) repository_id: String,
    pub(crate) rows: Vec<SnapshotRow>,
}

pub(crate) struct SnapshotRow {
    pub(crate) id: String,
    pub(crate) time: String,
    pub(crate) host: String,
    pub(crate) tags: Vec<String>,
    pub(crate) size: Option<u64>,
    pub(crate) paths: Vec<String>,
}

pub(crate) enum ContentKind {
    Parent,
    Dir,
    File,
    Symlink,
    Other,
}

impl ContentRow {
    pub(crate) fn parent() -> Self {
        Self {
            name: "..".to_string(),
            kind: ContentKind::Parent,
            size: 0,
            mtime: String::new(),
            subtree: None,
        }
    }
}

pub(crate) struct ContentRow {
    pub(crate) name: String,
    pub(crate) kind: ContentKind,
    pub(crate) size: u64,
    pub(crate) mtime: String,
    pub(crate) subtree: Option<TreeId>,
}

pub(crate) struct PreviewEntry {
    pub(crate) path: String,
    pub(crate) kind: ContentKind,
    pub(crate) size: u64,
}

pub(crate) struct ContentsPreview {
    pub(crate) entries: Vec<PreviewEntry>,
    pub(crate) truncated: bool,
}

pub(crate) struct DeleteSnapshotInfo {
    pub(crate) hostname: String,
    pub(crate) paths: Vec<String>,
    pub(crate) tags: Vec<String>,
    pub(crate) files: Option<u64>,
    pub(crate) bytes: Option<u64>,
    // Pretty-printed JSON of the snapshot file, for the raw-details view.
    pub(crate) raw_json: String,
}

pub(crate) struct FileDetails {
    pub(crate) name: String,
    pub(crate) full_path: String,
    pub(crate) kind: ContentKind,
    pub(crate) kind_label: String,
    pub(crate) size: u64,
    pub(crate) mode: Option<u32>,
    pub(crate) mtime: Option<String>,
    pub(crate) atime: Option<String>,
    pub(crate) ctime: Option<String>,
    pub(crate) uid: Option<u32>,
    pub(crate) gid: Option<u32>,
    pub(crate) user: Option<String>,
    pub(crate) group: Option<String>,
    pub(crate) linktarget: Option<String>,
    // SHA-256 chunk ids that make up the file's content. For a single-chunk
    // file this is effectively the file's SHA-256; for multi-chunk files
    // (restic CDC-chunks anything large) each entry hashes one chunk.
    pub(crate) content_hashes: Vec<String>,
}

/// How long a repository backend (REST or S3) waits for a connection before
/// the attempt fails. Each request's overall time stays unbounded (S3) or
/// generous (REST: rustic_backend's 10 minutes) so large packs can stream,
/// so without this a host that never answers would hold every attempt for
/// the OS connect timeout. 30 s is what the lock module's REST client allows
/// a whole request.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// How a repository backend (REST or S3) handles a request that fails or
/// stops receiving data.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RequestPolicy {
    /// Retries after a failed request.
    pub(crate) retries: usize,
    /// How long a request may go without receiving a byte before the attempt
    /// fails.
    pub(crate) read_timeout: Duration,
}

impl RequestPolicy {
    /// Everything that reads or writes repository data. 5 retries match the
    /// defaults of both rustic_backend's REST backend and its opendal one. The
    /// 5-minute read timeout is restic's own `--stuck-request-timeout` default,
    /// so wrustic never gives up on a slow server that restic itself would
    /// wait for (a REST server only starts answering a listing once it has
    /// walked every pack).
    pub(crate) const STANDARD: Self = Self {
        retries: 5,
        read_timeout: Duration::from_mins(5),
    };

    /// The add-profile check, which blocks the TUI while the user waits on the
    /// "verifying" screen. It reads only the config and key files, all tiny,
    /// so a server that stops sending for [`CONNECT_TIMEOUT`] has failed. A
    /// failure is reported at once rather than retried, because verifying
    /// again is one keypress.
    pub(crate) const VERIFY: Self = Self {
        retries: 0,
        read_timeout: CONNECT_TIMEOUT,
    };

    /// [`RequestPolicy::STANDARD`] without the retries, for the writes whose
    /// attempts the lock module has to count (`lock::gate_writes`): a backend
    /// that tries a request again by itself reports only its last attempt,
    /// and says nothing of an earlier one the server may still complete.
    pub(crate) const ONE_ATTEMPT: Self = Self {
        retries: 0,
        ..Self::STANDARD
    };
}

// All backends are write-capable; keeping write operations safe against
// concurrent restic processes is the lock module's job (docs/locking.md),
// not the backend's.
pub(crate) fn build_backends(profile: &Profile) -> Result<RepositoryBackends> {
    build_backends_with_policy(profile, RequestPolicy::STANDARD)
}

pub(crate) fn build_backends_with_policy(
    profile: &Profile,
    policy: RequestPolicy,
) -> Result<RepositoryBackends> {
    let mut opts = BackendOptions::default();
    match profile {
        Profile::Local { local_path, .. } => {
            opts = opts.repository(local_path.clone());
        }
        Profile::Rest {
            rest_url,
            rest_user,
            rest_password,
            ..
        } => {
            let mut url = url::Url::parse(rest_url)
                .with_context(|| format!("parsing REST URL `{rest_url}`"))?;
            if rest_user.is_empty() && !rest_password.is_empty() {
                bail!("REST profile has a password but no username");
            }
            if !rest_user.is_empty() {
                url.set_username(rest_user)
                    .map_err(|_| anyhow!("REST URL `{rest_url}` cannot carry a username"))?;
            }
            if !rest_password.is_empty() {
                url.set_password(Some(rest_password))
                    .map_err(|_| anyhow!("REST URL `{rest_url}` cannot carry a password"))?;
            }
            opts = opts
                .repository(format!("rest:{url}"))
                .options(BTreeMap::from([
                    ("retry".to_string(), policy.retries.to_string()),
                    (
                        "http-connect-timeout".to_string(),
                        format!("{}s", CONNECT_TIMEOUT.as_secs()),
                    ),
                    (
                        "http-read-timeout".to_string(),
                        format!("{}s", policy.read_timeout.as_secs()),
                    ),
                ]));
        }
        Profile::S3 {
            s3_endpoint,
            s3_bucket,
            s3_region,
            s3_root,
            s3_access_key,
            s3_secret_key,
            ..
        } => {
            // wrustic's own S3 backend, not rustic_backend's generic opendal
            // one: rustic_backend's `opendal` feature has no per-service
            // knob and compiles every opendal service (see src/s3_backend.rs).
            let backend = crate::s3_backend::S3DataBackend::new(
                s3_endpoint,
                s3_bucket,
                s3_region,
                s3_root,
                s3_access_key,
                s3_secret_key,
                policy,
            )?;
            return Ok(RepositoryBackends::new(std::sync::Arc::new(backend), None));
        }
    }
    Ok(opts.to_backends()?)
}

/// The add-profile check, under [`RequestPolicy::VERIFY`]: an unreachable
/// host or one that stops answering fails within about [`CONNECT_TIMEOUT`].
pub(crate) fn verify_profile(profile: &Profile) -> Result<()> {
    let backends = build_backends_with_policy(profile, RequestPolicy::VERIFY)?;
    Repository::new(&RepositoryOptions::default(), &backends)?
        .open(&Credentials::password(profile.password()))?;
    Ok(())
}

pub(crate) fn load_snapshots(profile: &Profile) -> Result<SnapshotList> {
    let backends = build_backends(profile)?;
    let repo = Repository::new(&RepositoryOptions::default(), &backends)?
        .open(&Credentials::password(profile.password()))?;

    let mut snaps = repo.get_all_snapshots()?;
    snaps.sort_by(|a, b| b.time.cmp(&a.time));

    let rows = snaps
        .into_iter()
        .map(|s| SnapshotRow {
            // `SnapshotId`'s Display impl yields the 8-char short id; `.to_hex()`
            // returns the full 64-char hex which is what restic CLI calls need.
            id: s.id.to_hex().as_str().to_string(),
            time: s.time.strftime("%Y-%m-%d %H:%M:%S").to_string(),
            host: s.hostname.clone(),
            tags: s.tags.iter().cloned().collect(),
            size: s.summary.as_ref().map(|summary| summary.total_bytes_processed),
            paths: s.paths.iter().cloned().collect(),
        })
        .collect();
    Ok(SnapshotList {
        repository_id: repository_id(&repo),
        rows,
    })
}

/// See [`SnapshotList::repository_id`].
pub(crate) fn repository_id<S: rustic_core::Open>(repo: &Repository<S>) -> String {
    repo.config().id.to_hex().as_str().to_string()
}

pub(crate) fn open_indexed(profile: &Profile) -> Result<Repository<IndexedIdsStatus>> {
    let backends = build_backends(profile)?;
    let repo = Repository::new(&RepositoryOptions::default(), &backends)?
        .open(&Credentials::password(profile.password()))?
        .to_indexed_ids()?;
    Ok(repo)
}

// Like open_indexed, but with the full blob index + cache so that file content
// can be read (Repository::dump). Used by the share-URL server, which needs
// to stream file contents rather than just metadata.
pub(crate) fn open_indexed_full(profile: &Profile) -> Result<Repository<IndexedFullStatus>> {
    let backends = build_backends(profile)?;
    let repo = Repository::new(&RepositoryOptions::default(), &backends)?
        .open(&Credentials::password(profile.password()))?
        .to_indexed()?;
    Ok(repo)
}

/// Like [`open_indexed_full`], but holding restic's non-exclusive lock — the
/// lock `restic mount` takes. Acquired between opening (which yields the
/// master key the lock file is encrypted with) and loading the index, in that
/// order so the index can never reference packs a concurrent prune already
/// deleted: once our lock is on the backend, no exclusive operation can
/// start, and one that was running would have blocked the acquisition.
/// The lock refreshes itself every 5 minutes for as long as the caller
/// holds it.
pub(crate) fn open_indexed_full_shared_lock(
    profile: &Profile,
) -> Result<(Repository<IndexedFullStatus>, lock::RepoLock)> {
    let backends = build_backends(profile)?;
    let repo = Repository::new(&RepositoryOptions::default(), &backends)?
        .open(&Credentials::password(profile.password()))?;
    let crypto = lock::RepoCrypto::from_repo(&repo)?;
    let repo_lock = lock::RepoLock::acquire_shared(lock::backend_for_profile(profile)?, crypto)?;
    let repo = repo.to_indexed()?;
    Ok((repo, repo_lock))
}

// Stream one file's content blob-by-blob into `tx`. Looks up the node by name
// inside the tree at `tree_id`. Each call to `Repository::dump` writes one
// blob at a time via `write_all`; our writer wraps each call in a single mpsc
// send so backpressure flows from the HTTP client through to the repo reader.
//
// Designed to be called from `tokio::task::spawn_blocking` — `tx.blocking_send`
// is used so the rustic_core synchronous calls don't need an async runtime.
pub(crate) fn stream_file_content<S: IndexedFull>(
    repo: &Repository<S>,
    tree_id: TreeId,
    name: &str,
    tx: &mpsc::Sender<io::Result<Bytes>>,
) -> Result<()> {
    let tree = repo.get_tree(&tree_id)?;
    let node = tree
        .nodes
        .into_iter()
        .find(|n| n.name().to_string_lossy() == name)
        .ok_or_else(|| anyhow!("file `{name}` not found in tree"))?;
    if !matches!(node.node_type, NodeType::File) {
        bail!("`{name}` is not a regular file");
    }
    let mut writer = ChannelWriter { tx };
    repo.dump(&node, &mut writer)?;
    Ok(())
}

struct ChannelWriter<'a> {
    tx: &'a mpsc::Sender<io::Result<Bytes>>,
}

impl Write for ChannelWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = buf.len();
        let bytes = Bytes::copy_from_slice(buf);
        self.tx
            .blocking_send(Ok(bytes))
            .map_err(|_| io::Error::other("client disconnected"))?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn snapshot_root_tree(
    repo: &Repository<IndexedIdsStatus>,
    snapshot_id: &str,
) -> Result<TreeId> {
    let snap = repo.get_snapshot_from_str(snapshot_id, |_| true)?;
    Ok(snap.tree)
}

pub(crate) fn snapshot_delete_info(
    repo: &Repository<IndexedIdsStatus>,
    snapshot_id: &str,
) -> Result<DeleteSnapshotInfo> {
    let snap = repo.get_snapshot_from_str(snapshot_id, |_| true)?;
    let raw_json = serde_json::to_string_pretty(&snap)
        .unwrap_or_else(|e| format!("(failed to serialize snapshot: {e})"));
    Ok(DeleteSnapshotInfo {
        hostname: snap.hostname.clone(),
        paths: snap.paths.iter().cloned().collect(),
        tags: snap.tags.iter().cloned().collect(),
        files: snap.summary.as_ref().map(|s| s.total_files_processed),
        bytes: snap.summary.as_ref().map(|s| s.total_bytes_processed),
        raw_json,
    })
}

/// Deletes one snapshot file natively, under an exclusive restic-compatible
/// repository lock — the same lock `restic forget` takes, so concurrent
/// restic processes either block us or are blocked by us, never corrupted.
/// `snapshot_id` must be the full 64-char hex hash (enforced — short ids are
/// rejected to avoid acting on the wrong snapshot when a prefix matches
/// multiple).
pub(crate) fn delete_snapshot(profile: &Profile, snapshot_id: &str) -> Result<()> {
    ensure_full_snapshot_id(snapshot_id)?;
    let backends = build_backends(profile)?;
    let repo = Repository::new(&RepositoryOptions::default(), &backends)?
        .open(&Credentials::password(profile.password()))?;
    let crypto = lock::RepoCrypto::from_repo(&repo)?;
    let _lock = lock::RepoLock::acquire_exclusive(lock::backend_for_profile(profile)?, crypto)?;
    // Resolve the id under the lock, like restic does.
    let snap = repo.get_snapshot_from_str(snapshot_id, |_| true)?;
    repo.delete_snapshots(&[snap.id])?;
    Ok(())
}

/// Replaces one snapshot's tag list natively, under the exclusive
/// restic-compatible lock `restic tag` takes (docs/locking.md, "Native tag
/// edits"). Mirrors restic's semantics: the snapshot is re-read *under* the
/// lock (a concurrent retag changes the id, so a stale id fails cleanly
/// instead of editing the wrong file), `original` is set to the pre-edit id
/// if unset, and the new snapshot file is written — and verified readable —
/// before the old one is deleted, so there is never a moment where the
/// snapshot doesn't exist.
///
/// The rewrite edits the raw snapshot JSON instead of round-tripping
/// rustic_core's typed `SnapshotFile`, which silently drops restic fields it
/// doesn't model (`excludes`) — this way every field wrustic doesn't touch
/// keeps its value and position (serde_json's `preserve_order` keeps the
/// layout; reserializing may still normalize JSON formatting details, such
/// as Go's `\u003c` HTML escaping of `<`, but drops and reorders nothing).
///
/// Returns the rewritten snapshot's id (a retag changes the id), or `None`
/// when the snapshot already carried exactly the requested tags — restic's
/// `changed == false` no-op, which avoids minting a new id for an identical
/// snapshot.
pub(crate) fn edit_snapshot_tags(
    profile: &Profile,
    snapshot_id: &str,
    new_tags: &[String],
) -> Result<Option<String>> {
    ensure_full_snapshot_id(snapshot_id)?;
    let backends = build_backends(profile)?;
    let repo = Repository::new(&RepositoryOptions::default(), &backends)?
        .open(&Credentials::password(profile.password()))?;
    if repo.config().append_only == Some(true) {
        bail!("the repository is append-only; snapshots cannot be rewritten");
    }
    let crypto = lock::RepoCrypto::from_repo(&repo)?;
    let _lock =
        lock::RepoLock::acquire_exclusive(lock::backend_for_profile(profile)?, crypto.clone())?;

    let raw = repo.cat_file(FileType::Snapshot, snapshot_id).map_err(|e| {
        anyhow!("reading snapshot {snapshot_id}: {e} (deleted or retagged concurrently?)")
    })?;
    let Some(new_json) = retag_snapshot_json(&raw, snapshot_id, new_tags)? else {
        return Ok(None);
    };

    let snapshots = lock::snapshot_backend_for_profile(profile)?;
    let new_id = lock::write_unpacked(snapshots.as_ref(), &crypto, &new_json)?;
    // Read the new file back through rustic_core's own decrypt path before
    // deleting anything: proves an independent reader decodes our envelope to
    // exactly the JSON we meant to store.
    let readback = repo
        .cat_file(FileType::Snapshot, &new_id)
        .map_err(|e| anyhow!("verifying rewritten snapshot {new_id}: {e}"))?;
    if readback.as_ref() != new_json.as_slice() {
        let _ = snapshots.remove(&new_id);
        bail!("rewritten snapshot {new_id} did not read back as written; old snapshot kept");
    }
    snapshots.remove(snapshot_id)?;
    Ok(Some(new_id))
}

/// The tag edit as a pure JSON transformation. Returns `None` when the
/// snapshot already carries `new_tags`. The comparison is *set*-based, not
/// list-based: restic attaches no meaning to tag order (its filters treat
/// tags as a set), and rustic_core models them as a `BTreeSet` outright, so
/// wrustic always displays them sorted — an order-sensitive check would make
/// "open the editor, press Enter" rewrite a snapshot whose stored order
/// merely differs from the sorted display. (restic's own `tag --set` is
/// blunter still and rewrites unconditionally, identical tags or not.)
///
/// Only the `tags` and `original` keys are touched: `tags` is replaced — or
/// removed when the new set is empty, matching restic's `omitempty` — and
/// `original` is set to `old_id` unless the snapshot, itself the product of
/// an earlier edit, already has one ("retain the original snapshot id over
/// all tag changes", cmd_tag.go).
fn retag_snapshot_json(raw: &[u8], old_id: &str, new_tags: &[String]) -> Result<Option<Vec<u8>>> {
    let mut value: serde_json::Value =
        serde_json::from_slice(raw).context("parsing snapshot JSON")?;
    let obj = value
        .as_object_mut()
        .ok_or_else(|| anyhow!("snapshot JSON is not an object"))?;
    let current: Vec<&str> = match obj.get("tags") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .map(|v| v.as_str().ok_or_else(|| anyhow!("snapshot tag is not a string: {v}")))
            .collect::<Result<_>>()?,
        Some(other) => bail!("snapshot `tags` is not an array: {other}"),
    };
    let current_set: std::collections::BTreeSet<&str> = current.iter().copied().collect();
    let new_set: std::collections::BTreeSet<&str> =
        new_tags.iter().map(String::as_str).collect();
    if current_set == new_set {
        return Ok(None);
    }
    if new_tags.is_empty() {
        let _ = obj.remove("tags");
    } else {
        let _ = obj.insert("tags".into(), serde_json::json!(new_tags));
    }
    if !matches!(obj.get("original"), Some(serde_json::Value::String(_))) {
        let _ = obj.insert("original".into(), serde_json::Value::String(old_id.to_string()));
    }
    Ok(Some(serde_json::to_vec(&value).context("serializing snapshot JSON")?))
}

/// The fewest characters of a snapshot id [`resolve_snapshot_ids`] takes: the
/// length of the short id restic prints. restic itself accepts any start
/// that is unambiguous, down to one character — which in a small repository
/// is nearly any character, too little to name what a write is done to.
const SHORT_ID_LEN: usize = 8;

/// The full ids of the snapshots `given` names, in the order given. Each is a
/// full snapshot id or the start of one, [`SHORT_ID_LEN`] characters or more;
/// a start has to be that of exactly one snapshot.
///
/// For the headless `merge`, whose ids are typed or scripted rather than
/// picked from a list. Read without a lock, and only when a short id is among
/// them: the write that follows reads each snapshot again by its full id
/// under its own lock.
pub(crate) fn resolve_snapshot_ids(profile: &Profile, given: &[String]) -> Result<Vec<String>> {
    for id in given {
        if !(SHORT_ID_LEN..=64).contains(&id.len()) || !id.bytes().all(|b| b.is_ascii_hexdigit())
        {
            bail!(
                "`{id}` is not a snapshot id: expected a full 64-character hex id or at least \
                 its first {SHORT_ID_LEN} characters"
            );
        }
    }
    let given: Vec<String> = given.iter().map(|id| id.to_ascii_lowercase()).collect();
    if given.iter().all(|id| id.len() == 64) {
        return Ok(given);
    }
    let backends = build_backends(profile)?;
    let repo = Repository::new(&RepositoryOptions::default(), &backends)?
        .open(&Credentials::password(profile.password()))?;
    let present: Vec<String> = repo
        .list::<SnapshotId>()?
        .map(|id| id.to_hex().as_str().to_string())
        .collect();
    ids_starting_with(&present, &given)
}

// For each of `starts`, the one id of `present` that begins with it.
fn ids_starting_with(present: &[String], starts: &[String]) -> Result<Vec<String>> {
    starts
        .iter()
        .map(|start| {
            let mut matching = present.iter().filter(|id| id.starts_with(start.as_str()));
            match (matching.next(), matching.next()) {
                (Some(id), None) => Ok(id.clone()),
                (None, _) => bail!("no snapshot id starts with `{start}`"),
                (Some(_), Some(_)) => bail!(
                    "more than one snapshot id starts with `{start}`: give more of the id"
                ),
            }
        })
        .collect()
}

/// Merges snapshots into one new snapshot natively (docs/locking.md, "Native
/// snapshot merge") and returns the new snapshot's id. restic has no merge
/// command, so this is the one write wrustic offers that restic itself cannot
/// do — but everything it writes is plain restic-format data.
///
/// The directory trees are merged by path from the root: an entry only one
/// snapshot has is taken as is, directories are merged recursively, and where
/// the same path differs the entry with the newer mtime wins. Only tree blobs
/// are written (no file content is read or stored again), then one snapshot
/// file. Nothing is deleted or rewritten: the source snapshots stay.
///
/// That makes it a pure append, so it holds the lock restic takes for one —
/// the **non-exclusive** lock of `restic backup`. It coexists with running
/// backups and with wrustic's own SMB share, and is blocked by (and blocks)
/// everything exclusive: forget, prune, tag edits. The order is restic's:
/// open → lock → load the index → resolve the snapshots, so nothing read can
/// be deleted underneath, and tree packs → index → snapshot when writing, so
/// the snapshot never refers to a blob that is not indexed yet.
///
/// The trees go through `Repository::merge_trees`, which round-trips every
/// node through rustic_core's typed `Node` — and that type does not model
/// everything restic stores (`generic_attributes`, the Windows metadata).
/// Metadata is kept as far as that type goes: what it cannot hold is left
/// out of the merged snapshot, and the sources, which still carry it, are
/// scanned so the caller can say so ([`scan_source_trees`]).
///
/// The snapshot file is written by wrustic, not by rustic_core's
/// `merge_snapshots`: that one stamps the merging machine's hostname and
/// keeps nested paths apart, either of which stops `restic backup` from
/// finding the merged snapshot as its parent (see [`merged_snapshot_json`]).
pub(crate) fn merge_snapshots(
    profile: &Profile,
    snapshot_ids: &[String],
    retries: &std::sync::Arc<lock::WriteRetries>,
) -> Result<MergeOutcome> {
    for id in snapshot_ids {
        ensure_full_snapshot_id(id)?;
    }
    let distinct: std::collections::BTreeSet<String> =
        snapshot_ids.iter().map(|id| id.to_ascii_lowercase()).collect();
    if distinct.len() < 2 || distinct.len() != snapshot_ids.len() {
        bail!("a merge needs at least two different snapshots");
    }

    // Everything rustic_core writes for the merge goes through a gate on the
    // lock: `merge_trees` writes packs and then the index naming them and
    // cannot be interrupted, and an index written after the lock was lost
    // could name packs a prune has deleted in between.
    let (backends, write_gate) = lock::gate_writes(
        &build_backends(profile)?,
        &build_backends_with_policy(profile, RequestPolicy::ONE_ATTEMPT)?,
        std::sync::Arc::clone(retries),
        data_write_can_land_later(profile),
    );
    merge_through_gate(profile, snapshot_ids, retries, &backends, &write_gate).map_err(|e| {
        // A merge that failed leaves its packs for the next prune, and that
        // is when a late copy of an index naming them does harm. The success
        // path says the same through `MergeOutcome::attempt_still_open`.
        if write_gate.attempt_still_open() {
            anyhow!(
                "{e:#} — also: an index file this merge stored may be written again by a \
                 request the server still holds. If a prune removes the merge's packs before \
                 it arrives, it names packs that are gone: give the server time before the \
                 next prune, and run `restic check` after it (docs/locking.md)"
            )
        } else {
            e
        }
    })
}

// [`merge_snapshots`] from the opened gate on.
fn merge_through_gate(
    profile: &Profile,
    snapshot_ids: &[String],
    retries: &std::sync::Arc<lock::WriteRetries>,
    backends: &RepositoryBackends,
    write_gate: &lock::WriteGate,
) -> Result<MergeOutcome> {
    // Stopping (`lock::WriteRetries::stop`) refuses writes; the long reads
    // around them ask here, so that a stop does not wait for them to finish.
    let stopped_before_the_snapshot = |written: &str| -> Result<()> {
        if retries.stopped() {
            bail!("the merge was stopped before writing its snapshot; {written}");
        }
        Ok(())
    };
    let repo = Repository::new(&RepositoryOptions::default(), backends)?
        .open(&Credentials::password(profile.password()))?;
    let crypto = lock::RepoCrypto::from_repo(&repo)?;
    let repo_lock =
        lock::RepoLock::acquire_shared(lock::backend_for_profile(profile)?, crypto.clone())?;
    write_gate.arm(&repo_lock);
    // Declared after the lock, so dropped before it: no write of rustic_core's
    // is under way or can start once the lock is given up, however this
    // function is left.
    let _writes_end_before_the_lock = write_gate.close_on_drop();
    // The full index, not the ids-only one: the scan for dropped metadata
    // reads raw tree blobs, which rustic_core only offers on a fully indexed
    // repository.
    let repo = repo.to_indexed()?;

    // Resolve the ids under the lock, like every other native write: the rows
    // the TUI shows were read lock-free.
    let mut sources = Vec::with_capacity(snapshot_ids.len());
    let mut trees = Vec::with_capacity(snapshot_ids.len());
    let mut newest: Option<(usize, rustic_core::jiff::Timestamp)> = None;
    for (i, id) in snapshot_ids.iter().enumerate() {
        let raw = repo.cat_file(FileType::Snapshot, id).map_err(|e| {
            anyhow!("reading snapshot {id}: {e} (deleted or retagged concurrently?)")
        })?;
        let typed: SnapshotFile = serde_json::from_slice(&raw)
            .with_context(|| format!("parsing snapshot {id}"))?;
        let time = typed.time.timestamp();
        // Strictly newer only, so equal times keep the earlier-listed source.
        if newest.is_none_or(|(_, t)| time > t) {
            newest = Some((i, time));
        }
        trees.push(typed.tree);
        sources.push(
            serde_json::from_slice::<serde_json::Value>(&raw)
                .with_context(|| format!("parsing snapshot {id}"))?,
        );
    }
    let newest = newest.map(|(i, _)| i).unwrap_or(0);

    let scan = scan_source_trees(&trees, |id| {
        stopped_before_the_snapshot("nothing was written")?;
        Ok(repo.cat_blob(BlobType::Tree, id.to_hex().as_str())?)
    })?;

    let started = rustic_core::jiff::Timestamp::now();
    let mut summary = SnapshotSummary::default();
    let merged = repo.merge_trees(&trees, &last_modified_node, &mut summary);
    // `merge_trees` waits for the threads that store its packs only when it
    // succeeds; after an error they may still be writing. Nothing below
    // writes through rustic_core, so the gate is closed here already: that
    // waits for those writes and refuses any that would follow.
    write_gate.close();
    let finished = rustic_core::jiff::Timestamp::now();

    // What the gate could not take back is worse than orphaned trees: an
    // index file that is there after all may name packs that prune deleted.
    let left_behind = write_gate.unconfirmed_removals();
    let left_behind = (!left_behind.is_empty()).then(|| {
        format!(
            "{} is not known to be out of the repository for good: it could not be removed \
             again, or the server can still complete a write it reported as failed. If it \
             is there after a prune it names packs that are gone: remove it from the \
             repository and run `restic check`",
            left_behind.join(", ")
        )
    });
    // restic's abort-if-unrefreshable rule: a lock that went unrefreshed for
    // too long may already have been removed as stale, after which a prune
    // could have run — the merged tree may refer to blobs that are gone. It
    // is also why `merge_trees` failed, if it did: the gate refused a write.
    if repo_lock.poisoned() {
        if let Some(left_behind) = left_behind {
            bail!(
                "the repository lock could not be refreshed in time, so the merge was \
                 abandoned before writing its snapshot — but {left_behind}"
            );
        }
        bail!(
            "the repository lock could not be refreshed in time, so the merge was abandoned \
             before writing its snapshot; nothing refers to the trees it wrote, and the next \
             prune removes them"
        );
    }
    let tree = match (merged, left_behind) {
        (Ok(tree), _) => tree,
        (Err(e), None) => return Err(e.into()),
        (Err(e), Some(left_behind)) => {
            return Err(anyhow::Error::from(e).context(format!(
                "the merge failed before writing its snapshot, and {left_behind}"
            )));
        }
    };

    // Two things `merge_trees` gets wrong for restic, both rare and neither
    // visible from the sources alone, so the merged tree is read back — when
    // the sources make them possible, because that takes a second handle
    // (this one's index predates the trees just written).
    if scan.quoted_names || scan.hardlinked_files {
        let merged = open_indexed_full(profile)?;
        let read_tree = |id: &TreeId| -> Result<_> {
            stopped_before_the_snapshot(
                "nothing refers to the trees it wrote, and the next prune removes them",
            )?;
            Ok(merged.cat_blob(BlobType::Tree, id.to_hex().as_str())?)
        };
        let hostname = |source: &serde_json::Value| {
            source.get("hostname").and_then(|h| h.as_str()).unwrap_or("").to_string()
        };
        let several_hosts = sources.iter().any(|source| hostname(source) != hostname(&sources[0]));
        let defect = match merged_tree_defect(tree, read_tree)? {
            None if scan.hardlinked_files && several_hosts => {
                cross_host_link_defect(tree, &trees, read_tree)?
            }
            defect => defect,
        };
        if let Some(defect) = defect {
            bail!(
                "these snapshots cannot be merged: {defect}. No snapshot was written; nothing \
                 refers to the trees the attempt wrote, and the next prune removes them"
            );
        }
    }

    // The source paths whose files are not where the path says: see
    // `merged_paths`.
    let mut misplaced_paths = std::collections::BTreeSet::new();
    let read_tree = |id: &TreeId| -> Result<_> {
        stopped_before_the_snapshot(
            "nothing refers to the trees it wrote, and the next prune removes them",
        )?;
        Ok(repo.cat_blob(BlobType::Tree, id.to_hex().as_str())?)
    };
    for (source, root) in sources.iter().zip(&trees) {
        let paths = source.get("paths").and_then(|paths| paths.as_array());
        let paths: Vec<&str> =
            paths.into_iter().flatten().filter_map(|path| path.as_str()).collect();
        // A tree that holds anything outside its paths is not laid out as
        // they say, wherever a path of that name happens to lead in it.
        let keeps_to_paths = tree_keeps_to_paths(*root, &paths, read_tree)?;
        for path in paths {
            if !(keeps_to_paths && tree_holds_path(*root, path, read_tree)?) {
                let _ = misplaced_paths.insert(path.to_string());
            }
        }
    }

    let json = merged_snapshot_json(
        &sources,
        &misplaced_paths,
        newest,
        tree.to_hex().as_str(),
        &summary,
        &started.to_string(),
        &finished.to_string(),
    )?;
    // Before anything is stored: the snapshot must be one rustic_core reads
    // back as pointing at the merged tree.
    let check: SnapshotFile =
        serde_json::from_slice(&json).context("the merged snapshot does not parse")?;
    if check.tree != tree {
        bail!("the merged snapshot does not point at the merged tree");
    }

    let snapshots = lock::snapshot_backend_for_profile(profile)?;
    // Published through the lock, which takes the snapshot back if it turns
    // out to have gone bad while the write was under way: until the snapshot
    // exists nothing refers to the merged trees, and a prune that got in
    // would have removed them.
    let published =
        repo_lock.write_unpacked_while_held(snapshots.as_ref(), &crypto, &json, retries)?;
    let new_id = published.name;
    // Same proof the tag edit asks for: an independent reader decodes our
    // envelope to exactly the JSON we meant to store.
    // A snapshot that cannot be shown to be what was meant is not left
    // standing behind an error: it is removed, and the error says whether
    // that worked.
    let problem = match repo.cat_file(FileType::Snapshot, &new_id) {
        Ok(readback) if readback.as_ref() == json.as_slice() => None,
        Ok(_) => Some("did not read back as written".to_string()),
        Err(e) => Some(format!("could not be read back ({e})")),
    };
    if let Some(problem) = problem {
        match snapshots.remove(&new_id) {
            // The removal is final only for writes that are over.
            Ok(()) if published.attempt_still_open => bail!(
                "merged snapshot {new_id} {problem}; it was removed again, but the server can \
                 still complete an earlier write of it that was reported as failed — if \
                 {new_id} turns up later it was not meant to be published: remove it"
            ),
            Ok(()) => bail!("merged snapshot {new_id} {problem}; it was removed again"),
            Err(e) => bail!(
                "merged snapshot {new_id} {problem}, and its removal could not be confirmed \
                 ({e:#}) — check whether {new_id} is in the repository; if it is, it is \
                 unverified: remove it"
            ),
        }
    }
    Ok(MergeOutcome {
        snapshot_id: new_id,
        dropped_node_fields: scan.dropped_node_fields.into_iter().collect(),
        attempt_still_open: published.attempt_still_open || write_gate.attempt_still_open(),
    })
}

/// Whether a write of repository data that failed with the given error can
/// still be stored by the backend afterwards
/// (`lock::LockBackend::failed_write_can_land_later`, for the backends
/// rustic_core writes through).
///
/// A local write is this process's own system calls and is over when it has
/// returned. A server can store what it took in full after the client gave
/// up, unless the error is its own refusal (`lock::server_refused`). That
/// reads the error as one request's, which it is for what the gate writes
/// one attempt at a time ([`RequestPolicy::ONE_ATTEMPT`]) — all but packs,
/// where a late arrival is only waste.
pub(crate) fn data_write_can_land_later(
    profile: &Profile,
) -> impl Fn(&rustic_core::RusticError) -> bool + Send + Sync + 'static {
    let backend = profile.backend_kind();
    move |error| match backend {
        crate::config::BackendKind::Local => false,
        crate::config::BackendKind::Rest | crate::config::BackendKind::S3 => {
            !lock::server_refused(error)
        }
    }
}

/// What [`merge_snapshots`] produced.
#[derive(Debug)]
pub(crate) struct MergeOutcome {
    /// The new snapshot's id.
    pub(crate) snapshot_id: String,
    /// Tree-node fields the sources hold and the merged snapshot does not
    /// ([`scan_source_trees`]), sorted; empty when nothing was lost.
    pub(crate) dropped_node_fields: Vec<String>,
    /// The snapshot or an index file was stored while another attempt at
    /// writing it, reported as failed, may still be completed by the server
    /// (`lock::Published::attempt_still_open`,
    /// `lock::WriteGate::attempt_still_open`). That attempt writes the same
    /// file again. It matters only if the file is gone by the time it
    /// arrives — the snapshot deleted, or the index rewritten by a prune,
    /// which the merged snapshot being kept does not prevent: it then brings
    /// back a file that names what the prune removed.
    pub(crate) attempt_still_open: bool,
}

/// What a merge has to know about its sources before it runs.
#[derive(Default)]
struct SourceScan {
    /// The node metadata the merge leaves behind, by field name.
    ///
    /// `Repository::merge_trees` reads every directory of every source into
    /// rustic_core's typed `Node` and writes it back from there, and a field
    /// that type does not model is not in the merged snapshot — as of
    /// rustic_core 0.14 that is restic's `generic_attributes` (Windows
    /// creation time, file attributes and security descriptors). The merge
    /// goes ahead regardless; this is how it knows what to report
    /// ([`unpreserved_node_fields`]).
    dropped_node_fields: std::collections::BTreeSet<String>,
    /// Some entry has a name restic stores quoted, and
    /// `hardlinked_files`: some file has more than one link. Either makes a
    /// defect in the merged tree possible ([`merged_tree_defect`]).
    quoted_names: bool,
    hardlinked_files: bool,
}

/// Reads every tree the sources reach, raw, through `read_tree`.
fn scan_source_trees<B: AsRef<[u8]>>(
    roots: &[TreeId],
    read_tree: impl Fn(&TreeId) -> Result<B>,
) -> Result<SourceScan> {
    let mut scan = SourceScan::default();
    visit_raw_trees(roots, read_tree, |_dir, nodes| {
        for node in nodes {
            scan.dropped_node_fields.extend(unpreserved_node_fields(node)?);
            scan.quoted_names |= raw_name(node).contains('\\');
            scan.hardlinked_files |= file_identity(node).is_some_and(|(_, links)| links > 1);
        }
        Ok(())
    })?;
    Ok(scan)
}

/// Calls `visit` with every tree reachable from `roots` — its entries as the
/// raw JSON restic reads, in stored order — and the path of the directory it
/// is. A tree reached more than once is read and visited once, under the
/// first path.
fn visit_raw_trees<B: AsRef<[u8]>>(
    roots: &[TreeId],
    read_tree: impl Fn(&TreeId) -> Result<B>,
    visit: impl FnMut(&str, &[serde_json::Value]) -> Result<()>,
) -> Result<()> {
    walk_raw_trees(roots, true, read_tree, visit)
}

/// [`visit_raw_trees`], or with `each_tree_once` off, every *directory*:
/// a tree that is two directories is then visited as both, each under its
/// own path — what a caller needs that goes by the paths.
fn walk_raw_trees<B: AsRef<[u8]>>(
    roots: &[TreeId],
    each_tree_once: bool,
    read_tree: impl Fn(&TreeId) -> Result<B>,
    mut visit: impl FnMut(&str, &[serde_json::Value]) -> Result<()>,
) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    let mut pending: Vec<(TreeId, String)> = roots
        .iter()
        .filter(|id| seen.insert(**id) || !each_tree_once)
        .map(|id| (*id, String::new()))
        .collect();
    while let Some((id, dir)) = pending.pop() {
        let hex = id.to_hex();
        let raw = read_tree(&id)?;
        let tree: serde_json::Value = serde_json::from_slice(raw.as_ref())
            .with_context(|| format!("parsing tree {}", hex.as_str()))?;
        let nodes = match tree.get("nodes") {
            None | Some(serde_json::Value::Null) => continue,
            Some(serde_json::Value::Array(nodes)) => nodes,
            Some(_) => bail!("tree {} has a `nodes` entry that is not a list", hex.as_str()),
        };
        visit(&dir, nodes)?;
        for node in nodes {
            if let Some(subtree) = node.get("subtree").and_then(|s| s.as_str()) {
                let subtree: TreeId = subtree
                    .parse()
                    .map_err(|e| anyhow!("tree {} names a bad subtree id: {e}", hex.as_str()))?;
                if seen.insert(subtree) || !each_tree_once {
                    pending.push((subtree, format!("{dir}/{}", raw_name(node))));
                }
            }
        }
    }
    Ok(())
}

/// A raw node's name as stored: quoted the way restic quotes it.
fn raw_name(node: &serde_json::Value) -> &str {
    node.get("name").and_then(|n| n.as_str()).unwrap_or("?")
}

/// The bytes of a name as restic compares them. restic stores a name as Go's
/// `strconv.Quote` writes it, without the surrounding quotes, and sorts the
/// entries of a tree by the name itself; this undoes the quoting. An escape
/// `strconv.Quote` does not produce is kept as it stands.
fn restic_name_bytes(quoted: &str) -> Vec<u8> {
    let bytes = quoted.as_bytes();
    let hex = |from: usize, len: usize| -> Option<u32> {
        let digits = bytes.get(from..from + len)?;
        let text = std::str::from_utf8(digits).ok()?;
        digits.iter().all(u8::is_ascii_hexdigit).then(|| u32::from_str_radix(text, 16).ok())?
    };
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let simple = |byte: u8| Some((vec![byte], 2));
        let escape = match (bytes[i], bytes.get(i + 1)) {
            (b'\\', Some(b'a')) => simple(0x07),
            (b'\\', Some(b'b')) => simple(0x08),
            (b'\\', Some(b'f')) => simple(0x0c),
            (b'\\', Some(b'n')) => simple(b'\n'),
            (b'\\', Some(b'r')) => simple(b'\r'),
            (b'\\', Some(b't')) => simple(b'\t'),
            (b'\\', Some(b'v')) => simple(0x0b),
            (b'\\', Some(b'\\')) => simple(b'\\'),
            (b'\\', Some(b'"')) => simple(b'"'),
            (b'\\', Some(b'x')) => {
                hex(i + 2, 2).and_then(|v| u8::try_from(v).ok()).map(|byte| (vec![byte], 4))
            }
            (b'\\', Some(b'u')) => hex(i + 2, 4)
                .and_then(char::from_u32)
                .map(|c| (c.to_string().into_bytes(), 6)),
            (b'\\', Some(b'U')) => hex(i + 2, 8)
                .and_then(char::from_u32)
                .map(|c| (c.to_string().into_bytes(), 10)),
            _ => None,
        };
        match escape {
            Some((decoded, used)) => {
                out.extend(decoded);
                i += used;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    out
}

/// A raw file node's device and inode, and its link count; `None` for
/// anything that is not a file.
fn file_identity(node: &serde_json::Value) -> Option<((u64, u64), u64)> {
    if node.get("type").and_then(|t| t.as_str()) != Some("file") {
        return None;
    }
    let number = |key: &str| node.get(key).and_then(serde_json::Value::as_u64).unwrap_or(0);
    Some(((number("device_id"), number("inode")), number("links")))
}

/// What restic's restorer goes by to rebuild hardlinks, from a raw file node.
struct RawFile {
    /// Device and inode.
    identity: (u64, u64),
    links: u64,
    content: serde_json::Value,
    /// What a restore puts back on a path besides its content, by the name
    /// to call it: an inode has one of each, so links of one file agree on
    /// all of them. Change times are left out because no restore sets them.
    /// Access times are left out although restic restores them: it does not
    /// record them alike for the links of one file. Under `--with-atime`,
    /// reading one link moves the time the next is recorded with wherever
    /// restic cannot open the file without touching it, so one snapshot of
    /// its own holds links that differ, and comparing would refuse those.
    metadata: [(&'static str, serde_json::Value); 4],
}

impl RawFile {
    fn of(node: &serde_json::Value) -> Option<Self> {
        let (identity, links) = file_identity(node)?;
        let number = |key: &str| node.get(key).and_then(serde_json::Value::as_u64).unwrap_or(0);
        // Nothing and an empty list are the same thing written two ways: an
        // empty file is `null` to restic and `[]` to rustic_core.
        let list = |key: &str| match node.get(key) {
            Some(value) if !value.is_null() => value.clone(),
            _ => serde_json::Value::Array(Vec::new()),
        };
        // One instant can be written with different offsets.
        let mtime = node.get("mtime").and_then(|t| t.as_str()).map(|text| {
            text.parse::<rustic_core::jiff::Timestamp>()
                .map_or_else(|_| text.to_string(), |instant| instant.to_string())
        });
        // A name that is not recorded and an empty one are the same.
        let text = |key: &str| node.get(key).and_then(|t| t.as_str()).unwrap_or("").to_string();
        // Attributes are a set: the order they are listed in is whatever the
        // filesystem gave at the time, and says nothing.
        let mut attributes = match list("extended_attributes") {
            serde_json::Value::Array(attributes) => attributes,
            other => vec![other],
        };
        attributes.sort_by_cached_key(|attribute| {
            let name = attribute.get("name").and_then(|n| n.as_str()).unwrap_or("");
            (name.to_string(), attribute.to_string())
        });
        Some(Self {
            identity,
            links,
            content: list("content"),
            metadata: [
                ("permissions", serde_json::json!(number("mode"))),
                // By number and by name: restic restores the numbers, a
                // restore through rustic_core goes by the names.
                (
                    "owners",
                    serde_json::json!([number("uid"), number("gid"), text("user"), text("group")]),
                ),
                ("modification times", serde_json::json!(mtime)),
                ("extended attributes", serde_json::Value::Array(attributes)),
            ],
        })
    }
}

/// What restic would get wrong in a merged tree, in words, if anything.
///
/// **Order.** restic keeps the entries of a directory sorted by name and
/// relies on it. `merge_trees` merges two directories by walking both in the
/// order of the names *as stored* — quoted, where a name has a quote, a
/// backslash, a control character or bytes that are not UTF-8 — and a quoted
/// name sorts differently from the name it stands for (`"a` is before `A`,
/// `\"a` after). Directories restic wrote are then not in the order the walk
/// assumes: an entry both sources hold can come out twice, the older copy
/// last, which is the one a restore leaves behind; or the entries come out
/// in an order restic does not keep.
///
/// **Hardlinks.** `merge_trees` passes each file's device and inode on as
/// recorded, and restic's restorer goes by those: of the files with more than
/// one link that share a device and inode it writes the first, and it makes
/// every *other* file with that device and inode — whatever its own link
/// count — a hardlink to it. Within one backup these are the links of one
/// file. Across two they need not be: an inode rewritten or reused under
/// another path, or two filesystems given the same device number, and files
/// with different content are restored as one. Links of one file also share
/// everything else an inode has one of — permissions, owner, modification
/// time, extended attributes — and restic puts each path's own back after
/// linking it, so of two that differ only one survives. The first walk
/// collects the groups, the second holds every file against them.
fn merged_tree_defect<B: AsRef<[u8]>>(
    root: TreeId,
    read_tree: impl Fn(&TreeId) -> Result<B>,
) -> Result<Option<String>> {
    let mut defect = None;
    // (device, inode) → a file with several links, and its path.
    let mut groups = std::collections::HashMap::new();
    visit_raw_trees(&[root], &read_tree, |dir, nodes| {
        let mut previous: Option<(&str, Vec<u8>)> = None;
        for node in nodes {
            let name = raw_name(node);
            let decoded = restic_name_bytes(name);
            if let Some((before, before_decoded)) = &previous
                && defect.is_none()
                && *before_decoded >= decoded
            {
                let how = if *before_decoded == decoded {
                    format!("would hold `{name}` twice")
                } else {
                    format!("would list `{name}` after `{before}`, which is not restic's order")
                };
                defect = Some(format!(
                    "the merged directory `{dir}/` {how} — some names in it are stored \
                     quoted, and the merge goes by the quoted form where restic goes by the \
                     name"
                ));
            }
            previous = Some((name, decoded));
            if let Some(file) = RawFile::of(node)
                && file.links > 1
            {
                let path = format!("{dir}/{name}");
                let _ = groups.entry(file.identity).or_insert_with(|| (file, path));
            }
        }
        Ok(())
    })?;
    if defect.is_some() || groups.is_empty() {
        return Ok(defect);
    }
    visit_raw_trees(&[root], &read_tree, |dir, nodes| {
        for node in nodes {
            let Some(file) = RawFile::of(node) else { continue };
            let Some((group, first)) = groups.get(&file.identity) else { continue };
            if defect.is_some() {
                continue;
            }
            let differ = if group.content != file.content {
                "hold different content, and restic would restore them as hardlinks of one \
                 file, both with the content of one"
                    .to_string()
            } else if let Some((what, _)) =
                group.metadata.iter().zip(&file.metadata).find(|(a, b)| a.1 != b.1).map(|(a, _)| a)
            {
                format!(
                    "have different {what}, and restic would restore them as hardlinks of one \
                     file, which keeps only one of the two"
                )
            } else {
                continue;
            };
            defect = Some(format!(
                "`{first}` and `{dir}/{}` are recorded under one device and inode but {differ}",
                raw_name(node)
            ));
        }
        Ok(())
    })?;
    Ok(defect)
}

/// What [`merged_tree_defect`] cannot see, for sources of more than one host.
///
/// It lets files of different sources share a device and inode when they
/// agree in everything else, because on one machine that is one file seen by
/// two backups. Between machines the numbers say nothing: two hosts set up
/// alike hand out the same ones, and a file copied to both agrees in the
/// rest. restic would restore such files as hardlinks of one another. So
/// across hosts a group of files restic would link has to be one that some
/// single source records as it is — every path of it, under that device and
/// inode. `sources` are walked by path, so that a directory stored once and
/// found in two places counts as both.
fn cross_host_link_defect<B: AsRef<[u8]>>(
    merged: TreeId,
    sources: &[TreeId],
    read_tree: impl Fn(&TreeId) -> Result<B>,
) -> Result<Option<String>> {
    use std::collections::{BTreeMap, HashSet};
    type Identity = (u64, u64);

    // The groups restic would form: every file that shares a device and inode
    // with one of several links, by path.
    let mut groups: BTreeMap<Identity, Vec<String>> = BTreeMap::new();
    visit_raw_trees(&[merged], &read_tree, |_, nodes| {
        for (identity, _) in nodes.iter().filter_map(file_identity).filter(|(_, links)| *links > 1)
        {
            let _ = groups.entry(identity).or_default();
        }
        Ok(())
    })?;
    if groups.is_empty() {
        return Ok(None);
    }
    walk_raw_trees(&[merged], false, &read_tree, |dir, nodes| {
        for node in nodes {
            if let Some((identity, _)) = file_identity(node)
                && let Some(paths) = groups.get_mut(&identity)
            {
                paths.push(format!("{dir}/{}", raw_name(node)));
            }
        }
        Ok(())
    })?;
    groups.retain(|_, paths| paths.len() > 1);
    if groups.is_empty() {
        return Ok(None);
    }

    // What each source records of them.
    let mut recorded: Vec<HashSet<(Identity, String)>> = Vec::with_capacity(sources.len());
    for source in sources {
        let mut own = HashSet::new();
        walk_raw_trees(&[*source], false, &read_tree, |dir, nodes| {
            for node in nodes {
                if let Some((identity, _)) = file_identity(node)
                    && groups.contains_key(&identity)
                {
                    let _ = own.insert((identity, format!("{dir}/{}", raw_name(node))));
                }
            }
            Ok(())
        })?;
        recorded.push(own);
    }

    for (identity, paths) in &groups {
        let holds = |own: &HashSet<(Identity, String)>, path: &String| {
            own.contains(&(*identity, path.clone()))
        };
        if recorded.iter().any(|own| paths.iter().all(|path| holds(own, path))) {
            continue;
        }
        let first = &paths[0];
        let other = paths[1..]
            .iter()
            .find(|path| !recorded.iter().any(|own| holds(own, first) && holds(own, path)))
            .unwrap_or(&paths[1]);
        return Ok(Some(format!(
            "`{first}` and `{other}` are recorded under one device and inode by snapshots of \
             different hosts, where the numbers of one machine say nothing about another's, \
             and restic would restore them as hardlinks of one file"
        )));
    }
    Ok(None)
}

/// The names a backed-up path has in a restic tree, from the root down.
/// restic stores a target under its absolute path: `/data/extra` is `data`,
/// then `extra`. On Windows the volume is the first directory, without its
/// colon: `C:\Users\me` is `C`, `Users`, `me`. A network share is one
/// directory under its whole name, `\\nas\share\dir` being `\\nas\share`, then
/// `dir`: restic puts the volume name first as it stands, and takes the colon
/// off a drive letter only (`pathComponents` in its `archiver/tree.go`).
fn archive_components(path: &str) -> Vec<&str> {
    if path.starts_with('/') {
        return path.split('/').filter(|part| !part.is_empty()).collect();
    }
    // `\\?\C:\…` is the same path spelled the long way.
    let path = path.strip_prefix(r"\\?\").unwrap_or(path);
    let (volume, rest) = match path.strip_prefix(r"\\") {
        // Host and share, up to the separator after the share.
        Some(unc) => {
            let end = unc
                .match_indices(['/', '\\'])
                .nth(1)
                .map_or(path.len(), |(at, _)| at + r"\\".len());
            (Some(&path[..end]), &path[end..])
        }
        None => (None, path),
    };
    volume
        .into_iter()
        .chain(
            rest.split(['/', '\\'])
                .filter(|part| !part.is_empty())
                .enumerate()
                .map(|(i, part)| match (i, volume) {
                    (0, None) => part.strip_suffix(':').unwrap_or(part),
                    _ => part,
                }),
        )
        .collect()
}

/// Whether everything in the tree at `root` lies within `paths`, laid out as
/// restic stores absolute paths ([`archive_components`]): above the targets
/// such a tree holds only the directories that lead to them. An entry beside
/// those was not put there by a backup of these paths as absolute ones — a
/// target given as a relative path, or a merge that kept such a one — and
/// then a path of the right name in the tree ([`tree_holds_path`]) need not
/// be the directory the path names.
fn tree_keeps_to_paths<B: AsRef<[u8]>>(
    root: TreeId,
    paths: &[&str],
    read_tree: impl Fn(&TreeId) -> Result<B>,
) -> Result<bool> {
    let targets: Vec<Vec<&str>> = paths.iter().map(|path| archive_components(path)).collect();
    // The directories above the targets still to look into, each with how
    // deep it is and the targets that lie below it.
    let mut above = vec![(root, 0, targets.iter().collect::<Vec<_>>())];
    while let Some((tree, depth, below)) = above.pop() {
        // A target itself: all of it is within the paths.
        if below.iter().any(|target| target.len() == depth) {
            continue;
        }
        let raw = read_tree(&tree)?;
        let parsed: serde_json::Value = serde_json::from_slice(raw.as_ref())
            .with_context(|| format!("parsing tree {}", tree.to_hex().as_str()))?;
        let nodes = parsed.get("nodes").and_then(serde_json::Value::as_array);
        for node in nodes.into_iter().flatten() {
            let name = restic_name_bytes(raw_name(node));
            let through: Vec<_> = below
                .iter()
                .copied()
                .filter(|target| target[depth].as_bytes() == name)
                .collect();
            if through.is_empty() {
                return Ok(false);
            }
            if through.iter().any(|target| target.len() == depth + 1) {
                continue;
            }
            match node.get("subtree").and_then(|s| s.as_str()).map(str::parse::<TreeId>) {
                Some(Ok(subtree)) => above.push((subtree, depth + 1, through)),
                _ => return Ok(false),
            }
        }
    }
    Ok(true)
}

/// Whether the tree at `root` holds `path` where restic stores an absolute
/// path ([`archive_components`]). It does not for a target that was given to
/// `restic backup` as a relative path: `paths` still records the absolute
/// path, while the tree is rooted at the relative one — `cd /data && restic
/// backup extra` records `/data/extra` and stores `/extra`.
fn tree_holds_path<B: AsRef<[u8]>>(
    root: TreeId,
    path: &str,
    read_tree: impl Fn(&TreeId) -> Result<B>,
) -> Result<bool> {
    let mut tree = root;
    let components = archive_components(path);
    for (i, component) in components.iter().enumerate() {
        let raw = read_tree(&tree)?;
        let parsed: serde_json::Value = serde_json::from_slice(raw.as_ref())
            .with_context(|| format!("parsing tree {}", tree.to_hex().as_str()))?;
        let Some(node) = parsed
            .get("nodes")
            .and_then(serde_json::Value::as_array)
            .and_then(|nodes| {
                // The name as stored is quoted; the path is not.
                nodes
                    .iter()
                    .find(|node| restic_name_bytes(raw_name(node)) == component.as_bytes())
            })
        else {
            return Ok(false);
        };
        if i + 1 == components.len() {
            break;
        }
        match node.get("subtree").and_then(|s| s.as_str()).map(str::parse::<TreeId>) {
            Some(Ok(subtree)) => tree = subtree,
            _ => return Ok(false),
        }
    }
    Ok(true)
}

/// The fields of one raw tree node that would not survive a round trip
/// through rustic_core's typed `Node`. Found by doing the round trip rather
/// than from a list of field names, so it stays right when rustic_core learns
/// a field. A field the round trip leaves out is only a loss when it held
/// something: restic and rustic_core differ in which empty values they write.
fn unpreserved_node_fields(raw: &serde_json::Value) -> Result<Vec<String>> {
    let fields = raw
        .as_object()
        .ok_or_else(|| anyhow!("tree node is not a JSON object"))?;
    let typed: Node = serde_json::from_value(raw.clone()).context("parsing a tree node")?;
    let kept = serde_json::to_value(&typed).context("re-serializing a tree node")?;
    Ok(fields
        .iter()
        .filter(|(key, value)| kept.get(key.as_str()).is_none() && !json_is_empty(value))
        .map(|(key, _)| key.clone())
        .collect())
}

fn json_is_empty(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => true,
        serde_json::Value::Bool(b) => !b,
        serde_json::Value::Number(n) => n.as_f64() == Some(0.0),
        serde_json::Value::String(s) => s.is_empty(),
        serde_json::Value::Array(a) => a.is_empty(),
        serde_json::Value::Object(o) => o.is_empty(),
    }
}

/// The merged snapshot's file, built field by field in restic's layout
/// (`internal/data/snapshot.go`) rather than copied from a source: a snapshot
/// that is the product of several describes none of their backup runs, so
/// `parent`, `original` and `excludes` are left out.
///
/// What it does carry is chosen so restic treats it as the latest backup of
/// what it contains — `restic backup` picks its parent by exact hostname and
/// path set:
///
/// - `username`, `uid`, `gid` come from the newest source (`newest` indexes
///   `sources`), copied as stored.
/// - `hostname` is the sources' own where they share one, and otherwise a
///   name of its own made of all of theirs ([`merged_hostname`]) — a merge
///   across hosts is not a backup of either, and should not be taken for the
///   parent of one.
/// - `time` is the newest source's plus one nanosecond ([`just_after`]): as
///   recent as its newest data, and still the *latest* of the snapshots that
///   match — restic takes the latest as parent and leaves a tie to chance,
///   and the newest source matches too whenever its paths are the merged
///   ones.
/// - `paths` is every source's paths with nested ones folded into their
///   ancestor ([`merged_paths`]).
/// - `tags` is the union.
/// - `summary` holds the fields restic and rustic_core share; the totals are
///   those of the merged tree.
fn merged_snapshot_json(
    sources: &[serde_json::Value],
    misplaced_paths: &std::collections::BTreeSet<String>,
    newest: usize,
    tree: &str,
    summary: &SnapshotSummary,
    started: &str,
    finished: &str,
) -> Result<Vec<u8>> {
    use serde_json::{Value, json};

    let newest = sources
        .get(newest)
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("the newest source snapshot is not a JSON object"))?;
    let strings = |key: &str| -> Result<Vec<&str>> {
        let mut out = Vec::new();
        for source in sources {
            match source.get(key) {
                None | Some(Value::Null) => {}
                Some(Value::Array(items)) => {
                    for item in items {
                        out.push(item.as_str().ok_or_else(|| {
                            anyhow!("snapshot `{key}` holds something that is not a string: {item}")
                        })?);
                    }
                }
                Some(other) => bail!("snapshot `{key}` is not a list: {other}"),
            }
        }
        Ok(out)
    };

    let mut snapshot = serde_json::Map::new();
    let time = newest
        .get("time")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("the newest source snapshot has no `time`"))?;
    let _ = snapshot.insert("time".into(), json!(just_after(time)?));
    let _ = snapshot.insert("tree".into(), json!(tree));
    let _ = snapshot.insert(
        "paths".into(),
        json!(merged_paths(&strings("paths")?, misplaced_paths)),
    );
    let hosts: Vec<&str> = sources
        .iter()
        .map(|source| source.get("hostname").and_then(Value::as_str).unwrap_or(""))
        .collect();
    if let Some(host) = merged_hostname(&hosts) {
        let _ = snapshot.insert("hostname".into(), json!(host));
    }
    for key in ["username", "uid", "gid"] {
        if let Some(value) = newest.get(key) {
            let _ = snapshot.insert(key.into(), value.clone());
        }
    }
    let tags: std::collections::BTreeSet<&str> = strings("tags")?.into_iter().collect();
    // restic's `omitempty`: no tags means no key.
    if !tags.is_empty() {
        let _ = snapshot.insert("tags".into(), json!(tags));
    }
    let _ = snapshot.insert(
        "program_version".into(),
        json!(concat!("wrustic ", env!("CARGO_PKG_VERSION"))),
    );
    let _ = snapshot.insert(
        "summary".into(),
        json!({
            "backup_start": started,
            "backup_end": finished,
            "files_new": summary.files_new,
            "files_changed": summary.files_changed,
            "files_unmodified": summary.files_unmodified,
            "dirs_new": summary.dirs_new,
            "dirs_changed": summary.dirs_changed,
            "dirs_unmodified": summary.dirs_unmodified,
            "data_blobs": summary.data_blobs,
            "tree_blobs": summary.tree_blobs,
            "data_added": summary.data_added,
            "data_added_packed": summary.data_added_packed,
            "total_files_processed": summary.total_files_processed,
            "total_bytes_processed": summary.total_bytes_processed,
        }),
    );
    serde_json::to_vec(&Value::Object(snapshot)).context("serializing the merged snapshot")
}

/// The instant one nanosecond after an RFC 3339 `time`, written with the same
/// UTC offset — the smallest step that puts a snapshot strictly after another.
fn just_after(time: &str) -> Result<String> {
    use rustic_core::jiff::fmt::temporal::{Pieces, PiecesOffset};
    use rustic_core::jiff::{SignedDuration, Timestamp};

    let instant: Timestamp =
        time.parse().with_context(|| format!("parsing snapshot time `{time}`"))?;
    let later = instant
        .checked_add(SignedDuration::from_nanos(1))
        .with_context(|| format!("stepping past snapshot time `{time}`"))?;
    let offset = Pieces::parse(time)
        .with_context(|| format!("parsing snapshot time `{time}`"))?
        .offset();
    Ok(match offset {
        Some(PiecesOffset::Numeric(offset)) => {
            later.display_with_offset(offset.offset()).to_string()
        }
        _ => later.to_string(),
    })
}

/// The hostname of a merged snapshot, if it gets one. Sources of one host
/// keep it, which is what lets `restic backup` on that host find the merged
/// snapshot as its parent (it looks for its own hostname and path set).
/// Sources of several hosts get a name made of all of them, sorted and joined
/// with `+`, a source without a hostname counting as `unknown`: such a merge
/// holds another machine's files, and a backup that took it for its parent
/// would compare its own against those. The name says where the snapshot
/// came from, and is not one a machine has — which keeps backups away from
/// it unless one is run with `--host` set to that very name. Leaving the
/// hostname out would close that gap too, at the price of a snapshot that
/// shows no host anywhere. Sources none of which names a host give none.
///
/// A name made of two or more different parts is longer than any of them,
/// so it is never a source's own hostname. That only fails if the stand-in
/// for a missing hostname is also a real one among the sources — a host
/// called `unknown` merged with a snapshot that names none would come out as
/// plain `unknown` — and then the hostname is left out instead.
pub(crate) fn merged_hostname(hosts: &[&str]) -> Option<String> {
    const UNNAMED: &str = "unknown";
    let first = hosts.first()?;
    if hosts.iter().all(|host| host == first) {
        return (!first.is_empty()).then(|| first.to_string());
    }
    let mut names: std::collections::BTreeSet<&str> =
        hosts.iter().copied().filter(|host| !host.is_empty()).collect();
    if hosts.iter().any(|host| host.is_empty()) && !names.insert(UNNAMED) {
        return None;
    }
    Some(names.into_iter().collect::<Vec<_>>().join("+"))
}

/// The path set of a merged snapshot: every source path, sorted, without
/// duplicates, and without any path that lies inside another one — a backup
/// of `/data` already covers `/data/extra`. Folding those is what lets a later
/// `restic backup /data` recognize the merged snapshot as its parent; restic
/// compares path sets exactly.
///
/// That holds only where the trees are laid out as the paths say. A path in
/// `misplaced` is one whose source does not hold it there
/// ([`tree_holds_path`]: a backup of a relative path), so its files were not
/// merged into the directory its path names, and it is neither folded into
/// another nor another into it: the merged snapshot then lists both, and
/// does not pass for a backup of the one.
pub(crate) fn merged_paths(
    paths: &[&str],
    misplaced: &std::collections::BTreeSet<String>,
) -> Vec<String> {
    let set: std::collections::BTreeSet<&str> = paths.iter().copied().collect();
    let placed = |path: &str| !misplaced.contains(path);
    set.iter()
        .filter(|path| {
            !set.iter().any(|other| {
                path_is_inside(path, other) && placed(path) && placed(other)
            })
        })
        .map(|path| path.to_string())
        .collect()
}

/// Whether `path` lies strictly inside `ancestor`, compared by whole
/// components. A restic path that starts with `/` is a Unix one, where `\` is
/// an ordinary filename character; anything else is a Windows path
/// (`C:\Users\x`), which separates with either.
fn path_is_inside(path: &str, ancestor: &str) -> bool {
    fn components(path: &str) -> Vec<&str> {
        let unix = path.starts_with('/');
        path.split(|c: char| c == '/' || (!unix && c == '\\'))
            .filter(|part| !part.is_empty())
            .collect()
    }
    if path.starts_with('/') != ancestor.starts_with('/') {
        return false;
    }
    let (path, ancestor) = (components(path), components(ancestor));
    path.len() > ancestor.len() && path[..ancestor.len()] == ancestor[..]
}

/// Backend + crypto pair for talking to the repo's `locks/` natively —
/// everything needed to list, read, or evaluate lock files for a profile.
/// Opens the repository (no index) to obtain the master key.
pub(crate) fn lock_context(
    profile: &Profile,
) -> Result<(std::sync::Arc<dyn lock::LockBackend>, lock::RepoCrypto)> {
    let backends = build_backends(profile)?;
    let repo = Repository::new(&RepositoryOptions::default(), &backends)?
        .open(&Credentials::password(profile.password()))?;
    let crypto = lock::RepoCrypto::from_repo(&repo)?;
    Ok((lock::backend_for_profile(profile)?, crypto))
}

/// Removes stale repository locks (native equivalent of `restic unlock`).
/// Returns how many lock files were removed; live locks are left in place.
pub(crate) fn unlock(profile: &Profile) -> Result<usize> {
    let (backend, crypto) = lock_context(profile)?;
    lock::remove_stale_locks(backend.as_ref(), &crypto)
}

// restic/rustic snapshot ids are SHA-256 hashes — 32 bytes = 64 hex chars
// (either case accepted; hex is case-insensitive).
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

pub(crate) fn list_tree(
    repo: &Repository<IndexedIdsStatus>,
    tree_id: TreeId,
) -> Result<Vec<ContentRow>> {
    let tree = repo.get_tree(&tree_id)?;
    let mut rows: Vec<ContentRow> = tree
        .nodes
        .into_iter()
        .map(|n| {
            let kind = if n.is_dir() {
                ContentKind::Dir
            } else if n.is_file() {
                ContentKind::File
            } else if n.is_symlink() {
                ContentKind::Symlink
            } else {
                ContentKind::Other
            };
            let mtime = n
                .meta
                .mtime
                .map(|t| t.strftime("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_default();
            ContentRow {
                name: n.name().to_string_lossy().into_owned(),
                kind,
                size: n.meta.size,
                mtime,
                subtree: n.subtree,
            }
        })
        .collect();

    // Dirs first, then by name (case-sensitive, byte order).
    rows.sort_by(|a, b| {
        let ad = matches!(a.kind, ContentKind::Dir);
        let bd = matches!(b.kind, ContentKind::Dir);
        bd.cmp(&ad).then_with(|| a.name.cmp(&b.name))
    });
    Ok(rows)
}

// DFS-walk the snapshot tree, emitting each entry with its full path until
// `limit` items are collected. Used to give the user a peek at what they're
// about to delete — snapshots' top-level often looks like a single
// path-prefix directory chain (`home/`, `home/x/`, ...) before reaching the
// actual backed-up files, so a plain root listing isn't very informative.
pub(crate) fn preview_snapshot_contents(
    repo: &Repository<IndexedIdsStatus>,
    snapshot_id: &str,
    limit: usize,
) -> Result<ContentsPreview> {
    let root = snapshot_root_tree(repo, snapshot_id)?;
    let mut entries = Vec::new();
    let mut truncated = false;
    walk_preview(repo, root, "", &mut entries, limit, &mut truncated)?;
    Ok(ContentsPreview { entries, truncated })
}

pub(crate) fn get_file_details(
    repo: &Repository<IndexedIdsStatus>,
    tree_id: TreeId,
    file_name: &str,
    full_path: String,
) -> Result<FileDetails> {
    let tree = repo.get_tree(&tree_id)?;
    let node = tree
        .nodes
        .into_iter()
        .find(|n| n.name().to_string_lossy() == file_name)
        .ok_or_else(|| anyhow!("file `{file_name}` not found in tree"))?;

    let (kind, kind_label, linktarget) = match &node.node_type {
        NodeType::File => (ContentKind::File, "file".to_string(), None),
        NodeType::Dir => (ContentKind::Dir, "directory".to_string(), None),
        NodeType::Symlink { linktarget, .. } => (
            ContentKind::Symlink,
            format!("symlink → {linktarget}"),
            Some(linktarget.clone()),
        ),
        other => (ContentKind::Other, other.to_string(), None),
    };

    let content_hashes = node
        .content
        .map(|ids| {
            ids.iter()
                .map(|id| id.to_hex().as_str().to_string())
                .collect()
        })
        .unwrap_or_default();

    Ok(FileDetails {
        name: file_name.to_string(),
        full_path,
        kind,
        kind_label,
        size: node.meta.size,
        mode: node.meta.mode,
        mtime: node.meta.mtime.map(|t| t.strftime("%Y-%m-%d %H:%M:%S").to_string()),
        atime: node.meta.atime.map(|t| t.strftime("%Y-%m-%d %H:%M:%S").to_string()),
        ctime: node.meta.ctime.map(|t| t.strftime("%Y-%m-%d %H:%M:%S").to_string()),
        uid: node.meta.uid,
        gid: node.meta.gid,
        user: node.meta.user,
        group: node.meta.group,
        linktarget,
        content_hashes,
    })
}

fn walk_preview(
    repo: &Repository<IndexedIdsStatus>,
    tree_id: TreeId,
    prefix: &str,
    out: &mut Vec<PreviewEntry>,
    limit: usize,
    truncated: &mut bool,
) -> Result<()> {
    if out.len() >= limit {
        *truncated = true;
        return Ok(());
    }
    let rows = list_tree(repo, tree_id)?;
    for row in rows {
        if out.len() >= limit {
            *truncated = true;
            return Ok(());
        }
        let path = format!("{prefix}/{}", row.name);
        let is_dir = matches!(row.kind, ContentKind::Dir);
        let subtree = row.subtree;
        out.push(PreviewEntry {
            path: path.clone(),
            kind: row.kind,
            size: row.size,
        });
        if is_dir
            && let Some(sub) = subtree
        {
            walk_preview(repo, sub, &path, out, limit, truncated)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Snapshot diff (native, no restic CLI)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiffModifier {
    Added,
    Removed,
    Modified,
    TypeChanged,
}

impl DiffModifier {
    pub(crate) fn as_char(self) -> char {
        match self {
            DiffModifier::Added => '+',
            DiffModifier::Removed => '-',
            DiffModifier::Modified => 'M',
            DiffModifier::TypeChanged => 'T',
        }
    }
}

#[derive(Debug)]
pub(crate) struct DiffChange {
    pub(crate) modifier: DiffModifier,
    pub(crate) path: String,
}

#[derive(Debug, Default)]
pub(crate) struct DiffSummary {
    pub(crate) changed_files: u64,
    pub(crate) added_files: u64,
    pub(crate) added_bytes: u64,
    pub(crate) removed_files: u64,
    pub(crate) removed_bytes: u64,
}

pub(crate) fn diff_snapshots(
    repo: &Repository<IndexedIdsStatus>,
    first_id: &str,
    second_id: &str,
) -> Result<(DiffSummary, Vec<DiffChange>)> {
    let tree1 = snapshot_root_tree(repo, first_id)?;
    let tree2 = snapshot_root_tree(repo, second_id)?;

    let mut changes = Vec::new();
    let mut summary = DiffSummary::default();

    if tree1 != tree2 {
        diff_trees(repo, tree1, tree2, "", &mut changes, &mut summary)?;
    }

    Ok((summary, changes))
}

fn diff_trees(
    repo: &Repository<IndexedIdsStatus>,
    tree1: TreeId,
    tree2: TreeId,
    prefix: &str,
    changes: &mut Vec<DiffChange>,
    summary: &mut DiffSummary,
) -> Result<()> {
    let nodes1 = repo.get_tree(&tree1)?.nodes;
    let nodes2 = repo.get_tree(&tree2)?.nodes;

    let mut i = 0;
    let mut j = 0;
    while i < nodes1.len() && j < nodes2.len() {
        let n1 = &nodes1[i];
        let n2 = &nodes2[j];
        let raw1 = n1.name();
        let raw2 = n2.name();
        let name1 = raw1.to_string_lossy();
        let name2 = raw2.to_string_lossy();

        match name1.as_ref().cmp(name2.as_ref()) {
            std::cmp::Ordering::Less => {
                let path = format!("{prefix}/{name1}");
                emit_node(n1, &path, DiffModifier::Removed, changes, summary);
                if let Some(sub) = n1.subtree {
                    collect_all_as(repo, sub, &path, DiffModifier::Removed, changes, summary)?;
                }
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                let path = format!("{prefix}/{name2}");
                emit_node(n2, &path, DiffModifier::Added, changes, summary);
                if let Some(sub) = n2.subtree {
                    collect_all_as(repo, sub, &path, DiffModifier::Added, changes, summary)?;
                }
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                let path = format!("{prefix}/{name1}");
                diff_matched_nodes(repo, n1, n2, &path, changes, summary)?;
                i += 1;
                j += 1;
            }
        }
    }
    for n in &nodes1[i..] {
        let path = format!("{prefix}/{}", n.name().to_string_lossy());
        emit_node(n, &path, DiffModifier::Removed, changes, summary);
        if let Some(sub) = n.subtree {
            collect_all_as(repo, sub, &path, DiffModifier::Removed, changes, summary)?;
        }
    }
    for n in &nodes2[j..] {
        let path = format!("{prefix}/{}", n.name().to_string_lossy());
        emit_node(n, &path, DiffModifier::Added, changes, summary);
        if let Some(sub) = n.subtree {
            collect_all_as(repo, sub, &path, DiffModifier::Added, changes, summary)?;
        }
    }
    Ok(())
}

fn diff_matched_nodes(
    repo: &Repository<IndexedIdsStatus>,
    n1: &Node,
    n2: &Node,
    path: &str,
    changes: &mut Vec<DiffChange>,
    summary: &mut DiffSummary,
) -> Result<()> {
    if mem::discriminant(&n1.node_type) != mem::discriminant(&n2.node_type) {
        changes.push(DiffChange {
            modifier: DiffModifier::TypeChanged,
            path: path.to_string(),
        });
        if let Some(sub) = n1.subtree {
            collect_all_as(repo, sub, path, DiffModifier::Removed, changes, summary)?;
        }
        if let Some(sub) = n2.subtree {
            collect_all_as(repo, sub, path, DiffModifier::Added, changes, summary)?;
        }
        return Ok(());
    }

    match (&n1.node_type, &n2.node_type) {
        (NodeType::Dir, NodeType::Dir) => {
            let s1 = n1.subtree;
            let s2 = n2.subtree;
            if s1 != s2
                && let (Some(s1), Some(s2)) = (s1, s2)
            {
                diff_trees(repo, s1, s2, path, changes, summary)?;
            }
        }
        (NodeType::File, NodeType::File) => {
            if n1.content != n2.content {
                changes.push(DiffChange {
                    modifier: DiffModifier::Modified,
                    path: path.to_string(),
                });
                summary.changed_files += 1;
            }
        }
        (
            NodeType::Symlink {
                linktarget: lt1, ..
            },
            NodeType::Symlink {
                linktarget: lt2, ..
            },
        ) => {
            if lt1 != lt2 {
                changes.push(DiffChange {
                    modifier: DiffModifier::Modified,
                    path: path.to_string(),
                });
            }
        }
        _ => {
            if n1.node_type != n2.node_type {
                changes.push(DiffChange {
                    modifier: DiffModifier::Modified,
                    path: path.to_string(),
                });
            }
        }
    }
    Ok(())
}

fn emit_node(
    node: &Node,
    path: &str,
    modifier: DiffModifier,
    changes: &mut Vec<DiffChange>,
    summary: &mut DiffSummary,
) {
    changes.push(DiffChange {
        modifier,
        path: path.to_string(),
    });
    if matches!(node.node_type, NodeType::File) {
        let size = node.meta.size;
        match modifier {
            DiffModifier::Added => {
                summary.added_files += 1;
                summary.added_bytes += size;
            }
            DiffModifier::Removed => {
                summary.removed_files += 1;
                summary.removed_bytes += size;
            }
            _ => {}
        }
    }
}

fn collect_all_as(
    repo: &Repository<IndexedIdsStatus>,
    tree_id: TreeId,
    prefix: &str,
    modifier: DiffModifier,
    changes: &mut Vec<DiffChange>,
    summary: &mut DiffSummary,
) -> Result<()> {
    let nodes = repo.get_tree(&tree_id)?.nodes;
    for n in &nodes {
        let path = format!("{prefix}/{}", n.name().to_string_lossy());
        emit_node(n, &path, modifier, changes, summary);
        if let Some(sub) = n.subtree {
            collect_all_as(repo, sub, &path, modifier, changes, summary)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // The merge and its parts as most tests want them: watched by nobody,
    // and with every source laid out as its paths say.
    fn merge_snapshots(profile: &Profile, snapshot_ids: &[String]) -> Result<MergeOutcome> {
        super::merge_snapshots(profile, snapshot_ids, &Default::default())
    }

    fn merged_paths(paths: &[&str]) -> Vec<String> {
        super::merged_paths(paths, &Default::default())
    }

    fn merged_snapshot_json(
        sources: &[serde_json::Value],
        newest: usize,
        tree: &str,
        summary: &SnapshotSummary,
        started: &str,
        finished: &str,
    ) -> Result<Vec<u8>> {
        super::merged_snapshot_json(
            sources,
            &Default::default(),
            newest,
            tree,
            summary,
            started,
            finished,
        )
    }
    use crate::testrepo::TestRepo;

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

    fn tags(v: &[&str]) -> Vec<String> {
        v.iter().map(ToString::to_string).collect()
    }

    const OLD_ID: &str = "ceedd62f4a63412571eac929f67931fb9702f31b681387e446e61cae3e039e73";

    // The shape restic 0.19 writes for a `backup --exclude` snapshot —
    // `excludes` has no counterpart in rustic_core's SnapshotFile, and the
    // raw-JSON rewrite exists precisely so it survives a tag edit.
    const RESTIC_SNAPSHOT: &str = r#"{"time":"2026-08-05T12:00:31.123456789+02:00","parent":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","tree":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","paths":["/home/it3"],"hostname":"it3s-MBP-4","username":"it3","uid":501,"gid":20,"excludes":["*.o","target/"],"tags":["old","keep"],"program_version":"restic 0.19.1","summary":{"backup_start":"2026-08-05T12:00:31.1+02:00","backup_end":"2026-08-05T12:00:32.2+02:00","files_new":3,"files_changed":0,"files_unmodified":0,"dirs_new":1,"dirs_changed":0,"dirs_unmodified":0,"data_blobs":3,"tree_blobs":2,"data_added":1000,"data_added_packed":900,"total_files_processed":3,"total_bytes_processed":1000}}"#;

    #[test]
    fn retag_replaces_tags_and_touches_nothing_else() {
        let out = retag_snapshot_json(RESTIC_SNAPSHOT.as_bytes(), OLD_ID, &tags(&["new"]))
            .unwrap()
            .expect("tags differ, must rewrite");
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["tags"], serde_json::json!(["new"]));
        assert_eq!(v["original"], serde_json::json!(OLD_ID));
        // Everything wrustic doesn't model must survive byte-identically —
        // strip the two edited keys and the rest equals the input.
        let mut expect: serde_json::Value = serde_json::from_str(RESTIC_SNAPSHOT).unwrap();
        let mut got = v.clone();
        for doc in [&mut expect, &mut got] {
            let o = doc.as_object_mut().unwrap();
            o.remove("tags");
            o.remove("original");
        }
        assert_eq!(got, expect, "only tags/original may change");
        // With preserve_order the untouched prefix keeps restic's layout.
        let out_str = String::from_utf8(out).unwrap();
        assert!(out_str.starts_with(r#"{"time":"2026-08-05T12:00:31.123456789+02:00","parent""#));
    }

    #[test]
    fn retag_to_empty_removes_the_tags_key_like_restic_omitempty() {
        let out = retag_snapshot_json(RESTIC_SNAPSHOT.as_bytes(), OLD_ID, &[])
            .unwrap()
            .expect("clearing tags is a change");
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert!(v.get("tags").is_none());
        assert_eq!(v["excludes"], serde_json::json!(["*.o", "target/"]));
    }

    #[test]
    fn retag_is_a_noop_when_tags_already_match() {
        assert!(
            retag_snapshot_json(RESTIC_SNAPSHOT.as_bytes(), OLD_ID, &tags(&["old", "keep"]))
                .unwrap()
                .is_none()
        );
        // Also for the no-tags ↔ empty-request pair (key absent entirely).
        let untagged = r#"{"time":"2026-08-05T12:00:31Z","tree":"cc","paths":["/x"]}"#;
        assert!(retag_snapshot_json(untagged.as_bytes(), OLD_ID, &[]).unwrap().is_none());
        // The comparison is set-based: the same tags in another order are a
        // no-op, because rustic sorts tags for display (BTreeSet) and a
        // reordered prefill must not rewrite an untouched snapshot.
        assert!(
            retag_snapshot_json(RESTIC_SNAPSHOT.as_bytes(), OLD_ID, &tags(&["keep", "old"]))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn retag_keeps_an_existing_original_id() {
        // A snapshot that is itself the product of an earlier edit: restic
        // retains the *first* original over all tag changes.
        let first = "1111111111111111111111111111111111111111111111111111111111111111";
        let edited = RESTIC_SNAPSHOT.replace(
            r#""program_version""#,
            &format!(r#""original":"{first}","program_version""#),
        );
        let out = retag_snapshot_json(edited.as_bytes(), OLD_ID, &tags(&["x"]))
            .unwrap()
            .expect("rewrite");
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["original"], serde_json::json!(first));
    }

    #[test]
    fn retag_rejects_malformed_snapshots() {
        assert!(retag_snapshot_json(b"[]", OLD_ID, &[]).is_err());
        assert!(retag_snapshot_json(b"not json", OLD_ID, &[]).is_err());
        let bad_tags = r#"{"time":"2026-08-05T12:00:31Z","tags":"oops"}"#;
        assert!(retag_snapshot_json(bad_tags.as_bytes(), OLD_ID, &tags(&["x"])).is_err());
    }


    // ---- Lock coverage of the native writes -------------------------------
    //
    // Every native write that removes or rewrites something must take the
    // *exclusive* lock before it touches anything (docs/locking.md, Tier 2;
    // the merge, which only adds, takes the shared one and has its own test
    // further down). The tests below plant a live
    // *shared* lock first — the lock a concurrent `restic backup` or a
    // running SMB share holds. A shared lock never blocks another shared
    // acquisition (proven by lock::tests::
    // exclusive_conflicts_with_any_lock_shared_only_with_exclusive), so an
    // operation that fails against one can only have asked for an exclusive
    // lock: this catches both a dropped acquisition and one downgraded to
    // shared. Comparing the repository fingerprint either side of the blocked
    // attempt then proves the refusal landed before the first write rather
    // than midway through.
    //
    // Unlike the live_* tests these need no restic binary — the fixture repo
    // is built in-process (src/testrepo.rs) — so removing an
    // `acquire_exclusive` fails a plain `cargo test`.
    fn plant_shared_lock(fixture: &TestRepo) -> lock::RepoLock {
        lock::RepoLock::acquire_shared(fixture.lock_backend(), fixture.crypto())
            .expect("plant a shared lock")
    }

    fn assert_lock_conflict(err: &anyhow::Error) {
        assert!(
            lock::is_lock_error(&format!("{err:#}")),
            "expected a lock conflict, got: {err:#}"
        );
    }

    #[test]
    fn delete_snapshot_takes_the_exclusive_lock() {
        // Acquires RepoLocks — serialize with other acquiring tests (SIGHUP
        // disposition is process-global).
        let _guard = lock::test_acquire_guard();
        let fixture = TestRepo::init("delete");
        let snap_id = fixture.backup(&[("a.txt", b"hello\n")], &["keep"]);
        let before = fixture.fingerprint().expect("fingerprint the repository");

        let held = plant_shared_lock(&fixture);
        let err = delete_snapshot(fixture.profile(), &snap_id)
            .expect_err("a delete must not run while another process holds a lock");
        assert_lock_conflict(&err);
        assert_eq!(
            fixture.fingerprint().expect("fingerprint the repository"),
            before,
            "a blocked delete must not have written or removed anything"
        );
        assert_eq!(
            fixture.lock_count(),
            1,
            "the failed acquisition must clean up after itself, leaving only the planted lock"
        );
        assert_eq!(
            load_snapshots(fixture.profile()).expect("list snapshots").rows.len(),
            1,
            "the snapshot must survive the blocked delete"
        );

        // Released: the very same delete now goes through, and leaves no lock.
        drop(held);
        delete_snapshot(fixture.profile(), &snap_id).expect("delete once unlocked");
        assert!(
            load_snapshots(fixture.profile())
                .expect("list snapshots")
                .rows
                .is_empty()
        );
        assert_eq!(
            fixture.lock_count(),
            0,
            "the delete must release its lock when it returns"
        );
    }

    #[test]
    fn edit_snapshot_tags_takes_the_exclusive_lock() {
        let _guard = lock::test_acquire_guard();
        let fixture = TestRepo::init("tag");
        let snap_id = fixture.backup(&[("a.txt", b"hello\n")], &["old"]);
        let before = fixture.fingerprint().expect("fingerprint the repository");

        let held = plant_shared_lock(&fixture);
        let err = edit_snapshot_tags(fixture.profile(), &snap_id, &["blocked".into()])
            .expect_err("a tag edit must not run while another process holds a lock");
        assert_lock_conflict(&err);
        assert_eq!(
            fixture.fingerprint().expect("fingerprint the repository"),
            before,
            "a blocked tag edit must not have written the rewritten snapshot"
        );
        assert_eq!(fixture.lock_count(), 1, "only the planted lock may remain");
        let snapshots = load_snapshots(fixture.profile()).expect("list snapshots").rows;
        assert_eq!(snapshots.len(), 1);
        assert_eq!(
            snapshots[0].tags,
            vec!["old".to_string()],
            "the tags must survive the blocked edit"
        );

        drop(held);
        let new_id = edit_snapshot_tags(fixture.profile(), &snap_id, &["fresh".into()])
            .expect("tag edit once unlocked")
            .expect("tags changed, so the snapshot is rewritten");
        let snapshots = load_snapshots(fixture.profile()).expect("list snapshots").rows;
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].id, new_id);
        assert_eq!(snapshots[0].tags, vec!["fresh".to_string()]);
        assert_eq!(
            fixture.lock_count(),
            0,
            "the tag edit must release its lock when it returns"
        );
    }

    // ---- Native snapshot merge --------------------------------------------

    #[test]
    fn merged_paths_fold_nested_paths_into_their_ancestor() {
        assert_eq!(merged_paths(&["/data", "/data/extra"]), ["/data"]);
        assert_eq!(merged_paths(&["/data/extra/deep", "/data"]), ["/data"]);
        assert_eq!(
            merged_paths(&["/mnt/usb/extra", "/data"]),
            ["/data", "/mnt/usb/extra"],
            "unrelated paths are both kept, sorted"
        );
        assert_eq!(merged_paths(&["/data", "/data"]), ["/data"]);
        assert_eq!(merged_paths(&["/x", "/"]), ["/"]);
        // Whole components, not string prefixes.
        assert_eq!(merged_paths(&["/data", "/database"]), ["/data", "/database"]);
        // A backslash is an ordinary character in a Unix name…
        assert_eq!(merged_paths(&["/a", "/a\\b"]), ["/a", "/a\\b"]);
        // …and a separator in a Windows path.
        assert_eq!(
            merged_paths(&["C:\\Users\\me\\Docs", "C:\\Users\\me"]),
            ["C:\\Users\\me"]
        );
        assert_eq!(
            merged_paths(&["C:\\Users\\me", "D:\\Users\\me\\Docs"]),
            ["C:\\Users\\me", "D:\\Users\\me\\Docs"]
        );
        assert!(merged_paths(&[]).is_empty());

        // A path whose files are not where it says is not folded, either way
        // round: the merged snapshot is then no backup of the one directory.
        let misplaced = |paths: &[&str]| paths.iter().map(|path| path.to_string()).collect();
        assert_eq!(
            super::merged_paths(&["/data", "/data/extra"], &misplaced(&["/data/extra"])),
            ["/data", "/data/extra"]
        );
        assert_eq!(
            super::merged_paths(&["/data", "/data/extra"], &misplaced(&["/data"])),
            ["/data", "/data/extra"]
        );
        assert_eq!(
            super::merged_paths(&["/data", "/data/extra", "/data/more"], &misplaced(&["/data/more"])),
            ["/data", "/data/more"]
        );
    }

    fn tree_id(n: u8) -> TreeId {
        format!("{n:02x}").repeat(32).parse().expect("tree id")
    }

    // Trees given as `(tree number, entries)`, to read by id.
    fn tree_store(
        trees: &[(u8, Vec<serde_json::Value>)],
    ) -> impl Fn(&TreeId) -> Result<Vec<u8>> + use<> {
        let stored: std::collections::HashMap<TreeId, Vec<u8>> = trees
            .iter()
            .map(|(n, nodes)| {
                (tree_id(*n), serde_json::to_vec(&serde_json::json!({"nodes": nodes})).unwrap())
            })
            .collect();
        move |id| stored.get(id).cloned().ok_or_else(|| anyhow!("no such tree"))
    }

    // restic stores a target under its absolute path, and a target given as
    // a relative path under that one instead — while recording the absolute
    // path in `paths` either way. Only the tree tells them apart.
    #[test]
    fn a_tree_holds_a_path_where_restic_stores_an_absolute_one() {
        let file = |name: &str| raw_file(name, 1, 1, 0, "aa");
        let read = tree_store(&[
            (1, vec![raw_dir("data", 2)]),
            (2, vec![raw_dir("extra", 3), file("keep.txt")]),
            (3, vec![file("n.txt")]),
            // `cd /data && restic backup extra`.
            (4, vec![raw_dir("extra", 3)]),
            // A Windows volume is the first directory.
            (5, vec![raw_dir("C", 6)]),
            (6, vec![raw_dir("Users", 3)]),
            // Names restic stores quoted: `we"ird` and `tab<TAB>bed`.
            (7, vec![raw_dir(r#"we\"ird"#, 3), raw_dir(r"tab\tbed", 3)]),
            // A network share: one directory, stored under its quoted name.
            (8, vec![raw_dir(r"\\\\nas\\share", 3)]),
            // `/data` with a file beside it, and with what a relative backup
            // of `extra` left at the root.
            (9, vec![raw_dir("data", 2), file("root.txt")]),
            (10, vec![raw_dir("data", 2), raw_dir("extra", 3)]),
        ]);
        let holds = |root: u8, path: &str| tree_holds_path(tree_id(root), path, &read).unwrap();
        assert!(holds(1, "/data"));
        assert!(holds(1, "/data/extra"));
        assert!(holds(1, "/data/extra/n.txt"), "a file target");
        assert!(holds(1, "/"));
        assert!(!holds(1, "/data/missing"));
        assert!(!holds(1, "/data/keep.txt/below"), "nothing is inside a file");
        assert!(!holds(4, "/data/extra"), "a relative backup is rooted at the relative path");
        assert!(holds(4, "/extra"));
        assert!(holds(5, r"C:\Users"));
        assert!(holds(5, r"\\?\C:\Users\n.txt"));
        assert!(!holds(5, r"D:\Users"));
        assert!(holds(7, "/we\"ird/n.txt"), "a quoted name is the plain one in `paths`");
        assert!(holds(7, "/tab\tbed"));
        assert!(!holds(7, r#"/we\"ird"#), "the quoted form is not the name");
        assert!(holds(8, r"\\nas\share\n.txt"), "the share is the volume, whole");
        assert!(!holds(8, r"\\nas\other\n.txt"));

        // A path of the right name is not enough: a tree laid out as its
        // paths say holds nothing beside the way to them.
        let keeps = |root: u8, paths: &[&str]| {
            tree_keeps_to_paths(tree_id(root), paths, &read).unwrap()
        };
        assert!(keeps(1, &["/data"]));
        assert!(keeps(1, &["/data", "/data/extra"]));
        assert!(keeps(1, &["/data/extra", "/data/keep.txt"]));
        assert!(keeps(1, &["/"]));
        assert!(!keeps(1, &["/data/extra"]), "`keep.txt` is beside it");
        assert!(keeps(4, &["/extra"]));
        assert!(!keeps(4, &["/data/extra"]));
        assert!(holds(9, "/data") && !keeps(9, &["/data"]), "`/root.txt` is outside `/data`");
        assert!(keeps(9, &["/data", "/root.txt"]));
        assert!(
            holds(10, "/data/extra") && !keeps(10, &["/data", "/data/extra"]),
            "`/extra` is outside both, though `/data` holds an `extra`"
        );
        assert!(keeps(8, &[r"\\nas\share\n.txt"]));

        assert_eq!(archive_components("/data/extra/"), ["data", "extra"]);
        assert_eq!(archive_components(r"C:\Users/me"), ["C", "Users", "me"]);
        assert_eq!(archive_components(r"\\nas\share\dir\sub"), [r"\\nas\share", "dir", "sub"]);
        assert_eq!(archive_components(r"\\nas\share"), [r"\\nas\share"]);
        // Nested paths on a share fold into the outer one's path set.
        assert_eq!(
            merged_paths(&[r"\\nas\share\data\extra", r"\\nas\share\data"]),
            [r"\\nas\share\data"]
        );
        assert!(archive_components("/").is_empty());
    }

    // Device and inode numbers of two machines say nothing about each other.
    // In a merge across hosts, files restic would link have to be a group
    // some one source records as it is; one made of two sources' files is
    // refused, however alike they are.
    #[test]
    fn across_hosts_a_hardlink_group_must_be_one_sources_own() {
        let link = |name: &str, links: u64| raw_file(name, links, 1, 7, "aa");
        let other = |name: &str| raw_file(name, 1, 1, 8, "bb");
        let read = tree_store(&[
            // One source holds `/a` and `/a2`, one file; the other `/b`, with
            // the same numbers and content.
            (1, vec![link("a", 2), link("a2", 2)]),
            (2, vec![link("b", 1), other("c")]),
            (3, vec![link("a", 2), link("a2", 2), link("b", 1), other("c")]),
            // The first source's group alone, next to another file.
            (4, vec![link("a", 2), link("a2", 2), other("c")]),
            // A directory stored once and found in two places: four paths of
            // one file, all of them the one source's.
            (5, vec![raw_dir("x", 6), raw_dir("y", 6)]),
            (6, vec![link("f", 2), link("g", 2)]),
            (7, vec![link("b", 1), raw_dir("x", 6), raw_dir("y", 6)]),
            (8, vec![other("c")]),
        ]);
        let defect = |merged: u8, sources: &[u8]| {
            let sources: Vec<TreeId> = sources.iter().map(|n| tree_id(*n)).collect();
            cross_host_link_defect(tree_id(merged), &sources, &read).expect("read the trees")
        };

        let clash = defect(3, &[1, 2]).expect("a group made of two hosts' files");
        assert!(clash.contains("`/a`") && clash.contains("`/b`"), "{clash}");
        assert!(clash.contains("different hosts"), "{clash}");

        assert_eq!(defect(4, &[1, 2]), None, "one source's own group");
        assert_eq!(defect(1, &[1, 1]), None, "a group both sources record whole");
        assert_eq!(defect(8, &[8, 2]), None, "no hardlinks at all");
        assert_eq!(defect(5, &[5, 8]), None, "every path of a directory found twice");
        let clash = defect(7, &[5, 2]).expect("the other host's file joins the group");
        assert!(clash.contains("`/b`"), "{clash}");
    }

    #[test]
    fn a_local_write_is_over_when_it_has_returned() {
        let local = Profile::Local { password: "pw".into(), local_path: "tmp/none".into() };
        let error = rustic_core::RusticError::new(rustic_core::ErrorKind::Backend, "failed");
        assert!(!data_write_can_land_later(&local)(&error));
    }

    fn summary_for_tests() -> SnapshotSummary {
        let mut summary = SnapshotSummary::default();
        summary.total_files_processed = 17;
        summary.total_bytes_processed = 195;
        summary.files_unmodified = 17;
        summary.dirs_changed = 9;
        summary.tree_blobs = 9;
        summary
    }

    #[test]
    fn merged_snapshot_takes_identity_from_the_newest_source() {
        // Source 0 is restic's layout with everything a backup run records;
        // source 1 is the newer one.
        let older: serde_json::Value = serde_json::from_str(RESTIC_SNAPSHOT).unwrap();
        let newer = serde_json::json!({
            "time": "2026-09-01T08:00:00.5+02:00",
            "parent": "22",
            "tree": "33",
            "paths": ["/home/it3/extra", "/mnt/usb"],
            "hostname": "it3s-MBP-4",
            "username": "root",
            "excludes": ["*.tmp"],
            "tags": ["keep", "added"],
            "original": "44",
            "program_version": "restic 0.19.1",
        });
        let tree = "ab".repeat(32);
        let out = merged_snapshot_json(
            &[older, newer],
            1,
            &tree,
            &summary_for_tests(),
            "2026-11-20T10:00:00Z",
            "2026-11-20T10:00:01Z",
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        // restic's field order; the newer source has no uid/gid, so neither
        // does the result — and nothing that describes a single backup run
        // (parent, excludes, original) is carried over.
        assert_eq!(
            keys,
            ["time", "tree", "paths", "hostname", "username", "tags", "program_version", "summary"]
        );
        assert_eq!(
            v["time"], "2026-09-01T08:00:00.500000001+02:00",
            "just after the newest source, in its offset"
        );
        assert_eq!(v["tree"], serde_json::json!(tree));
        assert_eq!(v["hostname"], "it3s-MBP-4", "both sources are this host's");
        assert_eq!(v["username"], "root");
        assert_eq!(
            v["paths"],
            serde_json::json!(["/home/it3", "/mnt/usb"]),
            "the nested path folds into the older source's"
        );
        assert_eq!(v["tags"], serde_json::json!(["added", "keep", "old"]));
        assert_eq!(
            v["program_version"],
            serde_json::json!(concat!("wrustic ", env!("CARGO_PKG_VERSION")))
        );
        assert_eq!(v["summary"]["total_files_processed"], 17);
        assert_eq!(v["summary"]["total_bytes_processed"], 195);
        assert_eq!(v["summary"]["backup_start"], "2026-11-20T10:00:00Z");
        // Only the fields restic's summary has.
        assert!(v["summary"].get("command").is_none());
        assert!(v["summary"].get("total_dirs_processed").is_none());

        // rustic_core reads it back as a snapshot of the merged tree.
        let typed: SnapshotFile = serde_json::from_slice(&out).unwrap();
        assert_eq!(typed.tree.to_hex().as_str(), tree);
        assert_eq!(typed.hostname, "it3s-MBP-4");
    }

    // restic looks for a backup's parent by hostname and paths. A merge of
    // two hosts' snapshots holds another machine's files, so it must not
    // answer to either host's name — while sources of one host keep theirs.
    #[test]
    fn merged_snapshot_of_two_hosts_is_named_for_both() {
        assert_eq!(merged_hostname(&["laptop", "laptop"]).as_deref(), Some("laptop"));
        assert_eq!(merged_hostname(&["laptop"]).as_deref(), Some("laptop"));
        assert_eq!(merged_hostname(&["nas", "laptop"]).as_deref(), Some("laptop+nas"));
        assert_eq!(merged_hostname(&["nas", "laptop", "nas"]).as_deref(), Some("laptop+nas"));
        assert_eq!(merged_hostname(&["laptop", ""]).as_deref(), Some("laptop+unknown"));
        assert_eq!(merged_hostname(&["", "laptop"]).as_deref(), Some("laptop+unknown"));
        assert_eq!(merged_hostname(&["", ""]), None);
        assert_eq!(merged_hostname(&[]), None);
        // A host really called what stands for a missing name: the two must
        // not fold into that host's own name, which its backups look for.
        assert_eq!(merged_hostname(&["", "unknown"]), None);
        assert_eq!(merged_hostname(&["unknown", ""]), None);
        assert_eq!(merged_hostname(&["unknown", "", "nas"]), None);
        assert_eq!(merged_hostname(&["unknown", "unknown"]).as_deref(), Some("unknown"));
        assert_eq!(merged_hostname(&["unknown", "nas"]).as_deref(), Some("nas+unknown"));
        // Whatever comes out for several hosts is none of theirs.
        for hosts in [["a", "b"], ["a", "a+b"], ["a+b", "b"], ["", "a"], ["unknown", ""]] {
            if let Some(merged) = merged_hostname(&hosts) {
                assert!(!hosts.contains(&merged.as_str()), "{hosts:?} gave {merged}");
            }
        }

        let source = |host: Option<&str>, time: &str| {
            let mut v = serde_json::json!({"time": time, "tree": "11", "paths": ["/data"]});
            if let Some(host) = host {
                v["hostname"] = serde_json::json!(host);
            }
            v
        };
        let hostname_of = |sources: &[serde_json::Value]| {
            let out = merged_snapshot_json(
                sources,
                0,
                &"ab".repeat(32),
                &summary_for_tests(),
                "2026-11-20T10:00:00Z",
                "2026-11-20T10:00:01Z",
            )
            .unwrap();
            serde_json::from_slice::<serde_json::Value>(&out).unwrap().get("hostname").cloned()
        };
        let (newer, older) = ("2026-02-01T00:00:00Z", "2026-01-01T00:00:00Z");
        assert_eq!(
            hostname_of(&[source(Some("nas"), newer), source(Some("nas"), older)]),
            Some(serde_json::json!("nas"))
        );
        assert_eq!(
            hostname_of(&[source(Some("nas"), newer), source(Some("laptop"), older)]),
            Some(serde_json::json!("laptop+nas")),
            "not the newest source's alone"
        );
        assert_eq!(
            hostname_of(&[source(Some("nas"), newer), source(None, older)]),
            Some(serde_json::json!("nas+unknown"))
        );
        assert_eq!(hostname_of(&[source(None, newer), source(None, older)]), None);

        // rustic_core still reads a snapshot without a hostname.
        let out = merged_snapshot_json(
            &[source(None, newer), source(None, older)],
            0,
            &"ab".repeat(32),
            &summary_for_tests(),
            "2026-11-20T10:00:00Z",
            "2026-11-20T10:00:01Z",
        )
        .unwrap();
        let typed: SnapshotFile = serde_json::from_slice(&out).unwrap();
        assert_eq!(typed.hostname, "");
    }

    #[test]
    fn merged_snapshot_without_tags_has_no_tags_key() {
        let a = serde_json::json!({"time": "2026-01-01T00:00:00Z", "tree": "11", "paths": ["/a"], "uid": 0, "gid": 0});
        let b = serde_json::json!({"time": "2025-01-01T00:00:00Z", "tree": "22", "paths": ["/b"], "tags": null});
        let out = merged_snapshot_json(&[a, b], 0, &"cd".repeat(32), &summary_for_tests(), "s", "e")
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert!(v.get("tags").is_none(), "restic's omitempty");
        assert!(v.get("hostname").is_none());
        // Present on the newest source, so kept — zero or not.
        assert_eq!(v["uid"], 0);
        assert_eq!(v["gid"], 0);
        assert_eq!(v["paths"], serde_json::json!(["/a", "/b"]));
    }

    #[test]
    fn merged_snapshot_rejects_malformed_sources() {
        let ok = serde_json::json!({"time": "2026-01-01T00:00:00Z", "paths": ["/a"]});
        let summary = summary_for_tests();
        let tree = "cd".repeat(32);
        let bad_paths = serde_json::json!({"time": "2026-01-01T00:00:00Z", "paths": "/a"});
        assert!(merged_snapshot_json(&[ok.clone(), bad_paths], 0, &tree, &summary, "s", "e").is_err());
        let bad_tag = serde_json::json!({"time": "2026-01-01T00:00:00Z", "paths": ["/a"], "tags": [1]});
        assert!(merged_snapshot_json(&[ok.clone(), bad_tag], 0, &tree, &summary, "s", "e").is_err());
        let no_time = serde_json::json!({"paths": ["/a"]});
        assert!(merged_snapshot_json(&[no_time, ok.clone()], 0, &tree, &summary, "s", "e").is_err());
        assert!(merged_snapshot_json(&[ok], 3, &tree, &summary, "s", "e").is_err());
    }

    #[test]
    fn node_fields_the_merge_would_drop_are_found() {
        // A file node as restic 0.19 writes it on Linux: several fields
        // rustic_core spells differently or always writes, none of them lost.
        let linux = serde_json::json!({
            "name": "a.txt", "type": "file", "mode": 420,
            "mtime": "2026-11-20T06:50:55.1-08:00", "atime": "2026-11-20T06:50:55.1-08:00",
            "ctime": "2026-11-20T06:50:55.1-08:00", "uid": 1000, "gid": 1000,
            "user": "debian", "group": "debian", "inode": 4242, "device_id": 2049,
            "size": 6, "links": 1,
            "extended_attributes": [{"name": "user.x", "value": "eA=="}],
            "content": ["aa00000000000000000000000000000000000000000000000000000000000000"],
        });
        assert!(unpreserved_node_fields(&linux).unwrap().is_empty());

        let symlink = serde_json::json!({
            "name": "l", "type": "symlink", "mode": 134218239, "uid": 0, "gid": 0,
            "mtime": "2026-11-20T06:50:55Z", "linktarget": "a.txt", "content": null,
        });
        assert!(unpreserved_node_fields(&symlink).unwrap().is_empty());

        // restic on Windows: metadata rustic_core's node has no place for.
        let mut windows = linux.clone();
        windows["generic_attributes"] = serde_json::json!({
            "windows.creation_time": "AAAA", "windows.file_attributes": 32,
        });
        assert_eq!(unpreserved_node_fields(&windows).unwrap(), ["generic_attributes"]);

        // Left out by the round trip, but empty: nothing is lost.
        let mut empty = linux.clone();
        empty["generic_attributes"] = serde_json::json!({});
        empty["error"] = serde_json::json!("");
        assert!(unpreserved_node_fields(&empty).unwrap().is_empty());

        assert!(unpreserved_node_fields(&serde_json::json!([])).is_err());
    }

    // The merge is best effort about metadata, and has to know what it left
    // behind: the scan must reach every directory of every source — a field
    // lost three levels down counts — and read a directory both share once.
    #[test]
    fn dropped_node_fields_are_collected_from_every_tree_the_sources_reach() {
        let id = |n: u8| -> TreeId { format!("{n:02x}").repeat(32).parse().expect("tree id") };
        let file = |name: &str| {
            serde_json::json!({
                "name": name, "type": "file", "mode": 420, "uid": 0, "gid": 0,
                "mtime": "2026-11-20T06:50:55Z", "content": [],
            })
        };
        let dir = |name: &str, subtree: TreeId| {
            serde_json::json!({
                "name": name, "type": "dir", "mode": 2147484141u32, "uid": 0, "gid": 0,
                "mtime": "2026-11-20T06:50:55Z", "subtree": subtree.to_hex().as_str(),
            })
        };
        let mut windows = file("w.txt");
        windows["generic_attributes"] = serde_json::json!({"windows.file_attributes": 32});
        let mut unknown = file("u.txt");
        unknown["a_field_of_the_future"] = serde_json::json!("x");

        let (first, second, shared, deep, deeper) = (id(1), id(2), id(3), id(4), id(5));
        use std::collections::HashMap;
        let trees: HashMap<TreeId, serde_json::Value> = HashMap::from([
            (first, serde_json::json!({"nodes": [file("a.txt"), dir("shared", shared)]})),
            (second, serde_json::json!({"nodes": [dir("shared", shared), dir("deep", deep)]})),
            (shared, serde_json::json!({"nodes": [file("s.txt")]})),
            (deep, serde_json::json!({"nodes": [unknown, dir("deeper", deeper)]})),
            (deeper, serde_json::json!({"nodes": [windows]})),
        ]);
        let reads = std::cell::RefCell::new(Vec::new());
        let read_tree = |id: &TreeId| -> Result<Vec<u8>> {
            reads.borrow_mut().push(*id);
            let tree = trees.get(id).ok_or_else(|| anyhow!("no such tree"))?;
            Ok(serde_json::to_vec(tree)?)
        };

        let dropped = |roots: &[TreeId]| {
            scan_source_trees(roots, read_tree).map(|scan| scan.dropped_node_fields)
        };
        assert_eq!(
            dropped(&[first, second]).expect("scan").into_iter().collect::<Vec<_>>(),
            ["a_field_of_the_future", "generic_attributes"]
        );
        let mut read = reads.borrow().clone();
        read.sort();
        assert_eq!(read, [first, second, shared, deep, deeper], "each tree is read once");

        // Nothing to report where every field survives.
        assert!(dropped(&[first]).expect("scan").is_empty());
        // A tree that cannot be read is an error, not "nothing lost".
        assert!(dropped(&[id(9)]).is_err());
    }

    #[test]
    fn restic_names_are_compared_unquoted() {
        assert_eq!(restic_name_bytes("plain name.txt"), b"plain name.txt");
        assert_eq!(restic_name_bytes(r#"\"a"#), b"\"a");
        assert_eq!(restic_name_bytes(r"back\\slash"), b"back\\slash");
        assert_eq!(restic_name_bytes(r"tab\there\nline"), b"tab\there\nline");
        assert_eq!(restic_name_bytes(r"bad\xff\xfeutf8"), b"bad\xff\xfeutf8");
        assert_eq!(restic_name_bytes(r"\u200b\U0001f600"), "\u{200b}\u{1f600}".as_bytes());
        assert_eq!(restic_name_bytes("é stays"), "é stays".as_bytes());
        // Not something restic writes: left as it stands rather than guessed at.
        assert_eq!(restic_name_bytes(r"odd\q \x4 \"), br"odd\q \x4 \");
        // The pair that sorts one way quoted and the other way unquoted.
        assert!(r#"\"a"# > "A");
        assert!(restic_name_bytes(r#"\"a"#) < restic_name_bytes("A"));
    }

    #[test]
    fn a_snapshot_time_is_stepped_by_one_nanosecond_in_its_own_offset() {
        assert_eq!(just_after("2026-09-01T08:00:00.5+02:00").unwrap(), "2026-09-01T08:00:00.500000001+02:00");
        assert_eq!(just_after("2026-09-01T06:00:00Z").unwrap(), "2026-09-01T06:00:00.000000001Z");
        assert_eq!(
            just_after("2026-12-31T23:59:59.999999999-08:00").unwrap(),
            "2027-01-01T00:00:00-08:00"
        );
        assert_eq!(just_after("2026-09-01T06:00:00+00:00").unwrap(), "2026-09-01T06:00:00.000000001+00:00");
        assert!(just_after("yesterday").is_err());
    }

    // A merged tree given as `(tree number, entries)`; the first is the root.
    fn defect_of(trees: &[(u8, Vec<serde_json::Value>)]) -> Option<String> {
        let id = |n: u8| -> TreeId { format!("{n:02x}").repeat(32).parse().expect("tree id") };
        let stored: std::collections::HashMap<TreeId, Vec<u8>> = trees
            .iter()
            .map(|(n, nodes)| (id(*n), serde_json::to_vec(&serde_json::json!({"nodes": nodes})).unwrap()))
            .collect();
        merged_tree_defect(id(trees[0].0), |id| {
            stored.get(id).cloned().ok_or_else(|| anyhow!("no such tree"))
        })
        .expect("read the merged tree")
    }

    fn raw_dir(name: &str, tree: u8) -> serde_json::Value {
        serde_json::json!({"name": name, "type": "dir", "subtree": format!("{tree:02x}").repeat(32)})
    }

    fn raw_file(name: &str, links: u64, device: u64, inode: u64, content: &str) -> serde_json::Value {
        serde_json::json!({
            "name": name, "type": "file", "links": links, "device_id": device,
            "inode": inode, "content": [content],
        })
    }

    // restic keeps a directory's entries sorted by name; `merge_trees` sorts
    // by the name as stored, quoted. Where the two disagree the merged
    // directory comes out with an entry twice or in an order restic does not
    // keep, and either must be found wherever in the tree it is.
    #[test]
    fn a_merged_directory_out_of_restics_order_is_a_defect() {
        let plain = |name: &str| raw_file(name, 1, 1, 0, "aa");
        // Quoted names in restic's order are fine, also next to plain ones.
        assert_eq!(defect_of(&[(1, vec![plain(r#"\"a"#), plain("A"), plain("b")])]), None);
        assert_eq!(defect_of(&[(1, vec![])]), None);

        // What merge_trees makes of [`"a`, `A`] and [`A`].
        let twice = defect_of(&[(1, vec![plain("A"), plain(r#"\"a"#), plain("A")])])
            .expect("an entry listed twice");
        assert!(twice.contains("not restic's order") || twice.contains("twice"), "{twice}");
        let adjacent = defect_of(&[(1, vec![plain("A"), plain("A")])]).expect("a duplicate");
        assert!(adjacent.contains("would hold `A` twice"), "{adjacent}");

        // The quoted order, two levels down.
        let nested = defect_of(&[
            (1, vec![raw_dir("top", 2)]),
            (2, vec![raw_dir("sub", 3), plain("z")]),
            (3, vec![plain("A"), plain(r#"\"a"#)]),
        ])
        .expect("a directory in the quoted order");
        assert!(nested.contains("`/top/sub/`"), "{nested}");
        assert!(nested.contains("not restic's order"), "{nested}");
    }

    // restic writes the first multi-link file of a device and inode, and makes
    // every other file with that device and inode a hardlink to it — whatever
    // link count that file itself records. So what makes a merged tree wrong
    // is a file whose content differs from the group it would be linked into.
    // Everything else has to pass: links of one file, the same inode number on
    // another device, single-link files sharing an inode with no group, and
    // directories (whose link count is not about hardlinks).
    #[test]
    fn a_file_restic_would_link_to_different_content_is_a_defect() {
        let fine = vec![
            raw_file("p", 2, 1, 7, "aa"),
            raw_file("q", 2, 1, 7, "aa"),
            // Fell to one link in a later backup, content unchanged.
            raw_file("r", 1, 1, 7, "aa"),
            raw_file("s-other-disk", 2, 2, 7, "bb"),
            // No file with several links has this inode: nothing links them.
            raw_file("t", 1, 1, 9, "cc"),
            raw_file("u", 1, 1, 9, "dd"),
        ];
        let mut dir = raw_dir("v", 2);
        dir["links"] = serde_json::json!(2);
        dir["device_id"] = serde_json::json!(1);
        dir["inode"] = serde_json::json!(7);
        let mut tree = fine.clone();
        tree.push(dir);
        // An empty file: `null` from restic, `[]` from rustic_core.
        let mut empty = raw_file("e1", 2, 1, 8, "");
        empty["content"] = serde_json::Value::Null;
        let mut also_empty = raw_file("e2", 2, 1, 8, "");
        also_empty["content"] = serde_json::json!([]);
        assert_eq!(defect_of(&[(1, tree), (2, vec![empty, also_empty])]), None);

        // Two files with several links.
        let mut clash = fine.clone();
        clash.push(raw_file("w", 2, 1, 7, "ee"));
        let found = defect_of(&[(1, clash)]).expect("two groups under one identity");
        assert!(found.contains("hardlinks of one file"), "{found}");
        assert!(found.contains("`/p`") || found.contains("`/w`"), "{found}");

        // The same content with other metadata an inode has one of: restic
        // links the files and then puts each path's own back, so the two
        // cannot both be restored as recorded.
        let with = |name: &str, links: u64, fields: serde_json::Value| {
            let mut file = raw_file(name, links, 1, 7, "aa");
            for (key, value) in fields.as_object().unwrap() {
                file[key.as_str()] = value.clone();
            }
            file
        };
        let recorded = serde_json::json!({
            "mode": 0o644, "uid": 1000, "gid": 1000, "user": "debian", "group": "staff",
            "mtime": "2026-11-20T06:50:55.5-08:00",
            "atime": "2026-11-20T06:50:55.5-08:00", "ctime": "2026-11-20T06:50:55.5-08:00",
            "extended_attributes": [
                {"name": "user.x", "value": "eA=="},
                {"name": "user.y", "value": "eQ=="},
            ],
        });
        // What does not make two links differ: the change time, which no
        // restore sets, the access time, which restic records differently
        // for the links of one file, the same instant in another offset,
        // and nothing written two ways.
        let mut same = recorded.clone();
        same["atime"] = serde_json::json!("2026-11-21T00:00:00Z");
        same["ctime"] = serde_json::json!("2026-11-21T00:00:00Z");
        same["mtime"] = serde_json::json!("2026-11-20T14:50:55.5Z");
        // The same attributes, listed the other way round.
        same["extended_attributes"] = serde_json::json!([
            {"name": "user.y", "value": "eQ=="},
            {"name": "user.x", "value": "eA=="},
        ]);
        assert_eq!(
            defect_of(&[(1, vec![with("p", 2, recorded.clone()), with("q", 2, same)])]),
            None
        );
        let none = serde_json::json!({"extended_attributes": null, "user": null});
        let empty = serde_json::json!({"extended_attributes": [], "user": ""});
        assert_eq!(defect_of(&[(1, vec![with("p", 2, none), with("q", 2, empty)])]), None);
        for (key, other, what) in [
            ("mode", serde_json::json!(0o600), "different permissions"),
            ("uid", serde_json::json!(0), "different owners"),
            ("gid", serde_json::json!(0), "different owners"),
            // The same numbers under another name: another machine's user.
            ("user", serde_json::json!("backup"), "different owners"),
            ("group", serde_json::json!("users"), "different owners"),
            ("mtime", serde_json::json!("2026-11-20T06:50:56-08:00"), "different modification times"),
            ("extended_attributes", serde_json::json!([]), "different extended attributes"),
            // One attribute's value differs, in either order.
            (
                "extended_attributes",
                serde_json::json!([
                    {"name": "user.y", "value": "eQ=="},
                    {"name": "user.x", "value": "other"},
                ]),
                "different extended attributes",
            ),
        ] {
            let mut changed = recorded.clone();
            changed[key] = other;
            for other_links in [2, 1] {
                let found = defect_of(&[(
                    1,
                    vec![with("p", 2, recorded.clone()), with("q", other_links, changed.clone())],
                )])
                .unwrap_or_else(|| panic!("one inode recorded with two values of {key}"));
                assert!(found.contains(what), "{key}: {found}");
                assert!(found.contains("hardlinks of one file"), "{key}: {found}");
            }
        }

        // One whose link count fell to one before it was rewritten, in
        // another directory, and listed before the group it would join. Only
        // a restic backup records this (rustic_core's leaves the device of a
        // single-link file out), so past this test it takes the live one.
        let found = defect_of(&[
            (1, vec![raw_dir("a-first", 2), raw_dir("b-group", 3)]),
            (2, vec![raw_file("moved", 1, 1, 7, "new")]),
            (3, vec![raw_file("p", 2, 1, 7, "old"), raw_file("q", 2, 1, 7, "old")]),
        ])
        .expect("a single-link file with a group's identity");
        assert!(found.contains("hardlinks of one file"), "{found}");
        assert!(found.contains("`/a-first/moved`"), "{found}");
    }

    // One hardlink identity on different content, the way it happens for
    // real: a directory of hardlinked files is renamed and a file rewritten in
    // place between two backups, so both snapshots record the same inode with
    // different content, at different paths. Merged as they are, restic would
    // restore all four files as links to one (see
    // `live_native_merge_restores_hardlinks_with_restic`), so the merge must
    // refuse — and leave no snapshot behind.
    #[cfg(unix)]
    #[test]
    fn merge_refuses_one_hardlink_identity_on_different_content() {
        let _guard = lock::test_acquire_guard();
        let fixture = TestRepo::init("merge-hardlink-clash");
        let source = fixture.source_path();

        std::fs::create_dir_all(source.join("one")).unwrap();
        std::fs::write(source.join("one/p"), b"old\n").unwrap();
        std::fs::hard_link(source.join("one/p"), source.join("one/q")).unwrap();
        let first = fixture.backup(&[], &["one"]);

        std::fs::rename(source.join("one"), source.join("two")).unwrap();
        // Rewritten in place: still the inode `two/q` links to.
        std::fs::write(source.join("two/p"), b"new content\n").unwrap();
        let second = fixture.backup(&[], &["two"]);

        let err = merge_snapshots(fixture.profile(), &[first, second])
            .expect_err("a merge restic would restore wrong must be refused");
        let message = format!("{err:#}");
        assert!(message.contains("hardlinks of one file"), "{message}");
        assert!(message.contains("/one/") && message.contains("/two/"), "{message}");
        assert!(!lock::is_lock_error(&message), "unlocking would not help: {message}");
        assert_eq!(
            load_snapshots(fixture.profile()).expect("list snapshots").rows.len(),
            2,
            "no merged snapshot may have been written"
        );
        assert_eq!(fixture.lock_count(), 0, "the refused merge must release its lock");
    }

    // The same identity on different content in the *sources* is not yet a
    // clash in the merged tree: two backups of one directory, with a
    // hardlinked file rewritten in between, differ exactly like that, and the
    // merge takes both links from the newer backup. That must go through,
    // with the hardlink group intact.
    #[cfg(unix)]
    #[test]
    fn merge_keeps_a_hardlink_group_both_sources_hold_at_different_times() {
        let _guard = lock::test_acquire_guard();
        let fixture = TestRepo::init("merge-hardlink-kept");
        let source = fixture.source_path();

        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("a"), b"old\n").unwrap();
        std::fs::hard_link(source.join("a"), source.join("b")).unwrap();
        set_mtime(&source.join("a"), 3600);
        let first = fixture.backup(&[], &["one"]);
        let second = fixture.backup(&[("a", b"new content\n")], &["two"]);

        let merged = merge_snapshots(fixture.profile(), &[first, second.clone()])
            .expect("the merged tree holds one consistent group")
            .snapshot_id;
        let root = snapshot_root_tree(
            &open_indexed(fixture.profile()).expect("open the repository"),
            &merged,
        )
        .expect("merged root");
        let repo = open_indexed_full(fixture.profile()).expect("open with the full index");
        let mut files = Vec::new();
        visit_raw_trees(
            &[root],
            |id| Ok(repo.cat_blob(BlobType::Tree, id.to_hex().as_str())?),
            |_dir, nodes| {
                files.extend(nodes.iter().filter_map(RawFile::of).map(|file| {
                    (file.identity, file.links, file.content)
                }));
                Ok(())
            },
        )
        .expect("walk the merged tree");
        assert_eq!(files.len(), 2);
        assert_eq!(files[0], files[1], "the two files are one hardlink group");
        assert_eq!(files[0].1, 2);
        let newer = snapshot_root_tree(
            &open_indexed(fixture.profile()).expect("open the repository"),
            &second,
        )
        .expect("newer root");
        let mut newer_content = Vec::new();
        visit_raw_trees(
            &[newer],
            |id| Ok(repo.cat_blob(BlobType::Tree, id.to_hex().as_str())?),
            |_dir, nodes| {
                newer_content.extend(nodes.iter().filter_map(RawFile::of).map(|f| f.content));
                Ok(())
            },
        )
        .expect("walk the newer source");
        assert_eq!(files[0].2, newer_content[0], "both links hold the newer content");
    }

    fn set_mtime(path: &std::path::Path, secs_ago: u64) {
        let when = std::time::SystemTime::now() - Duration::from_secs(secs_ago);
        std::fs::File::options()
            .write(true)
            .open(path)
            .and_then(|f| f.set_modified(when))
            .expect("set fixture mtime");
    }

    // A stop refuses writes, and the reads before them ask for it too: a
    // merge stopped while it reads its sources ends there, not at the first
    // write it would have got to.
    #[test]
    fn a_merge_stopped_while_reading_ends_before_it_writes() {
        let _guard = lock::test_acquire_guard();
        let fixture = TestRepo::init("merge-stopped");
        let first = fixture.backup(&[("a.txt", b"a\n")], &[]);
        let second = fixture.backup(&[("b.txt", b"b\n")], &[]);
        let retries = std::sync::Arc::new(lock::WriteRetries::default());
        retries.stop();
        let err = super::merge_snapshots(fixture.profile(), &[first, second], &retries)
            .expect_err("stopped");
        let message = format!("{err:#}");
        assert!(
            message.contains("stopped before writing its snapshot; nothing was written"),
            "{message}"
        );
        assert_eq!(load_snapshots(fixture.profile()).unwrap().rows.len(), 2);
    }

    /// A short id is the start of exactly one snapshot's id, in any letter
    /// case, and at least as long as the one restic prints. A start that
    /// fits none or several is an error naming it, and so is anything that
    /// is no id or too little of one.
    #[test]
    fn snapshot_ids_resolve_from_an_unambiguous_start() {
        let present =
            ["ab12".repeat(16), "ab34".repeat(16), "cd56".repeat(16)].map(String::from).to_vec();
        let starts = |starts: &[&str]| {
            ids_starting_with(&present, &starts.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        };
        assert_eq!(
            starts(&["cd", "ab12", &present[1]]).expect("unambiguous"),
            vec![present[2].clone(), present[0].clone(), present[1].clone()]
        );
        let err = starts(&["cd", "ab"]).expect_err("two ids start with ab");
        assert!(format!("{err:#}").contains("more than one snapshot id starts with `ab`"));
        let err = starts(&["ef"]).expect_err("no id starts with ef");
        assert!(format!("{err:#}").contains("no snapshot id starts with `ef`"));

        let fixture = TestRepo::init("resolve-ids");
        let id = fixture.backup(&[("a.txt", b"a\n")], &[]);
        let resolve = |given: &str| resolve_snapshot_ids(fixture.profile(), &[given.to_string()]);
        assert_eq!(resolve(&id[..8].to_ascii_uppercase()).expect("short id"), vec![id.clone()]);
        // A full id is taken as given, present or not: whatever uses it reads
        // the snapshot under its lock and says so if it is not there.
        let absent = "0".repeat(64);
        assert_eq!(resolve(&absent).expect("full id"), vec![absent.clone()]);
        for bad in ["", "latest", "xyz", &id[..7], &format!("{id}0")] {
            let err = resolve(bad).expect_err("not a snapshot id");
            assert!(format!("{err:#}").contains("is not a snapshot id"), "{bad}: {err:#}");
        }
    }

    // The merge end to end on an in-process repository, and its lock: the
    // non-exclusive one, proven from both sides. An *exclusive* lock held by
    // someone else — a running prune, forget or tag edit — must block it
    // before anything is written, which a merge that took no lock at all would
    // sail past. A *shared* one — a running backup, or wrustic's own SMB
    // share — must not, which a merge that asked for the exclusive lock would
    // trip over.
    #[test]
    fn merge_snapshots_combines_trees_under_the_shared_lock() {
        let _guard = lock::test_acquire_guard();
        let fixture = TestRepo::init("merge");
        let source = fixture.source_path();

        // First snapshot: a.txt, sub/x.txt, and the older side of two conflicts.
        let first = fixture.backup(
            &[
                ("a.txt", b"only in the first\n"),
                ("sub/x.txt", b"x\n"),
                ("newer-in-second.txt", b"old\n"),
                ("newer-in-first.txt", b"the first one wins\n"),
            ],
            &["one", "both"],
        );
        set_mtime(&source.join("newer-in-second.txt"), 3600);
        set_mtime(&source.join("newer-in-first.txt"), 60);
        let first_again = fixture.backup(&[], &["one", "both"]);
        // The first backup predates the mtimes set above; merge from the one
        // that recorded them.
        delete_snapshot(fixture.profile(), &first).expect("drop the pre-mtime snapshot");
        let first = first_again;

        // Second snapshot: neither a.txt nor sub/x.txt, but b.txt, sub/y.txt
        // and the other side of both conflicts.
        std::fs::remove_file(source.join("a.txt")).unwrap();
        std::fs::remove_file(source.join("sub/x.txt")).unwrap();
        let second = fixture.backup(
            &[
                ("b.txt", b"only in the second\n"),
                ("sub/y.txt", b"y\n"),
                ("newer-in-second.txt", b"the second one wins\n"),
                ("newer-in-first.txt", b"old\n"),
            ],
            &["two", "both"],
        );
        set_mtime(&source.join("newer-in-second.txt"), 30);
        set_mtime(&source.join("newer-in-first.txt"), 7200);
        let second_again = fixture.backup(&[], &["two", "both"]);
        delete_snapshot(fixture.profile(), &second).expect("drop the pre-mtime snapshot");
        let second = second_again;

        let ids = [first.clone(), second.clone()];
        let before = fixture.fingerprint().expect("fingerprint the repository");

        // Refused without two different snapshots, before any lock is taken.
        assert!(merge_snapshots(fixture.profile(), std::slice::from_ref(&first)).is_err());
        assert!(merge_snapshots(fixture.profile(), &[first.clone(), first.clone()]).is_err());

        // Blocked by an exclusive lock, having written nothing.
        let exclusive =
            lock::RepoLock::acquire_exclusive(fixture.lock_backend(), fixture.crypto())
                .expect("plant an exclusive lock");
        let err = merge_snapshots(fixture.profile(), &ids)
            .expect_err("a merge must not run while an exclusive lock is held");
        assert_lock_conflict(&err);
        assert_eq!(
            fixture.fingerprint().expect("fingerprint the repository"),
            before,
            "a blocked merge must not have written anything"
        );
        assert_eq!(fixture.lock_count(), 1, "only the planted lock may remain");
        drop(exclusive);

        // Coexists with a shared lock.
        let shared = plant_shared_lock(&fixture);
        let outcome = merge_snapshots(fixture.profile(), &ids)
            .expect("a merge runs alongside a shared lock");
        assert_eq!(fixture.lock_count(), 1, "the merge must release its own lock");
        assert!(
            outcome.dropped_node_fields.is_empty(),
            "nothing in these trees is beyond rustic_core's node: {:?}",
            outcome.dropped_node_fields
        );
        let merged = outcome.snapshot_id;
        drop(shared);

        // Nothing was removed or rewritten: every file from before is intact.
        let after = fixture.fingerprint().expect("fingerprint the repository");
        for entry in &before {
            assert!(after.contains(entry), "{} changed or vanished", entry.0);
        }

        // Three snapshots now; the merged one takes its identity from the
        // newer source and the union of the tags.
        let rows = load_snapshots(fixture.profile()).expect("list snapshots").rows;
        assert_eq!(rows.len(), 3, "both sources are kept");
        let row = |id: &str| rows.iter().find(|r| r.id == id).expect("snapshot listed");
        let (m, newer) = (row(&merged), row(&second));
        assert_eq!(m.host, newer.host);
        assert_eq!(m.paths, newer.paths, "both sources back up the same path");
        assert_eq!(m.tags, ["both", "one", "two"]);

        // The merged tree: everything from both, the newer mtime winning each
        // conflict whichever snapshot it came from.
        let repo = open_indexed(fixture.profile()).expect("open the repository");
        // The time as stored, which the list has cut to the second: exactly
        // one nanosecond after the newer source's.
        let stored_time = |id: &str| -> rustic_core::jiff::Timestamp {
            let raw = repo.cat_file(FileType::Snapshot, id).expect("read the snapshot file");
            let snapshot: serde_json::Value = serde_json::from_slice(&raw).expect("snapshot json");
            snapshot["time"].as_str().expect("a time").parse().expect("an RFC 3339 time")
        };
        assert_eq!(
            stored_time(&merged).duration_since(stored_time(&second)),
            rustic_core::jiff::SignedDuration::from_nanos(1)
        );
        let preview = preview_snapshot_contents(&repo, &merged, 1000).expect("walk merged tree");
        let size_of = |suffix: &str| {
            preview
                .entries
                .iter()
                .find(|e| e.path.ends_with(suffix))
                .unwrap_or_else(|| panic!("{suffix} missing from the merged snapshot"))
                .size
        };
        assert_eq!(size_of("/a.txt"), 18);
        assert_eq!(size_of("/b.txt"), 19);
        assert_eq!(size_of("/sub/x.txt"), 2);
        assert_eq!(size_of("/sub/y.txt"), 2);
        assert_eq!(size_of("/newer-in-second.txt"), 20, "the second snapshot's copy is newer");
        assert_eq!(size_of("/newer-in-first.txt"), 19, "the first snapshot's copy is newer");
        assert_eq!(m.size, Some(18 + 19 + 2 + 2 + 20 + 19), "the summary totals the merged tree");

        // The file content is reachable through the merged tree.
        let full = open_indexed_full(fixture.profile()).expect("open with the full index");
        let mut dir = snapshot_root_tree(&repo, &merged).expect("merged root");
        let source_abs = std::fs::canonicalize(&source).unwrap();
        for part in source_abs.components().filter_map(|c| match c {
            std::path::Component::Normal(p) => Some(p.to_string_lossy().into_owned()),
            // A Windows drive is a directory of its own in the tree
            // rustic_core's backup writes, named for the letter.
            std::path::Component::Prefix(p) => match p.kind() {
                std::path::Prefix::Disk(d) | std::path::Prefix::VerbatimDisk(d) => {
                    Some(char::from(d).to_string())
                }
                _ => None,
            },
            _ => None,
        }) {
            dir = full
                .get_tree(&dir)
                .expect("read directory")
                .nodes
                .into_iter()
                .find(|n| n.name().to_string_lossy() == part)
                .and_then(|n| n.subtree)
                .unwrap_or_else(|| panic!("{part} missing on the way to the source directory"));
        }
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let dump = std::thread::spawn(move || {
            stream_file_content(&full, dir, "newer-in-second.txt", &tx)
        });
        let mut bytes = Vec::new();
        while let Some(chunk) = rx.blocking_recv() {
            bytes.extend_from_slice(&chunk.expect("file chunk"));
        }
        dump.join().expect("dump thread").expect("stream merged file");
        assert_eq!(bytes, b"the second one wins\n");
    }

    // The other direction: the shared lock long-running reads take. Unlike
    // the writes above, the guard is handed to the caller, so this can assert
    // the lock is *held for the whole time the repository handle is alive* —
    // present on the backend, tolerant of a concurrent backup's append lock,
    // and blocking every native write until it drops.
    #[test]
    fn shared_open_holds_the_append_lock_for_the_handle_lifetime() {
        let _guard = lock::test_acquire_guard();
        let fixture = TestRepo::init("shared");
        let snap_id = fixture.backup(&[("a.txt", b"hello\n")], &[]);
        let backend = fixture.lock_backend();
        let crypto = fixture.crypto();

        let (repo, held) =
            open_indexed_full_shared_lock(fixture.profile()).expect("open under a shared lock");
        assert_eq!(fixture.lock_count(), 1, "the open must have left one lock");
        assert!(!held.poisoned(), "a fresh lock must not be poisoned");
        // The handle works, so the lock is genuinely being held alongside it
        // rather than acquired and released inside the open.
        assert_eq!(repo.get_all_snapshots().expect("snapshots").len(), 1);

        // A concurrent backup or a second share takes an append lock: allowed.
        assert!(
            lock::check_blocking_locks(backend.as_ref(), &crypto, false).is_ok(),
            "an append lock must coexist with the share's lock"
        );
        // Anything exclusive is refused for as long as the handle lives.
        assert_lock_conflict(
            &lock::check_blocking_locks(backend.as_ref(), &crypto, true)
                .expect_err("an exclusive acquisition must be blocked"),
        );
        assert_lock_conflict(
            &delete_snapshot(fixture.profile(), &snap_id)
                .expect_err("a native delete must be blocked"),
        );

        drop(repo);
        drop(held);
        assert_eq!(
            fixture.lock_count(),
            0,
            "dropping the guard must remove the lock file"
        );
        delete_snapshot(fixture.profile(), &snap_id).expect("delete once the share released");
    }

    // End-to-end interop with the restic CLI against a fresh local repo:
    // restic must see (and be blocked by) wrustic's native lock, `restic
    // unlock` must not remove it while fresh, and the native delete must
    // work. restic CLI is used only for repo setup (init/backup — dev-flow
    // write ops) and for observing lock behavior from restic's side.
    // Marked #[ignore]; run with `cargo test -- --ignored` (needs a restic
    // copied to target/debug/deps/restic/, the harness's only lookup).
    #[test]
    #[ignore]
    fn live_native_lock_and_delete_interop_with_restic() {
        // Acquires RepoLocks — serialize with other acquiring tests (SIGHUP
        // disposition is process-global).
        let _guard = lock::test_acquire_guard();

        let root = std::path::PathBuf::from("tmp")
            .join(format!("lock-it-{}", std::process::id()));
        let repo_path = root.join("repo");
        let source = root.join("source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("a.txt"), b"hello\n").unwrap();

        let profile = Profile::Local {
            password: "pw".into(),
            local_path: repo_path.to_string_lossy().into_owned(),
        };
        // Dev-flow writes (init/backup) and the restic-side observations
        // below all go through the secure spawn harness — never a bare
        // `restic` with the password exported into the child environment.
        crate::restic::run(&profile, &["init", "--json"]).expect("restic init");
        crate::restic::run(&profile, &["backup", source.to_str().unwrap(), "--json"])
            .expect("restic backup");

        let snapshots = load_snapshots(&profile).expect("list snapshots").rows;
        assert_eq!(snapshots.len(), 1);
        let snap_id = snapshots[0].id.clone();

        // Acquire an exclusive native lock; restic must refuse to forget.
        let backends = build_backends(&profile).unwrap();
        let repo = Repository::new(&RepositoryOptions::default(), &backends)
            .unwrap()
            .open(&Credentials::password(profile.password()))
            .unwrap();
        let crypto = lock::RepoCrypto::from_repo(&repo).unwrap();
        let held = lock::RepoLock::acquire_exclusive(
            lock::backend_for_profile(&profile).unwrap(),
            crypto.clone(),
        )
        .expect("acquire exclusive lock");

        let forget_err = crate::restic::run(&profile, &["forget", &snap_id, "--json"])
            .expect_err("restic forget should hit our lock");
        assert!(
            lock::is_lock_error(&format!("{forget_err:#}")),
            "restic should report a lock conflict, got: {forget_err:#}"
        );

        // `restic unlock` removes stale locks only — ours is fresh.
        crate::restic::run(&profile, &["unlock", "--json"]).expect("restic unlock");
        let locks_dir = repo_path.join("locks");
        let live_locks = std::fs::read_dir(&locks_dir).unwrap().count();
        assert_eq!(live_locks, 1, "our fresh lock must survive restic unlock");

        // Releasing the lock removes the file; restic can lock again.
        drop(held);
        let after = std::fs::read_dir(&locks_dir).map(|d| d.count()).unwrap_or(0);
        assert_eq!(after, 0, "dropping the lock must remove its file");

        // Native stale-lock removal: plant a restic-left lock by killing a
        // slow restic mid-operation is flaky, so simulate the same result —
        // an old lock file — through our own writer, then unlock natively.
        {
            let lb = lock::backend_for_profile(&profile).unwrap();
            lock::write_stale_lock_for_tests(lb.as_ref(), &crypto);
            assert_eq!(unlock(&profile).expect("native unlock"), 1);
        }

        // Native delete under the exclusive lock; snapshot must be gone for
        // both rustic and restic afterwards.
        delete_snapshot(&profile, &snap_id).expect("native delete");
        assert!(load_snapshots(&profile).expect("list after delete").rows.is_empty());
        let restic_list = crate::restic::run(&profile, &["snapshots", "--json"])
            .expect("restic snapshots");
        let listed: serde_json::Value =
            serde_json::from_slice(&restic_list).expect("restic snapshots json");
        assert_eq!(listed, serde_json::json!([]));

        std::fs::remove_dir_all(&root).ok();
    }

    // End-to-end interop for the native tag edit. restic creates a snapshot
    // with tags and an --exclude (the `excludes` field has no counterpart in
    // rustic_core's SnapshotFile — the raw-JSON rewrite exists precisely so
    // it survives an edit), wrustic retags natively under the exclusive
    // lock, and restic must afterwards see the new tags with everything else
    // intact and the repository healthy. Marked #[ignore]; run with
    // `cargo test -- --ignored` (needs a restic copied to
    // target/debug/deps/restic/, the harness's only lookup).
    #[test]
    #[ignore]
    fn live_native_tag_edit_interop_with_restic() {
        // Acquires RepoLocks — serialize with other acquiring tests (SIGHUP
        // disposition is process-global).
        let _guard = lock::test_acquire_guard();

        let root =
            std::path::PathBuf::from("tmp").join(format!("tag-it-{}", std::process::id()));
        let repo_path = root.join("repo");
        let source = root.join("source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("keep.txt"), b"hello").unwrap();
        std::fs::write(source.join("skip.o"), b"object file").unwrap();

        let profile = Profile::Local {
            password: "pw".into(),
            local_path: repo_path.to_string_lossy().into_owned(),
        };
        crate::restic::run(&profile, &["init", "--json"]).expect("restic init");
        crate::restic::run(
            &profile,
            &[
                "backup",
                source.to_str().unwrap(),
                "--tag",
                "old,keep",
                "--exclude",
                "*.o",
                "--json",
            ],
        )
        .expect("restic backup");

        let snapshots = load_snapshots(&profile).expect("list snapshots").rows;
        assert_eq!(snapshots.len(), 1);
        let snap_id = snapshots[0].id.clone();
        // rustic models tags as a BTreeSet, so wrustic's view is sorted even
        // though restic stored ["old", "keep"] in typed order.
        assert_eq!(snapshots[0].tags, vec!["keep", "old"]);

        // A concurrent holder (a shared lock, as a running backup would
        // take) must block the exclusive tag edit — restic's rule for `tag`.
        {
            let backends = build_backends(&profile).unwrap();
            let repo = Repository::new(&RepositoryOptions::default(), &backends)
                .unwrap()
                .open(&Credentials::password(profile.password()))
                .unwrap();
            let crypto = lock::RepoCrypto::from_repo(&repo).unwrap();
            let live = lock::RepoLock::acquire_shared(
                lock::backend_for_profile(&profile).unwrap(),
                crypto,
            )
            .expect("shared lock");
            let err = edit_snapshot_tags(&profile, &snap_id, &["blocked".into()])
                .expect_err("tag edit must be blocked by a live shared lock");
            assert!(
                lock::is_lock_error(&format!("{err:#}")),
                "expected a lock conflict, got: {err:#}"
            );
            drop(live);
        }

        // Same tags → restic's `changed == false` no-op: nothing written.
        let unchanged =
            edit_snapshot_tags(&profile, &snap_id, &["old".into(), "keep".into()])
                .expect("no-op edit");
        assert!(unchanged.is_none());
        assert_eq!(load_snapshots(&profile).unwrap().rows[0].id, snap_id);

        // The real edit.
        let new_id = edit_snapshot_tags(&profile, &snap_id, &["new".into(), "keep".into()])
            .expect("native tag edit")
            .expect("tags differ, must rewrite");
        assert_ne!(new_id, snap_id);

        // restic's view: one snapshot under the new id, retagged, with
        // `excludes` intact and `original` pointing at the pre-edit id.
        let listed = crate::restic::run(&profile, &["snapshots", "--json"])
            .expect("restic snapshots");
        let listed: serde_json::Value =
            serde_json::from_slice(&listed).expect("restic snapshots json");
        let arr = listed.as_array().expect("snapshot array");
        assert_eq!(arr.len(), 1);
        let snap = &arr[0];
        assert_eq!(snap["id"], serde_json::json!(new_id));
        assert_eq!(snap["tags"], serde_json::json!(["new", "keep"]));
        assert_eq!(
            snap["excludes"],
            serde_json::json!(["*.o"]),
            "the raw-JSON rewrite must preserve restic's excludes field"
        );
        assert_eq!(snap["original"], serde_json::json!(snap_id));

        // wrustic's native reader agrees (sorted view of the same set).
        let after = load_snapshots(&profile).expect("list after edit").rows;
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].id, new_id);
        assert_eq!(after[0].tags, vec!["keep", "new"]);

        // The repository is healthy from restic's side, and restic can
        // itself retag the rewritten snapshot (full round-trip of our file).
        crate::restic::run(&profile, &["check", "--read-data", "--json"])
            .expect("restic check");
        crate::restic::run(&profile, &["tag", "--add", "more", &new_id, "--json"])
            .expect("restic tag on our rewritten snapshot");

        std::fs::remove_dir_all(&root).ok();
    }

    // The path restic shows for a file inside a snapshot, from the path the
    // filesystem knows it by. The same on Unix. On Windows a snapshot has the
    // volume as its first directory and forward slashes throughout:
    // `C:\Users\me` is `/C/Users/me`.
    fn restic_archive_path(fs_path: &str) -> String {
        format!("/{}", archive_components(fs_path).join("/"))
    }

    // `std::fs::canonicalize`, for a path that goes to restic and is looked
    // for in what restic reports. On Windows the answer is in the verbatim
    // form (`\\?\D:\…`), which restic would take as given; this is the same
    // path with the drive letter first, the spelling restic's own output and
    // its `/D/…` archive paths go with.
    fn canonical(path: &std::path::Path) -> std::path::PathBuf {
        let path = std::fs::canonicalize(path).expect("canonicalize");
        match path.to_str().and_then(|verbatim| verbatim.strip_prefix(r"\\?\")) {
            Some(plain) => std::path::PathBuf::from(plain),
            None => path,
        }
    }

    #[test]
    fn restic_archive_paths_have_the_volume_as_a_directory() {
        assert_eq!(restic_archive_path("/home/me/data"), "/home/me/data");
        assert_eq!(restic_archive_path(r"C:\Users\me\data"), "/C/Users/me/data");
        assert_eq!(restic_archive_path(r"\\?\D:\ci\tmp\data"), "/D/ci/tmp/data");
    }

    // End-to-end interop for the native merge, which restic has no command
    // for: what matters is that restic treats the result as an ordinary
    // snapshot. restic backs up a directory and then, separately, one new
    // subdirectory of it; wrustic merges the two; restic must then list the
    // merged snapshot with the folded path set, read every file through it,
    // find the repository healthy — and pick the merged snapshot as the parent
    // of the next backup of the directory, with nothing left to read again.
    // Marked #[ignore]; run with `cargo test -- --ignored` (needs a restic
    // copied to target/debug/deps/restic/, the harness's only lookup).
    #[test]
    #[ignore]
    fn live_native_merge_interop_with_restic() {
        let _guard = lock::test_acquire_guard();

        let root =
            std::path::PathBuf::from("tmp").join(format!("merge-it-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("source/data/docs")).unwrap();
        // restic records absolute paths; the tree and `paths` are compared
        // against this below.
        let data = canonical(&root.join("source/data"));
        std::fs::write(data.join("docs/a.txt"), b"a\n").unwrap();
        std::fs::write(data.join("keep.txt"), b"keep\n").unwrap();
        std::fs::write(data.join("skip.o"), b"object file").unwrap();
        let data_str = data.to_str().unwrap();

        let profile = Profile::Local {
            password: "pw".into(),
            local_path: root.join("repo").to_string_lossy().into_owned(),
        };
        crate::restic::run(&profile, &["init", "--json"]).expect("restic init");
        crate::restic::run(
            &profile,
            &["backup", data_str, "--tag", "base", "--exclude", "*.o", "--json"],
        )
        .expect("restic backup of the directory");

        // The addition: a new subdirectory, backed up on its own.
        let extra = data.join("extra");
        std::fs::create_dir_all(extra.join("sub")).unwrap();
        std::fs::write(extra.join("n.txt"), b"new\n").unwrap();
        std::fs::write(extra.join("sub/n2.txt"), b"newer\n").unwrap();
        crate::restic::run(
            &profile,
            &["backup", extra.to_str().unwrap(), "--tag", "added", "--json"],
        )
        .expect("restic backup of the new subdirectory");

        // Newest first: the addition, then the base.
        let rows = load_snapshots(&profile).expect("list snapshots").rows;
        assert_eq!(rows.len(), 2);
        let (added, base) = (&rows[0], &rows[1]);
        assert_eq!(base.paths, [data_str]);

        let merged = merge_snapshots(&profile, &[base.id.clone(), added.id.clone()])
            .expect("native merge")
            .snapshot_id;

        let restic_snapshots = || -> Vec<serde_json::Value> {
            let out = crate::restic::run(&profile, &["snapshots", "--json"])
                .expect("restic snapshots");
            serde_json::from_slice(&out).expect("restic snapshots json")
        };
        let listed = restic_snapshots();
        assert_eq!(listed.len(), 3, "both sources are kept");
        let by_id = |id: &str| {
            listed
                .iter()
                .find(|s| s["id"] == serde_json::json!(id))
                .unwrap_or_else(|| panic!("restic does not list {id}"))
        };
        let (m, newer) = (by_id(&merged), by_id(&added.id));
        assert_eq!(
            m["paths"],
            serde_json::json!([data_str]),
            "the subdirectory's path folds into the directory's"
        );
        assert_eq!(
            m["time"],
            serde_json::json!(just_after(newer["time"].as_str().unwrap()).unwrap()),
            "just after the newer source"
        );
        assert_eq!(m["hostname"], newer["hostname"]);
        assert_eq!(m["username"], newer["username"]);
        assert_eq!(m["tags"], serde_json::json!(["added", "base"]));
        for single_run_field in ["parent", "original", "excludes"] {
            assert!(m.get(single_run_field).is_none(), "{single_run_field} must not be set");
        }
        assert!(m["program_version"].as_str().is_some_and(|v| v.starts_with("wrustic ")));
        assert_eq!(m["summary"]["total_files_processed"], 4);

        crate::restic::run(&profile, &["check", "--read-data", "--json"])
            .expect("restic check after the merge");

        // restic walks the merged tree: every file of both sources, at its
        // real path, and still without the excluded one.
        let ls = crate::restic::run(&profile, &["ls", &merged, "--json"]).expect("restic ls");
        let ls_paths: Vec<String> = String::from_utf8(ls)
            .unwrap()
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter_map(|v| v.get("path").and_then(|p| p.as_str()).map(str::to_string))
            .collect();
        // `ls` prints paths as the snapshot holds them, which on Windows is
        // not how the filesystem spells them.
        let data_in_snapshot = restic_archive_path(data_str);
        for file in ["docs/a.txt", "keep.txt", "extra/n.txt", "extra/sub/n2.txt"] {
            let want = format!("{data_in_snapshot}/{file}");
            assert!(ls_paths.contains(&want), "{want} missing from restic ls: {ls_paths:?}");
        }
        assert!(!ls_paths.iter().any(|p| p.ends_with("skip.o")));

        // The point of writing the snapshot file ourselves: the next backup of
        // the directory takes the merged snapshot as its parent and finds
        // every file — the new subdirectory's included — unmodified.
        let out = crate::restic::run(
            &profile,
            &["backup", data_str, "--tag", "base", "--exclude", "*.o", "--json"],
        )
        .expect("restic backup after the merge");
        let summary = String::from_utf8(out)
            .unwrap()
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .find(|v| v["message_type"] == "summary")
            .expect("restic backup summary");
        assert_eq!(summary["files_new"], 0, "{summary}");
        assert_eq!(summary["files_changed"], 0, "{summary}");
        assert_eq!(summary["files_unmodified"], 4, "{summary}");
        let latest = restic_snapshots()
            .into_iter()
            .find(|s| s["id"] == summary["snapshot_id"])
            .expect("the new snapshot is listed");
        assert_eq!(latest["parent"], serde_json::json!(merged));

        std::fs::remove_dir_all(&root).ok();
    }

    // Hardlinks through the merge, judged by what restic restores. restic
    // rebuilds them from each file's recorded device and inode, which the merge
    // passes on as it finds them: groups from different sources must come back
    // as the separate groups they were, with their own bytes — and the pair of
    // snapshots that put one inode on different content (a directory renamed
    // and a file rewritten in place between the backups), which restic would
    // restore as four links to one file, must not merge at all.
    // Marked #[ignore]; run with `cargo test -- --ignored` (needs a restic
    // copied to target/debug/deps/restic/, the harness's only lookup).
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_native_merge_restores_hardlinks_with_restic() {
        use std::os::unix::fs::MetadataExt;
        let _guard = lock::test_acquire_guard();

        let root =
            std::path::PathBuf::from("tmp").join(format!("merge-links-it-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("source/data/links")).unwrap();
        std::fs::create_dir_all(root.join("source/clash/one")).unwrap();
        let root = canonical(&root);
        let (data, clash) = (root.join("source/data"), root.join("source/clash"));

        let profile = Profile::Local {
            password: "pw".into(),
            local_path: root.join("repo").to_string_lossy().into_owned(),
        };
        crate::restic::run(&profile, &["init", "--json"]).expect("restic init");
        let backup = |path: &std::path::Path, tag: &str| {
            crate::restic::run(&profile, &["backup", path.to_str().unwrap(), "--tag", tag, "--json"])
                .unwrap_or_else(|e| panic!("restic backup of {}: {e:#}", path.display()));
        };
        let snapshot_tagged = |tag: &str| {
            load_snapshots(&profile)
                .expect("list snapshots")
                .rows
                .into_iter()
                .find(|row| row.tags == [tag])
                .unwrap_or_else(|| panic!("no snapshot tagged {tag}"))
                .id
        };

        // Two sources, a hardlink group in each.
        std::fs::write(data.join("links/a"), b"linked\n").unwrap();
        std::fs::hard_link(data.join("links/a"), data.join("links/b")).unwrap();
        std::fs::write(data.join("plain"), b"plain\n").unwrap();
        backup(&data, "base");
        std::fs::create_dir_all(data.join("extra")).unwrap();
        std::fs::write(data.join("extra/x"), b"extra\n").unwrap();
        std::fs::hard_link(data.join("extra/x"), data.join("extra/y")).unwrap();
        backup(&data.join("extra"), "added");

        let merged = merge_snapshots(&profile, &[snapshot_tagged("base"), snapshot_tagged("added")])
            .expect("native merge")
            .snapshot_id;
        let target = root.join("restored");
        crate::restic::run(
            &profile,
            &["restore", &merged, "--target", target.to_str().unwrap(), "--json"],
        )
        .expect("restic restore of the merged snapshot");
        let restored = target.join(data.strip_prefix("/").unwrap());
        let file = |name: &str| {
            let path = restored.join(name);
            let meta = std::fs::metadata(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
            (std::fs::read(&path).unwrap(), meta.ino(), meta.nlink())
        };
        let (a, b, x, y, plain) =
            (file("links/a"), file("links/b"), file("extra/x"), file("extra/y"), file("plain"));
        assert_eq!((a.0.as_slice(), a.2), (b"linked\n".as_slice(), 2));
        assert_eq!(a, b, "links/a and links/b are one file again");
        assert_eq!((x.0.as_slice(), x.2), (b"extra\n".as_slice(), 2));
        assert_eq!(x, y, "extra/x and extra/y are one file again");
        assert_ne!(a.1, x.1, "the two groups stay apart");
        assert_eq!((plain.0.as_slice(), plain.2), (b"plain\n".as_slice(), 1));

        // One inode, two contents, two paths.
        std::fs::write(clash.join("one/p"), b"old\n").unwrap();
        std::fs::hard_link(clash.join("one/p"), clash.join("one/q")).unwrap();
        backup(&clash.join("one"), "clash-one");
        std::fs::rename(clash.join("one"), clash.join("two")).unwrap();
        std::fs::write(clash.join("two/p"), b"new content\n").unwrap();
        backup(&clash.join("two"), "clash-two");

        let before = load_snapshots(&profile).expect("list snapshots").rows.len();
        let err = merge_snapshots(
            &profile,
            &[snapshot_tagged("clash-one"), snapshot_tagged("clash-two")],
        )
        .expect_err("restic would restore this merge with the wrong bytes");
        assert!(format!("{err:#}").contains("hardlinks of one file"), "{err:#}");
        assert_eq!(load_snapshots(&profile).expect("list snapshots").rows.len(), before);

        // A group whose second link is gone, the survivor moved and rewritten:
        // one link now, the old inode still, and restic links it regardless.
        let fell = root.join("source/fell");
        std::fs::create_dir_all(fell.join("old")).unwrap();
        std::fs::write(fell.join("old/a"), b"old\n").unwrap();
        std::fs::hard_link(fell.join("old/a"), fell.join("old/b")).unwrap();
        backup(&fell, "fell-one");
        std::fs::create_dir_all(fell.join("new")).unwrap();
        std::fs::rename(fell.join("old/a"), fell.join("new/c")).unwrap();
        std::fs::remove_dir_all(fell.join("old")).unwrap();
        std::fs::write(fell.join("new/c"), b"new content\n").unwrap();
        backup(&fell, "fell-two");
        let before = load_snapshots(&profile).expect("list snapshots").rows.len();
        let err = merge_snapshots(
            &profile,
            &[snapshot_tagged("fell-one"), snapshot_tagged("fell-two")],
        )
        .expect_err("restic would restore new/c with the old bytes");
        assert!(format!("{err:#}").contains("hardlinks of one file"), "{err:#}");
        assert_eq!(load_snapshots(&profile).expect("list snapshots").rows.len(), before);

        crate::restic::run(&profile, &["check", "--read-data", "--json"])
            .expect("restic check after the refused merges");

        std::fs::remove_dir_all(&root).ok();
    }

    // Two things about how restic reads a merged snapshot that only restic
    // can show. Names it stores quoted: restic sorts a directory by the name,
    // the merge by the quoted form, and where those disagree (`"a` and `A`)
    // the merged directory would list an entry twice and restore the older
    // copy — refused; where they agree the merge goes through and the quoted
    // name comes back byte for byte. And the parent of the next backup when
    // the newest source has the merged snapshot's own host and paths: restic
    // takes the latest snapshot and leaves a tie to chance, so the merged one
    // has to be strictly later, or files only the merge holds are read again.
    // Marked #[ignore]; run with `cargo test -- --ignored` (needs a restic
    // copied to target/debug/deps/restic/, the harness's only lookup).
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_native_merge_quoted_names_and_parent_with_restic() {
        let _guard = lock::test_acquire_guard();

        let root =
            std::path::PathBuf::from("tmp").join(format!("merge-names-it-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("source")).unwrap();
        let root = canonical(&root);
        let profile = Profile::Local {
            password: "pw".into(),
            local_path: root.join("repo").to_string_lossy().into_owned(),
        };
        crate::restic::run(&profile, &["init", "--json"]).expect("restic init");
        let backup = |path: &std::path::Path, tag: &str| -> serde_json::Value {
            let out = crate::restic::run(
                &profile,
                &["backup", path.to_str().unwrap(), "--tag", tag, "--json"],
            )
            .unwrap_or_else(|e| panic!("restic backup of {}: {e:#}", path.display()));
            String::from_utf8(out)
                .unwrap()
                .lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .find(|v| v["message_type"] == "summary")
                .expect("restic backup summary")
        };
        let snapshot_tagged = |tag: &str| {
            load_snapshots(&profile)
                .expect("list snapshots")
                .rows
                .into_iter()
                .find(|row| row.tags == [tag])
                .unwrap_or_else(|| panic!("no snapshot tagged {tag}"))
                .id
        };
        let restic_snapshots = || -> Vec<serde_json::Value> {
            let out = crate::restic::run(&profile, &["snapshots", "--json"])
                .expect("restic snapshots");
            serde_json::from_slice(&out).expect("restic snapshots json")
        };

        // `"a` sorts before `A`, `\"a` after it.
        let flipped = root.join("source/flipped");
        std::fs::create_dir_all(&flipped).unwrap();
        std::fs::write(flipped.join("\"a"), b"quoted\n").unwrap();
        std::fs::write(flipped.join("A"), b"older\n").unwrap();
        backup(&flipped, "flipped-all");
        std::fs::write(flipped.join("A"), b"newer content\n").unwrap();
        backup(&flipped.join("A"), "flipped-one");
        let before = restic_snapshots().len();
        let err = merge_snapshots(
            &profile,
            &[snapshot_tagged("flipped-all"), snapshot_tagged("flipped-one")],
        )
        .expect_err("the merged directory would list A twice");
        assert!(format!("{err:#}").contains("stored quoted"), "{err:#}");
        assert_eq!(restic_snapshots().len(), before, "no snapshot may have been written");

        // `"a` and `b` sort the same way quoted and unquoted.
        let agreeing = root.join("source/agreeing");
        std::fs::create_dir_all(&agreeing).unwrap();
        std::fs::write(agreeing.join("\"a"), b"quoted\n").unwrap();
        std::fs::write(agreeing.join("b"), b"older\n").unwrap();
        backup(&agreeing, "agreeing-all");
        std::fs::write(agreeing.join("b"), b"newer content\n").unwrap();
        backup(&agreeing.join("b"), "agreeing-one");
        let merged = merge_snapshots(
            &profile,
            &[snapshot_tagged("agreeing-all"), snapshot_tagged("agreeing-one")],
        )
        .expect("names in one order either way merge")
        .snapshot_id;
        let target = root.join("restored");
        crate::restic::run(
            &profile,
            &["restore", &merged, "--target", target.to_str().unwrap(), "--json"],
        )
        .expect("restic restore of the merged snapshot");
        let restored = target.join(agreeing.strip_prefix("/").unwrap());
        assert_eq!(std::fs::read(restored.join("\"a")).unwrap(), b"quoted\n");
        assert_eq!(std::fs::read(restored.join("b")).unwrap(), b"newer content\n");
        let mut names: Vec<_> = std::fs::read_dir(&restored)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["\"a", "b"]);

        // Two backups of one directory: the newer source has the merged
        // snapshot's host and paths, and only the merge still holds `gone`.
        let twice = root.join("source/twice");
        std::fs::create_dir_all(&twice).unwrap();
        std::fs::write(twice.join("gone"), b"only in the first\n").unwrap();
        std::fs::write(twice.join("kept"), b"kept\n").unwrap();
        backup(&twice, "twice-one");
        std::fs::remove_file(twice.join("gone")).unwrap();
        std::fs::write(twice.join("kept"), b"kept, changed\n").unwrap();
        backup(&twice, "twice-two");
        let (older, newer) = (snapshot_tagged("twice-one"), snapshot_tagged("twice-two"));
        let merged = merge_snapshots(&profile, &[older, newer.clone()])
            .expect("native merge")
            .snapshot_id;
        let listed = restic_snapshots();
        let time_of = |id: &str| -> rustic_core::jiff::Timestamp {
            listed
                .iter()
                .find(|s| s["id"] == serde_json::json!(id))
                .and_then(|s| s["time"].as_str())
                .unwrap_or_else(|| panic!("restic does not list {id}"))
                .parse()
                .expect("snapshot time")
        };
        assert!(time_of(&merged) > time_of(&newer), "the merged snapshot must be the latest");
        std::fs::write(twice.join("gone"), b"only in the first\n").unwrap();
        let summary = backup(&twice, "twice-three");
        let latest = restic_snapshots()
            .into_iter()
            .find(|s| s["id"] == summary["snapshot_id"])
            .expect("the new snapshot is listed");
        assert_eq!(latest["parent"], serde_json::json!(merged));

        // The same directory backed up as two hosts: the merged snapshot is
        // named for both, and the next backup as either host — or with no
        // host given, which is the machine's own name to restic — passes it
        // over.
        let hosts = root.join("source/hosts");
        std::fs::create_dir_all(&hosts).unwrap();
        std::fs::write(hosts.join("f"), b"from alpha\n").unwrap();
        let backup_as = |host: &str, tag: &str| -> serde_json::Value {
            let out = crate::restic::run(
                &profile,
                &["backup", hosts.to_str().unwrap(), "--host", host, "--tag", tag, "--json"],
            )
            .unwrap_or_else(|e| panic!("restic backup as {host}: {e:#}"));
            String::from_utf8(out)
                .unwrap()
                .lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .find(|v| v["message_type"] == "summary")
                .expect("restic backup summary")
        };
        backup_as("alpha", "hosts-alpha");
        std::fs::write(hosts.join("g"), b"from beta\n").unwrap();
        backup_as("beta", "hosts-beta");
        let beta = snapshot_tagged("hosts-beta");
        let merged = merge_snapshots(&profile, &[snapshot_tagged("hosts-alpha"), beta.clone()])
            .expect("native merge across hosts")
            .snapshot_id;
        let listed = restic_snapshots();
        let merged_listed = listed
            .iter()
            .find(|s| s["id"] == serde_json::json!(merged))
            .expect("restic lists the merged snapshot");
        assert_eq!(merged_listed["hostname"], "alpha+beta");
        let summary = backup_as("beta", "hosts-next");
        let latest = restic_snapshots()
            .into_iter()
            .find(|s| s["id"] == summary["snapshot_id"])
            .expect("the new snapshot is listed");
        assert_eq!(
            latest["parent"],
            serde_json::json!(beta),
            "beta's backup must take beta's own, not the merge of two hosts"
        );
        let summary = backup_as("", "hosts-unnamed");
        let unnamed = restic_snapshots()
            .into_iter()
            .find(|s| s["id"] == summary["snapshot_id"])
            .expect("the new snapshot is listed");
        assert!(
            unnamed["hostname"].as_str().is_some_and(|host| !host.is_empty()),
            "restic gives every backup a hostname: {unnamed}"
        );
        assert_ne!(unnamed["parent"], serde_json::json!(merged));

        crate::restic::run(&profile, &["check", "--read-data", "--json"])
            .expect("restic check");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    #[ignore]
    fn live_silo_s3_profile_reads_seeded_repository() {
        let endpoint = std::env::var("WRUSTIC_SILO_ENDPOINT")
            .unwrap_or_else(|_| "http://127.0.0.1:9000".into());
        let profile = Profile::S3 {
            password: "silo-repository-password".into(),
            s3_endpoint: endpoint,
            s3_bucket: "wrustic-it".into(),
            s3_region: "us-east-1".into(),
            s3_root: "repository".into(),
            s3_access_key: "wrustic-it".into(),
            s3_secret_key: "wrustic-it-secret".into(),
        };

        verify_profile(&profile).expect("verify Silo profile");
        let snapshots = load_snapshots(&profile).expect("list Silo snapshots").rows;
        let snapshot = snapshots.first().expect("seeded Silo snapshot");
        let previous = snapshots.get(1).expect("second seeded Silo snapshot");
        assert!(snapshot.tags.iter().any(|tag| tag == "silo-e2e-second"));

        let repo = open_indexed(&profile).expect("open Silo repository");
        let (summary, changes) =
            diff_snapshots(&repo, &previous.id, &snapshot.id).expect("diff Silo snapshots");
        assert!(summary.changed_files > 0);
        assert!(changes.iter().any(|change| change.path.ends_with("/hello.txt")));
        assert!(changes.iter().any(|change| change.path.ends_with("/second.txt")));

        let preview =
            preview_snapshot_contents(&repo, &snapshot.id, 100).expect("preview Silo tree");
        let hello = preview
            .entries
            .iter()
            .find(|entry| entry.path.ends_with("/hello.txt"))
            .expect("hello.txt in Silo snapshot");

        let full_repo = open_indexed_full(&profile).expect("open full Silo repository");
        let mut parent_tree =
            snapshot_root_tree(&repo, &snapshot.id).expect("Silo snapshot root tree");
        let mut components = hello.path.trim_start_matches('/').split('/').peekable();
        let file_name = loop {
            let component = components.next().expect("hello.txt path component");
            if components.peek().is_none() {
                break component.to_string();
            }
            let tree = full_repo
                .get_tree(&parent_tree)
                .expect("read Silo directory tree");
            parent_tree = tree
                .nodes
                .into_iter()
                .find(|node| node.name().to_string_lossy() == component)
                .and_then(|node| node.subtree)
                .expect("Silo directory subtree");
        };

        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let dump = std::thread::spawn(move || {
            stream_file_content(&full_repo, parent_tree, &file_name, &tx)
        });
        let mut bytes = Vec::new();
        while let Some(chunk) = rx.blocking_recv() {
            bytes.extend_from_slice(&chunk.expect("Silo file chunk"));
        }
        dump.join()
            .expect("Silo dump thread")
            .expect("stream Silo hello.txt");
        assert_eq!(bytes, b"hello from Silo S3 integration, revision 2\n");
    }
}
