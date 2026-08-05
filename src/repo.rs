use std::io::{self, Write};
use std::mem;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use rustic_backend::BackendOptions;
use rustic_core::repofile::{Node, NodeType};
use rustic_core::{
    Credentials, IndexedFull, IndexedFullStatus, IndexedIdsStatus, LimitOption, Progress,
    ProgressBars, ProgressType, PruneOptions, PruneStats, Repository, RepositoryOptions,
    RepositoryBackends, RusticProgress, TreeId,
};
use tokio::sync::mpsc;

use crate::config::Profile;
use crate::lock;

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

// All backends are write-capable; keeping write operations safe against
// concurrent restic processes is the lock module's job (docs/locking.md),
// not the backend's.
fn build_backends(profile: &Profile) -> Result<RepositoryBackends> {
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
            opts = opts.repository(format!("rest:{url}"));
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
            )?;
            return Ok(RepositoryBackends::new(std::sync::Arc::new(backend), None));
        }
    }
    Ok(opts.to_backends()?)
}

pub(crate) fn verify_profile(profile: &Profile) -> Result<()> {
    let backends = build_backends(profile)?;
    Repository::new(&RepositoryOptions::default(), &backends)?
        .open(&Credentials::password(profile.password()))?;
    Ok(())
}

pub(crate) fn load_snapshots(profile: &Profile) -> Result<Vec<SnapshotRow>> {
    let backends = build_backends(profile)?;
    let repo = Repository::new(&RepositoryOptions::default(), &backends)?
        .open(&Credentials::password(profile.password()))?;

    let mut snaps = repo.get_all_snapshots()?;
    snaps.sort_by(|a, b| b.time.cmp(&a.time));

    Ok(snaps
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
        .collect())
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

/// Prunes the repository natively, under an exclusive restic-compatible lock —
/// the same lock `restic prune` takes (docs/locking.md). The lock covers
/// planning *and* execution: rustic_core's executor never re-validates the
/// plan, so the snapshot set enumerated during planning must stay frozen
/// until the last pack is deleted.
///
/// `instant_delete` is always on. rustic's default two-phase delete records
/// removed packs under `packs_to_delete` in the index — a rustic-only
/// extension restic cannot see (restic 0.19 decodes only `packs` and drops
/// unknown keys on rewrite), so a restic prune would void that bookkeeping
/// and delete the marked packs immediately anyway. Instant delete is also
/// restic's own semantic, and it needs no time-based grace period for the
/// same reason restic needs none: the exclusive lock excludes every
/// concurrent writer. The resulting repo state — new index files covering
/// exactly the surviving packs, old indexes and unused packs gone — is
/// indistinguishable from a restic prune.
///
/// `max_repack` is lifted to unlimited to match `restic prune` (rustic's
/// 10%-per-run default merely spreads repacking over several runs).
///
/// The deletion order is crash-safe like restic's: repacked data and the new
/// index are written before old indexes are removed, and packs are removed
/// last — an interruption at any point leaves a valid repository plus some
/// garbage the next prune collects.
///
/// Progress lines are written into `progress` for the TUI to render; the
/// returned report summarizes the executed plan.
pub(crate) fn prune(
    profile: &Profile,
    progress: std::sync::Arc<std::sync::Mutex<String>>,
) -> Result<String> {
    let backends = build_backends(profile)?;
    let repo = Repository::new_with_progress(
        &RepositoryOptions::default(),
        &backends,
        TuiProgressBars { buf: progress },
    )?
    .open(&Credentials::password(profile.password()))?;
    let crypto = lock::RepoCrypto::from_repo(&repo)?;
    let repo_lock =
        lock::RepoLock::acquire_exclusive(lock::backend_for_profile(profile)?, crypto)?;

    let opts = PruneOptions::default()
        .instant_delete(true)
        .max_repack(LimitOption::Unlimited);
    let plan = repo.prune_plan(&opts)?;
    let report = prune_report(&plan.stats);
    // Planning walks every snapshot tree and can take a long time on a big
    // repo. Apply restic's refreshability-abort rule at the last gate before
    // anything destructive: a lock that went unrefreshed for 22.5 minutes may
    // already have been judged stale and removed by another process.
    if repo_lock.poisoned() {
        bail!(
            "the repository lock could not be refreshed while the prune was being planned; \
             aborting before deleting anything (the repository is unchanged)"
        );
    }
    repo.prune(&opts, plan)?;
    Ok(report)
}

/// Plain-text summary of a prune plan, in the spirit of `restic prune`'s
/// report. Rendered from the plan (before execution) and shown only after
/// the execution succeeded, so past tense is accurate.
fn prune_report(stats: &PruneStats) -> String {
    use std::fmt::Write;

    let packs = &stats.packs;
    let blobs = stats.blobs_sum();
    let size = stats.size_sum();
    let mut out = String::new();

    let _ = writeln!(
        out,
        "used:       {:>9} blobs, {:>10}",
        blobs.used,
        human_bytes(size.used)
    );
    let _ = writeln!(
        out,
        "unused:     {:>9} blobs, {:>10}",
        blobs.unused,
        human_bytes(size.unused)
    );
    let _ = writeln!(
        out,
        "repacked:   {:>9} packs, {:>10} ({} blobs, {} thereof dropped)",
        packs.repack,
        human_bytes(size.repack),
        blobs.repack,
        blobs.repackrm,
    );
    let _ = writeln!(
        out,
        "deleted:    {:>9} packs, {:>10} ({} blobs)",
        packs.unused,
        human_bytes(size.remove),
        blobs.remove,
    );
    if stats.packs_unref > 0 {
        let _ = writeln!(
            out,
            "unindexed:  {:>9} packs, {:>10} (leftovers of interrupted runs, deleted)",
            stats.packs_unref,
            human_bytes(stats.size_unref)
        );
    }
    // Packs an earlier `rustic prune` marked for deletion (wrustic never
    // marks — instant delete): recovered ones move back into the index,
    // everything else is deleted now.
    let marked = &stats.packs_to_delete;
    if marked.total() > 0 {
        let _ = writeln!(
            out,
            "marked:     {:>9} packs, {:>10} ({} deleted now, {} recovered)",
            marked.total(),
            human_bytes(stats.size_to_delete.total()),
            marked.remove + marked.keep,
            marked.recover,
        );
    }
    let reclaimed = size.repackrm + size.remove + stats.size_unref;
    let _ = writeln!(out, "\ntotal space reclaimed: {}", human_bytes(reclaimed));
    let remaining_size = size.total_after_prune();
    let _ = writeln!(
        out,
        "remaining:  {:>9} blobs, {:>10}",
        blobs.total_after_prune(),
        human_bytes(remaining_size)
    );
    if remaining_size > 0 {
        let _ = writeln!(
            out,
            "unused size after prune: {} ({:.2}% of remaining size)",
            human_bytes(size.unused_after_prune()),
            size.unused_after_prune() as f64 / remaining_size as f64 * 100.0
        );
    }
    let _ = write!(
        out,
        "index files rebuilt: {} of {}",
        stats.index_files_rebuild, stats.index_files
    );
    out
}

pub(crate) fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Adapter feeding rustic_core's per-phase progress into the shared text
/// buffer the prune screen renders. Each phase gets one line in the buffer,
/// updated in place as the phase advances, so the screen shows the newest
/// state of every phase rather than a scrolling log.
#[derive(Debug)]
struct TuiProgressBars {
    buf: std::sync::Arc<std::sync::Mutex<String>>,
}

impl ProgressBars for TuiProgressBars {
    fn progress(&self, progress_type: ProgressType, prefix: &str) -> Progress {
        let line = {
            let mut buf = self.buf.lock().unwrap_or_else(|p| p.into_inner());
            let line = buf.lines().count();
            if !buf.is_empty() {
                buf.push('\n');
            }
            buf.push_str(prefix);
            line
        };
        Progress::new(TuiProgress {
            buf: std::sync::Arc::clone(&self.buf),
            line,
            title: std::sync::Mutex::new(prefix.to_string()),
            kind: progress_type,
            len: AtomicU64::new(0),
            pos: AtomicU64::new(0),
            started: std::time::Instant::now(),
            last_render_ms: AtomicU64::new(0),
        })
    }
}

/// One phase's progress line. `inc` can fire per blob during a repack, so
/// re-rendering is throttled to ~10 Hz — the TUI polls the buffer at a
/// similar rate anyway.
#[derive(Debug)]
struct TuiProgress {
    buf: std::sync::Arc<std::sync::Mutex<String>>,
    line: usize,
    title: std::sync::Mutex<String>,
    kind: ProgressType,
    len: AtomicU64,
    pos: AtomicU64,
    started: std::time::Instant,
    last_render_ms: AtomicU64,
}

impl TuiProgress {
    fn render(&self, finished: bool) {
        use std::sync::PoisonError;
        let title = self
            .title
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let pos = self.pos.load(Ordering::Relaxed);
        let len = self.len.load(Ordering::Relaxed);
        let text = match self.kind {
            ProgressType::Spinner => {
                if finished {
                    format!("{title} done")
                } else {
                    format!("{title}…")
                }
            }
            ProgressType::Counter => {
                if len > 0 {
                    format!("{title} {pos}/{len}")
                } else {
                    format!("{title} {pos}")
                }
            }
            ProgressType::Bytes => {
                if len > 0 {
                    format!("{title} {} / {}", human_bytes(pos), human_bytes(len))
                } else {
                    format!("{title} {}", human_bytes(pos))
                }
            }
        };
        let mut buf = self.buf.lock().unwrap_or_else(PoisonError::into_inner);
        let mut lines: Vec<String> = buf.lines().map(str::to_string).collect();
        if let Some(slot) = lines.get_mut(self.line) {
            *slot = text;
            *buf = lines.join("\n");
        }
    }
}

impl RusticProgress for TuiProgress {
    fn is_hidden(&self) -> bool {
        false
    }

    fn set_length(&self, len: u64) {
        self.len.store(len, Ordering::Relaxed);
        self.render(false);
    }

    fn set_title(&self, title: &str) {
        use std::sync::PoisonError;
        *self.title.lock().unwrap_or_else(PoisonError::into_inner) = title.to_string();
        self.render(false);
    }

    fn inc(&self, inc: u64) {
        self.pos.fetch_add(inc, Ordering::Relaxed);
        let now = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let last = self.last_render_ms.load(Ordering::Relaxed);
        if now.saturating_sub(last) >= 100
            && self
                .last_render_ms
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.render(false);
        }
    }

    fn finish(&self) {
        self.render(true);
    }
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

    // End-to-end interop with the restic CLI against a fresh local repo:
    // restic must see (and be blocked by) wrustic's native lock, `restic
    // unlock` must not remove it while fresh, and the native delete must
    // work. restic CLI is used only for repo setup (init/backup — dev-flow
    // write ops) and for observing lock behavior from restic's side.
    // Marked #[ignore]; run with `cargo test -- --ignored` (needs restic on
    // PATH).
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

        let snapshots = load_snapshots(&profile).expect("list snapshots");
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
        assert!(load_snapshots(&profile).expect("list after delete").is_empty());
        let restic_list = crate::restic::run(&profile, &["snapshots", "--json"])
            .expect("restic snapshots");
        let listed: serde_json::Value =
            serde_json::from_slice(&restic_list).expect("restic snapshots json");
        assert_eq!(listed, serde_json::json!([]));

        std::fs::remove_dir_all(&root).ok();
    }

    // End-to-end interop for the native prune. restic sets up the repo
    // (dev-flow writes through the harness), wrustic deletes a snapshot and
    // prunes natively, and restic must afterwards consider the repository
    // pristine: `restic check --read-data` passes with no errors and no
    // orphaned packs (instant delete leaves neither garbage packs nor
    // rustic's `packs_to_delete` bookkeeping behind), the surviving
    // snapshot restores intact, and a follow-up `restic prune` runs clean.
    // Marked #[ignore]; run with `cargo test -- --ignored` (needs restic on
    // PATH).
    #[test]
    #[ignore]
    fn live_native_prune_interop_with_restic() {
        // Acquires RepoLocks — serialize with other acquiring tests (SIGHUP
        // disposition is process-global).
        let _guard = lock::test_acquire_guard();

        let root = std::path::PathBuf::from("tmp")
            .join(format!("prune-it-{}", std::process::id()));
        let repo_path = root.join("repo");
        let source = root.join("source");
        std::fs::create_dir_all(&source).unwrap();
        // Two files that land in the same data pack: after the first
        // snapshot is deleted, that pack is partly used, so the prune must
        // *repack* (rewrite keep.txt's blob, drop drop.txt's) rather than
        // just delete whole packs — exercising the riskiest prune path.
        let keep_content = vec![b'k'; 300_000];
        std::fs::write(source.join("keep.txt"), &keep_content).unwrap();
        std::fs::write(source.join("drop.txt"), vec![b'd'; 300_000]).unwrap();

        let profile = Profile::Local {
            password: "pw".into(),
            local_path: repo_path.to_string_lossy().into_owned(),
        };
        crate::restic::run(&profile, &["init", "--json"]).expect("restic init");
        crate::restic::run(&profile, &["backup", source.to_str().unwrap(), "--json"])
            .expect("restic backup 1");
        std::fs::remove_file(source.join("drop.txt")).unwrap();
        crate::restic::run(&profile, &["backup", source.to_str().unwrap(), "--json"])
            .expect("restic backup 2");

        let snapshots = load_snapshots(&profile).expect("list snapshots");
        assert_eq!(snapshots.len(), 2);
        // Newest first — delete the older snapshot, the only holder of
        // drop.txt.
        let victim = snapshots[1].id.clone();
        delete_snapshot(&profile, &victim).expect("native delete");

        // A concurrent holder (here a shared lock, as a running backup would
        // take) must block the exclusive prune with a lock error.
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
            let progress = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
            let err = prune(&profile, progress).expect_err("prune must be blocked");
            assert!(
                lock::is_lock_error(&format!("{err:#}")),
                "expected a lock error, got: {err:#}"
            );
            drop(live);
        }

        // The native prune under the exclusive lock.
        let progress = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let report = prune(&profile, progress.clone()).expect("native prune");
        assert!(report.contains("total space reclaimed"), "{report}");
        assert!(
            !progress.lock().unwrap().is_empty(),
            "the prune must have reported progress"
        );

        // The lock must be gone the moment the prune returns.
        let locks = std::fs::read_dir(repo_path.join("locks"))
            .map(|d| d.count())
            .unwrap_or(0);
        assert_eq!(locks, 0, "the prune must not leave a lock behind");

        // restic's verdict. `check --read-data` re-reads every pack and
        // validates it against the index; instant delete must leave no
        // orphaned ("additional") files either.
        let check = crate::restic::run(&profile, &["check", "--read-data"])
            .expect("restic check after native prune");
        let check_text = String::from_utf8_lossy(&check);
        assert!(
            check_text.contains("no errors were found"),
            "restic check must pass: {check_text}"
        );
        assert!(
            !check_text.contains("additional files were found"),
            "instant delete must leave no orphaned packs: {check_text}"
        );

        // The surviving snapshot must restore intact through restic.
        let restore_dir = root.join("restore");
        crate::restic::run(
            &profile,
            &["restore", "latest", "--target", restore_dir.to_str().unwrap(), "--json"],
        )
        .expect("restic restore after native prune");
        let mut restored = Vec::new();
        collect_files(&restore_dir, &mut restored);
        let keep = restored
            .iter()
            .find(|p| p.file_name().is_some_and(|n| n == "keep.txt"))
            .expect("keep.txt restored");
        assert_eq!(std::fs::read(keep).expect("read keep.txt"), keep_content);
        assert!(
            !restored.iter().any(|p| p.file_name().is_some_and(|n| n == "drop.txt")),
            "drop.txt only existed in the deleted snapshot"
        );

        // And restic's own prune must run clean on the repository state the
        // native prune left.
        crate::restic::run(&profile, &["prune", "--json"])
            .expect("restic prune after native prune");

        std::fs::remove_dir_all(&root).ok();
    }

    // Recursive file listing for the restore assertion — restic recreates
    // the snapshot's absolute directory structure under the target.
    fn collect_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_files(&path, out);
            } else {
                out.push(path);
            }
        }
    }

    #[test]
    #[ignore]
    fn live_garage_s3_profile_reads_seeded_repository() {
        let endpoint = std::env::var("WRUSTIC_GARAGE_ENDPOINT")
            .unwrap_or_else(|_| "http://127.0.0.1:3900".into());
        let profile = Profile::S3 {
            password: "garage-repository-password".into(),
            s3_endpoint: endpoint,
            s3_bucket: "wrustic-it".into(),
            s3_region: "garage".into(),
            s3_root: "repository".into(),
            s3_access_key: "GK22222222222222222222222222222222".into(),
            s3_secret_key:
                "3333333333333333333333333333333333333333333333333333333333333333".into(),
        };

        verify_profile(&profile).expect("verify Garage profile");
        let snapshots = load_snapshots(&profile).expect("list Garage snapshots");
        let snapshot = snapshots.first().expect("seeded Garage snapshot");
        let previous = snapshots.get(1).expect("second seeded Garage snapshot");
        assert!(snapshot.tags.iter().any(|tag| tag == "garage-e2e-second"));

        let repo = open_indexed(&profile).expect("open Garage repository");
        let (summary, changes) =
            diff_snapshots(&repo, &previous.id, &snapshot.id).expect("diff Garage snapshots");
        assert!(summary.changed_files > 0);
        assert!(changes.iter().any(|change| change.path.ends_with("/hello.txt")));
        assert!(changes.iter().any(|change| change.path.ends_with("/second.txt")));

        let preview =
            preview_snapshot_contents(&repo, &snapshot.id, 100).expect("preview Garage tree");
        let hello = preview
            .entries
            .iter()
            .find(|entry| entry.path.ends_with("/hello.txt"))
            .expect("hello.txt in Garage snapshot");

        let full_repo = open_indexed_full(&profile).expect("open full Garage repository");
        let mut parent_tree =
            snapshot_root_tree(&repo, &snapshot.id).expect("Garage snapshot root tree");
        let mut components = hello.path.trim_start_matches('/').split('/').peekable();
        let file_name = loop {
            let component = components.next().expect("hello.txt path component");
            if components.peek().is_none() {
                break component.to_string();
            }
            let tree = full_repo
                .get_tree(&parent_tree)
                .expect("read Garage directory tree");
            parent_tree = tree
                .nodes
                .into_iter()
                .find(|node| node.name().to_string_lossy() == component)
                .and_then(|node| node.subtree)
                .expect("Garage directory subtree");
        };

        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let dump = std::thread::spawn(move || {
            stream_file_content(&full_repo, parent_tree, &file_name, &tx)
        });
        let mut bytes = Vec::new();
        while let Some(chunk) = rx.blocking_recv() {
            bytes.extend_from_slice(&chunk.expect("Garage file chunk"));
        }
        dump.join()
            .expect("Garage dump thread")
            .expect("stream Garage hello.txt");
        assert_eq!(bytes, b"hello from Garage S3 integration, revision 2\n");
    }
}
