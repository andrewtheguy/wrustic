use std::io::{self, Write};
use std::mem;

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use rustic_backend::BackendOptions;
use rustic_core::repofile::{Node, NodeType};
use rustic_core::{
    Credentials, IndexedFull, IndexedFullStatus, IndexedIdsStatus, Repository, RepositoryOptions,
    RepositoryBackends, TreeId,
};
use tokio::sync::mpsc;

use crate::config::Profile;
use crate::s3_backend::S3ReadOnlyBackend;

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
    pub(crate) tree: String,
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
            return Ok(S3ReadOnlyBackend::new(
                s3_endpoint,
                s3_bucket,
                s3_region,
                s3_root,
                s3_access_key,
                s3_secret_key,
            )?
            .into());
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
    Ok(DeleteSnapshotInfo {
        hostname: snap.hostname.clone(),
        paths: snap.paths.iter().cloned().collect(),
        tags: snap.tags.iter().cloned().collect(),
        tree: snap.tree.to_hex().as_str().to_string(),
    })
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
