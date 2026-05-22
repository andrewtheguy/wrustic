use std::collections::BTreeMap;
use std::io::{self, Write};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use rustic_backend::BackendOptions;
use rustic_core::repofile::NodeType;
use rustic_core::{
    Credentials, IndexedFull, IndexedFullStatus, IndexedIdsStatus, Repository, RepositoryOptions,
    TreeId,
};
use tokio::sync::mpsc;

use crate::config::Profile;

pub(crate) struct SnapshotRow {
    pub(crate) id: String,
    pub(crate) time: String,
    pub(crate) host: String,
    pub(crate) tags: Vec<String>,
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
    pub(crate) limit: usize,
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

fn build_backend_opts(profile: &Profile) -> Result<BackendOptions> {
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
            opts = opts.repository("opendal:s3:");
            let mut s3_opts = BTreeMap::new();
            s3_opts.insert("bucket".to_string(), s3_bucket.clone());
            s3_opts.insert("region".to_string(), s3_region.clone());
            s3_opts.insert("access_key_id".to_string(), s3_access_key.clone());
            s3_opts.insert("secret_access_key".to_string(), s3_secret_key.clone());
            if !s3_endpoint.is_empty() {
                s3_opts.insert("endpoint".to_string(), s3_endpoint.clone());
            }
            if !s3_root.is_empty() {
                s3_opts.insert("root".to_string(), s3_root.clone());
            }
            opts = opts.options(s3_opts);
        }
    }
    Ok(opts)
}

pub(crate) fn verify_profile(profile: &Profile) -> Result<()> {
    let backends = build_backend_opts(profile)?.to_backends()?;
    Repository::new(&RepositoryOptions::default(), &backends)?
        .open(&Credentials::password(profile.password()))?;
    Ok(())
}

pub(crate) fn load_snapshots(profile: &Profile) -> Result<Vec<SnapshotRow>> {
    let backends = build_backend_opts(profile)?.to_backends()?;
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
            paths: s.paths.iter().cloned().collect(),
        })
        .collect())
}

pub(crate) fn open_indexed(profile: &Profile) -> Result<Repository<IndexedIdsStatus>> {
    let backends = build_backend_opts(profile)?.to_backends()?;
    let repo = Repository::new(&RepositoryOptions::default(), &backends)?
        .open(&Credentials::password(profile.password()))?
        .to_indexed_ids()?;
    Ok(repo)
}

// Like open_indexed, but with the full blob index + cache so that file content
// can be read (Repository::dump). Used by the share-URL server, which needs
// to stream file contents rather than just metadata.
pub(crate) fn open_indexed_full(profile: &Profile) -> Result<Repository<IndexedFullStatus>> {
    let backends = build_backend_opts(profile)?.to_backends()?;
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
    Ok(ContentsPreview { entries, truncated, limit })
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
