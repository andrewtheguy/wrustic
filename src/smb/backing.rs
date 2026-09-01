// The seam between the SMB wire code and the repository.
//
// The protocol layer deals in `NodeInfo` and byte ranges; it never sees a
// `Repository`, a `Vfs` or a rustic error. That is not architectural politeness
// — the info-class encoders below are byte-exact structures whose correctness
// has to be pinned by tests, and requiring a real restic repository to test them
// would mean they never got tested properly.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use bytes::Bytes;
use rustic_core::repofile::Node;
use rustic_core::vfs::OpenFile;
use rustic_core::{IndexedFullStatus, Repository, TreeId};

use smbanything_core::smb::{Backing, FileReader, NodeInfo, NodeKind, SmbPath, status};
use smbanything_core::smb_log;

fn to_system_time(ts: Option<rustic_core::jiff::Timestamp>) -> Option<SystemTime> {
    let ts = ts?;
    let secs = ts.as_second();
    let nanos = ts.subsec_nanosecond();
    // Timestamps before the Unix epoch are legal in a repository but have no
    // useful SMB representation; drop them rather than wrapping into the future.
    if secs < 0 {
        return None;
    }
    let nanos = u32::try_from(nanos.max(0)).unwrap_or(0);
    // `checked_add` rather than `+`: SystemTime's Add panics on overflow, and a
    // timestamp the platform cannot represent is a reason to fall back to the
    // server's start time, not to take down a response mid-listing.
    UNIX_EPOCH.checked_add(Duration::new(secs as u64, nanos))
}

/// A name that SMB2 can carry.
///
/// SMB2 filenames are UTF-16 with no path separators: a directory entry whose
/// name contains one makes the Windows redirector throw away the entire
/// response, so a single such file would hide every other file in its
/// directory. macOS allows a backslash in a filename, so this is reachable with
/// nothing more exotic than an oddly named download. The character is replaced
/// rather than the entry dropped — a file that cannot be opened through the
/// share is still worth knowing about — and the substitution means the name no
/// longer maps back to the repository, so opening it answers "no such file".
fn wire_safe(name: String) -> String {
    if !name.contains(['\\', '/', '\0']) {
        return name;
    }
    let safe: String = name
        .chars()
        .map(|c| if matches!(c, '\\' | '/' | '\0') { '\u{fffd}' } else { c })
        .collect();
    smb_log!("listing {name:?} as {safe:?}: SMB filenames cannot hold a separator");
    safe
}

fn node_info(node: &Node, now: SystemTime) -> NodeInfo {
    let kind = if node.is_dir() {
        NodeKind::Dir
    } else {
        NodeKind::File
    };
    NodeInfo {
        // `node.name` is the raw stored spelling, which restic writes quoted;
        // `Node::name()` would decode it on Unix and not on Windows, so the
        // decoding is done here instead — see `super::name`.
        name: wire_safe(super::name::from_repo(&node.name)),
        kind,
        // Directories report zero: restic stores the source filesystem's
        // directory size, which is meaningless to a client and makes some of
        // them try to read it.
        size: if kind.is_dir() { 0 } else { node.meta.size },
        mtime: to_system_time(node.meta.mtime).unwrap_or(now),
        atime: to_system_time(node.meta.atime).unwrap_or(now),
        ctime: to_system_time(node.meta.ctime).unwrap_or(now),
    }
}

/// Serves one snapshot out of a restic repository.
///
/// Paths are resolved by walking trees rather than through `rustic_core::vfs`,
/// whose entry points take a `Path` and split it with `Path::components`. A
/// repository name is stored quoted (see `super::name`), the quoted form of an
/// ordinary macOS filename contains a backslash, and on Windows a backslash
/// *is* a path separator — so a name like that can never be expressed as a
/// `Path` component, and every file with one would be unreachable.
pub(crate) struct SnapshotBacking {
    repo: Arc<Repository<IndexedFullStatus>>,
    root: TreeId,
    label: String,
    total_size: u64,
    /// Captured once, so every node missing a timestamp reports the same one.
    now: SystemTime,
}

impl SnapshotBacking {
    /// Build a backing for the tree rooted at `tree_id`.
    ///
    /// `total_size` is the snapshot's size in bytes, reported as the volume
    /// size. Pass restic's own recorded figure where available: summing the
    /// tree here would mean either a full recursive walk at mount time, or the
    /// top level only — and the latter reports 4 KiB for a snapshot whose whole
    /// content sits one directory down.
    pub(crate) fn new(
        repo: Arc<Repository<IndexedFullStatus>>,
        tree_id: rustic_core::TreeId,
        label: impl Into<String>,
        total_size: Option<u64>,
    ) -> Result<Self> {
        let total_size = match total_size {
            Some(n) => n,
            // No summary recorded (older snapshots have none): fall back to the
            // top level, which at least reads the root and confirms the tree is
            // there before a client ever connects.
            //
            // Files only, and only at this level. Nested content is not counted,
            // so this under-reports whenever the snapshot has depth. Directory
            // entries are skipped because restic records the *source*
            // filesystem's directory size, typically 4 KiB of nothing — and
            // `node_info` already reports zero for them, so counting them here
            // would make the volume total disagree with the listing a client can
            // add up itself.
            None => nodes_in(&repo, &tree_id)
                .map_err(|e| anyhow!("reading snapshot root: {e}"))?
                .iter()
                .filter(|n: &&Node| !n.is_dir())
                .map(|n| n.meta.size)
                // Saturating rather than `sum`, which panics on overflow in a
                // debug build: the sizes come out of the repository.
                .fold(0u64, u64::saturating_add),
        };

        Ok(Self {
            repo,
            root: tree_id,
            label: label.into(),
            total_size,
            now: SystemTime::now(),
        })
    }

    /// Resolve a client path to its node, one tree at a time.
    ///
    /// Each component is matched against the name the repository stores, which
    /// is the quoted one — and, failing that, against the component as the
    /// client sent it. The second comparison is not a guess: a repository
    /// written by rustic on Windows stores names *un*quoted (its
    /// `escape_filename` is the identity there), so both spellings occur in the
    /// wild, and neither can be told from the other without looking.
    ///
    /// The root has no node of its own; callers handle it before getting here.
    fn lookup(&self, path: &SmbPath) -> Result<Node, String> {
        let mut tree = self.root;
        let mut found: Option<Node> = None;
        for component in path.components() {
            if let Some(parent) = &found {
                tree = parent
                    .subtree
                    .ok_or_else(|| format!("{:?} is not a directory", parent.name))?;
            }
            let stored = super::name::to_repo(component);
            found = Some(
                nodes_in(&self.repo, &tree)?
                    .into_iter()
                    .find(|n| n.name == stored || n.name == *component)
                    .ok_or_else(|| format!("no entry named {stored:?}"))?,
            );
        }
        found.ok_or_else(|| "the share root has no node".to_string())
    }

    /// The children of the directory a path names.
    ///
    /// The status rides along with the reason because the two failures are
    /// different answers: a path that is not there, and a path that is there
    /// and is a file. `MemBacking` has always drawn that line, and a real
    /// backing that blurred it would make the in-memory one a poor stand-in.
    fn entries(&self, path: &SmbPath) -> Result<Vec<Node>, (u32, String)> {
        let tree = if path.is_root() {
            self.root
        } else {
            let node = self
                .lookup(path)
                .map_err(|e| (status::OBJECT_PATH_NOT_FOUND, e))?;
            node.subtree.ok_or_else(|| {
                (
                    status::NOT_A_DIRECTORY,
                    format!("{:?} is not a directory", node.name),
                )
            })?
        };
        nodes_in(&self.repo, &tree).map_err(|e| (status::OBJECT_PATH_NOT_FOUND, e))
    }
}

fn nodes_in(
    repo: &Repository<IndexedFullStatus>,
    tree: &TreeId,
) -> Result<Vec<Node>, String> {
    repo.get_tree(tree)
        .map(|t| t.nodes)
        .map_err(|e| e.to_string())
}

impl Backing for SnapshotBacking {
    fn stat(&self, path: &SmbPath) -> Result<NodeInfo, u32> {
        if path.is_root() {
            return Ok(NodeInfo::synthetic_dir("", self.now));
        }
        // rustic reports "no such path" and "path is not valid here" through the
        // same error kind, so both become OBJECT_NAME_NOT_FOUND. That is the
        // status a client can act on, and the distinction would not change what
        // it does next.
        //
        // A backend failure lands here too, though — a cold pack, an S3 hiccup,
        // a read that timed out — and it is *not* the same thing: the client
        // shows "no such folder" for something that exists and will work on the
        // next attempt. The status stays as it is, since nothing a client does
        // differs, but the reason is traced so an intermittent one is
        // recognisable as an intermittent one.
        let node = self.lookup(path).map_err(|e| {
            smb_log!("stat {:?} failed: {e}", path.to_smb_absolute());
            status::OBJECT_NAME_NOT_FOUND
        })?;
        Ok(node_info(&node, self.now))
    }

    fn list(&self, path: &SmbPath) -> Result<Vec<NodeInfo>, u32> {
        let entries = self.entries(path).map_err(|(status, e)| {
            smb_log!("list {:?} failed: {e}", path.to_smb_absolute());
            status
        })?;
        Ok(entries.iter().map(|n| node_info(n, self.now)).collect())
    }

    fn open(&self, path: &SmbPath) -> Result<Arc<dyn FileReader>, u32> {
        let node = self.lookup(path).map_err(|e| {
            smb_log!("open {:?} failed: {e}", path.to_smb_absolute());
            status::OBJECT_NAME_NOT_FOUND
        })?;
        if node.is_dir() {
            return Err(status::FILE_IS_A_DIRECTORY);
        }
        let open_file = self.repo.open_file(&node).map_err(|e| {
            smb_log!("open_file {:?} failed: {e}", path.to_smb_absolute());
            status::OBJECT_NAME_NOT_FOUND
        })?;
        Ok(Arc::new(SnapshotFile {
            repo: self.repo.clone(),
            open_file,
            size: node.meta.size,
        }))
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn total_size(&self) -> u64 {
        self.total_size
    }
}

/// Wraps a backing so its whole tree appears one level down, inside a single
/// synthetic top-level directory.
///
/// A snapshot share nests under the snapshot's short id (restic's standard
/// 8-hex-char form, so the name pastes straight into restic commands): the
/// share name and mount commands stay fixed (`\\127.0.0.1\snap`, fstab-safe),
/// while the mount's contents — and anything copied out of it, or several
/// snapshots mounted side by side — say which snapshot they came from.
pub(crate) struct NestedBacking<B> {
    inner: B,
    /// Name of the single top-level directory.
    dir: String,
    /// Timestamp reported for the two synthetic directories (the root and
    /// `dir`), mirroring what `SnapshotBacking` does for its own root.
    now: SystemTime,
}

/// Where a client path lands relative to the synthetic directory.
enum Route {
    Root,
    Dir,
    Inner(SmbPath),
    Missing,
}

impl<B: Backing> NestedBacking<B> {
    pub(crate) fn new(inner: B, dir: impl Into<String>) -> Self {
        Self {
            inner,
            dir: dir.into(),
            now: SystemTime::now(),
        }
    }

    // The directory name is matched case-insensitively: SMB names are
    // case-preserving but not case-sensitive, and a Windows client may upcase
    // a typed path. The inner tree keeps the repository's own (case-sensitive)
    // semantics — only the synthetic level is ours to define.
    fn route(&self, path: &SmbPath) -> Route {
        match path.split_first() {
            None => Route::Root,
            Some((first, rest)) if first.eq_ignore_ascii_case(&self.dir) => {
                if rest.is_root() {
                    Route::Dir
                } else {
                    Route::Inner(rest)
                }
            }
            Some(_) => Route::Missing,
        }
    }
}

impl<B: Backing> Backing for NestedBacking<B> {
    fn stat(&self, path: &SmbPath) -> Result<NodeInfo, u32> {
        match self.route(path) {
            Route::Root => Ok(NodeInfo::synthetic_dir("", self.now)),
            Route::Dir => Ok(NodeInfo::synthetic_dir(&self.dir, self.now)),
            Route::Inner(rest) => self.inner.stat(&rest),
            Route::Missing => Err(status::OBJECT_NAME_NOT_FOUND),
        }
    }

    fn list(&self, path: &SmbPath) -> Result<Vec<NodeInfo>, u32> {
        match self.route(path) {
            Route::Root => Ok(vec![NodeInfo::synthetic_dir(&self.dir, self.now)]),
            Route::Dir => self.inner.list(&SmbPath::default()),
            Route::Inner(rest) => self.inner.list(&rest),
            Route::Missing => Err(status::OBJECT_PATH_NOT_FOUND),
        }
    }

    fn open(&self, path: &SmbPath) -> Result<Arc<dyn FileReader>, u32> {
        match self.route(path) {
            Route::Root | Route::Dir => Err(status::FILE_IS_A_DIRECTORY),
            Route::Inner(rest) => self.inner.open(&rest),
            Route::Missing => Err(status::OBJECT_NAME_NOT_FOUND),
        }
    }

    fn label(&self) -> &str {
        self.inner.label()
    }

    fn total_size(&self) -> u64 {
        self.inner.total_size()
    }
}

struct SnapshotFile {
    repo: Arc<Repository<IndexedFullStatus>>,
    open_file: OpenFile,
    size: u64,
}

impl FileReader for SnapshotFile {
    fn read_at(&self, offset: u64, len: u32) -> Result<Bytes, u32> {
        if offset >= self.size {
            return Ok(Bytes::new());
        }
        // Clamp before the cast: on a 32-bit target a large offset would
        // otherwise truncate and read the wrong part of the file.
        let offset = usize::try_from(offset).map_err(|_| status::INVALID_PARAMETER)?;
        let available = self.size - offset as u64;
        let len = u64::from(len).min(available);
        let len = usize::try_from(len).map_err(|_| status::INVALID_PARAMETER)?;

        self.repo
            .read_file_at(&self.open_file, offset, len)
            // A failure here is a backend read, not a bad request: the blob is
            // missing, or the remote is unreachable.
            .map_err(|_| status::UNEXPECTED_IO_ERROR)
    }
}

// Also built for the tun harness, which serves this tree rather than standing
// up a repository so a mount can be timed against a known shape. That harness
// is the only non-test user, hence the same narrow gate it carries.
#[cfg(any(
    test,
    all(windows, feature = "dev-harness", feature = "smb-tun")
))]
pub(crate) mod test_support {
    //! An in-memory backing, so the wire encoders can be tested against a known
    //! tree without standing up a repository.

    use std::collections::BTreeMap;

    use super::*;

    #[derive(Default)]
    pub(crate) struct MemBacking {
        /// Keyed by SMB path string; the root is the empty string.
        entries: BTreeMap<String, (NodeInfo, Vec<u8>)>,
    }

    impl MemBacking {
        pub(crate) fn new() -> Self {
            let mut b = Self::default();
            b.entries.insert(
                String::new(),
                (NodeInfo::synthetic_dir("", UNIX_EPOCH), Vec::new()),
            );
            b
        }

        pub(crate) fn with_dir(mut self, path: &str) -> Self {
            let name = path.rsplit('\\').next().unwrap_or(path).to_string();
            self.entries.insert(
                path.to_string(),
                (
                    NodeInfo {
                        name,
                        kind: NodeKind::Dir,
                        size: 0,
                        mtime: UNIX_EPOCH + Duration::from_secs(1_600_000_000),
                        atime: UNIX_EPOCH + Duration::from_secs(1_600_000_001),
                        ctime: UNIX_EPOCH + Duration::from_secs(1_600_000_002),
                    },
                    Vec::new(),
                ),
            );
            self
        }

        pub(crate) fn with_file(mut self, path: &str, content: &[u8]) -> Self {
            let name = path.rsplit('\\').next().unwrap_or(path).to_string();
            self.entries.insert(
                path.to_string(),
                (
                    NodeInfo {
                        name,
                        kind: NodeKind::File,
                        size: content.len() as u64,
                        mtime: UNIX_EPOCH + Duration::from_secs(1_600_000_000),
                        atime: UNIX_EPOCH + Duration::from_secs(1_600_000_001),
                        ctime: UNIX_EPOCH + Duration::from_secs(1_600_000_002),
                    },
                    content.to_vec(),
                ),
            );
            self
        }
    }

    impl Backing for MemBacking {
        fn stat(&self, path: &SmbPath) -> Result<NodeInfo, u32> {
            self.entries
                .get(&path.to_smb_string())
                .map(|(info, _)| info.clone())
                .ok_or(status::OBJECT_NAME_NOT_FOUND)
        }

        fn list(&self, path: &SmbPath) -> Result<Vec<NodeInfo>, u32> {
            let prefix = path.to_smb_string();
            let (info, _) = self
                .entries
                .get(&prefix)
                .ok_or(status::OBJECT_PATH_NOT_FOUND)?;
            if !info.kind.is_dir() {
                return Err(status::NOT_A_DIRECTORY);
            }
            let scope = if prefix.is_empty() {
                String::new()
            } else {
                format!("{prefix}\\")
            };
            Ok(self
                .entries
                .iter()
                .filter(|(k, _)| {
                    !k.is_empty()
                        && k.starts_with(&scope)
                        && !k[scope.len()..].contains('\\')
                })
                .map(|(_, (info, _))| info.clone())
                .collect())
        }

        fn open(&self, path: &SmbPath) -> Result<Arc<dyn FileReader>, u32> {
            let (info, content) = self
                .entries
                .get(&path.to_smb_string())
                .ok_or(status::OBJECT_NAME_NOT_FOUND)?;
            if info.kind.is_dir() {
                return Err(status::FILE_IS_A_DIRECTORY);
            }
            Ok(Arc::new(MemFile {
                content: content.clone(),
            }))
        }

        fn label(&self) -> &str {
            "test"
        }

        fn total_size(&self) -> u64 {
            self.entries.values().map(|(i, _)| i.size).sum()
        }
    }

    struct MemFile {
        content: Vec<u8>,
    }

    impl FileReader for MemFile {
        fn read_at(&self, offset: u64, len: u32) -> Result<Bytes, u32> {
            // An offset that does not fit a usize is past the end of anything
            // held in memory, so it reads empty — same answer `SnapshotFile`
            // gives for a read at or past EOF, reached before it casts.
            let Ok(offset) = usize::try_from(offset) else {
                return Ok(Bytes::new());
            };
            if offset >= self.content.len() {
                return Ok(Bytes::new());
            }
            // Saturating: `offset + len` is two client-supplied numbers and can
            // exceed usize on a 32-bit target.
            let end = offset.saturating_add(len as usize).min(self.content.len());
            Ok(Bytes::copy_from_slice(&self.content[offset..end]))
        }
    }
}

#[cfg(test)]
mod tests {
    use rustic_core::repofile::{Metadata, NodeType};

    use super::test_support::MemBacking;
    use super::*;

    fn p(s: &str) -> SmbPath {
        SmbPath::parse(s).expect("test path parses")
    }

    /// A node holding a name exactly as a repository stores it.
    fn stored_node(name: &str) -> Node {
        Node::new(
            name.to_string(),
            NodeType::File,
            Metadata::default(),
            None,
            None,
        )
    }

    #[test]
    fn node_info_decodes_the_name_the_repository_stores() {
        // What restic writes for a file named with an EN SPACE.
        let node = stored_node(&format!("No.{}03-1532.pdf", "\\u2002"));
        assert_eq!(
            node_info(&node, UNIX_EPOCH).name,
            "No.\u{2002}03-1532.pdf",
            "the quoted form must never reach a client"
        );
        // A name with nothing to decode is untouched.
        assert_eq!(node_info(&stored_node("plain.pdf"), UNIX_EPOCH).name, "plain.pdf");
    }

    #[test]
    fn node_info_replaces_separators_the_wire_cannot_carry() {
        // A real backslash in a macOS filename: stored doubled, decoded back to
        // one, and then not sendable — a listing carrying it would be discarded
        // whole by the client, taking every sibling with it.
        let node = stored_node(r"od\\d");
        assert_eq!(node_info(&node, UNIX_EPOCH).name, "od\u{fffd}d");
    }

    #[test]
    fn wire_safe_only_touches_separators() {
        assert_eq!(wire_safe("ordinary name.txt".into()), "ordinary name.txt");
        assert_eq!(wire_safe("\u{5f71}\u{97f3}.pdf".into()), "\u{5f71}\u{97f3}.pdf");
        // Characters Windows dislikes in a path are still fine in a listing.
        assert_eq!(wire_safe("a:b*c?.txt".into()), "a:b*c?.txt");
        assert_eq!(wire_safe("a\\b/c\0d".into()), "a\u{fffd}b\u{fffd}c\u{fffd}d");
    }

    #[test]
    fn mem_backing_lists_only_direct_children() {
        let b = MemBacking::new()
            .with_dir("dir")
            .with_file("dir\\a.txt", b"aaa")
            .with_file("dir\\b.txt", b"bb")
            .with_dir("dir\\sub")
            .with_file("dir\\sub\\deep.txt", b"d")
            .with_file("top.txt", b"t");

        let mut root: Vec<_> = b.list(&p("")).unwrap().into_iter().map(|n| n.name).collect();
        root.sort();
        assert_eq!(root, vec!["dir", "top.txt"]);

        let mut inner: Vec<_> = b
            .list(&p("dir"))
            .unwrap()
            .into_iter()
            .map(|n| n.name)
            .collect();
        inner.sort();
        assert_eq!(inner, vec!["a.txt", "b.txt", "sub"]);
    }

    #[test]
    fn stat_reports_kind_and_size() {
        let b = MemBacking::new().with_dir("d").with_file("f", b"hello");
        assert_eq!(b.stat(&p("f")).unwrap().kind, NodeKind::File);
        assert_eq!(b.stat(&p("f")).unwrap().size, 5);
        assert_eq!(b.stat(&p("d")).unwrap().kind, NodeKind::Dir);
        assert!(b.stat(&p("")).unwrap().kind.is_dir(), "root is a directory");
        assert_eq!(
            b.stat(&p("missing")).unwrap_err(),
            status::OBJECT_NAME_NOT_FOUND
        );
    }

    #[test]
    fn opening_a_directory_is_refused() {
        let b = MemBacking::new().with_dir("d");
        // `.err()` rather than `.unwrap_err()`: the Ok type is a trait object
        // and deliberately not Debug.
        assert_eq!(b.open(&p("d")).err(), Some(status::FILE_IS_A_DIRECTORY));
    }

    #[test]
    fn reads_clamp_at_end_of_file() {
        let b = MemBacking::new().with_file("f", b"0123456789");
        let f = b.open(&p("f")).unwrap();
        assert_eq!(&f.read_at(0, 4).unwrap()[..], b"0123");
        assert_eq!(&f.read_at(6, 100).unwrap()[..], b"6789");
        assert!(f.read_at(10, 4).unwrap().is_empty(), "read at EOF is empty");
        assert!(f.read_at(999, 4).unwrap().is_empty(), "read past EOF");
    }

    #[test]
    fn listing_a_file_is_refused() {
        let b = MemBacking::new().with_file("f", b"x");
        assert_eq!(b.list(&p("f")).unwrap_err(), status::NOT_A_DIRECTORY);
    }

    #[test]
    fn nested_backing_puts_the_tree_one_level_down() {
        let b = NestedBacking::new(
            MemBacking::new()
                .with_dir("docs")
                .with_file("docs\\a.txt", b"aaa")
                .with_file("top.txt", b"t"),
            "1a2b3c4d",
        );

        // The share root holds exactly the one synthetic directory.
        let root = b.list(&p("")).unwrap();
        assert_eq!(root.len(), 1);
        assert_eq!(root[0].name, "1a2b3c4d");
        assert!(root[0].kind.is_dir());
        assert!(b.stat(&p("")).unwrap().kind.is_dir());
        assert!(b.stat(&p("1a2b3c4d")).unwrap().kind.is_dir());

        // Inside it: the inner backing's root, at its usual paths.
        let mut names: Vec<_> = b
            .list(&p("1a2b3c4d"))
            .unwrap()
            .into_iter()
            .map(|n| n.name)
            .collect();
        names.sort();
        assert_eq!(names, vec!["docs", "top.txt"]);
        assert_eq!(b.stat(&p("1a2b3c4d\\top.txt")).unwrap().size, 1);
        let f = b.open(&p("1a2b3c4d\\docs\\a.txt")).unwrap();
        assert_eq!(&f.read_at(0, 10).unwrap()[..], b"aaa");
    }

    #[test]
    fn nested_backing_matches_its_directory_case_insensitively() {
        // SMB names are case-preserving, not case-sensitive; Windows may
        // upcase a typed path, and the synthetic level must still resolve.
        let b = NestedBacking::new(MemBacking::new().with_file("f", b"x"), "1a2b3c4d");
        assert!(b.stat(&p("1A2B3C4D")).unwrap().kind.is_dir());
        assert_eq!(b.stat(&p("1A2B3C4D\\f")).unwrap().size, 1);
    }

    #[test]
    fn nested_backing_refuses_paths_outside_its_directory() {
        let b = NestedBacking::new(MemBacking::new().with_file("f", b"x"), "1a2b3c4d");
        assert_eq!(b.stat(&p("other")).unwrap_err(), status::OBJECT_NAME_NOT_FOUND);
        assert_eq!(b.list(&p("other")).unwrap_err(), status::OBJECT_PATH_NOT_FOUND);
        assert_eq!(b.open(&p("other")).err(), Some(status::OBJECT_NAME_NOT_FOUND));
        // The inner tree's names do not leak through to the root.
        assert_eq!(b.stat(&p("f")).unwrap_err(), status::OBJECT_NAME_NOT_FOUND);
        // Both synthetic directories refuse open like any directory.
        assert_eq!(b.open(&p("")).err(), Some(status::FILE_IS_A_DIRECTORY));
        assert_eq!(b.open(&p("1a2b3c4d")).err(), Some(status::FILE_IS_A_DIRECTORY));
    }

    #[test]
    fn nested_backing_delegates_label_and_size() {
        let b = NestedBacking::new(MemBacking::new().with_file("f", b"xyz"), "d");
        assert_eq!(b.label(), "test");
        assert_eq!(b.total_size(), 3);
    }

    #[test]
    fn pre_epoch_timestamps_are_dropped_rather_than_wrapped() {
        let before = rustic_core::jiff::Timestamp::from_second(-1).unwrap();
        assert!(to_system_time(Some(before)).is_none());
        let after = rustic_core::jiff::Timestamp::from_second(1_600_000_000).unwrap();
        assert_eq!(
            to_system_time(Some(after)).unwrap(),
            UNIX_EPOCH + Duration::from_secs(1_600_000_000)
        );
        assert!(to_system_time(None).is_none());
    }
}
