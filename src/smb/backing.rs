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
use rustic_core::repofile::{Metadata, Node, NodeType};
use rustic_core::vfs::{OpenFile, Vfs};
use rustic_core::{IndexedFullStatus, Repository};

use super::path::SmbPath;
use super::proto::status;

/// What kind of entry this is, as far as SMB is concerned.
///
/// SMB2 without POSIX extensions has exactly two answers, so everything that is
/// neither a regular file nor a directory — symlinks, devices, fifos, sockets —
/// is reported as an empty regular file. restic stores no content for any of
/// them, so nothing is lost from a read; what is lost is the distinction, which
/// a browse-only share can live without. Presenting them as reparse points
/// instead would drag in FSCTL_GET_REPARSE_POINT and a reparse-tag vocabulary
/// for no gain here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NodeKind {
    File,
    Dir,
}

impl NodeKind {
    pub(crate) fn is_dir(self) -> bool {
        matches!(self, Self::Dir)
    }
}

/// One directory entry, flattened to what the wire format needs.
///
/// Timestamps are not optional. A repository may hold nodes with no recorded
/// mtime, and SMB has no way to say "unknown" — a client shown the zero
/// FILETIME renders the year 1601. Following rustic's own FUSE mount, a missing
/// timestamp becomes the server's start time, which is at least plausible and
/// is identical across every node in the share.
#[derive(Debug, Clone)]
pub(crate) struct NodeInfo {
    pub(crate) name: String,
    pub(crate) kind: NodeKind,
    pub(crate) size: u64,
    pub(crate) mtime: SystemTime,
    pub(crate) atime: SystemTime,
    pub(crate) ctime: SystemTime,
}

impl NodeInfo {
    /// A directory with no metadata of its own — the share root, and the
    /// synthetic `.` and `..` entries.
    pub(crate) fn synthetic_dir(name: &str, now: SystemTime) -> Self {
        Self {
            name: name.to_string(),
            kind: NodeKind::Dir,
            size: 0,
            mtime: now,
            atime: now,
            ctime: now,
        }
    }
}

/// A file opened for reading. Held by the handle table for the lifetime of an
/// SMB handle so that repeated READs do not re-resolve the path or rebuild the
/// blob start-point index.
pub(crate) trait FileReader: Send + Sync {
    /// Read up to `len` bytes at `offset`. A read starting at or past EOF
    /// returns empty, which the READ handler turns into STATUS_END_OF_FILE.
    fn read_at(&self, offset: u64, len: u32) -> Result<Bytes, u32>;
}

/// What the share serves. Errors are NTSTATUS values because every caller is
/// about to put one on the wire.
pub(crate) trait Backing: Send + Sync {
    fn stat(&self, path: &SmbPath) -> Result<NodeInfo, u32>;
    fn list(&self, path: &SmbPath) -> Result<Vec<NodeInfo>, u32>;
    fn open(&self, path: &SmbPath) -> Result<Arc<dyn FileReader>, u32>;
    /// Volume label reported by FileFsVolumeInformation.
    fn label(&self) -> &str;
    /// Total bytes, reported as the volume size. A snapshot has no free space,
    /// which is both true and what makes a client stop offering to write.
    fn total_size(&self) -> u64;
}

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
    Some(UNIX_EPOCH + Duration::new(secs as u64, nanos))
}

fn node_info(node: &Node, now: SystemTime) -> NodeInfo {
    let kind = if node.is_dir() {
        NodeKind::Dir
    } else {
        NodeKind::File
    };
    NodeInfo {
        name: node.name().to_string_lossy().to_string(),
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
pub(crate) struct SnapshotBacking {
    repo: Arc<Repository<IndexedFullStatus>>,
    vfs: Vfs,
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
        // `Vfs::from_dir_node` wants a directory node; the snapshot's root tree
        // id is all that actually matters to it.
        let root = Node::new(
            String::new(),
            NodeType::Dir,
            Metadata::default(),
            None,
            Some(tree_id),
        );
        let vfs = Vfs::from_dir_node(&root);

        let total_size = match total_size {
            Some(n) => n,
            // No summary recorded (older snapshots have none): fall back to the
            // top level, which at least reads the root and confirms the tree is
            // there before a client ever connects.
            None => vfs
                .dir_entries_from_path(repo.as_ref(), std::path::Path::new("/"))
                .map_err(|e| anyhow!("reading snapshot root: {e}"))?
                .iter()
                .map(|n| n.meta.size)
                .sum(),
        };

        Ok(Self {
            repo,
            vfs,
            label: label.into(),
            total_size,
            now: SystemTime::now(),
        })
    }
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
        let node = self
            .vfs
            .node_from_path(self.repo.as_ref(), &path.to_vfs_path())
            .map_err(|_| status::OBJECT_NAME_NOT_FOUND)?;
        Ok(node_info(&node, self.now))
    }

    fn list(&self, path: &SmbPath) -> Result<Vec<NodeInfo>, u32> {
        let entries = self
            .vfs
            .dir_entries_from_path(self.repo.as_ref(), &path.to_vfs_path())
            .map_err(|_| status::OBJECT_PATH_NOT_FOUND)?;
        Ok(entries.iter().map(|n| node_info(n, self.now)).collect())
    }

    fn open(&self, path: &SmbPath) -> Result<Arc<dyn FileReader>, u32> {
        let node = self
            .vfs
            .node_from_path(self.repo.as_ref(), &path.to_vfs_path())
            .map_err(|_| status::OBJECT_NAME_NOT_FOUND)?;
        if node.is_dir() {
            return Err(status::FILE_IS_A_DIRECTORY);
        }
        let open_file = self
            .repo
            .open_file(&node)
            .map_err(|_| status::OBJECT_NAME_NOT_FOUND)?;
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

#[cfg(test)]
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
            let offset = offset as usize;
            if offset >= self.content.len() {
                return Ok(Bytes::new());
            }
            let end = (offset + len as usize).min(self.content.len());
            Ok(Bytes::copy_from_slice(&self.content[offset..end]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::MemBacking;
    use super::*;

    fn p(s: &str) -> SmbPath {
        SmbPath::parse(s).expect("test path parses")
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
