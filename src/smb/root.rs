// The share root: a `README.txt` saying what the server is doing, beside the
// folder holding the shared snapshot when one is shared.
//
// The server outlives any one snapshot: it is turned on once, and snapshots
// are shared into it and taken out again from the snapshot list. A client that
// mounts the share before anything is shared, or after a snapshot is taken
// out, would otherwise see an empty directory and have no way to tell a
// working server from a broken mount. The README also carries what the
// eight-hex-character folder name cannot: the full snapshot id, its host,
// paths and time, and which profile it came from.

use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use smbanything_core::smb::{Backing, FileReader, NodeInfo, NodeKind, SmbPath, status};

pub(crate) const README_NAME: &str = "README.txt";

/// The volume label while no snapshot is shared.
const EMPTY_LABEL: &str = "wrustic";

/// What the README and the TUI say about the shared snapshot.
#[derive(Clone, Debug)]
pub(crate) struct SnapshotSummary {
    /// The full snapshot id, hex.
    pub(crate) id: String,
    /// restic's standard 8-hex-char short id, which is also the folder name.
    pub(crate) short_id: String,
    pub(crate) profile: String,
    pub(crate) time: String,
    pub(crate) host: String,
    pub(crate) paths: Vec<String>,
    pub(crate) tags: Vec<String>,
}

pub(crate) struct RootBacking {
    /// When this root was published, reported as every synthetic timestamp so
    /// a client sees the README change whenever the contents do.
    created: SystemTime,
    readme: Bytes,
    snapshot: Option<Folder>,
}

struct Folder {
    info: NodeInfo,
    backing: Arc<dyn Backing>,
}

/// Where a client path lands in the root.
enum Located<'a> {
    Root,
    Readme,
    /// Inside the snapshot folder; an empty path is the folder itself.
    Snapshot(&'a Folder, SmbPath),
}

impl RootBacking {
    /// A root holding only the README: nothing is shared.
    pub(crate) fn empty() -> Self {
        Self::build(None)
    }

    /// The README beside the snapshot's tree under its short-id folder.
    pub(crate) fn with_snapshot(summary: &SnapshotSummary, backing: Arc<dyn Backing>) -> Self {
        Self::build(Some((summary, backing)))
    }

    fn build(snapshot: Option<(&SnapshotSummary, Arc<dyn Backing>)>) -> Self {
        let created = SystemTime::now();
        Self {
            created,
            readme: Bytes::from(readme_text(snapshot.as_ref().map(|(s, _)| *s))),
            snapshot: snapshot.map(|(summary, backing)| Folder {
                info: NodeInfo::synthetic_dir(&summary.short_id, created),
                backing,
            }),
        }
    }

    fn readme_info(&self) -> NodeInfo {
        NodeInfo {
            name: README_NAME.to_string(),
            kind: NodeKind::File,
            size: self.readme.len() as u64,
            mtime: self.created,
            atime: self.created,
            ctime: self.created,
        }
    }

    // Names at this level are matched case-insensitively: SMB names are
    // case-preserving but not case-sensitive, and a Windows client may upcase a
    // typed path. The snapshot's own tree keeps the repository's
    // (case-sensitive) semantics — only the synthetic level is ours to define.
    fn locate(&self, path: &SmbPath) -> Option<Located<'_>> {
        let Some((first, rest)) = path.split_first() else {
            return Some(Located::Root);
        };
        if first.eq_ignore_ascii_case(README_NAME) {
            return rest.is_root().then_some(Located::Readme);
        }
        self.snapshot
            .as_ref()
            .filter(|folder| first.eq_ignore_ascii_case(&folder.info.name))
            .map(|folder| Located::Snapshot(folder, rest))
    }
}

impl Backing for RootBacking {
    fn stat(&self, path: &SmbPath) -> Result<NodeInfo, u32> {
        match self.locate(path).ok_or(status::OBJECT_NAME_NOT_FOUND)? {
            Located::Root => Ok(NodeInfo::synthetic_dir("", self.created)),
            Located::Readme => Ok(self.readme_info()),
            Located::Snapshot(folder, inner) if inner.is_root() => Ok(folder.info.clone()),
            Located::Snapshot(folder, inner) => folder.backing.stat(&inner),
        }
    }

    fn list(&self, path: &SmbPath) -> Result<Vec<NodeInfo>, u32> {
        match self.locate(path).ok_or(status::OBJECT_PATH_NOT_FOUND)? {
            Located::Root => Ok(std::iter::once(self.readme_info())
                .chain(self.snapshot.iter().map(|folder| folder.info.clone()))
                .collect()),
            Located::Readme => Err(status::NOT_A_DIRECTORY),
            Located::Snapshot(folder, inner) => folder.backing.list(&inner),
        }
    }

    fn open(&self, path: &SmbPath) -> Result<Arc<dyn FileReader>, u32> {
        match self.locate(path).ok_or(status::OBJECT_NAME_NOT_FOUND)? {
            // The root and the folder are the directories `stat` and `list`
            // report them to be; saying they do not exist contradicts that.
            Located::Root => Err(status::FILE_IS_A_DIRECTORY),
            Located::Readme => Ok(Arc::new(Readme(self.readme.clone()))),
            Located::Snapshot(_, inner) if inner.is_root() => Err(status::FILE_IS_A_DIRECTORY),
            Located::Snapshot(folder, inner) => folder.backing.open(&inner),
        }
    }

    fn label(&self) -> &str {
        self.snapshot
            .as_ref()
            .map_or(EMPTY_LABEL, |folder| folder.backing.label())
    }

    fn total_size(&self) -> u64 {
        let snapshot = self
            .snapshot
            .as_ref()
            .map_or(0, |folder| folder.backing.total_size());
        snapshot.saturating_add(self.readme.len() as u64)
    }
}

struct Readme(Bytes);

impl FileReader for Readme {
    fn read_at(&self, offset: u64, len: u32) -> Result<Bytes, u32> {
        let Ok(offset) = usize::try_from(offset) else {
            return Ok(Bytes::new());
        };
        if offset >= self.0.len() {
            return Ok(Bytes::new());
        }
        let end = offset.saturating_add(len as usize).min(self.0.len());
        Ok(self.0.slice(offset..end))
    }
}

/// The README's text. A blank line between paragraphs and CRLF-free, so it
/// reads the same in every client's default text viewer. The snapshot's own
/// fields (host, paths, tags, profile) are whatever the user typed and may be
/// non-ASCII; everything wrustic writes itself is ASCII.
fn readme_text(snapshot: Option<&SnapshotSummary>) -> String {
    let mut text = String::from(
        "wrustic read-only snapshot share\n\
         ================================\n\n",
    );
    match snapshot {
        Some(s) => {
            let list = |items: &[String]| {
                if items.is_empty() {
                    "(none)".to_string()
                } else {
                    items.join(", ")
                }
            };
            text.push_str(&format!(
                "Snapshot: {}\n\
                 Folder:   {}\n\
                 Profile:  {}\n\
                 Time:     {}\n\
                 Host:     {}\n\
                 Paths:    {}\n\
                 Tags:     {}\n\n\
                 The snapshot's files are under the folder named above: restic's\n\
                 short id for the snapshot, the same form `restic snapshots` prints,\n\
                 so the name pastes straight into restic commands.\n\n",
                s.id,
                s.short_id,
                s.profile,
                s.time,
                s.host,
                list(&s.paths),
                list(&s.tags),
            ));
        }
        None => text.push_str(
            "No snapshot is shared. This README is the only thing in the share.\n\n",
        ),
    }
    text.push_str(
        "About this share\n\
         ----------------\n\
         Everything here is read-only. Creating, changing, renaming and deleting\n\
         files are refused by the server itself, not merely by the mount.\n\n\
         Snapshots are shared from the wrustic terminal UI on the machine running\n\
         the server: press s on a snapshot in a profile's snapshot list to share\n\
         it in place of the one shared before, and s on it again to take it out.\n\
         The share stays mounted throughout; only its contents change. Switching\n\
         snapshots invalidates files still open from the previous one, and a\n\
         client may show a stale listing until it is refreshed.\n\n\
         While a snapshot is shared, wrustic holds restic's non-exclusive lock on\n\
         its repository: backups keep working, while prune and forget wait until\n\
         the snapshot is taken out of the share.\n\n\
         This README.txt is rewritten whenever the share's contents change.\n",
    );
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smb::backing::test_support::MemBacking;

    fn p(s: &str) -> SmbPath {
        SmbPath::parse(s).expect("valid path")
    }

    fn readme(backing: &RootBacking) -> String {
        let file = backing.open(&p("readme.TXT")).unwrap();
        let size = backing.stat(&p(README_NAME)).unwrap().size;
        let bytes = file.read_at(0, size as u32).unwrap();
        assert_eq!(bytes.len() as u64, size, "the reported size is the whole file");
        assert!(file.read_at(size, 16).unwrap().is_empty());
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn summary() -> SnapshotSummary {
        SnapshotSummary {
            id: "1a2b3c4d5e6f".to_string(),
            short_id: "1a2b3c4d".to_string(),
            profile: "laptop".to_string(),
            time: "2026-11-18 09:30:00".to_string(),
            host: "box".to_string(),
            paths: vec!["/home".to_string(), "/etc".to_string()],
            tags: Vec::new(),
        }
    }

    fn shared() -> RootBacking {
        RootBacking::with_snapshot(
            &summary(),
            Arc::new(
                MemBacking::new()
                    .with_dir("docs")
                    .with_file("docs\\a.txt", b"aaa")
                    .with_file("top.txt", b"t"),
            ),
        )
    }

    #[test]
    fn an_empty_root_holds_only_the_readme() {
        let backing = RootBacking::empty();

        let root = backing.list(&p("")).unwrap();
        assert_eq!(root.len(), 1);
        assert_eq!(root[0].name, README_NAME);
        assert!(!root[0].kind.is_dir());
        assert_eq!(root[0].size, backing.total_size());
        assert_eq!(backing.label(), "wrustic");

        let text = readme(&backing);
        assert!(text.contains("No snapshot is shared"), "{text}");
        assert!(text.contains("press s on a snapshot"), "{text}");
        assert!(text.is_ascii(), "{text}");

        assert_eq!(backing.open(&p("")).err(), Some(status::FILE_IS_A_DIRECTORY));
        assert_eq!(backing.list(&p(README_NAME)).err(), Some(status::NOT_A_DIRECTORY));
        assert_eq!(backing.stat(&p("1a2b3c4d")).err(), Some(status::OBJECT_NAME_NOT_FOUND));
        assert_eq!(
            backing.list(&p(r"README.txt\inside")).err(),
            Some(status::OBJECT_PATH_NOT_FOUND)
        );
    }

    #[test]
    fn a_shared_root_exposes_the_snapshot_only_beneath_its_folder() {
        let backing = shared();

        let root = backing.list(&p("")).unwrap();
        let names: Vec<&str> = root.iter().map(|info| info.name.as_str()).collect();
        assert_eq!(names, [README_NAME, "1a2b3c4d"]);
        assert!(root[1].kind.is_dir());

        // The folder level is ours and case-insensitive; the tree is the
        // snapshot's own.
        let mut inside: Vec<String> = backing
            .list(&p("1A2B3C4D"))
            .unwrap()
            .into_iter()
            .map(|n| n.name)
            .collect();
        inside.sort();
        assert_eq!(inside, ["docs", "top.txt"]);
        assert!(backing.list(&p("docs")).is_err(), "the tree is not at the root");

        let file = backing.open(&p(r"1a2b3c4d\docs\a.txt")).unwrap();
        assert_eq!(&file.read_at(0, 3).unwrap()[..], b"aaa");
        assert_eq!(backing.stat(&p(r"1a2b3c4d\top.txt")).unwrap().size, 1);
        // Both directories `stat` and `list` report must open as directories,
        // not as names that do not exist.
        for directory in ["", "1a2b3c4d"] {
            assert!(backing.stat(&p(directory)).unwrap().kind.is_dir());
            assert_eq!(
                backing.open(&p(directory)).err(),
                Some(status::FILE_IS_A_DIRECTORY),
                "opening {directory:?}"
            );
        }
        assert_eq!(
            backing.stat(&p("other")).err(),
            Some(status::OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(
            backing.list(&p(r"other\docs")).err(),
            Some(status::OBJECT_PATH_NOT_FOUND)
        );
        assert_eq!(backing.label(), "test", "the snapshot names the volume");
        assert_eq!(
            backing.total_size(),
            4 + backing.stat(&p(README_NAME)).unwrap().size,
            "the snapshot's 4 bytes plus the README"
        );
    }

    #[test]
    fn the_readme_describes_the_shared_snapshot() {
        let text = readme(&shared());
        assert!(text.contains("Snapshot: 1a2b3c4d5e6f"), "{text}");
        assert!(text.contains("Folder:   1a2b3c4d"), "{text}");
        assert!(text.contains("Profile:  laptop"), "{text}");
        assert!(text.contains("Paths:    /home, /etc"), "{text}");
        assert!(text.contains("Tags:     (none)"), "{text}");
        assert!(text.contains("non-exclusive lock"), "{text}");
        assert!(!text.contains("No snapshot is shared"), "{text}");
    }
}
