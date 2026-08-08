//! Throwaway restic-format repositories built in-process — **test-only**.
//!
//! The live interop tests in src/repo.rs seed their repositories by spawning
//! the restic CLI, which is what makes them `#[ignore]`d. The lock-coverage
//! tests need a repository too, but what they assert — that every native
//! write acquires the exclusive lock before touching anything — is about
//! wrustic's own code and needs no second implementation to check it against.
//! So they build their fixtures through rustic_core's `init` + `backup`
//! instead and run under a plain `cargo test`.
//!
//! `init`/`backup` are deliberately *not* wrustic features (docs/locking.md
//! Tier 1: the restic CLI keeps them). Using them here is the same
//! arrangement as src/restic.rs: setup machinery that exists only under
//! `#[cfg(test)]` and never ships in the binary.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use rustic_core::{
    BackupOptions, ConfigOptions, Credentials, KeyOptions, PathList, Repository,
    RepositoryOptions, SnapshotOptions,
};
use sha2::{Digest, Sha256};

use crate::config::Profile;
use crate::lock::{LockBackend, RepoCrypto};
use crate::repo::build_backends;

/// Distinguishes fixtures created within one test binary run. Test threads
/// share a process id, so that alone is not unique enough.
static SEQ: AtomicU64 = AtomicU64::new(0);

/// A freshly initialized local repository under the project's `tmp/`, removed
/// again when the fixture drops.
pub(crate) struct TestRepo {
    root: PathBuf,
    profile: Profile,
}

impl TestRepo {
    /// Initializes an empty repository. `name` only labels the directory, so
    /// a failed run leaves something recognizable behind.
    pub(crate) fn init(name: &str) -> Self {
        let root = PathBuf::from("tmp").join(format!(
            "testrepo-{name}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        // A leftover from a killed earlier run would make `init` refuse
        // ("config file already exists").
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("source")).expect("create fixture source dir");

        let profile = Profile::Local {
            password: "fixture".into(),
            local_path: root.join("repo").to_string_lossy().into_owned(),
        };
        let backends = build_backends(&profile).expect("fixture backends");
        Repository::new(&RepositoryOptions::default(), &backends)
            .expect("new repository")
            .init(
                &Credentials::password(profile.password()),
                &KeyOptions::default(),
                &ConfigOptions::default(),
            )
            .expect("init fixture repository");

        Self { root, profile }
    }

    pub(crate) fn profile(&self) -> &Profile {
        &self.profile
    }

    pub(crate) fn repo_path(&self) -> PathBuf {
        self.root.join("repo")
    }

    /// The tree [`TestRepo::backup`] snapshots. Exposed so a test can *remove*
    /// a file between backups, which is how a partly-used pack — and so a
    /// prune that must repack rather than drop whole packs — is arranged.
    pub(crate) fn source_path(&self) -> PathBuf {
        self.root.join("source")
    }

    /// Writes `files` into the fixture's source tree and backs it up, returning
    /// the new snapshot's full hex id. Later calls overwrite earlier files, so
    /// passing different content produces snapshots that share some packs and
    /// not others — the shape prune needs to have real work to do.
    pub(crate) fn backup(&self, files: &[(&str, &[u8])], tags: &[&str]) -> String {
        let source = self.root.join("source");
        for (name, content) in files {
            std::fs::write(source.join(name), content).expect("write fixture source file");
        }

        let backends = build_backends(&self.profile).expect("fixture backends");
        let repo = Repository::new(&RepositoryOptions::default(), &backends)
            .expect("new repository")
            .open(&Credentials::password(self.profile.password()))
            .expect("open fixture repository")
            .to_indexed_ids()
            .expect("index fixture repository");

        let snap = SnapshotOptions::default()
            .add_tags(&tags.join(","))
            .expect("fixture tags")
            .to_snapshot()
            .expect("build fixture snapshot");
        // `sanitize` wants a path it can resolve; the fixture root is relative
        // to the crate directory the tests run in.
        let abs = std::fs::canonicalize(&source).expect("canonicalize fixture source");
        let paths = PathList::from_string(&abs.to_string_lossy())
            .expect("fixture path list")
            .sanitize()
            .expect("sanitize fixture path list");
        let saved = repo
            .backup(&BackupOptions::default(), &paths, snap)
            .expect("backup fixture source");
        saved.id.to_hex().as_str().to_string()
    }

    pub(crate) fn lock_backend(&self) -> Arc<dyn LockBackend> {
        crate::lock::backend_for_profile(&self.profile).expect("fixture lock backend")
    }

    pub(crate) fn crypto(&self) -> RepoCrypto {
        crate::repo::lock_context(&self.profile)
            .expect("fixture lock context")
            .1
    }

    /// How many lock files the repository currently holds.
    pub(crate) fn lock_count(&self) -> usize {
        self.lock_backend().list().expect("list locks").len()
    }

    /// Every repository file except `locks/`, as sorted
    /// `(relative path, SHA-256 of the content)` pairs. Comparing two of these
    /// proves a blocked operation wrote, deleted and rewrote nothing — the
    /// point of taking the lock before the first write, not somewhere in the
    /// middle. Hashing rather than sizing matters for the repository files
    /// that are *not* content-addressed — `config`, `keys/<id>` — where a
    /// rewrite keeps both its name and, plausibly, its length.
    ///
    /// Every I/O failure propagates instead of being skipped: a fingerprint
    /// that silently came back short would make `assert_eq!(after, before)`
    /// pass while comparing two equally incomplete pictures.
    pub(crate) fn fingerprint(&self) -> Result<Vec<(String, String)>> {
        let repo = self.repo_path();
        let mut out = Vec::new();
        walk(&repo, &repo, &mut out)?;
        out.sort();
        return Ok(out);

        fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) -> Result<()> {
            let entries = std::fs::read_dir(dir)
                .with_context(|| format!("listing {}", dir.display()))?;
            for entry in entries {
                let entry =
                    entry.with_context(|| format!("reading an entry of {}", dir.display()))?;
                let path = entry.path();
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                if rel == "locks" {
                    continue;
                }
                let file_type = entry
                    .file_type()
                    .with_context(|| format!("stat {}", path.display()))?;
                if file_type.is_dir() {
                    walk(root, &path, out)?;
                } else {
                    let content = std::fs::read(&path)
                        .with_context(|| format!("reading {}", path.display()))?;
                    out.push((rel, crate::lock::hex(&Sha256::digest(&content))));
                }
            }
            Ok(())
        }
    }
}

impl Drop for TestRepo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
