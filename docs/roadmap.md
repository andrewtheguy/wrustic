# Roadmap

- Read passphrase from stdin (for scripted / non-interactive use)
- Diff arbitrary subdirectories across snapshots (currently limited to
  top-level diff via `restic diff`; can't pick a subdirectory from one
  snapshot and compare it against a different subdirectory in another,
  which is useful for comparing backups from different machines or after
  a directory has been moved)
- Moved-file detection in diffs (identify files that were renamed or
  relocated rather than showing them as a delete + add)
- Search across snapshot contents (find files by name or path pattern)
- Windows support (needs build and runtime testing on Windows)
