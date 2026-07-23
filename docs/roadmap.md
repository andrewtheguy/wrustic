# Roadmap

- Read passphrase from stdin (for securely passing passwords from external tools like password managers or keychain backends not supported by this program)
- Directory-level diff: compare arbitrary subdirectories across arbitrary snapshots
  — e.g. compare `/photos` in one snapshot against `/backup/old-photos`
  in another — useful for backups from different machines or after a
  directory has been moved
- Moved-file detection in diffs (identify files that were renamed or
  relocated rather than showing them as a delete + add)
- Search across snapshot contents (find files by name or path pattern)
- Search text file contents across snapshots (requires indexing and is a much larger project)
- Windows support (needs build and runtime testing on Windows)
