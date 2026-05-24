# Roadmap

- Read passphrase from stdin (for securely passing passwords from external tools like password managers)
- Directory-level diff: compare arbitrary subdirectories across arbitrary snapshots
  — e.g. compare `/photos` in one snapshot against `/backup/old-photos`
  in another — useful for backups from different machines or after a
  directory has been moved
- Moved-file detection in diffs (identify files that were renamed or
  relocated rather than showing them as a delete + add)
- Search across snapshot contents (find files by name or path pattern)
- Windows support (needs build and runtime testing on Windows)

## Ideas (Currently out of scope but worth considering for the future)

- Native write operations via rustic_core (backup, forget, etc.) if
  rustic_core's write path matures to production stability, removing the
  dependency on the restic CLI entirely
