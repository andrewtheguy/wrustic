# Roadmap

- Read passphrase from stdin (for scripted / non-interactive use)
- Native snapshot diff via rustic_core (the current compare feature shells
  out to `restic diff`, which only compares two full snapshots from their
  roots). A native implementation could diff arbitrary subdirectories
  across snapshots — e.g. compare `/photos` in one snapshot against
  `/backup/old-photos` in another — useful for backups from different
  machines or after a directory has been moved
- Moved-file detection in diffs (identify files that were renamed or
  relocated rather than showing them as a delete + add)
- Search across snapshot contents (find files by name or path pattern)
- Windows support (needs build and runtime testing on Windows)
