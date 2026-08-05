# Roadmap
- Have the smb snap's first directory to be short hash of the snapshot ID, or make it the name of the share
- Read passphrase from stdin (for securely passing passwords from external tools like password managers or keychain backends not supported by this program)
- Directory-level diff: compare arbitrary subdirectories across arbitrary snapshots
  — e.g. compare `/photos` in one snapshot against `/backup/old-photos`
  in another — useful for backups from different machines or after a
  directory has been moved
- Moved-file detection in diffs (identify files that were renamed or
  relocated rather than showing them as a delete + add)
- Search across snapshot contents (find files by name or path pattern, can workaround with smb and ripgrep for now)
- max login attempts for smb before server stops

## Ideas (Currently out of scope but worth considering for the future)

- More native write operations via rustic_core under the restic-compatible
  lock module (docs/locking.md) — snapshot delete and unlock are already
  native; next is backup under a non-exclusive lock, then copy / key add.
  prune/repair/migrate stay on the restic CLI