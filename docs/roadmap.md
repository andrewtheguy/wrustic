# Roadmap
- Read passphrase from stdin (for securely passing passwords from external tools like password managers or keychain backends not supported by this program)
- Directory-level diff: compare arbitrary subdirectories across arbitrary snapshots
  — e.g. compare `/photos` in one snapshot against `/backup/old-photos`
  in another — useful for backups from different machines or after a
  directory has been moved
- Moved-file detection in diffs (identify files that were renamed or
  relocated rather than showing them as a delete + add)
- Search across snapshot contents (find files by name or path pattern, can workaround with smb and ripgrep for now)
- Cache tree blobs while an SMB share is up. `SnapshotBacking::lookup` reads
  one tree per path component on every CREATE, and rustic_core does not cache
  those: its 32 MB blob cache on `IndexedFullStatus` is only consulted through
  `get_blob_cached`, which the file-content path uses, while `Tree::from_backend`
  re-reads and re-deserializes the tree JSON each call. Directory listings are
  already cached per handle, so what repeats is the ancestor walk — cheap
  against a local repository, a network round trip per component against S3. A
  snapshot is immutable, so the cache is trivially correct; the work is picking
  a bounded policy (a share can stay up for hours, and one tree can hold
  thousands of nodes), and measuring first to see whether it is worth it
- Read-only "index of" browser over HTTP: walk a snapshot's tree in a web
  browser and download files, served by the existing local file-share
  server. Where it starts is still to be decided — the snapshot list, or a
  single snapshot picked in the TUI. Filenames keep the TUI browser's
  representation, which is the name as stored; the SMB share deliberately
  differs, decoding restic's quoting and replacing what an SMB2 name cannot
  carry (docs/smb.md)

## Ideas (Currently out of scope but worth considering for the future)

- More native write operations via rustic_core under the restic-compatible
  lock module (docs/locking.md) — snapshot delete, tag edits, and unlock are
  already native; next is backup under a non-exclusive lock, then copy /
  key add. prune/repair/migrate stay on the restic CLI