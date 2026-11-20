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
- Choose where a merged-in backup lands. A merge (`M`) combines snapshots
  by path, so the addition has to have been backed up at the path it
  should occupy, and `restic backup` records real absolute paths with no
  way to override them (still true of restic 0.20.0; restic issues #2092
  and #2714 are open, and the pull requests that added a path option were
  closed unmerged). Two workarounds exist on the restic side and want
  documenting, perhaps driving from the TUI: a backup of a *relative* path
  roots the tree at that relative path (`cd /mnt/usb && restic backup
  extra` stores `/extra/…`), which strips a prefix; and binding the source
  over the wanted path for the duration of the backup (`proot -b
  <source>:<path> restic backup <path>`, what ../andrewserver's ZFS backup
  does to back up a snapshot directory as the live path) puts it anywhere.
  The alternative is a native backup through rustic_core, whose `as_path`
  option is exactly this — a long-running write under the non-exclusive
  lock that docs/locking.md so far keeps on the restic CLI
- Lossless snapshot merge. The merge goes through rustic_core's typed tree
  nodes, so the merged snapshot is without what that type cannot hold
  (restic's Windows `generic_attributes`), it rewrites every directory
  when the trees were written in another timezone, and it has to refuse
  what it cannot write correctly: sources that record one hardlink
  identity on different content, where giving the files separate
  identities would do, and directories whose quoted names sort
  differently from the names (docs/locking.md, "Native snapshot merge").
  Merging the tree JSON itself would lift all of these limits and write
  only the directories the sources share, but
  rustic_core has no public way to store a tree blob, so it means wrustic
  writing pack and index files itself — the same trade the lock module
  made for its envelope, at a larger size
- Read-only "index of" browser over HTTP: walk a snapshot's tree in a web
  browser and download files, served by the existing local file-share
  server. Where it starts is still to be decided — the snapshot list, or a
  single snapshot picked in the TUI. Filenames keep the TUI browser's
  representation, which is the name as stored; the SMB share deliberately
  differs, decoding restic's quoting and replacing what an SMB2 name cannot
  carry (docs/smb.md)

## Ideas (Currently out of scope but worth considering for the future)

- More native write operations via rustic_core under the restic-compatible
  lock module (docs/locking.md) — snapshot delete, lossless raw-JSON snapshot
  tag edits, snapshot merge, and unlock are already native; candidates would be backup under
  a non-exclusive lock, then copy / key add, though all three currently stay
  on the restic CLI. prune/repair/migrate stay on the restic CLI indefinitely