# Where restic is used

wrustic runs without the `restic` binary for everything except prune.
This page is the single overview of every workflow that uses the restic
CLI — today or by plan. The safety rationale behind the native/CLI split
(lock tiers) lives in [locking.md](locking.md) under "What writes wrustic
can safely support".

## Inside the app

One TUI flow shells out to restic: **prune** (`p` on the Snapshots
screen). Everything else wrustic does at runtime is native:

| Workflow | Implementation |
|---|---|
| All reads (snapshot list, tree browsing, diff, file view/share, filters) | `rustic_core` |
| Snapshot delete | native, under the restic-compatible repo lock (`repo::delete_snapshot`) |
| Tag edits (`t` on the snapshot list) | native, under the same exclusive lock (`repo::edit_snapshot_tags`, lossless raw-JSON rewrite) |
| Snapshot merge (`M` on the snapshot list) | native, under restic's non-exclusive lock (`repo::merge_snapshots`); restic has no merge command |
| Unlock / stale-lock removal (`u` shortcut) | native (`repo::unlock`) |
| Prune | **restic CLI**, via the spawn harness in `src/restic.rs` |

The prune flow runs `restic prune` through the secure spawn harness
(`restic::run_unsticking_locks_streaming`: password piped over stdin,
credentials over env vars, secrets never on argv, `--cache-dir <per-user
path private to wrustic> --cleanup-cache` unless the user passed
`--no-restic-cache`, which switches it to `--no-cache`). Before spawning,
the harness evaluates the repo's lock files natively and runs
`restic unlock` if a stale lock would block the exclusive acquisition.
restic ≥ 0.19 must be available for this one action, and at exactly one
place: the bundled `restic/restic(.exe)` under the wrustic executable's
directory, which the installers on every platform ship a pinned copy of
(in a subdirectory so it stays off the PATH they put wrustic on). Nothing
else is ever run — no PATH lookup, in any build. A missing one fails with
"reinstall wrustic" rather than silently pruning with whatever `restic`
the machine's PATH holds, which could be any version and is not the one
the release was tested against. A build from a checkout resolves the same
path under `target/…`, so working on the prune flow locally means copying
a restic there once. Every other feature works without restic at all. restic 0.19 has no JSON output for prune, so the report
is shown verbatim, never parsed; restic's stdout is streamed into the
running screen live (on a pipe restic reports progress roughly every
10 s). Ctrl+C interrupts the run safely — restic never removes data still
in use, so a cancelled prune just leaves the remaining work for the next
one (SIGINT on Unix, which restic catches and removes its lock; process
termination on Windows, whose leftover lock is stale and removed by the
next run's unstick pre-check).

## Expected to use restic from the app (planned, not wired yet)

**repair index** and **migrate** (locking.md Tier 3) would go through the
same harness if the TUI grows actions for them
(`restic::run_unsticking_locks`).

## Outside the app (run manually by the user)

These stay on a user-run `restic` (>= 0.19), outside wrustic — wrustic
itself will never run them:

- `restic init` — creating a new repository
- `restic backup` — creating snapshots. That is the whole of an ordinary
  backup flow; the merge is for special cases such as adding content to an
  existing snapshot, and there too the backup is restic's: back up only
  the new file or directory, then merge the two in wrustic. The two
  backups have to use one layout: the merge lines files up by their path
  in the snapshot's tree alone, whatever host or tags the snapshots share.
  restic stores a target given as an absolute path under that path, so
  with `restic backup /data` as the base, the addition is
  `restic backup /data/extra`: the directory in its place inside the base,
  not a copy of it somewhere else. A target given as a relative path is
  stored under the relative path instead (`cd /data && restic backup
  extra` holds `/extra/…`, while the snapshot's `paths` say
  `/data/extra`); `restic ls <snapshot>` shows where a snapshot's files
  are
- maintenance beyond prune: `repair`, `migrate`, key management

Description edits are not planned — `description` is a rustic-only
snapshot field that restic silently drops on any rewrite, and wrustic
only implements features common to both tools. Native backup, copy, and
key management were considered (locking.md Tier 1) and dropped from the
plan — they stay on the restic CLI indefinitely.

## Development and tests

- The `#[ignore]`d live tests spawn restic through the same harness, so
  they resolve the same bundled path — for a test binary that is
  `target/debug/deps/restic/restic(.exe)`. Copy a restic >= 0.19 there
  before running them with `cargo test -- --ignored`; a restic on PATH is
  not consulted.
- The live interop tests in `src/repo.rs` use `restic::run` for `init`,
  `backup`, `forget`, `unlock`, `snapshots --json`,
  `check --read-data --json`, `ls --json`, and `tag` to prove the native
  lock, delete, tag-edit, and merge paths are compatible with real restic.
- The live test in `src/restic.rs` exercises the harness itself end to
  end (stdin password channel, the native pre-spawn lock check that
  unlocks stale locks before running a restic command, and the streaming
  prune runner the TUI uses).
- `scripts/silo-e2e.sh seed` initializes and seeds the Silo S3 test
  repository with restic (requires restic >= 0.19.1). `restic init` creates
  the bucket too — Silo, like the MinIO it forks, ships with none.
