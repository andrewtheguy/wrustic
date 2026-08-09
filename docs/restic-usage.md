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
| Unlock / stale-lock removal (`u` shortcut) | native (`repo::unlock`) |
| Prune | **restic CLI**, via the spawn harness in `src/restic.rs` |

The prune flow runs `restic prune` through the secure spawn harness
(`restic::run_unsticking_locks_streaming`: password piped over stdin,
credentials over env vars, secrets never on argv, `--cache-dir <per-user
path private to wrustic> --cleanup-cache` unless the user passed
`--no-restic-cache`, which switches it to `--no-cache`). Before spawning,
the harness evaluates the repo's lock files natively and runs
`restic unlock` if a stale lock would block the exclusive acquisition.
restic ≥ 0.19 must be available for this one action — a bundled
`restic/restic(.exe)` under the wrustic executable's directory wins (the
installers on every platform ship a pinned one there, in a subdirectory
so it stays off the PATH they put wrustic on), otherwise PATH is
searched; every other feature works without it. restic 0.19 has no JSON output for prune, so the report
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
- `restic backup` — creating snapshots
- maintenance beyond prune: `repair`, `migrate`, key management

Description edits are not planned — `description` is a rustic-only
snapshot field that restic silently drops on any rewrite, and wrustic
only implements features common to both tools. Native backup, copy, and
key management were considered (locking.md Tier 1) and dropped from the
plan — they stay on the restic CLI indefinitely.

## Development and tests

- The live interop tests in `src/repo.rs` use `restic::run` for `init`,
  `backup`, `forget`, `unlock`, `snapshots --json`,
  `check --read-data --json`, and `tag` to prove the native lock, delete,
  and tag-edit paths are compatible with real restic.
- The live test in `src/restic.rs` exercises the harness itself end to
  end (stdin password channel, the native pre-spawn lock check that
  unlocks stale locks before running a restic command, and the streaming
  prune runner the TUI uses).
- `scripts/garage-e2e.sh seed` initializes and seeds the Garage S3 test
  repository with restic (requires restic >= 0.19.1).
