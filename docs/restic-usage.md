# Where restic is used

wrustic runs without the `restic` binary. This page is the single overview
of every workflow that still uses the restic CLI — today or by plan. The
safety rationale behind the native/CLI split (lock tiers, why prune stays
out) lives in [locking.md](locking.md) under "What writes wrustic can
safely support".

## Inside the app

One TUI flow shells out to restic: **prune** (`p` on the Snapshots
screen). Everything else wrustic does at runtime is native:

| Workflow | Implementation |
|---|---|
| All reads (snapshot list, tree browsing, diff, file view/share, filters) | `rustic_core` |
| Snapshot delete | native, under the restic-compatible repo lock (`repo::delete_snapshot`) |
| Unlock / stale-lock removal (`u` shortcut) | native (`repo::unlock`) |
| Prune | **restic CLI**, via the spawn harness in `src/restic.rs` |

Prune-class operations stay on the restic CLI indefinitely (locking.md
Tier 3), and the prune flow runs `restic prune` through the secure spawn
harness (`restic::run_unsticking_locks`: password piped over stdin,
credentials over env vars, secrets never on argv, `--no-cache` unless the
user passed `--restic-cache`). Before spawning, the harness evaluates the
repo's lock files natively and runs `restic unlock` if a stale lock would
block the exclusive acquisition. restic ≥ 0.19 must be on PATH for this
one action; every other feature works without it. restic 0.19 has no JSON
output for prune, so the report is shown verbatim, never parsed; restic's
stdout is streamed into the running screen live (on a pipe restic reports
progress roughly every 10 s). Ctrl+C interrupts the run safely — restic
never removes data still in use, so a cancelled prune just leaves the
remaining work for the next one (SIGINT on Unix, which restic catches and
removes its lock; process termination on Windows, whose leftover lock is
stale and removed by the next run's unstick pre-check).

## Expected to use restic from the app (planned, not wired yet)

**repair index** and **migrate** (also locking.md Tier 3) would go
through the same harness if the TUI grows actions for them.

Not expected to use restic: **backup**, **copy into repo**, and **key
add** are planned as *native* operations under a non-exclusive repo lock
(locking.md Tier 1); backup is next up.

## Outside the app (run manually by the user)

These stay on a user-run `restic` (>= 0.19), outside wrustic:

- `restic init` — creating a new repository
- `restic backup` — creating snapshots, until native backup ships
- maintenance beyond prune: `repair`, `migrate`, key management

## Development and tests only

- The live interop test in `src/repo.rs` uses `restic::run` for `init`,
  `backup`, `forget`, `unlock`, and `snapshots --json` to prove the
  native lock + delete path is compatible with real restic.
- `scripts/garage-e2e.sh seed` initializes and seeds the Garage S3 test
  repository with restic (requires restic >= 0.19.1).
