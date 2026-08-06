# Where restic is used

wrustic runs without the `restic` binary — no TUI flow shells out to
restic anymore. This page is the single overview of every workflow that
still uses the restic CLI — today or by plan. The safety rationale behind
the native/CLI split (lock tiers, why prune could go native) lives in
[locking.md](locking.md) under "What writes wrustic can safely support".

## Inside the app

Everything wrustic does at runtime is native:

| Workflow | Implementation |
|---|---|
| All reads (snapshot list, tree browsing, diff, file view/share, filters) | `rustic_core` |
| Snapshot delete | native, under the restic-compatible repo lock (`repo::delete_snapshot`) |
| Prune | native, under the same exclusive lock (`repo::prune`, instant delete) |
| Unlock / stale-lock removal (`u` shortcut) | native (`repo::unlock`) |

The prune flow (`p` on the Snapshots screen) runs rustic_core's prune
under wrustic's exclusive restic-compatible lock, always with instant
delete so the repository state it leaves is indistinguishable from a
`restic prune` (locking.md has the full rationale). Progress renders
live, one line per prune phase. A lock conflict — stale locks included,
restic's rule — offers `u` for native stale-lock removal and a retry. A
running native prune cannot be cancelled; Ctrl+C twice force-quits
wrustic instead, which is safe for the repository (prune deletes nothing
before all new data and the new index are written) but leaves a stale
lock for a later unlock.

## Expected to use restic from the app (planned, not wired yet)

**repair index** and **migrate** (locking.md Tier 3) would go through the
secure spawn harness in `src/restic.rs` if the TUI grows actions for them
(`restic::run_unsticking_locks`: password piped over stdin, credentials
over env vars, secrets never on argv, `--cache-dir <per-user path private
to wrustic> --cleanup-cache` unless the user passed `--no-restic-cache`,
which switches it to `--no-cache`; before spawning, the harness evaluates
the repo's lock files natively and runs `restic unlock` if a stale lock
would block the acquisition).

Not expected to use restic: **backup**, **copy into repo**, and **key
add** are planned as *native* operations under a non-exclusive repo lock
(locking.md Tier 1); backup is next up.

## Outside the app (run manually by the user)

These stay on a user-run `restic` (>= 0.19), outside wrustic:

- `restic init` — creating a new repository
- `restic backup` — creating snapshots, until native backup ships
- maintenance beyond prune: `repair`, `migrate`, key management

## Development and tests only

- The live interop tests in `src/repo.rs` use `restic::run` for `init`,
  `backup`, `forget`, `unlock`, `snapshots --json`, `check --read-data`,
  `restore`, and `prune` to prove the native lock, delete, and prune
  paths are compatible with real restic.
- The live test in `src/restic.rs` exercises the spawn harness itself
  (stdin password channel, unstick pre-check) end to end.
- `scripts/garage-e2e.sh seed` initializes and seeds the Garage S3 test
  repository with restic (requires restic >= 0.19.1).
