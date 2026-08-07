# Where restic is used

wrustic never invokes the `restic` binary — restic is used only by the
test suite (through a secure spawn harness) and by the user, manually,
outside the app. This page is the single overview of both. The safety
rationale behind the native/CLI split (lock tiers, why prune could go
native) lives in [locking.md](locking.md) under "What writes wrustic can
safely support".

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

## Outside the app (run manually by the user)

These stay on a user-run `restic` (>= 0.19), outside wrustic — wrustic
itself will never run them:

- `restic init` — creating a new repository
- `restic backup` — creating snapshots
- maintenance beyond prune: `repair`, `migrate`, key management

Planned native: **tag edits**, under the same exclusive
restic-compatible lock as delete and prune (locking.md Tier 2, "Native
tag edits"). Description edits are not planned — `description` is a
rustic-only snapshot field that restic silently drops on any rewrite,
and wrustic only implements features common to both tools. Native
backup, copy, and key management were considered (locking.md Tier 1)
and dropped from the plan — they stay on the restic CLI indefinitely.

## Tests only

`src/restic.rs` is a **test-only** module (`#[cfg(test)]`): a secure spawn
harness (password piped over stdin, credentials over env vars, secrets
never on argv, restic's cache pointed at a `--cache-dir` private to
wrustic with `--cleanup-cache`) that the live interop tests use to drive
real restic against throwaway repos:

- The live interop tests in `src/repo.rs` use `restic::run` for `init`,
  `backup`, `forget`, `unlock`, `snapshots --json`,
  `check --read-data --json`, `restore`, and `prune` to prove the native
  lock, delete, and prune paths are compatible with real restic.
- The live test in `src/restic.rs` exercises the harness itself end to
  end (stdin password channel, plus `restic::run_unsticking_locks` — the
  native pre-spawn lock check that unlocks stale locks before running a
  restic command).
- `scripts/garage-e2e.sh seed` initializes and seeds the Garage S3 test
  repository with restic (requires restic >= 0.19.1).
