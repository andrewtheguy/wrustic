# Where restic is used

wrustic runs without the `restic` binary. This page is the single overview
of every workflow that still uses the restic CLI — today or by plan. The
safety rationale behind the native/CLI split (lock tiers, why prune stays
out) lives in [locking.md](locking.md) under "What writes wrustic can
safely support".

## Inside the app: nothing

No TUI flow shells out to restic. Everything wrustic does at runtime is
native:

| Workflow | Implementation |
|---|---|
| All reads (snapshot list, tree browsing, diff, file view/share, filters) | `rustic_core` |
| Snapshot delete | native, under the restic-compatible repo lock (`repo::delete_snapshot`) |
| Unlock / stale-lock removal (`u` shortcut) | native (`repo::unlock`) |

## Expected to use restic from the app (planned, not wired yet)

Prune-class operations stay on the restic CLI indefinitely (locking.md
Tier 3): **prune, repair index, migrate**. If the TUI grows an action to
trigger one of these, it will go through the secure spawn harness in
`src/restic.rs` (`restic::run`: password piped over stdin, credentials
over env vars, secrets never on argv, `--no-cache` unless the user passed
`--restic-cache`). The harness exists and is tested, but no TUI flow
calls it yet — which also means `--restic-cache` currently changes the
behavior of nothing that actually runs.

Not expected to use restic: **backup**, **copy into repo**, and **key
add** are planned as *native* operations under a non-exclusive repo lock
(locking.md Tier 1); backup is next up.

## Outside the app (run manually by the user)

These stay on a user-run `restic` (>= 0.19), outside wrustic:

- `restic init` — creating a new repository
- `restic backup` — creating snapshots, until native backup ships
- maintenance: `restic prune` / `forget --prune`, `repair`, `migrate`,
  key management

## Development and tests only

- The live interop test in `src/repo.rs` uses `restic::run` for `init`,
  `backup`, `forget`, `unlock`, and `snapshots --json` to prove the
  native lock + delete path is compatible with real restic.
- `scripts/garage-e2e.sh seed` initializes and seeds the Garage S3 test
  repository with restic (requires restic >= 0.19.1).
