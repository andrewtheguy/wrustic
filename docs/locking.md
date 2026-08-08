# Native writes with restic-compatible locking

Decision record + design for evolving wrustic from "reads native, writes
shell out to restic" into a tool that performs write operations natively
via rustic_core while safely coexisting with concurrent `restic`
processes on the same repository. The alternative considered — abandoning
this repo in favor of resterm (a pure restic-CLI wrapper) — is rejected:
rustic_core's native reads are significantly more performant, and the
locking problem turns out to be solvable.

All restic facts below were verified against the restic 0.19.1 source
(`internal/restic/lock.go`, `internal/repository/lock.go`,
`cmd/restic/lock.go`, `doc/design.rst`). rustic_core facts were verified
against rustic_core 0.12.0 as pinned in `Cargo.lock`.

## The problem

rustic_core 0.12.0 is completely lock-oblivious. Its `FileType` enum has
no `Lock` variant, so the crate cannot even address a repository's
`locks/` directory — it cannot create, read, refresh, or honor restic
lock files. Every write API it exposes (`delete_snapshots`, `backup`,
`prune`, …) will happily run while a restic process holds an exclusive
lock, and conversely a concurrent `restic prune` sees no lock from a
rustic_core write in progress. Mixing the two tools on one repo without
extra work risks corruption.

restic, on the other hand, has a well-defined cooperative locking
protocol, and any process that speaks it — writes valid lock files,
checks for conflicting ones — participates in restic's own safety
guarantees. wrustic will implement that protocol itself.

## restic's locking model (restic 0.19.1)

### Lock files

- Stored under `locks/` in the repo. Content is JSON:
  `{time, exclusive, hostname, username, pid, uid, gid}`
  (`internal/restic/lock.go:31-43`).
- Encoded like any "unpacked" repo file: JSON → zstd (repo v2) →
  encrypted with the repo master key (AES-256-CTR + Poly1305-AES MAC).
  Filename = SHA-256 of the final ciphertext.
- **A garbage/unreadable lock file makes restic fail hard** ("Fatal: …
  `unlock --remove-all`"), so wrustic's lock files must be properly
  encrypted, never placeholder bytes.

### Semantics

- **Non-exclusive ("append") lock**: holder promises to only *add* files
  and relies on nobody deleting or rewriting anything. Many may coexist —
  concurrent backups are explicitly by design (`doc/design.rst:598-609`).
- **Exclusive lock**: holder may delete/rewrite; conflicts with all other
  locks.
- Acquisition protocol (`lock.go:105-141`): list + read all existing
  locks (0-byte files ignored as interrupted uploads) → conflict check →
  write own lock file → wait 200 ms (`waitBeforeLockCheck`) → re-check;
  on conflict, remove own lock and fail with "repository is already
  locked".
- Conflict rules: creating non-exclusive conflicts only with an existing
  exclusive lock; creating exclusive conflicts with any lock.
- **Refresh**: every 5 min the holder writes a *new* lock file and
  deletes the old one (the filename changes each refresh). If a lock
  cannot be refreshed within 22.5 min (`StaleLockTimeout − 1.5 ×
  refreshInterval`), restic aborts the running operation.
- **Staleness**: another process considers a lock stale when its
  timestamp is older than 30 min (`StaleLockTimeout`), or when it was
  created on the *same host* and the PID no longer exists.
- restic 0.19 **never auto-removes stale locks during acquisition** —
  only `restic unlock` does. A crashed holder therefore blocks everyone
  until an unlock is run (this is why wrustic's `u` shortcut exists).
- `--retry-lock` (default 0 = fail fast) makes restic poll with backoff
  instead of erroring on conflict.

### ⚠ The SIGHUP probe

restic's same-host staleness check probes the lock-holder PID by sending
it **SIGHUP** (`internal/restic/lock_unix.go`), and restic installs a
SIGHUP-ignore handler so its own processes survive the probe. The default
action for SIGHUP is process termination — so if wrustic holds a lock and
someone runs `restic unlock` on the same host, restic would *kill the
wrustic TUI*. wrustic must ignore SIGHUP while it holds any lock (and
restore the default disposition afterwards, so closing the terminal still
terminates the app normally).

Windows has no SIGHUP: restic probes liveness with `OpenProcess` there
(`internal/restic/lock_windows.go`) and writes uid/gid 0 into its lock
files (no numeric user IDs on Windows). wrustic's Windows build mirrors
both — OpenProcess for the same-host staleness probe, uid/gid 0 in the
locks it writes, and no signal handling at all.

### Per-command lock usage (restic 0.19.1)

| Lock taken | Commands |
|---|---|
| non-exclusive | backup, copy (destination side), key add, restore, mount, ls, snapshots, stats, find, diff, dump, cat, list, key list |
| **exclusive** | forget (even without `--prune`), prune, tag, key remove/passwd, check, repair index/packs/snapshots, migrate, recover, rewrite `--forget` |
| none | unlock, init, self-update |

`--no-lock` is honored only by read commands (and `check`); forget/prune
refuse it outright. The read/append distinction in the source is a TODO —
both map to non-exclusive today.

## What writes wrustic can safely support

(For the user-facing summary of which workflows use the restic CLI today
vs. by plan, see [restic-usage.md](restic-usage.md); these tables are the
safety rationale behind that split.)

Restic's own table above *is* the safety map. Tiered by lock type, with
each operation's implementation status (see Phases below for the history).
Implemented today: **forget / delete snapshots** (`repo::delete_snapshot`,
the TUI delete flow), **prune** (`repo::prune`, the TUI's `p` action —
see "Native prune" below), **tag edits** (`repo::edit_snapshot_tags`,
the TUI's `t` action — see "Native tag edits" below), the **snapshot SMB
share** (a long-running *read* under the same non-exclusive lock
`restic mount` takes — see "Long-running reads" below), and — outside
these tables because it takes no lock — **unlock** (`repo::unlock`,
native stale-lock removal behind the TUI's `u` shortcut, plus the
pre-spawn unstick in `restic::run_unsticking_locks`, nowadays
test-only).

**Tier 1 — non-exclusive lock (coexists with running restic backups):**

| Operation | rustic_core API | Status | Why safe |
|---|---|---|---|
| backup | `Repository::backup` | not planned — stays on the restic CLI | pure append: packs → index → snapshot, the ordering the design doc requires for concurrent-append safety |
| copy into repo | `Repository::copy` (dest side) | not planned | append-only |
| key add | `Repository::add_key` | not planned | writes one new key file |

**Tier 2 — exclusive lock (blocks restic while held; fully safe):**

| Operation | rustic_core API | Status |
|---|---|---|
| forget / delete snapshots | `delete_snapshots` | **implemented** — `repo::delete_snapshot` (phase 2) |
| prune | `prune_plan` + `prune` | **implemented** — `repo::prune` (phase 4) |
| tag edits | raw JSON via `cat_file` + own envelope (see below) | **implemented** — `repo::edit_snapshot_tags` (phase 5) |
| description edits | `save_snapshots` + `delete_snapshots` | not planned — `description` is rustic-only; restic silently drops it on any rewrite, so wrustic only implements what both tools share |
| key remove | `delete_key` | not planned |

Apart from prune these have tiny critical sections (seconds); a
concurrent restic command gets the ordinary "repository is already
locked" error it is designed to handle. Prune holds the lock for its
whole run — exactly like `restic prune` does.

**Native prune (implemented):** `repo::prune` was originally Tier 3
("stays on the restic CLI"), on two stated grounds: rustic_core's
two-phase delete bookkeeping and its `keep_pack = 0` default. Both
concerns predate the lock module and dissolve under a real exclusive
lock; the facts below were verified against restic 0.19.1 and
rustic_core 0.12.0 source.

- *Grace periods*: restic itself has **no** time-based grace anywhere —
  its prune never reads a pack mtime (`internal/repository/prune.go`
  enumerates packs as `(id, size)` only); safety comes purely from the
  exclusive lock (`cmd_prune.go` refuses `--no-lock`). Under wrustic's
  lock there is no concurrent writer to protect, which is the same
  argument restic relies on. (`keep_pack` could not protect
  restic-written packs anyway: it compares the index entry's `time`
  field, which restic's index format doesn't have.)
- *Two-phase delete*: opt-out. `repo::prune` always sets
  `instant_delete`, and rustic_core then never writes its rustic-only
  `packs_to_delete` index extension (every `add_remove` call site in
  `commands/prune.rs` is behind `!instant_delete`) — which matters
  because restic 0.19 decodes only the `packs` key (unknown JSON keys are
  silently ignored), treats marked packs as orphans, deletes them on its
  next prune, and drops the extension when it rewrites an index. Instant
  delete *is* restic's own semantic, and needs no grace period under the
  lock (see above). `max_repack` is lifted to unlimited to match restic;
  `early_delete_index` stays off (it inverts the crash-safe ordering).
- *Resulting state*: new index files covering exactly the surviving
  packs (`supersedes` unset — restic 0.17 dropped the field), old
  indexes and unused packs deleted. restic keeps no provenance and
  re-derives everything from listing `index/` and `data/`, so this is
  indistinguishable from a restic prune. Verified live:
  `live_native_prune_interop_with_restic` (repack-forcing shape) passes
  `restic check --read-data` with zero errors and zero orphaned packs,
  restores the surviving snapshot, and a follow-up `restic prune` runs
  clean.
- *Crash safety*: rustic_core's execution order matches restic's
  spec-mandated one — write repacked packs → write new index → delete
  old indexes → delete packs — so an interruption leaves a valid repo
  plus garbage the next prune collects.
- *Lock coverage*: the exclusive lock is acquired **before planning**,
  not just execution. rustic_core's executor never re-validates the plan
  (no re-read of snapshots), so the snapshot set enumerated at plan time
  must stay frozen throughout. `RepoLock::poisoned()` (the 22.5-minute
  refreshability rule) is enforced for the whole run, through the abort
  mechanism described next.

**Cancelling a native prune (`repo::AbortSignal`):** rustic_core 0.12.0
has no cancellation API of any kind — no token, no callback that can say
"stop". The one thing it does offer is progress callbacks, ticked
continuously: per file during deletions, per blob batch during repack. So
`repo::prune`'s progress adapter consults an `AbortSignal` on every phase
start and every ~10 Hz render tick, and panics out of rustic_core's
executor when it says stop; `abort_if_signalled` catches that unwind at
the call site and returns an ordinary error. `abort` is checked at each
phase boundary too, covering a signal that lands between ticks.

Two things can raise it, and the distinction is only in the message:

- **the lock became untrustworthy** — `RepoLock::poisoned()`, restic's
  22.5-minute cutoff. Aborts planning *and* execution within roughly one
  progress tick, before further writes or deletions.
- **the user asked to stop** — Esc or Ctrl+C on the prune screen. The TUI
  stays up and the prune returns like any other failure. This replaced the
  old double-Ctrl+C force-quit, which survives only as the fallback for a
  run that has somehow stopped ticking: a *second Ctrl+C* still force-quits.
  Esc never escalates however often it is pressed — it is the "I changed my
  mind" key everywhere else in the app, and must not become a way to lose
  the lock by accident.

An abort mid-run is safe for the same reason a crash is (see *Crash
safety*), and *better* than the force-quit in one respect: the lock guard
still drops, so no stale lock is left behind.

Why a flag rather than a distinctive panic payload: prune's repack is
rayon (`into_par_iter`), which resumes a worker's original payload, but
rustic_core's other parallelism is `pariter`, whose worker-panic path
discards the payload and raises a message of its own
(`pariter/src/parallel_map.rs`). Matching on the payload is therefore
correct for only part of rustic_core. `AbortSignal` records the reason
before throwing and the catch reads that record, which is correct for all
of it — and for whatever a future version does. (Two facts that make the
whole approach viable: rustic_core defines **no `Drop` impls** at all, so
no destructor can panic during the unwind and turn it into a process
`abort()`; and wrustic sets no `panic = "abort"`.)

Tested end to end, not just in the adapter: `a_signalled_abort_unwinds_
through_the_progress_adapter` and `an_abort_is_recognised_even_when_the_
payload_is_rewritten` cover the mapper (including the pariter-style
rewrite, and that unrelated panics still resume), and three tests cancel
a *real* prune from inside rustic_core's own call stack — during planning,
during index rebuild, and inside the parallel repack
(`cancelling_inside_the_parallel_repack_unwinds_to_an_error`, whose
fixture uses incompressible data so rustic actually repacks instead of
dropping whole packs). Each asserts the phase was really reached, the
error came back as an error, the lock was released, the surviving
snapshot is intact, and the repository is still prunable afterwards.

**Native tag edits (implemented — phase 5, `repo::edit_snapshot_tags`,
the TUI's `t` on the snapshot list):** what `restic tag` does, verified
against restic 0.19.1 (`cmd/restic/cmd_tag.go`), and what wrustic
mimics. Tags only — description edits are out of scope because
`description` is a rustic-only field restic cannot preserve (see the
round-trip bullet below); wrustic implements only features common to
both tools:

- restic takes the **exclusive** lock (`openWithExclusiveLock`) even
  though the edit only touches snapshot files, and resolves the target
  snapshots *under* the lock. wrustic does the same — the snapshot is
  re-read after acquiring the lock, exactly like `repo::delete_snapshot`
  does, because the row the TUI shows was read lock-free and may have
  been retagged or deleted in the meantime (a retag changes the snapshot
  id, so a stale id fails cleanly instead of editing the wrong file).
- Edit semantics: `time` is preserved; `original` is set to the pre-edit
  id if not already set ("retain the original snapshot id over all tag
  changes"); the **new snapshot file is written first, then the old one
  deleted** (restic's `SaveSnapshot` → `RemoveUnpacked` order), so there
  is never a moment where the snapshot doesn't exist. Between those two
  steps wrustic re-reads the new file through rustic_core's decrypt path
  and compares it byte-for-byte — an envelope bug aborts before anything
  is deleted. Snapshot files are not indexed, so nothing else needs
  rebuilding; the critical section is sub-second. An unchanged tag set
  is a no-op (no rewrite, id kept) — compared as a *set*, because restic
  attaches no meaning to tag order and rustic_core models tags as a
  `BTreeSet`, so wrustic's display (and editor prefill) is always
  sorted; an order-sensitive check would rewrite untouched snapshots.
  (restic's own `tag --set` rewrites unconditionally; wrustic is
  deliberately stricter.)
- Cross-tool field round-trip (restic 0.19.1 `internal/data/snapshot.go`
  vs rustic_core 0.12.0 `SnapshotFile`): `description` (and `label`,
  `delete`) are rustic-only — restic ignores them on read and silently
  drops them when *it* rewrites the snapshot (`restic tag`/`rewrite`
  round-trip through Go structs that don't have the fields). This is why
  description edits are out of scope: the field cannot survive a mixed
  restic/wrustic workflow. Mirror image: rustic_core's `SnapshotFile`
  has no `excludes` field, so a round-trip through the typed
  `save_snapshots` API would silently drop `excludes` from a
  `restic backup --exclude` snapshot. That is why the implementation
  does **not** use the typed API: it edits the raw snapshot JSON —
  `Repository::cat_file(FileType::Snapshot, …)` under the lock, a
  `serde_json::Value` mutation touching only `tags`/`original`
  (`preserve_order` keeps the layout), sealed and written through
  wrustic's own unpacked-file envelope (`RepoCrypto` + the lock module's
  backends pointed at `snapshots/`). Every field wrustic doesn't touch —
  `excludes` included, unknown future fields too — keeps its value and
  position (reserializing may normalize JSON formatting details, such as
  Go's `\u003c` HTML escaping of `<`, but drops and reorders nothing).
  Verified live end to end:
  `live_native_tag_edit_interop_with_restic` (restic sees the new tags,
  `excludes` intact, `original` set; `restic check --read-data` passes;
  restic can itself retag the rewritten snapshot).

**Long-running reads — non-exclusive lock (implemented):** the snapshot
SMB share (`smb::start_snapshot_share`). Reads take no lock in wrustic's
other flows because they are short and restic tolerates concurrent
readers, but a share can stay mounted for hours, and "snapshots are
immutable" only holds while nothing prunes — so the share does what
`restic mount` does (`cmd_mount.go` → `openWithReadLock`): it holds a
non-exclusive lock for its lifetime, refreshed every 5 minutes. The
acquisition order in `repo::open_indexed_full_shared_lock` is open →
lock → load index, restic's order, so the served index can never
reference packs a concurrent prune deleted. Concurrent backups coexist;
prune/forget get "repository is already locked" until the share screen
closes. rustic's own webdav/mount is lock-free (rustic_core cannot even
address `locks/`) and was deliberately not followed here — lock-free
serving is exactly what breaks coexistence with restic.

Because this is wrustic's first *long-running* lock, it also implements
restic's refreshability-abort rule (`refreshabilityTimeout`,
`internal/repository/lock.go`): if the lock has not been successfully
refreshed for 22.5 min (StaleLockTimeout − 1.5 × refresh interval),
`RepoLock::poisoned()` latches true — other processes are about to judge
the lock stale and may remove it — and the TUI (which polls once a second
while the share screen is up) stops the SMB server rather than serve
unlocked. Poisoning is a latch: a refresh that succeeds after the timeout
was observed does not resurrect trust, since an unlock + prune may have
happened in the gap.

**Tier 3 — stays on a user-run restic CLI indefinitely:** repair index,
migrate. Rare, hand-run recovery/upgrade operations with no TUI action —
the user runs them with restic outside the app; wrustic itself never
spawns restic (the harness in `src/restic.rs` is test-only). (Prune sat
here until the exclusive lock landed; see "Native prune" above for why
its original rationale no longer applied.)

## wrustic lock module design

### Crypto

`Repository::key()` is public in rustic_core 0.12.0 and returns
`MasterKey`, whose fields are public raw key material
(`repofile/keyfile.rs:324`): `encrypt` (32-byte AES-256 key) and `mac.k`
/ `mac.r` (Poly1305-AES MAC keys). rustic_core's own
`encrypt_data`/`decrypt_data` are `pub(crate)` and not reachable, so
wrustic implements the small envelope itself (in `src/lock.rs`, using the
same `aes256ctr_poly1305aes` crate rustic_core uses — no hand-rolled
primitives):

- encrypted file = `nonce(16) ‖ AES-256-CTR(ciphertext) ‖ Poly1305-AES tag(16)`
  (tag over the ciphertext, mask = AES(k, nonce))
- repo v2: plaintext is `0x02 ‖ zstd(JSON)`; repo v1: raw JSON —
  distinguished on read by the first decrypted byte, exactly like
  rustic_core's `backend/decrypt.rs`

An alternative — carrying a cargo `[patch]` fork of rustic_core that adds
`FileType::Lock` — was considered and rejected: the envelope is ~60
lines, while a fork is a standing maintenance cost.

### Backend access to `locks/`

rustic_backend's backends are `FileType`-addressed and can't reach
`locks/`, so wrustic carries a tiny `LockBackend` abstraction (list /
read / write / delete a lock file) with one impl per profile type:

- **local**: `std::fs` on `<repo>/locks/` (write-then-rename so other
  processes never observe a partial lock file)
- **REST**: direct HTTP against the rest-server lock endpoints
  (`GET /locks/` list — API v2 with a v1 fallback —,
  `GET|POST|DELETE /locks/<id>`), same credentials as the profile
- **S3**: a small opendal S3 client dedicated to `locks/`
  (`src/s3_backend.rs`). Repository *data* on S3 goes through wrustic's
  own `S3DataBackend` in the same file — a read/write rustic_core backend
  over `opendal-service-s3`, sharing its operator construction with the
  lock client. It replaced rustic_backend's generic opendal backend,
  whose all-services feature pulled in ~150 crates wrustic never uses.

### Protocol implementation

A `RepoLock` guard type that mirrors restic exactly:

1. acquire (shared or exclusive): conflict-check → write own lock →
   sleep 200 ms → re-check (excluding own file) → on conflict delete own
   lock and return a typed `AlreadyLocked` error carrying the holder's
   hostname/PID/age
2. background refresh every 5 min (write new file, delete old); if
   refresh has not succeeded for 22.5 min, `poisoned()` latches true so
   the owning operation aborts (implemented; the SMB share is its first
   consumer)
3. `Drop` deletes the lock file (best effort) and restores SIGHUP
   disposition
4. staleness evaluation (30 min age, or same-host + dead PID via
   `kill(pid, 0)` — *not* SIGHUP; existence-checking is enough and never
   harms an innocent process) for display and for native unlock
5. native unlock = remove stale locks only (mirrors `restic unlock`
   without `--remove-all`)

### Test coverage of the "writes are locked" rule

The per-operation live tests below prove interop with restic, but they need
a restic binary and are `#[ignore]`d, so on their own they let a dropped
`acquire_exclusive` through a plain `cargo test`. That rule is therefore also
enforced by tests with no external dependency:
`delete_snapshot_takes_the_exclusive_lock`,
`edit_snapshot_tags_takes_the_exclusive_lock` and
`prune_takes_the_exclusive_lock` each plant a live **non-exclusive** lock —
the one a concurrent `restic backup` or a running share holds — and assert
the operation fails with restic's lock error. Since a non-exclusive lock
never blocks another non-exclusive acquisition, only an *exclusive*
acquisition can fail against it, so a lock that was dropped **or merely
downgraded** fails the test. Comparing every repository file except `locks/`
either side of the blocked attempt proves the refusal landed before the first
write rather than midway through, and the lock count afterwards proves both
that a failed acquisition cleans up after itself and that a successful
operation releases on return.

`shared_open_holds_the_append_lock_for_the_handle_lifetime` covers the other
direction: the guard `open_indexed_full_shared_lock` hands back is held for
as long as the repository handle lives, tolerates a second append lock, and
blocks native writes until it drops —
`smb::tests::snapshot_share_holds_restics_append_lock` checks the same
properties through the share itself.

These fixtures are built in-process with rustic_core's `init`/`backup`
(`src/testrepo.rs`, `#[cfg(test)]`), which is what frees them from the restic
binary; `init`/`backup` remain non-features of wrustic itself (Tier 1 above),
exactly as `src/restic.rs` is test-only. Because restic's key file is
scrypt-derived, every repository open runs a full KDF — unoptimised that is
~10 s per open, so `Cargo.toml` raises `opt-level` for the scrypt crates in
the dev profile only.

## Phases

1. **Lock module** — DONE (`src/lock.rs` + `LockBackend` impls in
   `src/lock.rs`/`src/s3_backend.rs`). Unit tests cover the envelope,
   restic's JSON schema, conflict rules, staleness, the refresh cycle
   (via a test-only shortened interval: new file appears, old removed,
   never zero locks), the grace-window back-off (a competing lock planted
   between write and re-check makes acquisition remove its own lock and
   fail), simultaneous two-thread acquisition (never two holders, no
   orphaned lock files), SIGHUP disposition (ignored while any lock is
   held — the process survives a raised SIGHUP — restored after the last
   release), and `RestLockBackend` against an in-process rest-server mock
   (API v2 list with sizes, v1 name-array fallback, 404 semantics, basic
   auth on every request). Because signal disposition is process-global,
   every test that acquires a `RepoLock` serializes on
   `lock::test_acquire_guard()`. Live tests (`cargo test -- --ignored`):
   `live_native_lock_and_delete_interop_with_restic` proves interop from
   restic's side — `restic forget` is blocked by our exclusive lock with
   "already locked" (so restic lists *and decrypts* our lock files), and
   `restic unlock` leaves our fresh lock in place — and
   `live_garage_s3_lock_backend_cycle` runs the raw file ops plus the
   full acquire/conflict/release/stale-removal protocol against a real
   Garage S3 server (`scripts/garage-test-server.sh`).
2. **Native forget/delete** — DONE. The delete flow's `restic forget`
   subprocess became `Repository::delete_snapshots` under a native
   exclusive lock (`repo::delete_snapshot`), and the `u` shortcut's
   `restic unlock` became native stale-lock removal (`repo::unlock`).
   The restic/rustic metadata cross-check and `restic snapshots --json`
   fetch went away with it; from then until phase 4 the only feature that
   needed the restic binary was the TUI's prune action (`p` on the
   Snapshots screen).
   `src/restic.rs` is the secure spawn harness (stdin-piped
   password, env-var credentials, resterm's launch semantics including
   its private cache directory) the live tests use to drive restic —
   dev-flow repo setup plus restic-side observations; since phase 4 it
   is a `#[cfg(test)]`-only module, as wrustic itself never spawns
   restic. Before spawning a lock-taking command,
   `restic::run_unsticking_locks` performs restic's acquisition conflict
   check natively: the subcommand maps to the lock restic takes for it
   (the per-command table above) and `lock::check_blocking_locks`
   evaluates the repo's lock files under restic's rules without writing
   one. Only when blocked does it run restic's own `unlock` through the
   same harness — not native stale-lock removal, which serves the native
   flows — and re-check; a live lock fails the re-check and its holder
   details are surfaced without spawning restic. restic's own in-process
   check at startup remains the authoritative gate against races.
3. **SMB share under a non-exclusive lock** — DONE. The snapshot SMB
   server holds the lock `restic mount` takes for as long as the share
   runs (see "Long-running reads" above). This brought the
   refreshability-abort rule with it: `RepoLock::poisoned()` implements
   restic's 22.5-minute cutoff, the main loop polls it once a second on
   the share screen and tears the server down when it trips. Verified
   live against restic 0.19.1: `restic forget` is blocked by the share's
   lock with the ordinary "already locked" message naming our PID,
   `restic snapshots` coexists, and `restic unlock` leaves the fresh lock
   in place (and its SIGHUP probe doesn't kill the process). On a lock
   conflict at share start, the share screen offers `u` — native
   stale-lock removal, then retry.
4. **Native prune** — DONE. The TUI's last restic shell-out became
   `repo::prune`: rustic_core's `prune_plan` + `prune` with instant
   delete under the native exclusive lock, acquired before planning and
   poison-checked after it (see "Native prune" above for the full safety
   argument). The old prune-specific machinery in `src/restic.rs`
   (version detection, the streaming runner, the child tracker) went
   away with it, and the harness itself became test-only — wrustic never
   spawns restic; the restic CLI is for the user (Tier 3, init, backup)
   and for the live tests.
   Verified live: `live_native_prune_interop_with_restic` forces a
   repack, then passes `restic check --read-data` with zero errors and
   zero orphans, restores the surviving snapshot through restic, and a
   follow-up `restic prune` runs clean.
5. **Native tag edits** — DONE (`repo::edit_snapshot_tags`, the TUI's
   `t` on the snapshot list; see "Native tag edits" above for the full
   design). The exclusive lock, resolve-under-lock, `original`
   retention, and write-verify-then-delete ordering all mirror restic;
   the rewrite goes through raw JSON so restic-only fields like
   `excludes` survive. A lock conflict offers `u` (native stale-lock
   removal) and retries the same edit, like the delete flow. Description
   edits are out of scope (rustic-only field, not restic-preservable).
   Native backup / copy / key management, formerly this phase, were
   dropped from the plan — the restic CLI keeps them.

Non-goals: native backup, copy, and key management (the restic CLI
keeps them; the Tier 1 rows above remain as the safety map should that
ever change), native repair/migrate (Tier 3), multi-host clock-skew
mitigation beyond what restic itself does, and any restic < 0.19
compatibility.
