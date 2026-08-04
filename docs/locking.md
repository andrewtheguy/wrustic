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

Restic's own table above *is* the safety map. Tiered by lock type:

**Tier 1 — non-exclusive lock (coexists with running restic backups):**

| Operation | rustic_core API | Why safe |
|---|---|---|
| backup | `Repository::backup` | pure append: packs → index → snapshot, the ordering the design doc requires for concurrent-append safety |
| copy into repo | `Repository::copy` (dest side) | append-only |
| key add | `Repository::add_key` | writes one new key file |

**Tier 2 — exclusive lock (blocks restic briefly; fully safe):**

| Operation | rustic_core API |
|---|---|
| forget / delete snapshots | `delete_snapshots` |
| tag / description edits | `save_snapshots` + `delete_snapshots` |
| key remove | `delete_key` |

These have tiny critical sections (seconds); a concurrent restic command
gets the ordinary "repository is already locked" error it is designed to
handle.

**Tier 3 — stays on the restic CLI indefinitely:** prune, repair index,
migrate. Technically possible under an exclusive lock, but rustic_core's
prune semantics differ from restic's (two-phase delete with 23 h
`keep_delete`; `keep_pack` defaults to 0 so concurrently-written packs
get no grace period), and mixing two prune implementations on one repo is
where the real blast radius lives. No plan to go native here.

## wrustic lock module design

### Crypto

`Repository::key()` is public in rustic_core 0.12.0 and returns
`MasterKey`, whose fields are public raw key material
(`repofile/keyfile.rs:324`): `encrypt` (32-byte AES-256 key) and `mac.k`
/ `mac.r` (Poly1305-AES MAC keys). rustic_core's own
`encrypt_data`/`decrypt_data` are `pub(crate)` and not reachable, so
wrustic implements the small envelope itself:

- encrypted file = `nonce(16) ‖ AES-256-CTR(ciphertext) ‖ Poly1305-AES tag(16)`
  (tag over the ciphertext, mask = AES(k, nonce))
- repo v2: plaintext is zstd-compressed with restic's unpacked-file
  framing; repo v1: raw JSON (mirror what rustic_core's
  `backend/decrypt.rs` does — the implementation must match it exactly)

An alternative — carrying a cargo `[patch]` fork of rustic_core that adds
`FileType::Lock` — was considered and rejected for now: the envelope is
~100 lines, while a fork is a standing maintenance cost.

### Backend access to `locks/`

rustic_backend's backends are `FileType`-addressed and can't reach
`locks/`, so wrustic carries a tiny `LockBackend` abstraction (list /
read / write / delete a lock file) with one impl per profile type:

- **local**: `std::fs` on `<repo>/locks/`
- **REST**: direct HTTP against the rest-server lock endpoints
  (`GET /locks/` list, `GET|POST|DELETE /locks/<id>`), same credentials
  as the profile
- **S3**: extend `src/s3_backend.rs` with lock object operations. The
  backend's rustic-facing `WriteBackend` impl stays read-only; lock
  writes go through separate methods that are not part of that trait, so
  the "repository writes must use restic CLI" invariant is narrowed to
  "repository *data* writes" — locks are coordination metadata, not data.

### Protocol implementation

A `RepoLock` guard type that mirrors restic exactly:

1. acquire (shared or exclusive): conflict-check → write own lock →
   sleep 200 ms → re-check (excluding own file) → on conflict delete own
   lock and return a typed `AlreadyLocked` error carrying the holder's
   hostname/PID/age
2. background refresh every 5 min (write new file, delete old); if
   refresh has not succeeded for 22.5 min, mark the lock poisoned so the
   owning operation aborts
3. `Drop` deletes the lock file (best effort) and restores SIGHUP
   disposition
4. staleness evaluation (30 min age, or same-host + dead PID via
   `kill(pid, 0)` — *not* SIGHUP; existence-checking is enough and never
   harms an innocent process) for display and for native unlock
5. native unlock = remove stale locks only (mirrors `restic unlock`
   without `--remove-all`)

## Phases

1. **Lock module** (`src/lock.rs` + `LockBackend` impls): everything
   above, with unit tests against fixtures and a round-trip test that
   restic itself can read wrustic's lock files (dev-flow: create lock via
   wrustic, run `restic forget --dry-run` expecting the lock error… write
   ops in dev flows still use the restic CLI per CLAUDE.md until this
   lands).
2. **Native forget/delete — immediate next step once locks work**:
   replace the delete flow's `restic forget` subprocess with
   `Repository::delete_snapshots` under a native exclusive lock, and the
   `u`-shortcut's `restic unlock` subprocess with native stale-lock
   removal. The restic/rustic metadata cross-check and the
   `restic snapshots --json` fetch go away with it — the delete path
   becomes rustic-only, and the restic binary is no longer needed at
   runtime for any current wrustic feature.
3. **Native backup** under a non-exclusive lock (the headline win:
   wrustic backups running concurrently with restic cron backups), then
   copy / key add as wanted.

Non-goals: native prune/repair/migrate (Tier 3), multi-host clock-skew
mitigation beyond what restic itself does, and any restic < 0.19
compatibility.

Once phase 2 lands, the CLAUDE.md rule "use restic cli only for write
operations" changes to: *native writes are allowed for operations covered
by the lock module; prune/repair/migrate and dev-flow repo setup stay on
the restic CLI.*
