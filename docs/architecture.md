# Architecture

A working map of wrustic for anyone reading the code. Reflects current state
on `main`; if a section disagrees with the source, the source wins — please
update this file.

## What wrustic is

A read-only terminal UI for browsing restic backup repositories. It opens a
repo, lists snapshots, lets you walk the file tree, inspect file details,
diff two snapshots, and download a single file via a localhost signed URL.

**Scope: single-user, single-device.** wrustic is a personal tool — one
person, one machine (or one account on a shared box that they fully own).
Multi-user, multi-tenant, and shared-host scenarios are explicitly out of
scope: no per-user config separation, no privilege boundary inside the
binary, no defense-in-depth against another local account on the same
machine. This shapes the on-disk permissions, the threat model in
[encryption.md](encryption.md), and the choice to keep all state in one
flat `App` struct.

It is intentionally **not** a restic replacement:
- Reads go through `rustic_core` directly (no subprocess).
- The write operations wrustic exposes (snapshot delete + stale-lock
  removal today) are native too, guarded by restic-compatible repository
  locks (docs/locking.md) so they coexist safely with concurrent restic
  processes. Anything without a native + locked implementation (backup,
  prune, init, key add) is out of scope — use the `restic` CLI for those.

## Runtime shape

```
main()
 ├── config::paths(override) → Paths { dir, config, lock }
 ├── config::acquire_lock(paths) → ConfigLock   // refuse a second instance
 │                                              // before the TUI starts
 └── App::boot(paths, config_lock, port, smb_port, no_keychain)  // app.rs
      ├── start_passphrase_flow()           // app.rs + passphrase.rs
      └── load_config_or_set_fatal()
            └── config::load(paths, cipher) → Config (with profiles decrypted)
 │
 └── while !app.quit { terminal.draw(render); dispatch }
     ├── async-ish screens (Loading, Verifying, OpeningSnapshot,
     │   LoadingDir, LoadingFileDetails, SnapshotDeleteContentsLoading,
     │   SnapshotDeleting, SnapshotCompareLoading, SnapshotSmbStarting) —
     │   main.rs runs the blocking work synchronously and transitions the
     │   screen
     ├── Screen::PassphraseDerivingKey — runs scrypt synchronously
     └── otherwise — blocking event::read(), App::handle_key/mouse
```

The event loop lives in `main.rs` rather than `App` because some screens need
to take long-blocking work out of the rendering tick. Each "async-ish" branch
matches a `Screen::*Loading` variant, runs the blocking call inline, and
transitions to the next screen — there is no real async/await in the main
loop. The two servers are the only true async machinery, each isolated on its
own OS thread + tokio runtime: `share.rs` on a current-thread runtime, `smb/`
on a multi-thread one (it needs `block_in_place`, see below).

## State: `App` and `Screen`

`Screen` (in `app.rs`) is the discriminator for what's on screen. It's
about three dozen variants spanning first-run, profile CRUD, snapshot list,
snapshot delete/compare flows, tree browsing, file details, share dialog,
and passphrase dialog. Every screen is rendered by a corresponding
`render_<screen>` function in `ui.rs`.

`App` (in `app.rs`) is a flat struct holding *every* piece of session state.
This is deliberate — wrustic is small enough that a fat struct + an enum
discriminator is more legible than a nested per-screen state machine. The
struct includes:
- Always-present: `screen`, `paths`, `config_lock`, `config`, `cipher`,
  `server_port`, `smb_port`.
- Profile-creation scratch (`new_profile_name`, `local_path`, …) cleared
  whenever `enter_home()` runs.
- Snapshot browse state: `snapshots`, `repo_session`, `browse_stack`,
  `pending_descend` / `pending_file_lookup` / `pending_refresh_path`.
- Share dialog: `share_target`, `share_handle`, `share_url`, etc.
- SMB share: `smb_handle`, `smb_snapshot_id`, `smb_password`, `smb_error`.
- `help_overlay` — the `?` key list, drawn over the body of whichever screen
  is underneath.
- Passphrase dialog: `passphrase_input`, `passphrase_confirm`,
  `passphrase_instance_input`, `passphrase_phase`, `passphrase_error`.

Keypress handling is concentrated in `App::handle_key` (single big match on
`self.screen`); mouse in `App::handle_mouse`.

## Config + crypto

`src/config.rs` owns the TOML schema (`Config`, `Profile`,
`PassphraseMeta`) and the atomic save: write `config.toml.tmp` at mode
0600, then `rename(2)` over the target.

`config::acquire_lock` takes an exclusive lock on `<config-dir>/config.lock`
at startup and holds it for the process lifetime, stored on `App` as
`config_lock`. wrustic keeps the whole config in memory and rewrites the file
wholesale on every save, so a second instance on the same directory would
silently drop the first one's profiles; it is refused before the TUI starts
instead. The lock is `std::fs::File::try_lock` (stable since Rust 1.89) —
`flock(LOCK_EX | LOCK_NB)` on Unix, `LockFileEx` on Windows. No third-party
crate, and no stale-lock cleanup, because the kernel releases it when the
process dies for any reason.

Encryption is per-value (not whole-file) so non-secret edits diff cleanly.
For schema details, key derivation, threat model, and
the share-server signing-key derivation, see
[encryption.md](encryption.md).

## Localhost server (`share.rs`)

- One OS thread and one `tokio::runtime::Builder::new_current_thread`.
  No global runtime or shared executor.
- Binds on `127.0.0.1:<port>` and `[::1]:<port>`. User-facing URLs use
  `localhost`.
- Returns a `ShareHandle` that owns a
  `oneshot::Sender<()>` for shutdown plus a `JoinHandle`. Drop = stop server.
  Explicit `.stop()` joins the thread (port released by the time it returns).
- Routes are spelled out as a flat `match` inside one `async fn handle()`;
  there is no router crate.

### Share dialog (`src/share.rs`)

- Per-file: each `start()` call is bound to one `(snap_id, tree_id, name)`.
  A URL minted for file A cannot be replayed against a later server bound to
  file B — the name is part of the HMAC.
- HMAC signing key is derived from the passphrase-derived config key (via
  `passphrase::derive_share_signing_key`). Same key per passphrase → URLs
  survive across restarts within the TTL.
- Routes:
  - `GET /dl?snap=…&tree=…&exp=…&sig=…` — verifies sig + expiry, streams the
    file.
  - `GET /s/<short_id>` — 302 to the long `/dl?…` URL. `short_id` is a
    16-hex-char random alias generated at `start()`.
  - Anything else → 404.
- TTL: `SHARE_TTL = 1 h` baked into the signed `exp` claim. The server
  enforces expiry independently of any wall-clock state on its end.

### Passphrase (`src/passphrase.rs`)

No server is started. `passphrase.rs` exposes
`derive_config_key`, `verify_instance_sig`, `compute_instance_sig`, and
`passphrase_policy_error` for direct use by `app.rs`. Key derivation runs
synchronously on `Screen::PassphraseDerivingKey`.

## SMB server (`src/smb/`)

A hand-rolled read-only SMB 2.1 server exporting one snapshot, started with `s`
on the snapshot list — the only entry point there is. Full treatment — protocol
scope, security model, module map, tracing — in [smb.md](smb.md). The
architectural points:

- One OS thread and a `new_multi_thread` runtime with 2 workers, unlike
  `share.rs`. Protocol handling is synchronous code calling into `rustic_core`,
  wrapped in `tokio::task::block_in_place`; that requires a runtime that can
  hand the reactor to another worker while one is parked on a backend fetch.
- `SmbHandle` mirrors `ShareHandle`: `oneshot::Sender<()>` plus a `JoinHandle`,
  drop = stop, explicit `.stop()` joins.
- Binds `127.0.0.1` and `[::1]` via `local_server::bind_localhost`, the same
  helper the HTTP share uses. `Bind::AllInterfaces` exists but is constructed
  only by the `smb_manual_snapshot` ignored test — validating against macOS and
  Windows needs a reachable server. Nothing here is encrypted, so that stays a
  test affordance rather than a shipped option.
- The port is fixed (`--smb-port`, default 4456), not ephemeral: a mount
  outlives the screen that created it, so an fstab line has to keep resolving.
  A clash therefore surfaces inline on the share screen, with the flag that
  fixes it named in the message.
- `Backing` is a trait over `rustic_core::vfs` so the byte-exact wire encoders
  are testable against an in-memory tree with no repository.

## Repository access (`src/repo.rs`, `src/lock.rs`)

`repo.rs` is the rustic_core path — reads and the (lock-guarded) writes:
- `open_indexed(profile)` — opens with the lightweight id-only index, used
  for listing snapshots and walking trees.
- `open_indexed_full(profile)` — opens with the full blob index, used by
  the share dialog (needs to read blob bytes).
- `load_snapshots`, `list_tree`, `get_file_details`, `stream_file_content`,
  `preview_snapshot_contents`, `snapshot_root_tree`.
- `delete_snapshot(profile, id)` — native snapshot delete
  (`Repository::delete_snapshots`) under an exclusive restic-compatible
  repository lock. Full 64-char hex ids are enforced so a prefix can never
  match the wrong snapshot.
- `unlock(profile)` — native stale-lock removal, offered with `u` on the
  delete-error screen when `lock::is_lock_error()` matches the failure.
  Only locks that are provably dead are removed (older than restic's
  30-minute staleness timeout, or same-host with a gone PID); live locks —
  including a running restic's — are left alone. On success the delete
  flow re-runs from the confirmation step.

`lock.rs` implements restic 0.19's cooperative locking protocol so native
writes and concurrent restic processes block each other instead of
corrupting the repo — lock files under `locks/` are written/read in
restic's exact format (encrypted + zstd), acquisition/refresh timing
matches restic's constants, and while a lock is held the process ignores
SIGHUP (restic's staleness probe would otherwise kill the TUI). See
docs/locking.md for the full design. rustic_core itself is lock-oblivious,
so every native write MUST hold a `lock::RepoLock` — that discipline lives
in `repo.rs`, not in rustic_core.

Exactly one TUI flow shells out to restic: prune (`p` on the Snapshots
screen), which runs `restic prune` on a worker thread so the TUI stays
responsive; restic ≥ 0.19 on PATH is needed for that action alone, and
the binary is otherwise not required to run wrustic
(docs/restic-usage.md is the per-workflow overview). Write operations
without a native + locked implementation (init, backup, prune, key
management) stay on the restic CLI — when code needs to trigger one of
those, it goes through the secure spawn harness kept in `src/restic.rs`,
whose launch semantics mirror resterm's:
- `restic::run(profile, args)` pipes the master password via the child's
  stdin (`--password-file /dev/stdin`) and passes the repo URL and cloud
  credentials via env vars, so secrets never appear on argv; inherited
  `RESTIC_PASSWORD*` variables are scrubbed from the child environment.
- Every call carries `--cache-dir` pointed at a `wrustic` directory under
  the platform's own per-user cache root (`dirs::cache_dir()`: `~/.cache`
  on Linux, `~/Library/Caches` on macOS, `%LOCALAPPDATA%` on Windows),
  together with `--cleanup-cache`, which lets restic garbage collect the
  per-repository subdirectories it keeps there once they go 30 days
  unused. `--no-restic-cache` opts out and passes `--no-cache` instead —
  restic's default shared cache is never used either way. The cache path
  is independent of `--config-dir`, so instances on different config
  directories share it; that is safe, and so is the sweep, because restic
  stamps a subdirectory's timestamp when it *opens* that repository — the
  stamp is not refreshed as the command runs, so the 30-day threshold is
  what keeps an in-use cache out of reach, not the fact of it being in
  use. Lowering the threshold by hand erodes that. `restic cache`
  itself never opens the repository (no `--repo`, no password, no lock) —
  the only way to break a running command is a manual
  `cache --cleanup --max-age 0`, which ignores the in-use exemption.
- restic checks the repository lock before any of these commands run, so
  a leftover (crashed-holder) lock blocks them with "repository is
  already locked". wrustic speaks the lock protocol natively, so
  `restic::run_unsticking_locks(profile, args)` performs that same check
  itself *before* spawning: it maps the subcommand to the lock restic
  takes for it (restic 0.19.1's per-command table,
  `restic::lock_requirement`) and evaluates the repo's lock files with
  `lock::check_blocking_locks` — restic's acquisition conflict rules,
  without writing a lock. Only when blocked does it run restic's own
  `unlock` through the same harness (`restic::unlock`) and re-check —
  never the native stale-lock removal in `src/lock.rs`, which backs the
  TUI's `u` shortcut for *native* write failures. `unlock` removes only
  provably-stale locks, so a live holder still fails the re-check and
  that error (carrying the holder's details) is surfaced without
  spawning restic at all. restic re-runs the same check in-process at
  startup, so a lock appearing between our re-check and the spawn still
  fails safely inside restic.

## Verification and dev flow

Run from `CLAUDE.md`:
- `cargo clippy` and `cargo test` after every change. Don't run `cargo fmt`
  — it churns the diff.
- For local testing, use `cargo run -- --config-dir ./tmp/wrustic-sandbox`
  so the production `~/.config/wrustic` is never touched.
- Test fixtures live under `./tmp/` (gitignored). The scripts that build them
  live in `scripts/` and are tracked, so a fresh clone can recreate every
  fixture from nothing:
  - `scripts/garage-test-server.sh` / `garage-e2e.sh` — Garage S3 backend
  - `scripts/smb-sample.sh` — `seed` / `serve` / `verify` for the SMB server
    ([smb.md](smb.md))
- For write operations not exposed by the TUI, use the `restic` CLI
  directly against the tmp repos.
