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
 └── App::boot(config_dir, port, no_keychain)  // app.rs
      ├── config::paths(override) → Paths { config }
      ├── start_passphrase_flow()           // app.rs + passphrase.rs
      └── load_config_or_set_fatal()
            └── config::load(paths, cipher) → Config (with profiles decrypted)
 │
 └── while !app.quit { terminal.draw(render); dispatch }
     ├── async-ish screens (Loading, Verifying, OpeningSnapshot,
     │   LoadingDir, LoadingFileDetails, SnapshotDeleteContentsLoading,
     │   SnapshotDeleting, SnapshotCompareLoading) — main.rs runs the
     │   blocking work synchronously and transitions the screen
     ├── Screen::PassphraseDerivingKey — runs scrypt synchronously
     └── otherwise — blocking event::read(), App::handle_key/mouse
```

The event loop lives in `main.rs` rather than `App` because some screens need
to take long-blocking work out of the rendering tick. Each "async-ish" branch
matches a `Screen::*Loading` variant, runs the blocking call inline, and
transitions to the next screen — there is no real async/await in the main
loop. The share server is the only true async machinery, isolated on its own
OS thread + tokio current-thread runtime.

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
- Always-present: `screen`, `paths`, `config`, `cipher`, `server_port`.
- Profile-creation scratch (`new_profile_name`, `local_path`, …) cleared
  whenever `enter_home()` runs.
- Snapshot browse state: `snapshots`, `repo_session`, `browse_stack`,
  `pending_descend` / `pending_file_lookup` / `pending_refresh_path`.
- Share dialog: `share_target`, `share_handle`, `share_url`, etc.
- Passphrase dialog: `passphrase_input`, `passphrase_confirm`,
  `passphrase_instance_input`, `passphrase_phase`, `passphrase_error`.

Keypress handling is concentrated in `App::handle_key` (single big match on
`self.screen`); mouse in `App::handle_mouse`.

## Config + crypto

`src/config.rs` owns the TOML schema (`Config`, `Profile`,
`PassphraseMeta`) and the atomic save: write `config.toml.tmp` at mode
0600, then `rename(2)` over the target.

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

No TUI flow shells out to restic anymore, and the binary is not required
to run wrustic. Write operations without a native + locked implementation
(init, backup, prune, key management) stay on the restic CLI — when code
needs to trigger one of those (e.g. a future prune action), it goes
through the secure spawn harness kept in `src/restic.rs`, whose launch
semantics mirror resterm's:
- `restic::run(profile, args)` pipes the master password via the child's
  stdin (`--password-file /dev/stdin`) and passes the repo URL and cloud
  credentials via env vars, so secrets never appear on argv; inherited
  `RESTIC_PASSWORD*` variables are scrubbed from the child environment.
- Every call carries `--no-cache` unless the user opted in with the
  `--restic-cache` CLI flag, which points restic at a per-user directory
  private to wrustic (`~/.cache/wrustic`) — restic's default shared cache
  is never used.
- restic checks the repository lock before any of these commands run, so
  a leftover (crashed-holder) lock blocks them with "repository is
  already locked". Because the blocked process is restic itself, the
  unstick path is restic's own `unlock` run through the same harness
  (`restic::unlock`), not the native stale-lock removal in `src/lock.rs`
  (that one backs the TUI's `u` shortcut for *native* write failures).
  `restic::run_unsticking_locks(profile, args)` packages the flow the
  delete action used before it went native: run, and on a lock error
  (`lock::is_lock_error`) run `restic unlock` and retry once. `unlock`
  removes only provably-stale locks, so a live holder still fails the
  retry and the error is surfaced.

## Verification and dev flow

Run from `CLAUDE.md`:
- `cargo clippy` and `cargo test` after every change. Don't run `cargo fmt`
  — it churns the diff.
- For local testing, use `cargo run -- --config-dir ./tmp/wrustic-sandbox`
  so the production `~/.config/wrustic` is never touched.
- Test fixtures live under `./tmp/` (gitignored).
- For write operations not exposed by the TUI, use the `restic` CLI
  directly against the tmp repos.
