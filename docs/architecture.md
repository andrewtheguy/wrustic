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
- Write operations that wrustic exposes (only `forget` today) shell out to the
  `restic` CLI rather than reimplementing them. Anything more complex (backup,
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

## Repository access (`src/repo.rs`, `src/restic.rs`)

`repo.rs` is the read path through `rustic_core`:
- `open_indexed(profile)` — opens with the lightweight id-only index, used
  for listing snapshots and walking trees.
- `open_indexed_full(profile)` — opens with the full blob index, used by
  the share dialog (needs to read blob bytes).
- `load_snapshots`, `list_tree`, `get_file_details`, `stream_file_content`,
  `preview_snapshot_contents`, `snapshot_root_tree`.

`restic.rs` is the write path (via subprocess):
- `detect()` — checks `restic version` is on PATH; surfaced to the TUI in
  the verify dialog.
- `forget(profile, snapshot_id)` — `restic forget <id>` (snapshot delete).
- `diff(profile, a, b)` — `restic diff` parser; the result populates the
  compare screen.
- `snapshot_details_json` — `restic snapshots --json <id>` for the delete
  confirmation screen.

The split is intentional: anything that touches the on-disk repo state
goes through the CLI so we don't have to track invariants in two places. If
a write needs to grow beyond what `restic` itself can do, that's a signal
the work belongs upstream, not in wrustic.

## Verification and dev flow

Run from `CLAUDE.md`:
- `cargo clippy` and `cargo test` after every change. Don't run `cargo fmt`
  — it churns the diff.
- For local testing, use `cargo run -- --config-dir ./tmp/wrustic-sandbox`
  so the production `~/.config/wrustic` is never touched.
- Test fixtures live under `./tmp/` (gitignored).
- For write operations not exposed by the TUI, use the `restic` CLI
  directly against the tmp repos.
