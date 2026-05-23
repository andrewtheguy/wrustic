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

## Module layout (`src/*.rs`)

| Module | Lines | Role |
|---|---:|---|
| `main.rs` | ~370 | Entry point, terminal setup, event loop, async-screen driving |
| `app.rs` | ~2300 | `App` state, `Screen` enum, all key/mouse handlers, save flow |
| `ui.rs` | ~1220 | ratatui renderer — one `render_*` fn per screen, no logic |
| `cli.rs` | ~95 | Hand-rolled flag parser (`--config-dir`, `--port`, `--experimental-passkey`) |
| `config.rs` | ~990 | TOML schema, atomic save, peek (no-decrypt), cipher marker check |
| `crypto.rs` | ~225 | `Cipher` enum: age x25519 and passkey ChaCha20-Poly1305; per-value AEAD |
| `repo.rs` | ~385 | `rustic_core` wrappers: open, snapshots, list tree, file details, stream |
| `restic.rs` | ~740 | `restic` CLI shell-outs: detect, snapshot details JSON, forget, diff |
| `share.rs` | ~870 | Localhost server that serves one file via HMAC-signed URL |
| `passkey.rs` | ~950 | Localhost ceremony server for WebAuthn PRF unlock (experimental) |

The codebase is one binary crate, no library, no workspace.

## Runtime shape

```
main()
 └── App::boot(config_dir, port, experimental_passkey)        // app.rs
      ├── config::paths(override) → Paths { identity, config }
      ├── (age mode)     load_age_cipher(age.key) → Cipher::Age
      ├── (passkey mode) start_passkey_ceremony()              // app.rs + passkey.rs
      └── load_config_or_set_fatal()
            └── config::load(paths, cipher) → Config (with profiles decrypted)
 │
 └── while !app.quit { terminal.draw(render); dispatch }
     ├── async-ish screens (Loading, Verifying, OpeningSnapshot,
     │   LoadingDir, LoadingFileDetails, SnapshotDeleteContentsLoading,
     │   SnapshotDeleting, SnapshotCompareLoading) — main.rs runs the
     │   blocking work synchronously and transitions the screen
     ├── Screen::PasskeyUrl — short timeout poll so try_advance_passkey
     │   can pick up the mpsc message from passkey.rs without a keypress
     └── otherwise — blocking event::read(), App::handle_key/mouse
```

The event loop lives in `main.rs` rather than `App` because some screens need
to take long-blocking work out of the rendering tick. Each "async-ish" branch
matches a `Screen::*Loading` variant, runs the blocking call inline, and
transitions to the next screen — there is no real async/await in the main
loop. The two localhost servers (share, passkey) are the only true async
machinery, each isolated on its own OS thread + tokio current-thread runtime.

## State: `App` and `Screen`

`Screen` (in `app.rs:30`) is the discriminator for what's on screen. It's
about three dozen variants spanning first-run, profile CRUD, snapshot list,
snapshot delete/compare flows, tree browsing, file details, share dialog,
and passkey dialog. Every screen is rendered by a corresponding
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
- Passkey dialog: `passkey_handle`, `passkey_short_url`, `passkey_phase`.

Keypress handling is concentrated in `App::handle_key` (single big match on
`self.screen`); mouse in `App::handle_mouse`.

## Config + crypto

`src/config.rs` owns the TOML schema (`Config`, `Profile`, `PasskeyMeta`)
and the atomic save: write `config.toml.tmp` at mode 0600, then `rename(2)`
over the target.

Two ciphers are supported, per-value (not whole-file) so non-secret edits
diff cleanly: age x25519 (`ageenc:` prefix, default) and ChaCha20-Poly1305
keyed from a WebAuthn PRF output (`pkenc:` prefix, behind
`--experimental-passkey`). The two are deliberately non-interoperable —
the on-disk `cipher` marker plus a value-level prefix check on every
decrypt keeps them from ever mixing.

A `config::peek` helper parses the TOML *without* applying any cipher, so
the boot code can read the `[passkey]` block before the cipher itself
exists. That resolves the chicken-and-egg between "need the salt to do
the ceremony" and "need the ceremony to derive the cipher."

For schema details, key derivation, threat model, and the share-server
signing-key derivation, see [encryption.md](encryption.md).

## Localhost servers (`share.rs`, `passkey.rs`)

Both servers follow the same shape so the patterns transfer:

- One OS thread per server, one `tokio::runtime::Builder::new_current_thread`
  per thread. No global runtime, no shared executor.
- Bind on `127.0.0.1:<port>`. User-facing URLs use `localhost` for browser /
  authenticator compatibility.
- The two servers share the **same port** (`--port`, default 7834) because
  share and passkey dialogs are never simultaneously active.
- Each returns a handle (`ShareHandle`, `PasskeyHandle`) that owns a
  `oneshot::Sender<()>` for shutdown plus a `JoinHandle`. Drop = stop server.
  Explicit `.stop()` joins the thread (port released by the time it returns).
- Routes are spelled out as a flat `match` inside one `async fn handle()`;
  there is no router crate.

### Share dialog (`src/share.rs`)

- Per-file: each `start()` call is bound to one `(snap_id, tree_id, name)`.
  A URL minted for file A cannot be replayed against a later server bound to
  file B — the name is part of the HMAC.
- HMAC signing key is derived from the age identity bytes (age mode) or from
  the passkey PRF output (passkey mode, via `passkey::derive_share_signing_key`).
  Same key per identity → URLs survive across restarts within the TTL.
- Routes:
  - `GET /dl?snap=…&tree=…&exp=…&sig=…` — verifies sig + expiry, streams the
    file.
  - `GET /s/<short_id>` — 302 to the long `/dl?…` URL. `short_id` is a
    16-hex-char random alias generated at `start()`.
  - Anything else → 404.
- TTL: `SHARE_TTL = 1 h` baked into the signed `exp` claim. The server
  enforces expiry independently of any wall-clock state on its end.

### Passkey ceremony (`src/passkey.rs`, experimental)

This is the other localhost server — same shape as the share dialog (own OS
thread, current-thread tokio runtime, RAII handle), but bidirectional: the
browser POSTs the WebAuthn PRF output back to localhost, and the server
hands it to the App via an mpsc channel that the main loop polls every
150 ms while `Screen::PasskeyUrl` is up (see `main.rs:277`).

Auth, routing, the `/auth/<key>` capability URL, Setup vs Unlock phases,
the 30-minute expiry net, and the cryptographic key derivation all live in
[encryption.md](encryption.md). The server is in this same `Localhost
servers` family only as far as the runtime shape goes.

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
