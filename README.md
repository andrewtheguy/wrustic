# wrustic

A minimal read-only terminal UI for [restic](https://restic.net/)-format backup
repositories, built on [`rustic_core`](https://crates.io/crates/rustic_core)
and [`ratatui`](https://crates.io/crates/ratatui).

The current scope is intentionally tiny: open a **local** repository with a
password entered interactively, and list its snapshots.

## Status

Implemented:
- Interactive prompts for the repository path and password (masked input)
- Snapshot listing (short ID, time, host, tags, paths), sorted by time
- Keyboard navigation (`j`/`k`, arrow keys, Home/End, `g`/`G`) and quit (`q` / Esc / Ctrl-C)
- Error screen on bad password / bad path, with retry without restarting the binary

Out of scope (by design): any write operation on the repository — init, backup,
forget, prune, key management, etc. `wrustic` is a read-only viewer.

Not yet implemented but in scope: remote backends, browsing snapshot contents,
restoring.

## Build & run

Requires a Rust toolchain (developed against rustc 1.93).

```sh
cargo run
```

Then in the TUI:
1. Type the local repository path, press Enter.
2. Type the password (rendered as `*`), press Enter.
3. Browse the snapshot list.

## Relationship to the `restic` binary

`wrustic` does **not** call out to the `restic` executable for anything it
supports — `rustic_core` reads the on-disk repository format natively. You do
not need `restic` installed to run `wrustic`.

You *will* want `restic` (>= 0.18.1) on your `$PATH` for development. Use it
for:

- **All write operations** (init, backup, forget, prune, copy, key management,
  …) — these are out of scope for `wrustic` and will stay that way.
- Any read operation not yet wired up in the TUI.

Typical dev loop to get something to point `wrustic` at:

```sh
export RESTIC_PASSWORD=test
export RESTIC_REPOSITORY=/tmp/wrustic-test-repo
restic init
echo hello > /tmp/wrustic-test-file
restic backup /tmp/wrustic-test-file
restic backup --tag demo /tmp/wrustic-test-file

cargo run   # then enter the path and password above
```

As `wrustic` grows native support for more read operations, the set of things
that still require the `restic` binary will shrink — but write operations are
not on the roadmap.
