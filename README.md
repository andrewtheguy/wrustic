# wrustic

A minimal read-only terminal UI for [restic](https://restic.net/)-format backup
repositories, built on [`rustic_core`](https://crates.io/crates/rustic_core)
and [`ratatui`](https://crates.io/crates/ratatui).

The current scope is intentionally tiny: open a **local** or **REST-server**
repository with a password entered interactively, and list its snapshots.

## Status

Implemented:
- Interactive prompts for the repository path and password (masked input)
- Snapshot listing (short ID, time, host, tags, paths), sorted by time
- Keyboard navigation (`j`/`k`, arrow keys, Home/End, `g`/`G`) and quit (`q` / Esc / Ctrl-C)
- Error screen on bad password / bad path, with retry without restarting the binary

Out of scope (by design): any write operation on the repository — init, backup,
forget, prune, key management, etc. `wrustic` is a read-only viewer.

Not yet implemented but in scope: browsing snapshot contents, restoring, and
additional remote backends (SFTP via rclone, S3 / Azure / GCS via opendal — REST
is already supported).

## Build & run

Requires a Rust toolchain (developed against rustc 1.93).

```sh
cargo run
```

Then in the TUI:
1. Type the repository — either a local path (e.g. `/tmp/repo`) or a REST URL
   (e.g. `rest:http://localhost:8000/` or `rest:https://user:pass@host/path/`)
   — and press Enter.
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

### REST-server dev workflow

`wrustic` speaks the [restic REST
protocol](https://github.com/restic/rest-server) directly (via `reqwest`); it
does **not** invoke the `rest-server` binary at runtime. `rest-server` is
purely a dev/test peer — the easiest way to exercise the REST code path
locally.

Fetch and run [rest-server v0.14.0](https://github.com/restic/rest-server/releases/tag/v0.14.0)
(substitute the asset for your platform):

```sh
curl -fsSLO https://github.com/restic/rest-server/releases/download/v0.14.0/rest-server_0.14.0_linux_amd64.tar.gz
echo "4c9c95bc079a0334e81fad379b19dc5c3353c71c2c88d652cafce2081c2b1c66  rest-server_0.14.0_linux_amd64.tar.gz" | sha256sum -c
tar -xzf rest-server_0.14.0_linux_amd64.tar.gz
chmod +x rest-server_0.14.0_linux_amd64/rest-server   # the tarball ships mode 0644

mkdir -p /tmp/wrustic-rest-data
./rest-server_0.14.0_linux_amd64/rest-server \
    --listen :8000 --path /tmp/wrustic-rest-data --no-auth &
```

Then seed a repo through it with `restic`, and point `wrustic` at the same URL:

```sh
export RESTIC_REPOSITORY=rest:http://localhost:8000/
export RESTIC_PASSWORD=test
restic init
echo hello > /tmp/wrustic-test-file
restic backup /tmp/wrustic-test-file
restic backup --tag demo /tmp/wrustic-test-file

cargo run    # enter:  rest:http://localhost:8000/   then:  test
```

Note: `--no-auth` is a local-only convenience. For anything outside a dev
machine, use `--htpasswd-file` and TLS per the `rest-server` documentation;
`wrustic` accepts credentials embedded in the URL
(`rest:https://user:pass@host/`).
