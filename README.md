# wrustic

A minimal read-only terminal UI for [restic](https://restic.net/)-format backup
repositories, built on [`rustic_core`](https://crates.io/crates/rustic_core)
and [`ratatui`](https://crates.io/crates/ratatui).

The current scope is intentionally tiny: open a **local**, **REST-server**, or
**S3** repository with credentials entered interactively, and list its
snapshots.

## Status

Implemented:
- Interactive prompts for the repository path and password (masked input)
- Snapshot listing (short ID, time, host, tags, paths), sorted by time
- Keyboard navigation (`j`/`k`, arrow keys, Home/End, `g`/`G`) and quit (`q` / Esc / Ctrl-C)
- Error screen on bad password / bad path, with retry without restarting the binary

Out of scope (by design): any write operation on the repository — init, backup,
forget, prune, key management, etc. `wrustic` is a read-only viewer.

Not yet implemented but in scope: browsing snapshot contents, restoring,
encrypted credential profiles (so you don't re-enter S3 keys every time), and
additional remote backends (SFTP via rclone, Azure / GCS via opendal — Local,
REST, and S3 are already supported).

## Build & run

Requires a Rust toolchain (developed against rustc 1.93).

```sh
cargo run
```

Then in the TUI:
1. Pick a backend on the first screen (Local / REST / S3) with `j`/`k` + Enter.
2. Fill in the per-backend prompts (Esc on any prompt goes back one step):
   - **Local**: filesystem path, e.g. `./tmp/repo`.
   - **REST**: URL, e.g. `http://localhost:8000/` or `https://user:pass@host/path/`.
   - **S3**: endpoint (blank → AWS default), bucket, region (blank → `us-east-1`),
     access key ID, secret access key (masked).
3. Type the repository password (rendered as `*`), press Enter.
4. Browse the snapshot list.

## Relationship to the `restic` binary

`wrustic` does **not** call out to the `restic` executable for anything it
supports — `rustic_core` reads the on-disk repository format natively. You do
not need `restic` installed to run `wrustic`.

You *will* want `restic` (>= 0.18.1) on your `$PATH` for development. Use it
for:

- **All write operations** (init, backup, forget, prune, copy, key management,
  …) — these are out of scope for `wrustic` and will stay that way.
- Any read operation not yet wired up in the TUI.

All dev/test artifacts in the snippets below go under the project's `./tmp/`
directory (already in `.gitignore`) rather than the system `/tmp` — this keeps
the workspace self-contained and sidesteps permission issues.

Typical dev loop to get something to point `wrustic` at:

```sh
export RESTIC_PASSWORD=test
export RESTIC_REPOSITORY=./tmp/test-repo
restic init
echo hello > ./tmp/test-file
restic backup ./tmp/test-file
restic backup --tag demo ./tmp/test-file

cargo run   # pick "Local filesystem", enter ./tmp/test-repo, then password
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
cd ./tmp
curl -fsSLO https://github.com/restic/rest-server/releases/download/v0.14.0/rest-server_0.14.0_linux_amd64.tar.gz
echo "4c9c95bc079a0334e81fad379b19dc5c3353c71c2c88d652cafce2081c2b1c66  rest-server_0.14.0_linux_amd64.tar.gz" | sha256sum -c
tar -xzf rest-server_0.14.0_linux_amd64.tar.gz
chmod +x rest-server_0.14.0_linux_amd64/rest-server   # the tarball ships mode 0644

mkdir -p ./rest-data
./rest-server_0.14.0_linux_amd64/rest-server \
    --listen :8000 --path ./rest-data --no-auth &
cd ..
```

Then seed a repo through it with `restic`, and point `wrustic` at the same URL:

```sh
export RESTIC_REPOSITORY=rest:http://localhost:8000/
export RESTIC_PASSWORD=test
restic init
echo hello > ./tmp/test-file
restic backup ./tmp/test-file
restic backup --tag demo ./tmp/test-file

cargo run   # pick "REST server", enter http://localhost:8000/, then password
```

Note: `--no-auth` is a local-only convenience. For anything outside a dev
machine, use `--htpasswd-file` and TLS per the `rest-server` documentation;
`wrustic` accepts credentials embedded in the URL (`https://user:pass@host/`).

### S3 dev workflow (via `rclone serve s3`)

`wrustic` talks S3 through opendal — there's no built-in dev S3 server. The
simplest stand-in is [`rclone serve s3`](https://rclone.org/commands/rclone_serve_s3/)
pointed at a local directory, which lets you exercise the full S3 code path
without an AWS account.

Requires `rclone` (≥ v1.73) on `$PATH`. `serve s3` is marked **Experimental**
upstream but is sufficient for dev.

```sh
mkdir -p ./tmp/s3-data/wrustic-bucket    # bucket dir must pre-exist

rclone serve s3 ./tmp/s3-data \
    --addr 127.0.0.1:8333 \
    --auth-key 'wrustic-key,wrustic-secret' \
    --force-path-style=true \
    >./tmp/rclone-s3.log 2>&1 &
```

Seed a repo through it with `restic` (uses standard AWS env vars; the region
value is meaningless to rclone but restic's SDK requires *some* region):

```sh
export AWS_ACCESS_KEY_ID=wrustic-key
export AWS_SECRET_ACCESS_KEY=wrustic-secret
export AWS_DEFAULT_REGION=us-east-1
export RESTIC_REPOSITORY=s3:http://127.0.0.1:8333/wrustic-bucket
export RESTIC_PASSWORD=test
restic init
echo hello > ./tmp/test-file
restic backup ./tmp/test-file
restic backup --tag demo ./tmp/test-file
```

Then in `wrustic`, pick **S3** and enter:

| Prompt        | Value                       |
| ------------- | --------------------------- |
| endpoint      | `http://127.0.0.1:8333`     |
| bucket        | `wrustic-bucket`            |
| region        | `us-east-1` (or leave blank)|
| access key ID | `wrustic-key`               |
| secret access | `wrustic-secret`            |
| password      | `test`                      |

Cleanup: `kill` the `rclone` process and `rm -rf ./tmp/s3-data`.

Caveats:
- `rclone serve s3` does **not** auto-create buckets; the bucket directory has
  to exist on disk before `restic init`.
- `--force-path-style=true` is required — rclone's S3 server doesn't speak
  virtual-hosted-style addressing.
- Credentials are only held in memory for the current `wrustic` session. A
  later iteration will add encrypted credential profiles so you don't re-enter
  S3 keys every time.
