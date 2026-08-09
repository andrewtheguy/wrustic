# wrustic

A minimal terminal UI for [restic](https://restic.net/)-format backup
repositories, built on [`rustic_core`](https://crates.io/crates/rustic_core)
and [`ratatui`](https://crates.io/crates/ratatui).

`wrustic` is read-mostly by design: reads are native via `rustic_core`, and
the write operations it exposes (snapshot delete, tag edits) are native too,
guarded by restic-compatible repository locks (docs/locking.md). Stale-lock
removal is also native, but takes no lock itself — like `restic unlock`, it
only deletes lock files that are provably stale. Prune shells out to
`restic prune` through a secure spawn harness, and everything else that
writes stays on the `restic` CLI — docs/restic-usage.md is the overview of
exactly which workflows that means.

## Features

- **Backends**: local filesystem, REST-server, and S3
- **Profile management**: create, edit, and delete saved profiles; secrets
  (repository password, S3 keys) are encrypted per-value with AES-256-GCM
  under a passphrase-derived key
- **Snapshot browsing**: list snapshots, navigate the file tree, view file
  details, and compare two snapshots side-by-side
- **Snapshot filtering**: narrow by host, tag, or path
- **Snapshot deletion**, native and guarded by a restic-compatible exclusive
  repository lock; when the repo is locked, `u` on the error screen removes
  stale locks (live ones are kept) and retries
- **Prune** (`p` on the snapshot list): reclaim the space deleted snapshots
  left behind — runs `restic prune` (restic >= 0.19, bundled next to the
  executable or on PATH) with live progress and safe Ctrl+C cancellation;
  stale locks are removed automatically before the run via restic's own
  `unlock`
- **File sharing**: one-time signed download URLs served from localhost
- **Snapshot sharing over SMB** (`s` on the snapshot list): mount a whole
  snapshot read-only from Linux, macOS, or Windows 11 24H2+, served by a
  hand-rolled SMB 2.1 server bound to localhost, with NTLMv2 authentication
  and signing. Files mount `0444` and directories `0555` on Linux and macOS,
  and on every client opening a file for execute is refused — a share is for
  browsing a snapshot, not restoring from one; see
  [`docs/smb.md`](docs/smb.md). On Windows, `--smb-tun` serves the standard SMB
  port over a private adapter, which is both the only way to get a real UNC path
  (`\\169.254.255.1\snap`, usable in Explorer rather than only as a mapped
  drive) and the only way in from builds before 24H2; see
  [`docs/smb-tun.md`](docs/smb-tun.md)
- **Keyboard and mouse navigation**: Vim-style keys, arrow keys, PgUp/PgDn,
  mouse click/scroll; `--no-mouse` to disable
- **Passphrase entry**: masked TUI input, with optional keychain auto-unlock
- **Keychain integration** (macOS, Windows, Linux desktop): optionally save
  the passphrase to the OS credential store for auto-unlock; see
  [`docs/keychain.md`](docs/keychain.md)

See [`docs/roadmap.md`](docs/roadmap.md) for planned features.

## Install (prebuilt binary)

### Linux / macOS

A convenience script downloads the latest release binary from GitHub and
drops it at `$HOME/.local/bin/wrustic` — no `sudo`, no system-wide install.
Supported targets: `linux-amd64`, `linux-arm64`, `macos-arm64`.

```sh
curl -fsSL https://raw.githubusercontent.com/andrewtheguy/wrustic/main/install.sh | bash
```

Or clone the repo and run `./install.sh` directly. Useful flags:

- `./install.sh v0.0.1` — install a specific release tag
- `./install.sh --prerelease` — grab the latest prerelease
- `./install.sh --download-only` — drop the binary in the current directory
- `RELEASE_TAG=v0.0.1 ./install.sh` — same as passing the tag positionally

The script verifies the SHA-256 of the downloaded binary against the digest
GitHub publishes in the release metadata before installing, and runs the
binary's `--help` once to confirm it loads on the host. If `$HOME/.local/bin`
is not on your `$PATH`, the script prints the line you need to add to your
shell profile.

### Windows

Windows releases as an installer, `wrustic-windows-amd64-setup.exe` (built
with Inno Setup from `ci/windows/installer.iss`). It installs three files
side by side into `%LOCALAPPDATA%\Programs\wrustic` and adds that directory
to the **user** PATH — per-user, no admin rights:

- `wrustic.exe`
- `wintun-amd64.dll` — the signed wintun driver `--smb-tun` loads from next
  to the executable
- `restic.exe` — a pinned restic the prune flow uses (a sibling restic wins
  over PATH)

You can download and run the installer from the releases page, or use
`install.ps1`, which fetches the installer, verifies its SHA-256 against the
digest GitHub publishes in the release metadata, and runs it silently. The
script refuses to run elevated unless you pass `-Admin`.

```powershell
irm https://raw.githubusercontent.com/andrewtheguy/wrustic/main/install.ps1 | iex
```

Or clone the repo and run `.\install.ps1` directly. Useful flags:

- `.\install.ps1 <release-tag>` — install a specific release tag
- `.\install.ps1 -PreRelease` — grab the latest prerelease
- `.\install.ps1 -DownloadOnly` — drop the installer in the current directory
- `$env:RELEASE_TAG='<release-tag>'; .\install.ps1` — same as passing the tag

A piped `iex` one-liner cannot take arguments, so set
`$env:WRUSTIC_INSTALL_ARGS` instead:

```powershell
$env:WRUSTIC_INSTALL_ARGS='-PreRelease'; irm https://raw.githubusercontent.com/andrewtheguy/wrustic/main/install.ps1 | iex
```

## Build & run

Requires a Rust toolchain (rustc >= 1.89 for `std::fs::File::try_lock`;
developed against 1.93).

Platform: Linux, macOS, and Windows.

```sh
cargo run
```

### CLI flags

```text
wrustic [-c|--config-dir <PATH>] [-p|--port <N>] [--smb-port <N>] [--no-keychain] [-h|--help]
```

`--config-dir <PATH>` overrides the default config location —
`$XDG_CONFIG_HOME/wrustic` (else `~/.config/wrustic`) on Linux,
`~/Library/Application Support/wrustic` on macOS,
`%APPDATA%\wrustic` on Windows. Useful for keeping separate profile sets,
running tests, or driving an automation/CI flow against a throwaway directory:

```sh
cargo run -- --config-dir ./tmp/wrustic-sandbox
```

The directory is created on first run if it doesn't exist.

To back up your profiles, copy `config.toml` out of that directory — it is
self-contained, so that file plus your passphrase is all a restore needs:

```sh
cp "${XDG_CONFIG_HOME:-$HOME/.config}/wrustic/config.toml" ~/backups/   # Linux
cp "$HOME/Library/Application Support/wrustic/config.toml" ~/backups/   # macOS
```

```powershell
Copy-Item "$env:APPDATA\wrustic\config.toml" "$HOME\backups\"           # Windows
```

Nothing else in the directory needs copying. See
[`docs/encryption.md`](docs/encryption.md) for restore caveats (keychain
entries live in the OS credential store, not in the file) and for what a
leaked backup would expose.

Only one wrustic can use a config directory at a time. Startup takes an
exclusive lock on `<config-dir>/config.lock` and holds it until exit; a second
instance on the same directory exits with an error rather than overwriting the
first one's profiles when either saves. The lock is released by the OS even if
the process is killed, so there is nothing to clean up. To run two at once,
give each its own `--config-dir`.

`--port <N>` selects the localhost port for the file-share dialog
(default: 7834).

`--smb-port <N>` selects the localhost port for the snapshot SMB share
(default: 4456). It is fixed rather than picked per run so a mount command,
an `/etc/fstab` line, or a saved Windows drive mapping keeps working across
restarts. Mounting needs a client that can be pointed at a non-standard port:
Linux, macOS, and Windows 11 24H2 or newer all can, though on Windows that
mounts as a drive letter only, since no UNC path can carry a port. Earlier
Windows builds cannot reach a custom port at all. `--smb-tun` covers both cases
by serving the standard port; see [`docs/smb-tun.md`](docs/smb-tun.md) and
[`docs/smb.md`](docs/smb.md).

`--smb-tun` (Windows only, and only in builds compiled with
`--features smb-tun`) serves that share on SMB's standard port instead, over a
private tun adapter. Two independent reasons to want it: it is the only way to
get a real UNC path — `\\169.254.255.1\snap`, usable in Explorer's address bar
and in any program that takes one — and the only way in from Windows builds
before 11 24H2. It needs administrator rights to create the adapter and the
wintun driver (`wintun-amd64.dll`) next to the wrustic executable — the
Windows installer ships it there; a source build copies it from
`vendor/wintun/`. It leaves the host's own file sharing untouched, and while
a share is open two link-local `/32` host routes point at the tun — no subnet
is claimed. `--smb-tun-ip <IPv4>` moves them.

`--no-restic-cache` turns off restic's on-disk cache for the restic
commands wrustic shells out for (prune-class). By default those calls
keep their cache in a `wrustic` directory under the platform's per-user
cache root, private to this tool and garbage-collected by restic itself
(`--cleanup-cache`); see docs/restic-usage.md.

`--no-keychain` disables keychain integration at runtime, even when the
binary was built with the `keychain` feature. See
[`docs/keychain.md`](docs/keychain.md) for details on keychain support,
why it is not enabled on Linux by default, and how to build with it.

### First run

On first run (no existing `config.toml`), wrustic prompts for an
**instance name** — a short DNS-safe label (e.g. `laptop`, `workstation`).
Then you set a passphrase (min 12 chars, must include uppercase, lowercase,
digit, and special character). The passphrase derives a 32-byte encryption
key via scrypt; this key encrypts all secret fields in `config.toml`.

On subsequent launches, you re-enter the passphrase to unlock.

Then in the TUI:
1. The main menu lists saved profiles. Press `n` to create a new one.
2. **Create new profile**: type a profile name, pick a
   backend (Local / REST / S3), fill in the per-backend prompts (Esc on any
   prompt goes back one step):
   - **Local**: filesystem path, e.g. `./tmp/repo`.
   - **REST**: URL, e.g. `http://localhost:8000/` or `https://user:pass@host/path/`.
   - **S3**: endpoint (blank -> AWS default), bucket, region (blank -> `us-east-1`),
     access key ID, secret access key (masked).
   Finally type the repository password (masked) and press Enter — the profile
   is encrypted into `config.toml` and you return to the main menu.
3. **Open a profile**: pick a profile from the list, and the snapshot view
   opens directly. The repo password (stored encrypted in the profile) is
   applied automatically — the passphrase you entered at launch is the only
   credential you type.
4. **Delete a profile**: press `d` on a profile and confirm with `y`.

## Relationship to the `restic` binary

`wrustic` invokes the `restic` executable for exactly one feature: prune,
through a secure spawn harness (password piped over stdin, credentials
over env vars, secrets never on argv). A `restic(.exe)` sitting next to
the wrustic executable is preferred — that is how the Windows installer's
pinned restic is found — with PATH lookup as the fallback. Everything else
is native: `rustic_core` reads the on-disk repository format, and the
native write operations wrustic exposes (snapshot delete, tag edits) hold
restic-compatible repository locks, so they coexist safely with
concurrent restic processes; stale-lock removal takes no lock — like
`restic unlock`, it only deletes lock files that are provably stale.
[`docs/restic-usage.md`](docs/restic-usage.md) is the per-workflow overview
of where the restic CLI appears (the prune flow, manual use, and tests).

You *will* want `restic` (>= 0.19.0 — the release whose locking protocol and
JSON output wrustic is built against) on your `$PATH`. Use it for:

- **The prune flow** (`p` in the TUI shells out to it).
- **Write operations wrustic doesn't expose** (init, backup, copy, key
  management, …).
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
that still require the `restic` binary will shrink.

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

Requires `rclone` (>= v1.73) on `$PATH`. `serve s3` is marked **Experimental**
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
- Profiles are persisted in `~/.config/wrustic/config.toml`. Secret fields
  such as the restic password and S3 keys are encrypted per value with
  AES-256-GCM under a passphrase-derived key. The file itself is not a
  whole-file encrypted archive; see `docs/encryption.md` for the on-disk schema
  and threat model.
