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
- **Profile management**: create, edit, and delete saved profiles; repository
  passwords, REST passwords, and S3 secret access keys are encrypted per-value
  with AES-256-GCM under a passphrase-derived key
- **Snapshot browsing**: list snapshots, navigate the file tree, view file
  details, and compare two snapshots side-by-side
- **Snapshot filtering**: narrow by host, tag, or path
- **Snapshot deletion**, native and guarded by a restic-compatible exclusive
  repository lock; when the repo is locked, `u` on the error screen removes
  stale locks (live ones are kept) and retries
- **Prune** (`p` on the snapshot list): reclaim the space deleted snapshots
  left behind — runs `restic prune` (restic >= 0.19, the one the installers
  bundle and only that one) with live progress and safe Ctrl+C
  cancellation;
  stale locks are removed automatically before the run via restic's own
  `unlock`
- **File sharing**: one-time signed download URLs served from localhost
- **Snapshot sharing over SMB** (`s` on the snapshot list): mount a whole
  snapshot read-only from Linux, macOS, or Windows 11 24H2+. The SMB 2.1
  protocol and transport are the
  [smbanything](https://github.com/andrewtheguy/smbanything) project's
  `smbanything_core` crate; wrustic supplies the restic snapshot backing and
  ties the server's lifetime to the repository lock. Bound to localhost, with
  NTLMv2 authentication and signing. Files mount `0444` and directories `0555` on Linux and macOS,
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

## Install (packages)

A release ships packages only — a `.deb`, `.rpm`, `.pkg`, or the Windows
installer. Each lays down the program files only (config, state, and the
restic cache stay per-user, derived from the running user's profile at
runtime) and, crucially, a pinned restic in a `restic` subdirectory next to
the wrustic binary. wrustic prunes with **that** restic or none: it never
falls back to a `restic` on PATH, so which binary touches a repository is
decided by what was installed rather than by the machine's PATH. That is
also why there is no bare-binary download and no curl-to-shell install
script — an unpackaged copy would have no restic to run.

### Linux (.deb)

Each release ships `wrustic-linux-amd64.deb` / `wrustic-linux-arm64.deb`. The
package installs `/opt/wrustic/wrustic` and the pinned restic at
`/opt/wrustic/restic/restic` (the subdirectory keeps it from ever being a
terminal-visible `restic`), plus a `/usr/bin/wrustic` symlink:

```sh
sudo apt install ./wrustic-linux-amd64.deb   # or: sudo dpkg -i ...
```

### Linux (.rpm)

Same layout for Fedora / RHEL / openSUSE, as
`wrustic-linux-amd64.rpm` / `wrustic-linux-arm64.rpm`:

```sh
sudo dnf install ./wrustic-linux-amd64.rpm   # or: sudo rpm -i ...
```

### macOS (.pkg)

Each release ships `wrustic-macos-arm64.pkg` with the same layout —
`/opt/wrustic/wrustic`, the pinned `/opt/wrustic/restic/restic`, and a
`/usr/local/bin/wrustic` symlink. The package is unsigned and not notarized,
so Gatekeeper refuses a browser-downloaded copy; fetch it with `curl` (which
sets no quarantine flag) and install from the terminal instead:

```sh
curl -fsSLO https://github.com/andrewtheguy/wrustic/releases/latest/download/wrustic-macos-arm64.pkg
sudo installer -pkg wrustic-macos-arm64.pkg -target /
```

The package installs its own uninstaller at `/opt/wrustic/uninstall.sh`
(source: `ci/macos/uninstall.sh`). It removes `/opt/wrustic`, the
`/usr/local/bin/wrustic` symlink — only while that symlink still points into
`/opt/wrustic` — and the installer receipt:

```sh
sudo /opt/wrustic/uninstall.sh             # --dry-run first to see the list
```

That leaves this user's data alone. Add `--purge` to delete it too: the config
directory, the restic cache wrustic keeps for itself, and any passphrases
saved in the login keychain. Backup repositories are never touched either way.

### Windows

Windows releases as an installer, `wrustic-windows-amd64-setup.exe` (built
with Inno Setup from `ci/windows/installer.iss`). It installs machine-wide
(elevated) into `%ProgramFiles%\wrustic` and adds that directory to the
**system** PATH:

- `wrustic.exe`
- `wintun-amd64.dll` — the signed wintun driver `--smb-tun` loads from next
  to the executable
- `restic\restic.exe` — the pinned restic the prune flow runs, and the only
  one it will run. It sits in a subdirectory on purpose: only the install
  directory itself joins the system PATH, so the bundled restic never
  shadows or becomes a terminal-visible `restic`

Download the installer from the releases page and run it (elevated).

## Build & run

Requires a Rust toolchain (rustc >= 1.89 for `std::fs::File::try_lock`;
developed against 1.93).

Platform: Linux, macOS, and Windows.

```sh
cargo run
```

A binary built from a checkout resolves its restic exactly like an installed
one — `restic/restic(.exe)` next to itself, never PATH — so the prune flow
needs a restic >= 0.19 copied to `target/debug/restic/` (and to
`target/debug/deps/restic/` for the `#[ignore]`d live tests, which spawn
restic through the same harness). Everything else works with no restic at
all.

### CLI flags

```text
wrustic [-d|--config-dir <PATH>] [-p|--port <N>] [--smb-port <N>] [--no-restic-cache] [--no-keychain] [-h|--help]
wrustic env <PROFILE> [--json]
wrustic profiles [--json]
```

`--config-dir <PATH>` overrides the default config location —
`$XDG_CONFIG_HOME/wrustic` (else `~/.config/wrustic`) on Linux,
`~/Library/Application Support/wrustic` on macOS,
`%APPDATA%\wrustic` on Windows. The `WRUSTIC_CONFIG_DIR` environment variable
sets the same thing with lower precedence (`-d` flag beats it, it beats the
platform default; an empty value counts as unset) — set it once when the
config lives somewhere non-default, e.g. inside a versioned repo, so plain
`wrustic` and `wrustic env` find it without the flag. Also useful for keeping
separate profile sets, running tests, or driving an automation/CI flow
against a throwaway directory:

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

### Headless automation: `env` and `profiles`

Backup scripts and scheduled tasks can pull a profile's credentials out of the
encrypted config without starting the TUI:

```sh
wrustic profiles              # profile names, one per line (no passphrase needed)
wrustic env myrepo            # KEY=VALUE lines for restic
wrustic env myrepo --json     # same as a JSON object
```

`env` prints the environment restic needs for the profile: `RESTIC_REPOSITORY`
(REST credentials embedded in the URL), `RESTIC_PASSWORD`, and for S3 backends
`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_DEFAULT_REGION`. The
config passphrase comes from the `WRUSTIC_PASSPHRASE` environment variable if
set, otherwise from the file named by `WRUSTIC_PASSPHRASE_FILE`, otherwise
from the OS keychain entry saved by the TUI's "save passphrase to keychain"
option — so on a machine where that option is enabled, `wrustic env` works
unattended. When no source has the passphrase and stdin is a terminal, `env`
falls back to a hidden prompt on the terminal itself (so it still works while
a script captures stdout); without a terminal — a scheduled task, cron, a
keychain-less Linux host — it fails with a non-zero exit instead of hanging.
Both commands are read-only and skip the config-directory lock, so they keep
working while a TUI session is open.

Both variables unlock the TUI as well: with either set, `wrustic` goes
straight from launch to the profile list, skipping the unlock-method choice
and the passphrase prompt. A wrong or unreadable one is not fatal there the
way it is headless — a human is at the terminal — but it is never swallowed:
the unlock screen names the variable and takes the passphrase by hand
instead. Setup is unaffected; a brand-new config still has its passphrase
chosen in the TUI.

`WRUSTIC_PASSPHRASE_FILE` is the option for hosts with no keychain, where
putting the passphrase in the environment would expose it to every process
that can read `/proc/<pid>/environ` or a crash dump. The file holds the
passphrase and nothing else; one trailing line ending is stripped, so an
editor's newline is fine, but leading and interior whitespace is part of the
secret. Protect it with the filesystem — `chmod 600` and an owner that only
the backup account has. Type the passphrase into a hidden prompt rather than
putting it on a command line, where it would land in the shell history and in
every process list on the machine:

```sh
install -m 600 /dev/null ~/.config/wrustic/passphrase
IFS= read -r -s -p 'Config passphrase: ' pass && printf '%s' "$pass" \
  > ~/.config/wrustic/passphrase
unset pass; echo
WRUSTIC_PASSPHRASE_FILE=~/.config/wrustic/passphrase wrustic env myrepo
```

(`IFS= read -r` keeps leading whitespace and backslashes verbatim; `-s` keeps
the passphrase off the screen.)

A `WRUSTIC_PASSPHRASE_FILE` that is missing, unreadable, or empty is an
error — `env` does not quietly fall through to the keychain, so a broken
path is reported the first time it is used rather than the first time the
keychain is gone.

To try any of this without touching your own config, build a throwaway one:

```sh
cargo test --all-features -- --ignored --nocapture sandbox_config
```

That writes `tmp/wrustic-sandbox/` — one local profile behind a known
passphrase, and that passphrase in a file — and prints the commands to run
against it. Neither of them should ask for anything:

```sh
WRUSTIC_PASSPHRASE='Sandbox Pass 1!' \
  cargo run --all-features -- --config-dir ./tmp/wrustic-sandbox env sample

WRUSTIC_PASSPHRASE_FILE=tmp/wrustic-sandbox/passphrase \
  cargo run --all-features -- --config-dir ./tmp/wrustic-sandbox env sample
```

Drop `env sample` from either line to check the TUI the same way: it opens on
the profile list rather than the unlock screen. `rm -rf tmp/wrustic-sandbox`
when you are done.

`env` prints secrets — `RESTIC_PASSWORD`, S3 credentials — in cleartext on
stdout. That is its job, so treat the output accordingly: consume it directly
into environment variables, and never redirect it to shared logs or save it in
committed files.

PowerShell example (the pattern the
[windowsresticbackup](https://github.com/andrewtheguy/windowsresticbackup)
scripts use):

```powershell
$vars = wrustic env myrepo --json | ConvertFrom-Json
foreach ($p in $vars.PSObject.Properties) { Set-Item "Env:$($p.Name)" $p.Value }
restic snapshots
```

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
over env vars, secrets never on argv). The executable it runs is always
`restic/restic(.exe)` under the wrustic executable's own directory — that
is where the installers put their pinned restic, tucked into a
subdirectory so it never rides onto PATH — and nothing else: a missing one
is an error, never a fall back to a `restic` on PATH. Everything else
is native: `rustic_core` reads the on-disk repository format, and the
native write operations wrustic exposes (snapshot delete, tag edits) hold
restic-compatible repository locks, so they coexist safely with
concurrent restic processes; stale-lock removal takes no lock — like
`restic unlock`, it only deletes lock files that are provably stale.
[`docs/restic-usage.md`](docs/restic-usage.md) is the per-workflow overview
of where the restic CLI appears (the prune flow, manual use, and tests).

You *will* want `restic` (>= 0.19.0 — the release whose locking protocol and
JSON output wrustic is built against) on your `$PATH` as well, for the work
you do outside wrustic. That copy is yours alone; wrustic never looks at it,
and the prune flow is unaffected by whether it exists. Use it for:

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
machine, use `--htpasswd-file` and TLS per the `rest-server` documentation.
Enter authentication in wrustic's separate username and password fields. Do
not embed credentials in the URL (`https://user:pass@host/`): `rest_url` is
stored verbatim in plaintext, while the separate password field is encrypted.

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
- Profiles are persisted in `~/.config/wrustic/config.toml`. Repository
  passwords, REST passwords, and S3 secret access keys are encrypted per value
  with AES-256-GCM under a passphrase-derived key. REST usernames and S3 access
  key IDs remain plaintext metadata. The file itself is not a
  whole-file encrypted archive; see `docs/encryption.md` for the on-disk schema
  and threat model.
