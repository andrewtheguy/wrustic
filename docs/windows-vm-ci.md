# Running Windows CI locally, on a Hyper-V VM

`.github/workflows/windows-ci.yml` runs three steps on a `windows-latest`
runner: clippy with `-D warnings`, `cargo test --all-features`, and a release
build with `keychain,smb-tun` on. This describes how to run those same three
steps on a Windows Server 2022 VM, so a Windows-only failure can be found
without pushing a branch and waiting.

Everything is in `ci/windows/`:

| File | Runs on | Role |
| --- | --- | --- |
| `remote.ps1` | this machine | packs the working tree, ships it, invokes `ci.ps1` |
| `ci.ps1` | the VM | the three steps, natively |
| `provision.ps1` | the VM, once | turns a bare Server install into the CI box |

`ci.ps1` installs nothing and changes no machine state, so it also runs on a
dev box directly — `.\ci\windows\ci.ps1` — when you just want the three steps
without the trip over ssh.

## Why a VM rather than a container

This replaces an earlier setup that ran the same steps in a Windows container
on the dev box. The VM is better on the points that matter:

- **It matches the runner's OS.** `windows-latest` is Windows Server 2022, and
  so is this VM — build 20348, the same Server release. The container was
  `servercore:ltsc2022`, which shares the kernel but is a far smaller image
  than the runner's. (GitHub does move `windows-latest` between Server
  releases; when it moves, this VM is what has to follow it.)
- **Nothing is installed on the dev box.** No container engine, no daemon
  running as a service, no `nat` switch, no 20 GB of layers under
  `C:\ProgramData\docker`.
- **The rmeta problem is gone.** Under process isolation rustc could not emit
  `.rmeta` into a mapped directory, which forced Hyper-V isolation and a
  ~15-second utility-VM boot on every run. A VM has no mapped directories in
  the build path, so nothing to work around.

What it costs: the VM's disk and RAM, always allocated, and provisioning is an
imperative script rather than a Dockerfile — so it is idempotent by hand
(see below) rather than by construction.

## The VM

`ci-builder`, on this machine's Hyper-V: 4 vCPU, 8 GB RAM, 128 GB disk,
Windows Server 2022 Datacenter **Evaluation**, at `10.22.38.75`. The
evaluation edition is time-limited; when it lapses the VM stops being usable
and has to be rebuilt or licensed.

## SSH

The VM had OpenSSH Server installed but unconfigured. `sshd` is now Automatic
and running, and the `OpenSSH-Server-In-TCP` firewall rule is enabled for all
profiles (the adapter is classified Private, so a Private-scoped rule would
have been enough, but Any survives a reclassification).

Auth is by key. `~/.ssh/wrustic-winci` is a dedicated ed25519 key with **no
passphrase** — CI has to connect unattended, and a passphrase-less key scoped
to one sandbox VM is the smaller evil versus an agent that must be unlocked.
`~/.ssh/config` carries the alias:

```
 Host winci
    HostName 10.22.38.75
    User Administrator
    IdentityFile ~/.ssh/wrustic-winci
```

**Keys for an administrator account do not go in `~/.ssh/authorized_keys`.**
Windows OpenSSH reads one shared file for everyone in the Administrators group
and ignores the per-user one:

```powershell
$akf = 'C:\ProgramData\ssh\administrators_authorized_keys'
icacls $akf /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F'
```

Two things sshd is strict about, both of which fail silently as "permission
denied":

- **The ACL.** sshd refuses the file if anyone outside Administrators/SYSTEM
  can write it, and refuses it if the owner is neither.
- **No BOM.** Windows PowerShell 5.1 writes UTF-8 *with* a BOM, and sshd then
  rejects the file. It was written with `[System.IO.File]::WriteAllText` and
  ASCII encoding, which cannot produce one. Check with:

```powershell
[System.IO.File]::ReadAllBytes($akf)[0..2]   # want 115 115 104, i.e. "ssh"
```

Password authentication is still enabled on the VM. Turning it off
(`PasswordAuthentication no` in `C:\ProgramData\ssh\sshd_config`) is the
tightening to make once you are confident in the key — it also removes the
console-typed password as a way back in, so do it deliberately.

## Provisioning

`ci/windows/provision.ps1`, deployed to `C:\provision\provision.ps1` on the VM
and run as a SYSTEM scheduled task, logging to `C:\provision\provision.log`
with `DONE-OK` or `DONE-FAIL` as its last line. It runs as a task rather than
inline over WinRM so a dropped connection cannot kill a 20-minute installer
half way, and every step is guarded so re-running it is a no-op — a second run
logs two skips and finishes in a second.

It installs two things:

- **VS Build Tools 17** into `C:\BuildTools`, workload
  `Microsoft.VisualStudio.Workload.VCTools` with `--includeRecommended` —
  that flag is what brings the Windows SDK along with the compiler.
- **rustup**, `stable-x86_64-pc-windows-msvc` with the `clippy` component.

Rust is installed **machine-wide**, not into a profile:

```
RUSTUP_HOME       C:\rust\rustup
CARGO_HOME        C:\rust\cargo
Path             += C:\rust\cargo\bin
CARGO_TARGET_DIR  C:\ci-cache\target
CARGO_INCREMENTAL 0
```

That is not tidiness. The provisioning task runs as SYSTEM and ssh logs in as
Administrator; a default rustup install would land in SYSTEM's profile and be
invisible to every CI run. Machine-scoped variables and a machine PATH entry
are what make the two agree.

`CARGO_TARGET_DIR` points outside the workspace deliberately: `remote.ps1`
replaces the workspace directory outright on every run, so a target directory
inside it would mean compiling from cold every time. Kept at `C:\ci-cache`, the
build cache survives the swap. `CARGO_INCREMENTAL=0` because incremental
artefacts are never reused across a workspace that is recreated each run —
they would only cost disk.

Nothing pins the toolchain, so `stable` drifts. `rustup update` on the VM is
the whole story; there is no image to rebuild.

### Two things that will waste an afternoon

- **sshd caches its environment.** The service captures its environment block
  when it starts and every session inherits that copy, so a machine-scoped
  `PATH` or `CARGO_*` change is invisible over ssh until `Restart-Service sshd`.
  Set the variables, watch `rustc` still not be found, conclude the install
  failed — it did not. `provision.ps1` restarts sshd as its last step for this
  reason; if you set a machine variable by hand afterwards, restart it again.
- **aws-lc-sys looks like it needs cmake and NASM, and does not.** It comes in
  via rustls, pulls the `cmake` crate into `Cargo.lock`, and builds assembly.
  A bare Server install has neither tool and GitHub's runner image has both,
  which is the exact shape of a Windows-only failure — so it is worth saying
  plainly that a full run is green on this VM with both absent. aws-lc-sys 0.41
  ships prebuilt assembly for `x86_64-pc-windows-msvc` and never takes its
  cmake path. Do not install either on spec. If some future dependency does
  want cmake, VS Build Tools already ships one and it only needs a PATH entry:
  `C:\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin`.

## Using it

```powershell
.\ci\windows\remote.ps1              # clippy, test, release-profile build
.\ci\windows\remote.ps1 shell        # interactive shell on the VM, in the tree
.\ci\windows\remote.ps1 doctor       # report on the VM, change nothing
.\ci\windows\remote.ps1 clean        # drop the VM's cargo target cache
```

`WRUSTIC_WINCI_HOST` overrides the ssh target (default: the `winci` alias) and
`WRUSTIC_WINCI_REMOTE_DIR` the landing directory (default
`C:\ci-workspaces\wrustic`).

The first run is cold in two ways — it fetches the whole crates.io graph and
compiles it three times over, once per step — and took a bit over ten minutes
on 4 vCPU, of which the release build alone was 6m26s. After that the registry
lives in `C:\rust\cargo` and the build cache in `C:\ci-cache\target`, and both
survive the workspace being replaced, so later runs only rebuild what changed —
a warm run with no source changes is about 20 seconds end to end, most of it
the transfer.

The tree is copied rather than fetched from git: the reason to run this instead
of pushing a branch is to test what is in front of you, uncommitted changes
included. There is no git on the VM and nothing needs it — cargo fetches
crates.io over the sparse protocol, and the crate has no git dependencies.

## Two things that shape `remote.ps1`

**The transfer is a file, not a pipe.** The obvious `tar -czf - . | ssh "tar
-xzf -"` does not work from PowerShell: a native-to-native pipeline is text,
not bytes, and PowerShell re-encodes it, corrupting the archive. So the tree is
packed to a temp `.tgz`, handed to `scp`, and unpacked at the far end. The
happy side effect is that a half-finished transfer can never be unpacked.

**The workspace is replaced, not updated.** `tar` has no `--delete`, so
unpacking over the previous tree would leave a file you deleted here still
sitting there and still being compiled. `remote.ps1` removes the directory and
recreates it. Nothing under it needs to survive — the cargo caches live in
`C:\rust` and `C:\ci-cache`.

Paths on the remote side deliberately contain no spaces, so no remote command
needs quoting. A quoted string has to survive PowerShell, then ssh, then
cmd.exe, and the layers do not agree; not needing quotes is cheaper than
getting them right.

## Where this is not the real runner

Worth knowing before trusting a green run:

- **The toolchain floats.** GitHub's runner image pins its Rust and MSVC to
  whatever the image ships; this VM has whatever `stable` and VS Build Tools
  were on the day they were installed. Both drift.
- **It is a bare Server install.** `windows-latest` carries an enormous
  preinstalled toolbox. This VM has MSVC, the Windows SDK and rustup, and
  nothing else — a test that quietly depends on some other preinstalled tool
  would pass on GitHub and fail here.
- **It runs as Administrator.** Any test whose behaviour depends on privilege
  sees something different from CI.
- **Ignored tests stay ignored.** Same as CI: the live tests need a restic
  binary, an S3 server or the OS credential store, and none of that is here.
