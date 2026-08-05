# Running Windows CI locally, in a container

`.github/workflows/windows-ci.yml` runs three steps on a `windows-latest`
runner: clippy with `-D warnings`, `cargo test --all-features`, and a release
build with `keychain` on. This describes how to run those same three steps on
the Windows box inside a container, so a Windows-only failure can be found
without pushing a branch and waiting.

Everything is in `ci/windows/`:

| File | Runs on | Role |
| --- | --- | --- |
| `run.ps1` | Windows | **the runner** — images, isolation, volumes, `docker run` |
| `run.sh` | WSL, same machine | wrapper: translates paths, calls `run.ps1` |
| `remote.sh` | Linux/macOS | wrapper: copies the tree over ssh, calls `run.ps1` |
| `Dockerfile`, `entrypoint.cmd`, `ci.ps1` | in the container | the environment and the steps |

Both wrappers end at `run.ps1`, so there is one implementation rather than two
that drift.

## The one thing that decides the whole design

**A Windows container cannot run inside WSL.** Containers on Windows share the
host's kernel (or get a matched one from a utility VM under Hyper-V isolation);
WSL2 is a Linux VM with a Linux kernel and has nothing to share. `podman` in
Debian will never start `servercore`, and neither will a Linux docker daemon in
WSL. The engine is always the Windows host's, and that is why the runner is a
PowerShell script rather than a shell script.

It follows that WSL is never *required*. It is one way in, convenient when you
are already sitting in it on this machine; from another machine it would only
be a hop that has to be undone at the far end, so `remote.sh` talks to Windows
directly.

Neither wrapper connects to a daemon socket. `run.sh` drives Windows through
WSL interop and `remote.sh` goes over ssh, which avoids the usual alternative —
exposing `dockerd` on TCP and setting `DOCKER_HOST`. That is worth avoiding on
its own merits, since an unauthenticated Docker endpoint is root on the host,
and is worse here specifically: this machine's WSL runs `networkingMode=bridged`,
so WSL's `localhost` is not the Windows host and the endpoint would have to be
published to the LAN to be reachable at all.

One path problem shapes both wrappers. Bind mount sources are resolved by the
daemon, on Windows, so they must be Windows paths. `run.sh` translates with
`wslpath -w`; a checkout on the WSL filesystem has no such path
(`\\wsl.localhost\...` is not a valid bind mount source), so it stages a copy
under `%LOCALAPPDATA%\Temp\wrustic-winci-src` instead of mounting in place.
`remote.sh` copies into a Windows directory for the same reason.

## Host setup

Three things, once. All of it needs an elevated PowerShell.

**1. The Containers feature.** Hyper-V is the other prerequisite and is already
enabled here (Windows 11 client requires it for Hyper-V isolated containers,
which is the fallback isolation mode).

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Containers -All -NoRestart
```

This step is **not optional on a client OS**, whatever the installer script
below implies. That script tries to enable the feature itself with
`Get-WindowsFeature` / `Install-WindowsFeature`, which are Server-only cmdlets;
on Windows 11 they fail with "the target of the specified cmdlet cannot be a
Windows client-based operating system" and the script carries on regardless.
The errors are harmless *if* the feature is already on, and misleading if it
isn't.

**2. A Windows container engine.** Microsoft's script downloads the Docker CE
(moby) static binaries and registers `dockerd` as an automatic-start Windows
service. It installs `docker.exe` and `dockerd.exe` into `C:\Windows\System32`,
which is why docker ends up on PATH — for the whole machine and, through
interop, for WSL — without anything editing PATH:

```powershell
Invoke-WebRequest -UseBasicParsing `
  https://raw.githubusercontent.com/microsoft/Windows-Containers/Main/helpful_tools/Install-DockerCE/install-docker-ce.ps1 `
  -OutFile install-docker-ce.ps1
.\install-docker-ce.ps1 -NoRestart
```

**3. Reboot.** The Containers feature needs one.

Afterwards, `Get-Service docker` should be `Running`, and from WSL
`./ci/windows/run.sh doctor` should report a `windows` server OS.

### You do not need Docker Desktop, and it is not Windows-only

Docker Desktop *can* run Windows containers — `DockerCli.exe -SwitchDaemon`
flips it into that mode, and it works. But it is not a Windows-containers-only
install, and switching the mode does not make it one. Desktop runs **two**
engines side by side, each on its own named pipe:

```
NAME                DOCKER ENDPOINT
desktop-linux       npipe:////./pipe/dockerDesktopLinuxEngine
desktop-windows *   npipe:////./pipe/dockerDesktopWindowsEngine
```

`-SwitchDaemon` only changes which of those is the active context. The Linux
engine keeps running, and so does the `docker-desktop` WSL2 distro that hosts
it — visible in `wsl -l -v` alongside your own distros.

The engine install above has none of that: one `dockerd` service, one pipe
(`npipe:////./pipe/docker_engine`), no Linux engine, no extra WSL distro, no
GUI, no tray process, and no licence terms beyond the engine's. If Docker
Desktop is already installed, uninstalling it (`winget uninstall
Docker.DockerDesktop`, or the `uninstall` verb on
`Docker Desktop Installer.exe`) removes its WSL distro with it and leaves other
distros alone.

### A note on networking

Docker will create a `nat` Hyper-V switch and, by default, a 172.16/12-ish
subnet for containers. That does not collide with either this LAN (10.22.32/20)
or the external `bridge_main` switch WSL is bridged onto, so no special
handling is needed. If it ever does collide, `install-docker-ce.ps1` takes
`-NATSubnet`.

## Using it

```sh
./ci/windows/run.sh            # build the image if needed, then run the CI steps
./ci/windows/run.sh build      # rebuild the image
./ci/windows/run.sh shell      # interactive cmd.exe with the MSVC env set
./ci/windows/run.sh clean      # drop the cargo registry / target volumes
./ci/windows/run.sh doctor     # report on the setup, change nothing
```

From a PowerShell prompt on the Windows box itself, skip the wrapper and use
the runner directly — same subcommands:

```powershell
.\ci\windows\run.ps1
.\ci\windows\run.ps1 -Command doctor
```

The first `build` downloads Server Core plus the MSVC toolchain and Windows
SDK — several GB, and 20-40 minutes on this box. The first `ci` run then
compiles the whole dependency graph from scratch. After that the cargo registry
and the target directory live in named volumes and runs are incremental.

The source tree is bind-mounted at `C:\src`, so the container tests your
working tree, not `HEAD`. `CARGO_TARGET_DIR` points at `C:\target` in a volume
rather than the mounted `target/`, so a container run and a host `cargo build`
never fight over the same directory — and running this does not blow away your
host build cache.

## Watching a run

`docker stats` and `docker logs -f` cover most of it, and the CI output streams
to whichever terminal launched the run. For something more visual, the thing to
know first is what *not* to reach for.

**Docker Desktop is not an option that keeps this setup intact.** It has no
Windows-containers-only mode. Switching engines — the tray menu, `DockerCli.exe
-SwitchDaemon`, or `docker desktop engine use windows` on newer builds — changes
which engine is active, but Desktop's backend and the `docker-desktop` WSL2
distro come with the package regardless; that distro was observed running here
while Desktop was in Windows-container mode. Installing it puts back everything
the engine-only setup above exists to avoid.

**Portainer CE runs as a Windows container** on the engine already installed, so
it needs no Linux VM and no Desktop. It talks to the daemon over the named pipe:

```powershell
docker run -d --name portainer --restart=always `
  --isolation=hyperv --memory=2g `
  -p 127.0.0.1:9443:9443 `
  -v \\.\pipe\docker_engine:\\.\pipe\docker_engine `
  -v portainer_data:C:\data `
  portainer/portainer-ce@sha256:ebdd4ad94fd870df825ccc27f1be3f30c81c6727c5a57b6df4eb51414960a89b
```

Then `https://localhost:9443`, self-signed, first visit sets the admin password.

The digest is not fussiness. `portainer/portainer-ce:lts` is a multi-platform
manifest carrying three Windows variants — `10.0.17763.*` (WS2019),
`10.0.20348.*` (WS2022) and `10.0.26100.*` (WS2025) — and on a 25H2 host the
WS2025 one is the plausible match and the one that cannot start, for the same
reason the Dockerfile pins `ltsc2022`. There is no `:lts-windows-ltsc2022` tag
to name instead, so the WS2022 variant has to be pinned by digest. Re-resolve it
after an upgrade with:

```powershell
(docker manifest inspect portainer/portainer-ce:lts | ConvertFrom-Json).manifests |
  Where-Object { $_.platform.'os.version' -like '10.0.20348.*' } | Select-Object digest
```

Two things to weigh: it is a persistent service on 9443 (bound to loopback
above — dropping the `127.0.0.1:` publishes it to the LAN), and mounting
`\\.\pipe\docker_engine` into it is root-equivalent access to the host.

**The VS Code Container Tools extension** is the smaller option: it attaches to
the same named pipe and gives a container tree with live logs, without running
anything persistent.

## Image version pinning

The base image is `servercore:ltsc2022`, not `ltsc2025`, and that is not
conservatism. Windows Server 2025 images currently fail to start on Windows 11
25H2 hosts — this host is 25H2, build 26200 — with `hcsshim::PrepareLayer
failed ... the container image contains a layer with an unrecognized format
(0xc0370112)`, under both isolation modes (microsoft/hcsshim#2566). WS2022
images work on the same hosts, and are also the newest images Windows 11
supports running under *process* isolation, which is the faster mode.

## Isolation: Hyper-V, and why not the faster one

`run.ps1` runs containers with `--isolation=hyperv` and `--memory=8g` (the
utility VM defaults to 1 GB, which will not link this crate graph). Process
isolation *works* on this host and starts in about a second against the ~15 a
utility VM costs — but it cannot build Rust out of a mounted directory.

rustc emits each crate's `.rmeta` by creating a temp directory inside the
output directory, writing the metadata there, and renaming it into place. Under
process isolation that last part fails on **any** mapped directory — bind mount
and named volume alike — once per crate:

```
error: failed to write C:\target\debug\deps\libwindows_link-<hash>.rmeta:
       The system cannot find the path specified. (os error 3)
```

What makes it confusing is how narrow it is. `mkdir` and file writes several
levels deep into the same mount succeed from `cmd`. Cargo's own writes into the
mounted registry volume succeed — the whole dependency graph downloads
normally. A `cargo build` of a dependency-free crate onto the mount succeeds,
because nothing pipelines metadata. Only rustc's rmeta emission trips it, and
then it trips for every crate at once.

Two fixes exist. Moving `CARGO_TARGET_DIR` off the mount onto the container's
own writable layer works under process isolation — but a `--rm` container
throws that layer away, so every run recompiles from cold. Hyper-V isolation
maps directories through a different mechanism and has no such problem, so the
target directory can live in a volume and persist. Keeping the cache is worth
more than the VM boot, so that is the default.

If you want the process-isolation shape anyway, `WRUSTIC_WINCI_ISOLATION=process`
still works for anything that does not build Rust into a mount — `run.sh shell`,
for example.

## Triggering it from Linux or macOS

When the source lives on another machine, `ci/windows/remote.sh` runs *there*:
it copies the working tree over ssh and runs `run.ps1` on the Windows box.

```sh
export WRUSTIC_WINCI_HOST=andrew@10.22.36.116
./ci/windows/remote.sh              # clippy, test, release-profile compile
./ci/windows/remote.sh shell        # interactive, over ssh
```

`WRUSTIC_WINCI_SSH_OPTS` passes flags through to ssh (`-i ~/.ssh/winci`,
`-p 2222`, a jump host). `WRUSTIC_WINCI_REMOTE_DIR` sets the landing directory,
default `C:/ci-workspaces/wrustic`.

The ssh target is **Windows itself, not its WSL instance**. The daemon is a
Windows service and `run.ps1` is a Windows script, so routing through WSL would
only add a hop that has to be undone at the far end.

### Host setup for remote use

Only needed if you want to trigger from another machine. Elevated PowerShell:

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Set-Service sshd -StartupType Automatic
Start-Service sshd
```

The capability install creates the `OpenSSH-Server-In-TCP` firewall rule. Check
which profile it is scoped to (`Get-NetFirewallRule -Name OpenSSH-Server-In-TCP`)
against the profile of the adapter you will connect over
(`Get-NetConnectionProfile`) — a rule scoped to Private does nothing on a
network classified Public.

**Keys for an administrator account do not go in `~/.ssh/authorized_keys`.**
Windows OpenSSH reads a single shared file for everyone in the Administrators
group, and ignores the per-user one:

```powershell
$akf = 'C:\ProgramData\ssh\administrators_authorized_keys'
Add-Content -Path $akf -Value 'ssh-ed25519 AAAA... you@yourmac' -Encoding utf8
icacls $akf /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F'
```

The ACL matters: sshd refuses the file if anyone else can write it, and refuses
it if the owner is not SYSTEM or Administrators. It must also be UTF-8 **without
a BOM** — `Set-Content -Encoding utf8` does the right thing in PowerShell 7 but
writes a BOM in Windows PowerShell 5.1, which sshd will reject.

### Three things that will waste an afternoon

- **`localhost:22` on this machine is not Windows sshd.** WSL's `wslrelay.exe`
  binds `127.0.0.1:22` and `[::1]:22` and forwards them into the WSL instance,
  and those specific bindings win over sshd's `0.0.0.0`/`::`. So `ssh
  andrew@localhost` reaches Debian and fails on a Windows key, while
  `ssh andrew@10.22.36.116` reaches Windows and works. Test over the LAN
  address, which is what a remote machine uses anyway.
- **The transfer is tar, not rsync.** Windows has no rsync; bsdtar ships as
  `System32\tar.exe`, so `tar | ssh "tar -x"` needs nothing installed at either
  end. The whole tree goes each time, which is fine at this size.
- **The remote command runs under `cmd.exe`, deliberately.** That is OpenSSH's
  default shell on Windows and it is left alone: PowerShell treats a native
  command's stdin as text and re-encodes it, which corrupts a piped tar stream.
  `run.ps1` is invoked explicitly through `powershell -File` instead.

The tree is copied rather than fetched from git deliberately: the reason to run
this instead of pushing a branch is to test what you have in front of you,
uncommitted changes included. To test a *pushed* branch there is no need for
`remote.sh` at all:

```sh
ssh $WRUSTIC_WINCI_HOST "cd C:\ci-workspaces\wrustic && git fetch origin && ^
    git checkout -q <branch> && powershell -File ci\windows\run.ps1"
```

Because every workspace is bind-mounted at the same `C:\src` inside the
container, the cargo target volume stays usable across them — a local run and a
synced remote run share the cache instead of invalidating each other.

If you would rather trigger the *real* workflow than this local imitation, a
self-hosted runner on this box is the other option — but note that
`jobs.<id>.container` is Linux-only on GitHub Actions, so the job would run
natively on Windows and none of this container would be involved.

## Where this is not the real runner

Worth knowing before trusting a green run:

- **The base OS is Server Core, not the GitHub runner image.** GitHub's
  `windows-latest` is Windows Server 2022 with an enormous preinstalled
  toolbox. This image has the MSVC toolchain, the Windows SDK and rustup, and
  nothing else. A test that quietly depends on some other preinstalled tool
  would pass on GitHub and fail here.
- **No git in the image.** Nothing in the build needs it — cargo fetches
  crates.io over the sparse protocol — but a future git dependency would.
- **The toolchain floats.** `rustup ... --default-toolchain stable` pins to
  whatever stable was on the day the image was built, and MSVC likewise. Both
  drift from the runner until you build the image again.
- **It runs as ContainerAdministrator.** Any test whose behaviour depends on
  privilege or on a real user profile sees something different from CI.
- **Ignored tests stay ignored.** Same as CI: the live tests need a restic
  binary, an S3 server or the OS credential store, and none of that is here.

## Cheaper things that are not this

If the goal is only "does it still build and pass on Windows", this machine
already has `cargo` and `rustup` natively — running the three commands from
`ci/windows/ci.ps1` in a PowerShell window is free and takes no setup. The
container earns its cost when you want the *environment* checked too: a clean
machine with no rustup override, no stray env vars, no local credential store,
disposable and repeatable.

From WSL alone, `cargo-xwin` can cross-compile and clippy the
`x86_64-pc-windows-msvc` target without any Windows container at all. It cannot
run the tests, which is most of what this workflow is for, so it complements
this rather than replacing it.
