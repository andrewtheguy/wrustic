# Running Windows CI locally, on a Hyper-V VM

`.github/workflows/windows-ci.yml` runs three steps on a `windows-latest`
runner: clippy with `-D warnings`, `cargo test --all-features`, and a release
build with `keychain,smb-tun` on. This describes how to run those same three
steps on a local Windows Server VM, so a Windows-only failure can be found
without pushing a branch and waiting.

The VM tracks the runner on both halves of the image name: `windows-latest` is
currently the `windows-2025-vs2026` image — **Windows Server 2025** with
**Visual Studio 2026** — and this VM is Server 2025 with the VS 2026 build
tools. It is still not the same machine; see
[Where this is not the real runner](#where-this-is-not-the-real-runner).

Everything is in `ci/windows/`:

| File | Runs on | Role |
| --- | --- | --- |
| `remote.ps1` | this machine | packs the working tree, ships it, invokes `ci.ps1` |
| `ci.ps1` | the VM | the three steps, natively |
| `provision.ps1` | the VM, once | turns a bare Server install into the CI box |

`ci.ps1` installs nothing and changes no machine state, so it also runs on a
dev box directly — `.\ci\windows\ci.ps1` — when you just want the three steps
without the trip over ssh.

## The VM

A whole Server guest, rather than a container, because it can be moved onto
whatever release `windows-latest` points at and it keeps the dev box clean —
no container engine, no daemon, no `nat` switch, no layer store. The price is
disk and RAM that stay allocated, and a provisioning script that is idempotent
only because every step is guarded by hand.

`ci-builder`, on this machine's Hyper-V: 4 vCPU, dynamic memory (1 GB startup
and minimum, 8 GB maximum), 128 GB disk, Windows Server 2025 Datacenter
**Evaluation**, build 26100, at `10.22.38.75`. The evaluation edition is
time-limited; when it lapses the VM stops being usable and has to be rebuilt or
licensed.

**It needs a page file, and a bare install may not have one.** With dynamic
memory, Windows' commit limit is the RAM currently ballooned in plus the page
file — so with no page file a 1 GB guest has a ~1.6 GB commit limit, and four
parallel `rustc` processes exhaust it in seconds. What that looks like is not
an out-of-memory message but a compiler that appears broken:

```
failed to mmap file '...libcore-....rlib': The paging file is too small for
this operation to complete. (os error 1455)
memory allocation of 129536 bytes failed
error: could not compile `version_check` (lib) ... (exit code: 0xc0000409,
STATUS_STACK_BUFFER_OVERRUN)
```

`0xc0000409` is Rust's abort path on Windows, not a corrupted toolchain — the
allocation failure above it is the real error, and it lands on whichever trivial
crate happened to be compiling. Leave the page file system-managed (`System
Properties > Advanced > Performance > Virtual memory`, or
`(Get-CimInstance Win32_ComputerSystem).AutomaticManagedPagefile`); it grows on
demand, and dynamic memory needs it to signal pressure and balloon at all.
Ballooning is also why RAM does not need to be raised: the guest reports 1–2 GB
at rest and grows toward the 8 GB maximum under a build.

## SSH

`sshd` runs Automatic, and the `OpenSSH-Server-In-TCP` firewall rule is enabled
for all profiles — the adapter is classified Private, so a Private-scoped rule
would do, but Any survives a reclassification.

Auth is by key: this machine's default `~/.ssh/id_ed25519`, which has **no
passphrase** — CI has to connect unattended, and a passphrase-less key is the
smaller evil versus an agent that must be unlocked. `~/.ssh/config` carries the
alias `remote.ps1` connects to:

```
 Host windows-ci-build
    HostName 10.22.38.75
    User Administrator
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
  rejects the file. Write it with `[System.IO.File]::WriteAllText` and ASCII
  encoding, which cannot produce one. Check with:

```powershell
[System.IO.File]::ReadAllBytes($akf)[0..2]   # want 115 115 104, i.e. "ssh"
```

Getting back in when ssh breaks: the VM has a console. Open it from Hyper-V
Manager, sign in as Administrator with the password (console logon is
unaffected by `sshd_config`), and either fix the file or
`Set-Service sshd -StartupType Automatic; Start-Service sshd`. Losing ssh is
recoverable; there is no state on this VM worth protecting beyond that, and a
rebuild from `provision.ps1` is the fallback.

## Provisioning

`ci/windows/provision.ps1`, deployed to
`C:\ci-workspaces\provision\provision.ps1` on the VM and run as a SYSTEM
scheduled task, logging to `C:\ci-workspaces\provision\provision.log`
with `DONE-OK` or `DONE-FAIL` as its last line. It runs as a task rather than
inline over WinRM so a dropped connection cannot kill a 20-minute installer
half way, and every step is guarded so re-running it is a no-op — a second run
logs two skips and finishes in a second.

It installs two things:

- **VS Build Tools 2026** into `C:\BuildTools`, workload
  `Microsoft.VisualStudio.Workload.VCTools` with `--includeRecommended` —
  that flag is what brings the Windows SDK along with the compiler. See
  [The build tools step](#the-build-tools-step); it is more than one
  `Start-Process`.
- **rustup**, `stable-x86_64-pc-windows-msvc` with the `clippy` component.

### The build tools step

The bootstrapper comes from `https://aka.ms/vs/18/stable/vs_BuildTools.exe`.
**Note the channel.** VS 2026 uses `stable`/`insiders` where VS 2022 used
`release`, and `aka.ms/vs/18/release/...` is not a dead link — unknown `aka.ms`
shortlinks redirect to a Bing search, so it answers `200` and writes an HTML
page over `vs_BuildTools.exe`. Checking the HTTP status proves nothing.

Whether the step runs at all is decided by `vswhere`, not `Test-Path`, on two
questions:

- **Is it complete?** An install interrupted part way — the VM reboots, the
  task is killed — leaves `C:\BuildTools\VC\Tools\MSVC` populated but the
  toolchain unusable, and `Test-Path` would call that good and hand every later
  run a compiler that cannot link. `isComplete`/`isLaunchable` are false for
  such an instance. It is deliberately not deleted: the bootstrapper resumes
  one, which is far cheaper than starting over.
- **Is it the right product line?** `installationVersion` major 18 is VS 2026.
  An older instance would build perfectly well while testing a compiler the
  runner does not have, which is the one thing this box exists to prevent.

An instance failing the second question is uninstalled and replaced, and both
halves of that have a trap:

- `vs_installer.exe uninstall` **rejects `--wait`** — exit 87,
  `ERROR_INVALID_PARAMETER`, and no log written to say so. `-Wait` on
  `Start-Process` is what blocks. Exit 3010 is success with a restart pending.
  (The bootstrapper, confusingly, does accept `--wait`.)
- Uninstalling deregisters the instance but **leaves the directory behind**,
  and the installer refuses a non-empty target: `Visual Studio cannot be
  installed to a nonempty directory 'C:\BuildTools'`, exit 1 — logged as a
  *warning* in `%TEMP%\dd_installer_*.log`, with nothing in
  `dd_setup_*_errors.log`. So the leftover shell goes whenever there is no
  instance left to resume.

Drop the build cache after the toolset changes — `.\ci\windows\remote.ps1
clean`. Cargo fingerprints do not include the MSVC version, so C code compiled
by the old toolset would otherwise be linked into the new one's output without
a rebuild.

## Rust

Rust is installed **machine-wide**, not into a profile:

```
RUSTUP_HOME       C:\rust\rustup
CARGO_HOME        C:\rust\cargo
Path             += C:\rust\cargo\bin
CARGO_TARGET_DIR  C:\ci-workspaces\cargo-target
CARGO_INCREMENTAL 0
```

That is not tidiness. The provisioning task runs as SYSTEM and ssh logs in as
Administrator; a default rustup install would land in SYSTEM's profile and be
invisible to every CI run. Machine-scoped variables and a machine PATH entry
are what make the two agree.

`CARGO_TARGET_DIR` is a sibling of the workspace, not a child, deliberately:
`remote.ps1` replaces the workspace directory outright on every run, so a
target directory inside it would mean compiling from cold every time. Kept at
`C:\ci-workspaces\cargo-target`, the build cache survives the swap while still
staying inside the staging root. `CARGO_INCREMENTAL=0` because incremental
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

`WRUSTIC_WINCI_HOST` overrides the ssh target (default: the
`windows-ci-build` alias) and `WRUSTIC_WINCI_STAGING` the staging root
(default `C:\ci-workspaces`), under which the workspace, its lock, the upload
and the build cache all live.

The first run is cold in two ways — it fetches the whole crates.io graph and
compiles it three times over, once per step — and takes a bit over ten minutes
on 4 vCPU, of which the release build alone is about five. After that the registry
lives in `C:\rust\cargo` and the build cache in `C:\ci-workspaces\cargo-target`, and both
survive the workspace being replaced, so later runs only rebuild what changed —
a warm run with no source changes is about 20 seconds end to end, most of it
the transfer.

The tree is copied rather than fetched from git: the reason to run this instead
of pushing a branch is to test what is in front of you, uncommitted changes
included. There is no git on the VM and nothing needs it — cargo fetches
crates.io over the sparse protocol, and the crate has no git dependencies.

## Three things that shape `remote.ps1`

**The transfer is a file, not a pipe.** The obvious `tar -czf - . | ssh "tar
-xzf -"` does not work from PowerShell: a native-to-native pipeline is text,
not bytes, and PowerShell re-encodes it, corrupting the archive. So the tree is
packed to a `.tgz`, handed to `scp`, and unpacked at the far end. The happy
side effect is that a half-finished transfer can never be unpacked. Both ends
of that transfer are staged: the archive is written to this repo's gitignored
`tmp/` rather than the machine temp directory, and it lands in the staging root
on the VM rather than the login user's home directory. Both copies are deleted
when the run ends.

**The workspace is replaced, not updated.** `tar` has no `--delete`, so
unpacking over the previous tree would leave a file you deleted here still
sitting there and still being compiled. `remote.ps1` removes the directory and
recreates it. Nothing under it needs to survive — the registry cache lives in
`C:\rust` and the build cache in the sibling `C:\ci-workspaces\cargo-target`.

Paths on the remote side deliberately contain no spaces, so no remote command
needs quoting. A quoted string has to survive PowerShell, then ssh, then
cmd.exe, and the layers do not agree; not needing quotes is cheaper than
getting them right. `WRUSTIC_WINCI_STAGING` is checked against that rule
before use — every remote path is built from it, including command lines that
include `rmdir /s /q`, and a space or an `&` in it is not a parse error so much
as a demolition order.

**One run at a time.** The workspace and the cargo target directory are single
and shared — that is what makes a warm run 20 seconds — so a second run
starting mid-build would delete the tree the first is compiling. `remote.ps1`
claims `C:\ci-workspaces\wrustic.lock` with `mkdir` (which fails, atomically,
if it exists) and drops it in a `finally`. If a run is killed hard enough to
skip that, the next one says so and prints the `ssh windows-ci-build rmdir ...` to clear
it.

## Where this is not the real runner

Worth knowing before trusting a green run:

- **The OS matches, for now.** Both are Windows Server 2025 build 26100
  (`windows-latest` is the `windows-2025-vs2026` image). GitHub moves the
  label without notice, so re-check rather than assume:
  `gh run view <id> --log | grep 'Image:'`. When it moves again, rebuild the
  VM on the new release — do not pin the workflow to an older `runs-on`, which
  would make CI test an OS older than the one users get.
- **The compiler is the same product, not the same install.** The runner has
  Visual Studio *Enterprise* 2026; this VM has the *Build Tools* — the same
  MSVC toolset and Windows SDK without the IDE, which is all a Rust build
  touches. The runner also keeps older toolsets side by side (`VC.14.44`, and
  `VC.14.29` for ARM), so a project pinning one would get it there and not
  here; nothing in this repo does.
- **Both toolchains float, and neither is pinned.** Rust here is whatever
  `stable` was on install day (`rustup update` is the whole story); on GitHub
  it is whatever the image ships. The VS build tools update on their own
  channel. Re-read the versions rather than trusting this paragraph — the
  provisioning log records the MSVC toolset it installed, and
  `.\ci\windows\remote.ps1 doctor` reports what is there now.
- **It is a bare Server install.** `windows-latest` carries an enormous
  preinstalled toolbox. This VM has MSVC, the Windows SDK and rustup, and
  nothing else — a test that quietly depends on some other preinstalled tool
  would pass on GitHub and fail here.
- **It runs as Administrator.** Any test whose behaviour depends on privilege
  sees something different from CI.
- **Ignored tests stay ignored.** Same as CI: the live tests need a restic
  binary, an S3 server or the OS credential store, and none of that is here.
