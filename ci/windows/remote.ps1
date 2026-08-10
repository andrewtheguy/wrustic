# Run the Windows CI steps against *this* working tree on the CI VM.
#
#   .\ci\windows\remote.ps1              # clippy, test, release-profile build
#   .\ci\windows\remote.ps1 shell        # interactive shell on the VM
#   .\ci\windows\remote.ps1 doctor       # report on the VM, change nothing
#   .\ci\windows\remote.ps1 clean        # drop the VM's cargo target cache
#
# The far end is a Hyper-V VM running Windows Server 2022 with rustup and the
# MSVC build tools installed machine-wide; ci/windows/ci.ps1 is the half that
# runs over there. See docs/windows-vm-ci.md for how the VM was built.
#
# The tree is copied rather than fetched from git on purpose — the reason to
# run this instead of pushing a branch is to test what you have in front of
# you, uncommitted changes included.
#
# Overrides:
#   WRUSTIC_WINCI_HOST        ssh target        (default: the 'winci' ssh alias)
#   WRUSTIC_WINCI_REMOTE_DIR  landing directory (default: C:\ci-workspaces\wrustic)
param(
    [ValidateSet('ci', 'shell', 'doctor', 'clean')]
    [string] $Command = 'ci'
)

$ErrorActionPreference = 'Stop'

# The remote command lines below are assembled by hand and handed to cmd.exe on
# an Administrator session, and two of them are `rmdir /s /q`. A directory
# override carrying a space, a quote or an `&` would not merely fail to parse.
# Take only a plain drive-letter path.
function Assert-RemotePath {
    param([Parameter(Mandatory)][string] $Path, [Parameter(Mandatory)][string] $Name)

    if ($Path -notmatch '^[A-Za-z]:\\[A-Za-z0-9_.\\-]+$' -or $Path -match '\.\.' -or $Path.EndsWith('\')) {
        throw "$Name must be a drive-letter path of letters, digits, _ . - and \ with no trailing separator; got: $Path"
    }
}

# Not $Host — that name is taken by an automatic variable.
$Target    = if ($env:WRUSTIC_WINCI_HOST)       { $env:WRUSTIC_WINCI_HOST }       else { 'winci' }
$RemoteDir = if ($env:WRUSTIC_WINCI_REMOTE_DIR) { $env:WRUSTIC_WINCI_REMOTE_DIR } else { 'C:\ci-workspaces\wrustic' }
Assert-RemotePath $RemoteDir 'WRUSTIC_WINCI_REMOTE_DIR'
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

function Info($m) { Write-Host "[winci] $m" }

function Invoke-Remote {
    param([Parameter(Mandatory)][string] $CommandLine, [switch] $Tty, [switch] $IgnoreExitCode)

    if ($Tty) { & ssh -t $Target $CommandLine } else { & ssh $Target $CommandLine }
    if ($LASTEXITCODE -ne 0 -and -not $IgnoreExitCode) {
        throw "remote command failed (exit $LASTEXITCODE): $CommandLine"
    }
}

# No path here contains a space — Assert-RemotePath keeps the overrides that
# way — so nothing below needs quoting inside the remote command line, which
# keeps PowerShell, ssh and cmd.exe from having to agree on how quotes nest.
$CiScript = "$RemoteDir\ci\windows\ci.ps1"

switch ($Command) {
    'doctor' {
        Info "checking $Target"
        # Each of these is a plain cmd.exe command line. Wrapping them in a
        # remote `powershell -Command "..."` would mean one string quoted for
        # PowerShell, then ssh, then cmd.exe, then PowerShell again — four
        # layers that have to agree. These need no quotes at all.
        # link.exe is not on PATH and is not supposed to be — rustc locates the
        # MSVC toolchain through the registry, so a bare `where link.exe` exits
        # 1 on a perfectly healthy VM. Look where it actually lives instead.
        foreach ($probe in 'rustc --version', 'cargo --version', 'cargo clippy --version',
                           'where /r C:\BuildTools\VC\Tools\MSVC link.exe',
                           'echo CARGO_TARGET_DIR=%CARGO_TARGET_DIR%') {
            Invoke-Remote $probe -IgnoreExitCode
        }
        return
    }

    'clean' {
        # Not $target: PowerShell variable names are case-insensitive, so that
        # would be the same variable as the $Target ssh host.
        $CacheDir = if ($env:WRUSTIC_WINCI_TARGET_DIR) { $env:WRUSTIC_WINCI_TARGET_DIR } else { 'C:\ci-cache\target' }
        Assert-RemotePath $CacheDir 'WRUSTIC_WINCI_TARGET_DIR'
        Info "dropping $CacheDir on $Target"
        Invoke-Remote "if exist $CacheDir rmdir /s /q $CacheDir"
        Info 'done'
        return
    }
}

# Stage the whole tree into one archive before anything is sent. Piping tar
# straight into ssh is not an option from PowerShell: a native-to-native
# pipeline is text, not bytes, and it re-encodes — which corrupts the stream.
# Writing a file and handing it to scp keeps the transfer binary-clean, and has
# the side benefit that a half-finished transfer can never be unpacked.
$Archive = Join-Path $env:TEMP "wrustic-winci-$PID.tgz"
# Per-run, so two invocations cannot land on each other's upload in the shared
# login home directory.
$RemoteArchive = "wrustic-winci-src-$PID.tgz"

# The workspace and the cargo target directory are single, fixed and shared by
# design — that is what makes a warm run 20 seconds. It also means a second run
# starting mid-build would `rmdir /s /q` the tree the first one is compiling.
# Claim the workspace first: mkdir on an existing directory fails, and fails
# atomically, which is all a lock has to do.
$Lock = "${RemoteDir}.lock"
& ssh $Target "mkdir $Lock"
if ($LASTEXITCODE -ne 0) {
    throw "$Target is busy: $Lock already exists. Either another run holds the workspace, or one died holding it — clear it with: ssh $Target rmdir $Lock"
}

try {
    Info "packing $(Split-Path -Leaf $ProjectRoot)"
    & tar -C $ProjectRoot --exclude=./target --exclude=./tmp --exclude=./.git -czf $Archive .
    if ($LASTEXITCODE -ne 0) { throw "tar failed (exit $LASTEXITCODE)" }

    Info "copying to ${Target}:${RemoteDir}"
    # A relative destination lands in the login user's home directory, which
    # sidesteps scp's habit of reading the colon in C:\... as a host separator.
    & scp -q $Archive "${Target}:$RemoteArchive"
    if ($LASTEXITCODE -ne 0) { throw "scp failed (exit $LASTEXITCODE)" }

    # Replace the workspace outright. tar has no --delete, so unpacking over
    # the old tree would leave a file deleted here still sitting there, still
    # getting compiled. The cargo target directory lives outside the workspace
    # (CARGO_TARGET_DIR on the VM), so the build cache survives this.
    Invoke-Remote "if exist $RemoteDir rmdir /s /q $RemoteDir"
    Invoke-Remote "mkdir $RemoteDir"
    Invoke-Remote "tar -xzf %USERPROFILE%\$RemoteArchive -C $RemoteDir"

    if ($Command -eq 'shell') {
        Info "opening a shell on $Target at $RemoteDir"
        Invoke-Remote "cd /d $RemoteDir && cmd" -Tty
        return
    }

    Info "running ci.ps1 on $Target"
    Invoke-Remote "powershell -NoProfile -ExecutionPolicy Bypass -File $CiScript"
}
finally {
    Remove-Item -LiteralPath $Archive -Force -ErrorAction SilentlyContinue
    # Don't leave a copy of the source tree in the login home dir, and never
    # leave the lock behind — a stale one blocks every later run.
    try { & ssh $Target "del %USERPROFILE%\$RemoteArchive & rmdir $Lock" 2>&1 | Out-Null } catch { }
}
