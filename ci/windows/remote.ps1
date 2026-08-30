# Run the Windows CI steps against *this* working tree on the CI VM.
#
#   .\ci\windows\remote.ps1              # clippy, test, release-profile build
#   .\ci\windows\remote.ps1 shell        # interactive shell on the VM
#   .\ci\windows\remote.ps1 doctor       # report on the VM, change nothing
#   .\ci\windows\remote.ps1 clean        # drop the VM's cargo target cache
#
# The far end is a Hyper-V VM running Windows Server 2025 with rustup and the
# MSVC build tools installed machine-wide; ci/windows/ci.ps1 is the half that
# runs over there. See docs/windows-vm-ci.md for how the VM was built.
#
# The tree is copied rather than fetched from git on purpose — the reason to
# run this instead of pushing a branch is to test what you have in front of
# you, uncommitted changes included.
#
# Everything either end writes is scratch, and all of it stays in a staging
# directory: this repo's own gitignored tmp/ here, and one root on the VM that
# holds the upload, the unpacked workspace, its lock and the cargo target cache.
# Neither the machine temp directory nor the login home directory is written to.
#
# The VM is driven by PowerShell remoting over the SSH transport, not by ssh
# command lines: every remote step below is a script block that runs verbatim
# in a PowerShell 7 session on the VM, so nothing has to survive being quoted
# for ssh and then for cmd.exe, and results come back as objects. The transport
# is the same sshd and the same key as a plain `ssh windows-ci-build`; what it
# needs beyond that is PowerShell 7 on the VM and a `Subsystem powershell` line
# in its sshd_config, both of which provision.ps1 sets up. No WinRM.
#
# Overrides:
#   WRUSTIC_WINCI_HOST     ssh target   (default: the 'windows-ci-build' ssh alias)
#   WRUSTIC_WINCI_STAGING  staging root (default: C:\ci-workspaces)
param(
    [ValidateSet('ci', 'shell', 'doctor', 'clean')]
    [string] $Command = 'ci'
)

$ErrorActionPreference = 'Stop'

# -HostName/-SSHTransport is a PowerShell 7 parameter set; Windows PowerShell
# 5.1 has only WS-Man, which this deliberately does not use.
if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "this needs PowerShell 7 (found $($PSVersionTable.PSVersion)); run it as: pwsh -File $PSCommandPath $Command"
}

# The staging root is joined into remote paths that get passed to
# `Remove-Item -Recurse -Force`. Nothing parses them as a command line any
# more, but a typo with a `..` in it is still a demolition order aimed at the
# wrong directory. Take only a plain drive-letter path.
function Assert-RemotePath {
    param([Parameter(Mandatory)][string] $Path, [Parameter(Mandatory)][string] $Name)

    if ($Path -notmatch '^[A-Za-z]:\\[A-Za-z0-9_.\\-]+$' -or $Path -match '\.\.' -or $Path.EndsWith('\')) {
        throw "$Name must be a drive-letter path of letters, digits, _ . - and \ with no trailing separator; got: $Path"
    }
}

# Not $Host — that name is taken by an automatic variable.
$Target  = if ($env:WRUSTIC_WINCI_HOST)    { $env:WRUSTIC_WINCI_HOST }    else { 'windows-ci-build' }
$Staging = if ($env:WRUSTIC_WINCI_STAGING) { $env:WRUSTIC_WINCI_STAGING } else { 'C:\ci-workspaces' }
Assert-RemotePath $Staging 'WRUSTIC_WINCI_STAGING'

# Both hang off the staging root, and the cache is a sibling of the workspace
# rather than a child: the workspace is deleted outright on every run, so a
# target directory inside it would compile from cold every time.
$RemoteDir = "$Staging\wrustic"
$CacheDir  = "$Staging\cargo-target"

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

function Info($m) { Write-Host "[winci] $m" }

$Session = New-PSSession -HostName $Target -SSHTransport
try {

$CiScript = "$RemoteDir\ci\windows\ci.ps1"

switch ($Command) {
    'doctor' {
        Info "checking $Target"
        # Every probe is wrapped: a doctor run has to describe a broken VM
        # rather than fail on it. link.exe is not on PATH and is not supposed
        # to be — rustc locates the MSVC toolchain through the registry — so
        # look where it lives instead of asking PATH for it.
        Invoke-Command $Session {
            $ErrorActionPreference = 'Continue'
            function Probe([scriptblock] $sb) {
                try { $v = & $sb; if ($null -eq $v) { '<none>' } else { ($v | Select-Object -First 1) } }
                catch { "unavailable: $($_.Exception.Message)" }
            }
            [pscustomobject] @{
                pwsh             = $PSVersionTable.PSVersion.ToString()
                rustc            = Probe { rustc --version }
                cargo            = Probe { cargo --version }
                clippy           = Probe { cargo clippy --version }
                link             = Probe { (Get-ChildItem 'C:\BuildTools\VC\Tools\MSVC' -Recurse -Filter link.exe -ErrorAction Stop).FullName }
                CARGO_TARGET_DIR = Probe { $env:CARGO_TARGET_DIR }
            }
        } | Select-Object pwsh, rustc, cargo, clippy, link, CARGO_TARGET_DIR | Format-List
        return
    }

    'clean' {
        Info "dropping $CacheDir on $Target"
        Invoke-Command $Session { param($d) if (Test-Path $d) { Remove-Item -Recurse -Force $d } } -ArgumentList $CacheDir
        Info 'done'
        return
    }
}

# Stage the whole tree into one archive before anything is sent. Piping tar
# straight into the session is not an option: a native-to-native pipeline is
# text, not bytes, and it re-encodes — which corrupts the stream. Writing a
# file and handing it to Copy-Item keeps the transfer binary-clean, and has
# the side benefit that a half-finished transfer can never be unpacked.
# In this repo's tmp/, not the machine temp directory — scratch for this
# project stays inside the project. tar excludes ./tmp, so the archive cannot
# end up inside itself.
$LocalStaging = Join-Path $ProjectRoot 'tmp'
New-Item -ItemType Directory -Force -Path $LocalStaging | Out-Null
$Archive = Join-Path $LocalStaging "wrustic-winci-$PID.tgz"
# Per-run, so two invocations cannot land on each other's upload.
$RemoteArchive = "$Staging\wrustic-winci-src-$PID.tgz"

# The workspace and the cargo target directory are single, fixed and shared by
# design — that is what makes a warm run 20 seconds. It also means a second run
# starting mid-build would delete the tree the first one is compiling. Claim
# the workspace first: creating a directory that already exists fails, and
# fails atomically, which is all a lock has to do.
$Lock = "${RemoteDir}.lock"
# The staging root is the one directory this script creates outside its own
# scratch; provision.ps1 makes it too, so normally this is a no-op. Kept out of
# the claim below so that failing to create it reports itself rather than being
# read as a workspace that is already taken.
Invoke-Command $Session {
    param($Staging)
    New-Item -ItemType Directory -Force -Path $Staging | Out-Null
} -ArgumentList $Staging -ErrorAction Stop

try {
    Invoke-Command $Session {
        param($Lock)
        New-Item -ItemType Directory -Path $Lock -ErrorAction Stop | Out-Null
    } -ArgumentList $Lock -ErrorAction Stop
} catch {
    throw "$Target is busy: $Lock already exists. Either another run holds the workspace, or one died holding it — clear it with: pwsh -Command ""Invoke-Command -HostName $Target -SSHTransport { Remove-Item -Recurse -Force '$Lock' }"""
}

try {
    Info "packing $(Split-Path -Leaf $ProjectRoot)"
    # --dereference: ship symlinks (AGENTS.md -> CLAUDE.md) as regular files —
    # tar on the VM cannot recreate them, and a Windows checkout would have
    # materialized them as files anyway. Spelled long because the client may be
    # either tar: -L is bsdtar's dereference and GNU tar's --tape-length, which
    # fails with `Invalid tape length`.
    & tar -C $ProjectRoot --dereference --exclude=./target --exclude=./tmp --exclude=./.git -czf $Archive .
    if ($LASTEXITCODE -ne 0) { throw "tar failed (exit $LASTEXITCODE)" }

    Info "copying to ${Target}:${RemoteArchive}"
    # Over the session, not scp: no second authentication, and no destination
    # path to be re-split by a tool that reads `C:` as a host name.
    Copy-Item -Path $Archive -Destination $RemoteArchive -ToSession $Session -Force

    # Replace the workspace outright. tar has no --delete, so unpacking over
    # the old tree would leave a file deleted here still sitting there, still
    # getting compiled. The cargo target directory is a sibling, not a child
    # (CARGO_TARGET_DIR on the VM), so the build cache survives this.
    Invoke-Command $Session {
        param($RemoteDir, $RemoteArchive)
        if (Test-Path $RemoteDir) { Remove-Item -Recurse -Force $RemoteDir }
        New-Item -ItemType Directory -Path $RemoteDir | Out-Null
        & tar -xzf $RemoteArchive -C $RemoteDir
        if ($LASTEXITCODE -ne 0) { throw "tar -xzf failed (exit $LASTEXITCODE)" }
    } -ArgumentList $RemoteDir, $RemoteArchive

    if ($Command -eq 'shell') {
        Info "opening a shell on $Target at $RemoteDir"
        # ssh, not Enter-PSSession: entering a session from inside a script
        # pushes the remote runspace and then pops it the moment the script
        # ends, which is no shell at all. An interactive terminal is what ssh
        # is for; every non-interactive step above is the part that belongs on
        # the remoting transport.
        & ssh -t $Target "cd /d $RemoteDir && cmd"
        return
    }

    Info "running ci.ps1 on $Target"
    # ci.ps1 reports failure the way a CI script does — `exit <code>` — and an
    # exit code does not cross a remoting boundary on its own, so park it in a
    # session variable and read it back. The session outlives the call, so this
    # is the same runspace either way.
    #
    # `2>&1` merges cargo's stderr into the output stream *on the VM*. Without
    # it every "Compiling ..." line comes back as an error record: red, out of
    # order with the rest of the log, and liable to be turned into a terminating
    # error by an $ErrorActionPreference the remote session inherited.
    Invoke-Command $Session {
        param($CiScript)
        $ErrorActionPreference = 'Continue'
        $global:WrusticCiExit = $null
        try {
            & $CiScript 2>&1
            $global:WrusticCiExit = $LASTEXITCODE
        } catch {
            Write-Host "ci.ps1 terminated: $($_.Exception.Message)"
            $global:WrusticCiExit = 1
        }
    } -ArgumentList $CiScript

    $ExitCode = Invoke-Command $Session {
        if ($null -eq $global:WrusticCiExit) { 1 } else { [int] $global:WrusticCiExit }
    }
    if ($ExitCode -ne 0) { throw "ci.ps1 failed on $Target (exit $ExitCode)" }
}
finally {
    Remove-Item -LiteralPath $Archive -Force -ErrorAction SilentlyContinue
    # Don't leave a copy of the source tree in the staging root, and never
    # leave the lock behind — a stale one blocks every later run.
    try {
        Invoke-Command $Session {
            param($RemoteArchive, $Lock)
            Remove-Item -LiteralPath $RemoteArchive -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $Lock -Recurse -Force -ErrorAction SilentlyContinue
        } -ArgumentList $RemoteArchive, $Lock
    } catch { }
}

}
finally { Remove-PSSession $Session }
