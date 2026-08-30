# Turn a bare Windows Server 2025 install into the Windows CI box.
#
# Runs *on the VM*, elevated. Deployed and started as a SYSTEM scheduled task
# rather than inline over WinRM, so a dropped connection cannot kill a
# 20-minute installer half way:
#
#   $a  = New-ScheduledTaskAction -Execute 'powershell.exe' `
#           -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\ci-workspaces\provision\provision.ps1'
#   $pr = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
#   Register-ScheduledTask -TaskName 'wrustic-provision' -Action $a -Principal $pr
#   Start-ScheduledTask -TaskName 'wrustic-provision'
#
# Every step is guarded, so re-running it after adding a step is a no-op for
# everything already installed. Progress goes to
# C:\ci-workspaces\provision\provision.log; the last line is DONE-OK or DONE-FAIL.
#
# C:\ci-workspaces is the staging root: every scratch file either this script or
# remote.ps1 writes — installers, logs, the shipped tree, the build cache —
# lives under it. Only the two toolchains, which are installations rather than
# scratch, land elsewhere (C:\BuildTools and C:\rust).
#
# See docs/windows-vm-ci.md.
$ErrorActionPreference = 'Stop'

# Everything is machine-scoped, never per-profile. This script runs as SYSTEM
# and ssh logs in as Administrator; a per-profile install would land in
# SYSTEM's profile and be invisible to every CI run.

function Log($m) { "[{0:HH:mm:ss}] {1}" -f (Get-Date), $m | Tee-Object -FilePath C:\ci-workspaces\provision\provision.log -Append }

# The instance installed at C:\BuildTools, or $null. -products *: Build Tools
# is not in vswhere's default product set.
function Get-BuildToolsInstance {
    $vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) { return $null }
    & $vswhere -products * -all -format json | ConvertFrom-Json |
        Where-Object { $_.installationPath -eq 'C:\BuildTools' } | Select-Object -First 1
}

# Two ways C:\BuildTools can hold something that must not be kept:
#
#   - An install interrupted part way — the VM rebooted, the task was killed —
#     leaves the directory populated but the toolchain unusable, so a Test-Path
#     guard would skip it and hand every later run a compiler that cannot link.
#     vswhere reports isComplete/isLaunchable false for such an instance, and
#     re-running the bootstrapper over it resumes rather than starts again.
#   - An older product line. This box exists to predict what the runner will
#     say, so it tracks the runner's compiler: major 18 is VS 2026, and an
#     older instance would be testing a toolset the runner does not have.
function Test-BuildToolsCurrent {
    $i = Get-BuildToolsInstance
    return [bool]($i -and $i.isComplete -and $i.isLaunchable -and
                  ([version]$i.installationVersion).Major -ge 18)
}

function Add-MachinePath($dir) {
    $p = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if ($p -notlike "*$dir*") {
        [Environment]::SetEnvironmentVariable('Path', "$p;$dir", 'Machine')
        Log "added $dir to machine PATH"
    }
    # The running process needs it too — later steps in this script use it.
    if ($env:Path -notlike "*$dir*") { $env:Path = "$env:Path;$dir" }
}

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    New-Item -ItemType Directory -Force -Path C:\ci-workspaces\provision | Out-Null

    # --- MSVC toolchain + Windows SDK -------------------------------------
    if (-not (Test-BuildToolsCurrent)) {
        # An instance of the wrong product line has to be uninstalled before
        # anything can be put in its place. An *incomplete* instance of the
        # right one is left alone: the bootstrapper resumes it, which is much
        # cheaper than starting over.
        $old = Get-BuildToolsInstance
        if ($old -and ([version]$old.installationVersion).Major -lt 18) {
            Log "uninstalling the VS $($old.catalog.productLineVersion) build tools at C:\BuildTools"
            # No --wait here, unlike the bootstrapper below: vs_installer
            # rejects it outright and exits 87 (ERROR_INVALID_PARAMETER)
            # without writing a log to say why. -Wait on Start-Process is what
            # actually blocks. 3010 is success with a restart pending.
            $p = Start-Process 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vs_installer.exe' -Wait -PassThru -ArgumentList @(
                'uninstall', '--quiet', '--norestart',
                '--installPath', 'C:\BuildTools'
            )
            Log "vs_installer uninstall exit code $($p.ExitCode)"
            if ($p.ExitCode -notin 0, 3010) { throw "vs_installer uninstall failed with $($p.ExitCode)" }
            $old = $null
        }

        # Deregistering an instance does not empty its directory, and neither
        # does an install that died early — but the installer will not write
        # into a non-empty target: `Visual Studio cannot be installed to a
        # nonempty directory 'C:\BuildTools'`, exit 1, with the reason logged
        # only as a *warning* in dd_installer_*.log. So the leftover shell has
        # to go whenever there is no instance left to resume.
        if (-not $old -and (Test-Path 'C:\BuildTools')) {
            Log 'removing the leftover C:\BuildTools directory'
            Remove-Item -Recurse -Force 'C:\BuildTools'
        }

        Log 'downloading vs_BuildTools.exe'
        # VS 2026, to match the runner image (windows-2025-vs2026). Note the
        # channel: VS 2026 replaced `release` with `stable`/`insiders`, so
        # aka.ms/vs/18/release/... is not a broken link, it is a Bing search
        # that returns 200 and downloads an HTML page over the .exe.
        Invoke-WebRequest 'https://aka.ms/vs/18/stable/vs_BuildTools.exe' -OutFile C:\ci-workspaces\provision\vs_BuildTools.exe -UseBasicParsing
        Log 'installing VC++ build tools + Windows SDK (long)'
        # --includeRecommended is what drags in the Windows SDK and the CMake
        # that $CMakeBin points at; without it you get a compiler and no SDK.
        $p = Start-Process C:\ci-workspaces\provision\vs_BuildTools.exe -Wait -PassThru -ArgumentList @(
            '--quiet', '--wait', '--norestart', '--nocache',
            '--installPath', 'C:\BuildTools',
            '--add', 'Microsoft.VisualStudio.Workload.VCTools',
            '--includeRecommended'
        )
        Log "vs_BuildTools exit code $($p.ExitCode)"
        if ($p.ExitCode -notin 0, 3010) { throw "vs_BuildTools failed with $($p.ExitCode)" }
        # A zero exit is not the same as a usable instance when the bootstrapper
        # was resuming one; ask again rather than find out at link time.
        if (-not (Test-BuildToolsCurrent)) { throw 'vs_BuildTools exited 0 but the instance is still incomplete' }
        Log "MSVC toolset: $((Get-ChildItem C:\BuildTools\VC\Tools\MSVC -Name) -join ', ')"
    } else { Log 'MSVC already present, skipping' }

    # --- Rust, machine-wide -----------------------------------------------
    $env:RUSTUP_HOME = 'C:\rust\rustup'
    $env:CARGO_HOME  = 'C:\rust\cargo'
    [Environment]::SetEnvironmentVariable('RUSTUP_HOME', $env:RUSTUP_HOME, 'Machine')
    [Environment]::SetEnvironmentVariable('CARGO_HOME',  $env:CARGO_HOME,  'Machine')

    if (-not (Test-Path 'C:\rust\cargo\bin\rustc.exe')) {
        Log 'downloading rustup-init.exe'
        Invoke-WebRequest 'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe' -OutFile C:\ci-workspaces\provision\rustup-init.exe -UseBasicParsing
        Log 'installing rust stable (msvc) + clippy'
        $p = Start-Process C:\ci-workspaces\provision\rustup-init.exe -Wait -PassThru -ArgumentList @(
            '-y', '--no-modify-path', '--profile', 'minimal',
            '--default-toolchain', 'stable-x86_64-pc-windows-msvc',
            '--component', 'clippy'
        )
        Log "rustup-init exit code $($p.ExitCode)"
        if ($p.ExitCode -ne 0) { throw "rustup-init failed with $($p.ExitCode)" }
    } else { Log 'rust already present, skipping' }

    Add-MachinePath 'C:\rust\cargo\bin'

    # No cmake or NASM here on purpose. aws-lc-sys (via rustls) pulls in the
    # cmake crate and builds assembly, so it looks like it needs both — a bare
    # Server install has neither, and GitHub's runner image preinstalls them,
    # which is exactly the shape of a Windows-only CI failure. It builds fine
    # anyway: aws-lc-sys 0.41 ships prebuilt assembly for
    # x86_64-pc-windows-msvc and never takes its cmake path. Verified by a full
    # green run on this VM with both absent. If a future dependency does want
    # cmake, VS Build Tools already ships one that only needs a PATH entry:
    # C:\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin

    # --- PowerShell 7 + the sshd remoting subsystem ------------------------
    # remote.ps1 drives this box with PowerShell remoting over the SSH
    # transport, which needs PowerShell 7 at both ends plus a Subsystem line
    # telling sshd how to start it. Deliberately not WinRM: no service to
    # enable, no TrustedHosts list, no certificate — the same sshd, port and
    # key as a plain ssh session.
    #
    # PowerShell 7 itself is a prerequisite, not a step: this script checks for
    # it and stops. It has to be the MSI build — a Microsoft Store package runs
    # in an app container that sshd cannot launch as a subsystem, so installing
    # the wrong one produces a working `pwsh` and a remoting path that closes
    # the connection with no error to read.
    $Pwsh = 'C:\Program Files\PowerShell\7\pwsh.exe'
    if (-not (Test-Path $Pwsh)) {
        throw "PowerShell 7 is missing ($Pwsh). Install it by hand from the MSI at https://github.com/PowerShell/PowerShell/releases — not the Microsoft Store build — and run this again."
    }
    Log "PowerShell $(& $Pwsh -NoProfile -NoLogo -Command '$PSVersionTable.PSVersion.ToString()') present"

    $SshdConfig = 'C:\ProgramData\ssh\sshd_config'
    # -match against an array *filters* it, so this is a test for "no line
    # matched", not a negated match — `-notmatch` here would return every other
    # line in the file and read as true on a config that already has it.
    if (-not ((Get-Content $SshdConfig) -match '^\s*Subsystem\s+powershell\b')) {
        # The 8.3 short path is not a stylistic choice: sshd splits a Subsystem
        # line on whitespace, so C:\Program Files\... would be read as a
        # command followed by an argument.
        Add-Content -Path $SshdConfig -Value 'Subsystem powershell C:\progra~1\PowerShell\7\pwsh.exe -sshs -NoLogo'
        Log 'added the powershell subsystem to sshd_config'
    } else { Log 'sshd powershell subsystem already present, skipping' }

    # --- Cargo cache layout -----------------------------------------------
    # A sibling of the workspace inside the staging root, not a child of it:
    # remote.ps1 replaces the workspace directory outright on every run, so a
    # target dir inside it would compile from cold every time. Incremental is
    # off because those artefacts are never reused across a workspace that is
    # recreated each run.
    New-Item -ItemType Directory -Force -Path 'C:\ci-workspaces\cargo-target' | Out-Null
    [Environment]::SetEnvironmentVariable('CARGO_TARGET_DIR', 'C:\ci-workspaces\cargo-target', 'Machine')
    [Environment]::SetEnvironmentVariable('CARGO_INCREMENTAL', '0', 'Machine')

    # sshd captured its environment when the service started, and children
    # inherit that block — so machine PATH changes are invisible over ssh until
    # it restarts. Nothing else here takes effect without this, and the
    # Subsystem line added above needs the restart to be read at all.
    Log 'restarting sshd so sessions see the new machine environment and the powershell subsystem'
    Restart-Service sshd

    Log 'DONE-OK'
} catch {
    Log "DONE-FAIL $($_.Exception.Message)"
    # The log is for a human; the exit code is for the scheduler. Without it
    # the task records success and `Get-ScheduledTaskInfo` says 0 on a failed
    # provision.
    exit 1
}
