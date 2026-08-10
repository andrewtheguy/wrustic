# Turn a bare Windows Server 2022 install into the Windows CI box.
#
# Runs *on the VM*, elevated. Deployed and started as a SYSTEM scheduled task
# rather than inline over WinRM, so a dropped connection cannot kill a
# 20-minute installer half way:
#
#   $a  = New-ScheduledTaskAction -Execute 'powershell.exe' `
#           -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\provision\provision.ps1'
#   $pr = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
#   Register-ScheduledTask -TaskName 'wrustic-provision' -Action $a -Principal $pr
#   Start-ScheduledTask -TaskName 'wrustic-provision'
#
# Every step is guarded, so re-running it after adding a step is a no-op for
# everything already installed. Progress goes to C:\provision\provision.log;
# the last line is DONE-OK or DONE-FAIL.
#
# See docs/windows-vm-ci.md.
$ErrorActionPreference = 'Stop'

# Everything is machine-scoped, never per-profile. This script runs as SYSTEM
# and ssh logs in as Administrator; a per-profile install would land in
# SYSTEM's profile and be invisible to every CI run.

function Log($m) { "[{0:HH:mm:ss}] {1}" -f (Get-Date), $m | Tee-Object -FilePath C:\provision\provision.log -Append }

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
    New-Item -ItemType Directory -Force -Path C:\provision | Out-Null

    # --- MSVC toolchain + Windows SDK -------------------------------------
    if (-not (Test-Path 'C:\BuildTools\VC\Tools\MSVC')) {
        Log 'downloading vs_BuildTools.exe'
        Invoke-WebRequest 'https://aka.ms/vs/17/release/vs_BuildTools.exe' -OutFile C:\provision\vs_BuildTools.exe -UseBasicParsing
        Log 'installing VC++ build tools + Windows SDK (long)'
        # --includeRecommended is what drags in the Windows SDK and the CMake
        # that $CMakeBin points at; without it you get a compiler and no SDK.
        $p = Start-Process C:\provision\vs_BuildTools.exe -Wait -PassThru -ArgumentList @(
            '--quiet', '--wait', '--norestart', '--nocache',
            '--installPath', 'C:\BuildTools',
            '--add', 'Microsoft.VisualStudio.Workload.VCTools',
            '--includeRecommended'
        )
        Log "vs_BuildTools exit code $($p.ExitCode)"
        if ($p.ExitCode -notin 0, 3010) { throw "vs_BuildTools failed with $($p.ExitCode)" }
    } else { Log 'MSVC already present, skipping' }

    # --- Rust, machine-wide -----------------------------------------------
    $env:RUSTUP_HOME = 'C:\rust\rustup'
    $env:CARGO_HOME  = 'C:\rust\cargo'
    [Environment]::SetEnvironmentVariable('RUSTUP_HOME', $env:RUSTUP_HOME, 'Machine')
    [Environment]::SetEnvironmentVariable('CARGO_HOME',  $env:CARGO_HOME,  'Machine')

    if (-not (Test-Path 'C:\rust\cargo\bin\rustc.exe')) {
        Log 'downloading rustup-init.exe'
        Invoke-WebRequest 'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe' -OutFile C:\provision\rustup-init.exe -UseBasicParsing
        Log 'installing rust stable (msvc) + clippy'
        $p = Start-Process C:\provision\rustup-init.exe -Wait -PassThru -ArgumentList @(
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

    # --- Cargo cache layout -----------------------------------------------
    # Outside the workspace: remote.ps1 replaces the workspace directory
    # outright on every run, so a target dir inside it would compile from cold
    # every time. Incremental is off because those artefacts are never reused
    # across a workspace that is recreated each run.
    New-Item -ItemType Directory -Force -Path 'C:\ci-cache\target', 'C:\ci-workspaces' | Out-Null
    [Environment]::SetEnvironmentVariable('CARGO_TARGET_DIR', 'C:\ci-cache\target', 'Machine')
    [Environment]::SetEnvironmentVariable('CARGO_INCREMENTAL', '0', 'Machine')

    # sshd captured its environment when the service started, and children
    # inherit that block — so machine PATH changes are invisible over ssh until
    # it restarts. Nothing else here takes effect without this.
    Log 'restarting sshd so ssh sessions see the new machine environment'
    Restart-Service sshd

    Log 'DONE-OK'
} catch {
    Log "DONE-FAIL $($_.Exception.Message)"
    # The log is for a human; the exit code is for the scheduler. Without it
    # the task records success and `Get-ScheduledTaskInfo` says 0 on a failed
    # provision.
    exit 1
}
