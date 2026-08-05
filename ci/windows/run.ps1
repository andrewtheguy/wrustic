# Run the Windows CI steps (.github/workflows/windows-ci.yml) in a Windows
# container. This is the runner: it executes on the Windows box, against the
# Windows container daemon, and knows nothing about WSL or ssh.
#
#   .\ci\windows\run.ps1            # build the image if needed, then run CI
#   .\ci\windows\run.ps1 build      # rebuild the image
#   .\ci\windows\run.ps1 shell      # interactive cmd.exe in the CI environment
#   .\ci\windows\run.ps1 clean      # drop the cargo/target cache volumes
#   .\ci\windows\run.ps1 doctor     # check the setup, change nothing
#
# The two wrappers both end up here, so there is one implementation rather than
# two that drift:
#   ci/windows/run.sh      - from WSL on this machine
#   ci/windows/remote.sh   - from Linux/macOS, over ssh
#
# See docs/windows-container-ci.md for host setup.

[CmdletBinding()]
param(
    [ValidateSet('ci', 'build', 'shell', 'clean', 'doctor')]
    [string] $Command = 'ci'
)

$ErrorActionPreference = 'Stop'

function Get-Setting {
    param([string] $Name, [string] $Default)
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) { $Default } else { $value }
}

$Image = Get-Setting 'WRUSTIC_WINCI_IMAGE' 'wrustic-winci:ltsc2022'
# Hyper-V rather than process isolation, and not for compatibility: under
# process isolation rustc cannot write a crate's .rmeta into a mapped
# directory (bind mount or named volume alike), so the target directory cannot
# be cached between runs. docs/windows-container-ci.md has the detail.
$Isolation = Get-Setting 'WRUSTIC_WINCI_ISOLATION' 'hyperv'
# The utility VM defaults to 1 GB, which will not link this crate graph.
$Memory = Get-Setting 'WRUSTIC_WINCI_MEMORY' '8g'
$RegistryVolume = Get-Setting 'WRUSTIC_WINCI_REGISTRY_VOLUME' 'wrustic-winci-registry'
$TargetVolume = Get-Setting 'WRUSTIC_WINCI_TARGET_VOLUME' 'wrustic-winci-target'

$here = Split-Path -Parent $PSCommandPath
$projectRoot = (Resolve-Path (Join-Path $here '..\..')).Path

function Write-Info { param([string] $Message) Write-Host "[winci] $Message" }

function Stop-WithError {
    param([string] $Message)
    Write-Host "[winci] ERROR: $Message"
    exit 1
}

function Assert-Docker {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Stop-WithError 'docker not found on PATH. See docs/windows-container-ci.md for host setup.'
    }
    $os = & docker version --format '{{.Server.Os}}' 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $os) {
        Stop-WithError 'the docker daemon did not answer. Try (elevated): Start-Service docker'
    }
    if ($os -ne 'windows') {
        Stop-WithError "the daemon is serving $os containers, not Windows ones."
    }
}

function Get-IsolationArgs {
    $flags = @("--isolation=$Isolation")
    if ($Isolation -eq 'hyperv') { $flags += "--memory=$Memory" }
    $flags
}

function Get-MountArgs {
    @(
        '-v', ('{0}:C:\src' -f $projectRoot),
        '-v', ('{0}:C:\cargo\registry' -f $RegistryVolume),
        '-v', ('{0}:C:\target' -f $TargetVolume)
    )
}

function Test-ImagePresent {
    $id = & docker images -q $Image 2>$null
    -not [string]::IsNullOrWhiteSpace($id)
}

function Build-Image {
    Write-Info "building $Image (first time: several GB of Build Tools)"
    $isolationArgs = Get-IsolationArgs
    & docker build @isolationArgs -t $Image $here
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

switch ($Command) {
    'doctor' {
        Assert-Docker
        Write-Info ('docker: {0}' -f (Get-Command docker).Source)
        & docker version --format 'server {{.Server.Version}} ({{.Server.Os}}/{{.Server.Arch}})'
        Write-Info "source: $projectRoot"
        Write-Info "isolation: $Isolation"
        if (Test-ImagePresent) {
            Write-Info "image ${Image}: present"
        } else {
            Write-Info "image ${Image}: missing; 'run.ps1 build' will create it"
        }
    }

    'build' {
        Assert-Docker
        Build-Image
    }

    'clean' {
        Assert-Docker
        & docker volume rm $RegistryVolume $TargetVolume
        Write-Info "cache volumes removed; the image is still there (docker rmi $Image)"
    }

    'shell' {
        Assert-Docker
        if (-not (Test-ImagePresent)) { Build-Image }
        $isolationArgs = Get-IsolationArgs
        $mountArgs = Get-MountArgs
        & docker run --rm -it @isolationArgs @mountArgs $Image cmd.exe
        exit $LASTEXITCODE
    }

    'ci' {
        Assert-Docker
        if (-not (Test-ImagePresent)) { Build-Image }
        Write-Info "image $Image, $Isolation isolation, source $projectRoot"
        $isolationArgs = Get-IsolationArgs
        $mountArgs = Get-MountArgs
        & docker run --rm @isolationArgs @mountArgs $Image
        exit $LASTEXITCODE
    }
}
