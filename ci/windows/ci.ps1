# The steps from .github/workflows/windows-ci.yml, in the same order, with the
# same flags. When this file and that workflow disagree, the workflow is right
# and this is stale — it exists to say what CI will say before CI is asked.
#
# This runs natively on whatever Windows machine it is invoked on: the CI VM
# (see ci/windows/remote.ps1) or a dev box. It installs nothing and changes no
# machine state, so running it locally is safe.
#
# Windows PowerShell 5.1 does not fail on a non-zero exit from a native
# command, whatever $ErrorActionPreference says, so every step checks
# $LASTEXITCODE by hand.
$ErrorActionPreference = 'Stop'

# Invoked over ssh the working directory is the login user's home, not the
# checkout, so anchor to the repo root this script sits in.
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

function Invoke-Step {
    param(
        [Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)][string[]] $Arguments
    )

    Write-Host ''
    Write-Host "== $Name =="
    Write-Host "   cargo $($Arguments -join ' ')"

    & cargo @Arguments
    if ($LASTEXITCODE -ne 0) {
        Write-Host ''
        Write-Host "FAILED: $Name (exit $LASTEXITCODE)"
        exit $LASTEXITCODE
    }
}

Write-Host "== toolchain =="
& rustc --version
& cargo --version
& cargo clippy --version
if ($env:CARGO_TARGET_DIR) { Write-Host "   CARGO_TARGET_DIR=$env:CARGO_TARGET_DIR" }

Invoke-Step 'Clippy' @('clippy', '--all-features', '--all-targets', '--', '-D', 'warnings')

# The live tests (#[ignore]) need a restic binary / S3 server / OS credential
# store and stay out of CI; everything else runs.
Invoke-Step 'Test' @('test', '--all-features')

# Must stay in step with the windows-amd64 row of release.yml and the release
# step of windows-ci.yml, or this stops building what users download.
Invoke-Step 'Release build (same features as the shipped Windows binary)' `
    @('build', '--release', '--features', 'keychain,smb-tun')

Write-Host ''
Write-Host 'all steps passed'
