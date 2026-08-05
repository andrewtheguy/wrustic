# The steps from .github/workflows/windows-ci.yml, in the same order, with the
# same flags. When this file and that workflow disagree, the workflow is right
# and this is stale — it exists to say what CI will say before CI is asked.
#
# Windows PowerShell 5.1 does not fail on a non-zero exit from a native
# command, whatever $ErrorActionPreference says, so every step checks
# $LASTEXITCODE by hand.
$ErrorActionPreference = 'Stop'

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

Invoke-Step 'Clippy' @('clippy', '--all-features', '--all-targets', '--', '-D', 'warnings')

# The live tests (#[ignore]) need a restic binary / S3 server / OS credential
# store and stay out of CI; everything else runs.
Invoke-Step 'Test' @('test', '--all-features')

Invoke-Step 'Release build (keychain enabled, like the shipped Windows binary)' `
    @('build', '--release', '--features', 'keychain')

Write-Host ''
Write-Host 'all steps passed'
