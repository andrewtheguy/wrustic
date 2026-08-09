#!/usr/bin/env pwsh

# wrustic installer for Windows
# Downloads the latest installer (wrustic-windows-amd64-setup.exe) from
# https://github.com/andrewtheguy/wrustic/releases and runs it silently.
# The installer is machine-wide: it lays down wrustic.exe and
# wintun-amd64.dll in $env:ProgramFiles\wrustic, plus a pinned restic.exe
# in its restic\ subdirectory (kept off the PATH the install directory
# joins), so installing needs an elevated PowerShell. Config, state, and
# the restic cache stay per-user — wrustic derives them from the running
# user's profile at runtime.
#
# Adapted from the beam-rs installer. Flags are read from $args or
# $env:WRUSTIC_INSTALL_ARGS; there is no param() block, so the script behaves
# the same whether it is run directly or piped into Invoke-Expression.

# Defaults (overwritten by the fallback arg parser)
$ReleaseTag   = $null
$PreRelease   = $false
$DownloadOnly = $false

$ErrorActionPreference = "Stop"

$REPO_OWNER = "andrewtheguy"
$REPO_NAME = "wrustic"

# Allow passing flags when the script is piped into Invoke-Expression (iex),
# where normal PowerShell parameter binding is unavailable. Set
# $env:WRUSTIC_INSTALL_ARGS to a PowerShell-style argument string, e.g.:
#   $env:WRUSTIC_INSTALL_ARGS='-PreRelease'; irm https://raw.githubusercontent.com/andrewtheguy/wrustic/main/install.ps1 | iex

function Print-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Green
}

function Print-Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Print-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# Fetch the latest stable release tag (non-prerelease)
function Get-LatestReleaseTag {
    $apiUrl = "https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases/latest"

    try {
        $release = Invoke-RestMethod -Uri $apiUrl -Method Get
    }
    catch {
        Print-Error "Failed to fetch latest release from GitHub: $_"
        exit 1
    }

    if (-not $release.tag_name) {
        Print-Error "Could not find a latest release on GitHub"
        exit 1
    }

    return $release.tag_name
}

# Fetch the latest prerelease tag. The releases list is newest-first but
# paginated, so follow the Link header's rel="next" pages until a prerelease
# turns up or the pages run out.
function Get-LatestPrereleaseTag {
    $uri = "https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases?per_page=30"

    while ($uri) {
        try {
            $response = Invoke-WebRequest -Uri $uri -Method Get -UseBasicParsing
        }
        catch {
            Print-Error "Failed to fetch releases from GitHub: $_"
            exit 1
        }

        $releases = $response.Content | ConvertFrom-Json
        $latestPrerelease = $releases |
            Where-Object { $_.prerelease -eq $true } |
            Select-Object -First 1 -ExpandProperty tag_name
        if ($latestPrerelease) {
            return $latestPrerelease
        }

        # Windows PowerShell hands the Link header back as one string, pwsh as
        # a string array — joining first makes the match work on both.
        $uri = $null
        $link = $response.Headers['Link']
        if ($link -and (($link -join ', ') -match '<([^>]+)>;\s*rel="next"')) {
            $uri = $matches[1]
        }
    }

    Print-Error "Could not find any prerelease on GitHub"
    exit 1
}

# Fetch full release info (including asset checksums) from the GitHub API
function Get-ReleaseInfo {
    param([string]$Tag)

    $apiUrl = "https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases/tags/$Tag"

    try {
        $release = Invoke-RestMethod -Uri $apiUrl -Method Get
        return $release
    }
    catch {
        Print-Warn "Could not fetch release info: $_"
        return $null
    }
}

# Extract the SHA-256 checksum GitHub publishes for a specific asset
function Get-ExpectedChecksum {
    param(
        [object]$ReleaseInfo,
        [string]$BinaryName
    )

    if (-not $ReleaseInfo -or -not $ReleaseInfo.assets) {
        return $null
    }

    $asset = $ReleaseInfo.assets | Where-Object { $_.name -eq $BinaryName } | Select-Object -First 1

    if (-not $asset) {
        return $null
    }

    if ($asset.digest -match 'sha256:([a-f0-9]+)') {
        return $matches[1]
    }

    return $null
}

function Get-FileChecksum {
    param([string]$FilePath)

    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256
        return $hash.Hash.ToLower()
    }
    catch {
        Print-Error "Failed to compute checksum: $_"
        return $null
    }
}

function Test-Checksum {
    param(
        [string]$FilePath,
        [string]$ExpectedChecksum
    )

    Print-Info "Verifying checksum..."
    $actualChecksum = Get-FileChecksum -FilePath $FilePath

    if (-not $actualChecksum) {
        return $false
    }

    if ($ExpectedChecksum -eq $actualChecksum) {
        $shortHash = $actualChecksum.Substring(0, 16)
        Print-Info "Checksum verified: $shortHash..."
        return $true
    }
    else {
        Print-Error "Checksum verification FAILED!"
        Print-Error "Expected: $ExpectedChecksum"
        Print-Error "Actual:   $actualChecksum"
        return $false
    }
}

# Detect architecture. The release workflow only builds windows-amd64.
function Get-Architecture {
    # A 32-bit PowerShell on a 64-bit OS reports PROCESSOR_ARCHITECTURE=x86;
    # the real machine architecture is in PROCESSOR_ARCHITEW6432 then.
    $arch = [System.Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITEW6432")
    if (-not $arch) {
        $arch = [System.Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")
    }

    if ($arch -ne "AMD64") {
        Print-Error "Unsupported architecture: $arch"
        Print-Error "Only AMD64 (x86_64) is published for Windows; build from source instead:"
        Print-Error "  cargo build --release --features keychain"
        exit 1
    }

    return "amd64"
}

function Get-BinaryName {
    param([string]$Arch)

    if ($Arch -ne "amd64") {
        Print-Error "Unsupported architecture: $Arch"
        exit 1
    }

    return "wrustic-windows-amd64-setup.exe"
}

# Parse an argument string (e.g. from an environment variable) with PowerShell's
# own tokenizer, so quoting behaves the way a user would expect.
function Parse-ArgString {
    param([string]$ArgString)

    if ([string]::IsNullOrWhiteSpace($ArgString)) {
        return @()
    }

    $errors = $null
    $tokens = [System.Management.Automation.PSParser]::Tokenize($ArgString, [ref]$errors)

    if ($errors -and $errors.Count -gt 0) {
        Print-Warn "Could not parse WRUSTIC_INSTALL_ARGS: $($errors[0].Message)"
        return @()
    }

    return $tokens |
        Where-Object { $_.Type -in @('CommandArgument', 'CommandParameter', 'String', 'Number') } |
        ForEach-Object { $_.Content }
}

function Apply-FallbackArgs {
    param([string[]]$ArgList)

    if (-not $ArgList -or $ArgList.Count -eq 0) {
        return
    }

    $unhandled = @()

    foreach ($arg in $ArgList) {
        if (-not $arg) { continue }

        $argLower = $arg.ToLowerInvariant()
        switch ($argLower) {
            '-prerelease' { $script:PreRelease = $true; continue }
            '/prerelease' { $script:PreRelease = $true; continue }
            '-downloadonly' { $script:DownloadOnly = $true; continue }
            '/downloadonly' { $script:DownloadOnly = $true; continue }
            '-h' { Show-Usage; exit 0 }
            '/h' { Show-Usage; exit 0 }
            '--help' { Show-Usage; exit 0 }
            '-?' { Show-Usage; exit 0 }
            '/?' { Show-Usage; exit 0 }
            default {
                if (-not $script:ReleaseTag) {
                    $script:ReleaseTag = $arg
                }
                else {
                    $unhandled += $arg
                }
            }
        }
    }

    if ($unhandled.Count -gt 0) {
        Print-Warn "Ignoring unrecognized fallback arguments: $($unhandled -join ' ')"
    }
}

function Download-Binary {
    param(
        [string]$Url,
        [string]$OutputPath,
        [string]$ExpectedChecksum
    )

    Print-Info "Downloading from $Url"

    try {
        Invoke-WebRequest -Uri $Url -OutFile $OutputPath -UseBasicParsing
    }
    catch {
        Print-Error "Failed to download binary: $_"
        exit 1
    }

    if (-not $ExpectedChecksum) {
        Print-Error "No checksum available. Aborting."
        Remove-Item -Path $OutputPath -Force -ErrorAction SilentlyContinue
        exit 1
    }
    if (-not (Test-Checksum -FilePath $OutputPath -ExpectedChecksum $ExpectedChecksum)) {
        Print-Error "Binary integrity check failed. Aborting."
        Remove-Item -Path $OutputPath -Force -ErrorAction SilentlyContinue
        exit 1
    }
}

# `wrustic --version` prints and exits without touching config or repos, so
# this smoke test is safe on any machine.
function Test-InstalledBinary {
    param([string]$Path)

    Print-Info "Testing installed binary..."
    try {
        $versionInfo = & $Path --version 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Binary returned non-zero exit code"
        }
        Print-Info "Binary test successful: $versionInfo"
    }
    catch {
        Print-Error "Installed binary failed to run."
        Print-Error "Output: $_"
        exit 1
    }
}

# Download only - save the installer to the current directory
function Download-Only {
    param(
        [string]$BaseUrl,
        [string]$BinaryName,
        [string]$ExpectedChecksum
    )

    $url = "$BaseUrl/$BinaryName"
    $outputFile = Join-Path (Get-Location) $BinaryName
    # Stage in a temp directory rather than writing straight to $outputFile. A
    # failed transfer would otherwise leave a truncated installer sitting at
    # the advertised name, and a checksum mismatch would delete whatever file
    # the user already had there. Nothing touches $outputFile until the
    # download is verified.
    $tempDir = Join-Path $env:TEMP "wrustic-download-$(Get-Random)"
    $tempBinary = Join-Path $tempDir $BinaryName

    try {
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

        Download-Binary -Url $url -OutputPath $tempBinary -ExpectedChecksum $ExpectedChecksum

        try {
            Move-Item -Path $tempBinary -Destination $outputFile -Force
        }
        catch {
            Print-Error "Failed to write $($outputFile): $_"
            exit 1
        }

        Print-Info "Installer saved to: $outputFile"
    }
    finally {
        # Runs even on the `exit 1` paths inside Download-Binary.
        if (Test-Path $tempDir) {
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# Download the installer to a temporary location, run it silently, then smoke
# test what it installed.
function Install-Binary {
    param(
        [string]$BaseUrl,
        [string]$BinaryName,
        [string]$ExpectedChecksum
    )

    $url = "$BaseUrl/$BinaryName"
    $tempDir = Join-Path $env:TEMP "wrustic-install-$(Get-Random)"
    $tempBinary = Join-Path $tempDir $BinaryName
    $installDir = Join-Path $env:ProgramFiles "wrustic"

    try {
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

        Download-Binary -Url $url -OutputPath $tempBinary -ExpectedChecksum $ExpectedChecksum

        # The Inno Setup installer places wrustic.exe and wintun-amd64.dll
        # in $installDir (appended to the system PATH) and the pinned
        # restic.exe in its restic\ subdirectory, off that PATH entry.
        # /VERYSILENT keeps it non-interactive.
        Print-Info "Running installer..."
        $setup = Start-Process -FilePath $tempBinary `
            -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART' `
            -Wait -PassThru
        if ($setup.ExitCode -ne 0) {
            Print-Error "Installer exited with code $($setup.ExitCode)."
            Print-Error "If wrustic is currently running, close it and try again."
            exit 1
        }

        Print-Info "Installed to $installDir"
        Test-InstalledBinary -Path (Join-Path $installDir "wrustic.exe")
        Test-BundledRestic -InstallDir $installDir
    }
    finally {
        if (Test-Path $tempDir) {
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# The installer ships a pinned restic.exe in the install directory's
# restic\ subdirectory — wrustic prefers it over PATH for the prune flow,
# and the subdirectory keeps it off the system PATH — so report what landed.
function Test-BundledRestic {
    param([string]$InstallDir)

    $restic = Join-Path $InstallDir "restic\restic.exe"
    if (-not (Test-Path $restic)) {
        Print-Warn "restic\restic.exe was not found in $InstallDir."
        Print-Warn "The prune flow will fall back to a restic >= 0.19 on PATH."
        return
    }

    $versionLine = (& $restic version 2>&1 | Select-Object -First 1)
    Print-Info "Bundled restic: $versionLine"
}

function Show-Usage {
    Write-Host @"
Usage: .\install.ps1 [OPTIONS] [RELEASE_TAG]

Download and run the wrustic installer (wrustic-windows-amd64-setup.exe)

Options:
  -DownloadOnly  Download the installer to the current directory without running it
  -PreRelease    Use latest prerelease tag instead of latest stable release
  -h, --help     Show this help message

Arguments:
  RELEASE_TAG    GitHub release tag to download (default: latest)

Environment variables:
  `$env:RELEASE_TAG           Alternative way to specify release tag
  `$env:WRUSTIC_INSTALL_ARGS  Fallback flags for iex one-liners (e.g. "-PreRelease")

Examples:
  .\install.ps1                              # Install latest wrustic
  .\install.ps1 <release-tag>                # Install specific stable release
  .\install.ps1 -DownloadOnly                # Download latest installer to current directory
  .\install.ps1 -DownloadOnly <release-tag>  # Download specific installer
  `$env:RELEASE_TAG='<release-tag>'; .\install.ps1  # Use environment variable

Installs to: `$env:ProgramFiles\wrustic (added to the system PATH),
containing wrustic.exe, wintun-amd64.dll (the driver --smb-tun loads), and a
pinned restic.exe in the restic\ subdirectory that wrustic's prune flow uses
(kept out of the PATH entry on purpose). The install is machine-wide, so
running it requires an elevated PowerShell; config, state, and the restic
cache stay per-user.

Supported platforms: Windows (amd64). The Windows build ships with the
'keychain' feature enabled, so passphrases can be saved to Windows Credential
Manager.
"@
}

# The Inno Setup installer is machine-wide (PrivilegesRequired=admin), and
# running it /VERYSILENT from a non-elevated shell would stall on a UAC
# prompt or fail outright — so require the elevation up front.
function Test-AdminPrivileges {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Print-Error "Installing wrustic is machine-wide and needs administrator rights."
        Print-Error "Re-run this script from an elevated PowerShell (Run as administrator),"
        Print-Error "or use -DownloadOnly to fetch the installer and run it yourself."
        exit 1
    }
}

function Start-Installation {
    param(
        [string]$Tag,
        [bool]$DownloadOnly
    )

    if ($DownloadOnly) {
        Print-Info "wrustic downloader"
    }
    else {
        Print-Info "wrustic installer"
    }
    Print-Info "Release: $Tag"
    Print-Info "Repository: $REPO_OWNER/$REPO_NAME"

    $arch = Get-Architecture
    $binaryName = Get-BinaryName -Arch $arch

    Print-Info "Platform detected: windows-$arch"
    Print-Info "Binary name: $binaryName"

    $baseUrl = "https://github.com/$REPO_OWNER/$REPO_NAME/releases/download/$Tag"

    Print-Info "Fetching release information..."
    $releaseInfo = Get-ReleaseInfo -Tag $Tag

    if (-not $releaseInfo) {
        Print-Error "Could not fetch release info from GitHub. Cannot verify binary integrity."
        exit 1
    }

    $expectedChecksum = Get-ExpectedChecksum -ReleaseInfo $releaseInfo -BinaryName $binaryName
    if (-not $expectedChecksum) {
        Print-Error "No checksum found for $binaryName in release $Tag. Cannot verify binary integrity."
        exit 1
    }
    $shortHash = $expectedChecksum.Substring(0, 16)
    Print-Info "Expected checksum: $shortHash..."

    if ($DownloadOnly) {
        Download-Only -BaseUrl $baseUrl -BinaryName $binaryName -ExpectedChecksum $expectedChecksum
        Print-Info "Download completed successfully!"
    }
    else {
        Install-Binary -BaseUrl $baseUrl -BinaryName $binaryName -ExpectedChecksum $expectedChecksum
        Print-Info "Installation completed successfully!"
        Print-Info "You can now run 'wrustic' from your terminal (restart it to pick up PATH)."
    }
}

function Main {
    # Arguments arrive either from the caller (forwarded via `Main @args`) or
    # from the environment, which is the only channel an `iex` one-liner has.
    $fallbackArgs = @()
    if ($args -and $args.Count -gt 0) {
        $fallbackArgs += $args
    }
    if ($env:WRUSTIC_INSTALL_ARGS) {
        $fallbackArgs += (Parse-ArgString -ArgString $env:WRUSTIC_INSTALL_ARGS)
    }
    Apply-FallbackArgs -ArgList $fallbackArgs

    # Extra guard: honor env flags even if tokenization failed.
    $envArgs = $env:WRUSTIC_INSTALL_ARGS
    if ($envArgs) {
        if (-not $script:PreRelease -and $envArgs -match '(?i)(^|\s)--?prerelease(\s|$)') { $script:PreRelease = $true }
        if (-not $script:DownloadOnly -and $envArgs -match '(?i)(^|\s)--?downloadonly(\s|$)') { $script:DownloadOnly = $true }
        if (-not $script:ReleaseTag -and $envArgs -match '^(\s*[^-][^\s]+)') {
            $script:ReleaseTag = $matches[1].Trim()
        }
    }

    if ($script:DownloadOnly) {
        Print-Info "Starting wrustic download..."
    }
    else {
        Print-Info "Starting wrustic installation..."
    }

    # Determine release tag
    $tag = $script:ReleaseTag
    if (-not $tag) {
        $tag = $env:RELEASE_TAG
    }
    if (-not $tag) {
        if ($script:PreRelease) {
            Print-Info "Fetching latest prerelease tag from GitHub..."
            $tag = Get-LatestPrereleaseTag
        }
        else {
            Print-Info "Fetching latest release tag from GitHub..."
            $tag = Get-LatestReleaseTag
        }
    }

    if (-not $script:DownloadOnly) {
        Test-AdminPrivileges
    }

    Start-Installation -Tag $tag -DownloadOnly:$script:DownloadOnly
}

# `@args` forwards the script's own arguments, so `.\install.ps1 -DownloadOnly`
# works as well as the env-var channel used by `iex`.
#
# WRUSTIC_INSTALL_ARGS is read but never unset: the caller created it, so it is
# theirs to clear. (`$env:` variables are process-scoped anyway — they are
# inherited by child processes but invisible to any later session, so there is
# nothing to "leak".)
Main @args
