# escape=`
#
# A Windows build environment shaped like the `windows-latest` runner that
# .github/workflows/windows-ci.yml uses, so the same three steps can be run
# locally without pushing a branch.
#
# ltsc2022, not ltsc2025: Windows Server 2025 images currently fail to start on
# Windows 11 25H2 hosts with "the container image contains a layer with an
# unrecognized format" (microsoft/hcsshim#2566), under both isolation modes.
# WS2022 images are the documented-compatible choice on a Windows 11 host and
# are the only ones that also support process isolation there.
FROM mcr.microsoft.com/windows/servercore:ltsc2022

SHELL ["powershell", "-NoProfile", "-NoLogo", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

# The MSVC toolchain. `x86_64-pc-windows-msvc` links with link.exe against the
# CRT and the Windows SDK; none of that ships in servercore. Only the two
# components are added rather than the full VCTools workload with
# --includeRecommended, which drags in CMake, MSBuild and ATL for nothing.
#
# 3010 is "installed, reboot required" and is a success for our purposes: the
# reboot is for the host servicing stack, and the toolchain is already usable.
RUN Invoke-WebRequest -UseBasicParsing 'https://aka.ms/vs/17/release/vs_buildtools.exe' -OutFile 'C:\vs_buildtools.exe'; `
    $proc = Start-Process -FilePath 'C:\vs_buildtools.exe' -Wait -PassThru -ArgumentList `
        '--quiet', '--wait', '--norestart', '--nocache', `
        '--installPath', 'C:\BuildTools', `
        '--add', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', `
        '--add', 'Microsoft.VisualStudio.Component.Windows11SDK.22621'; `
    if ($proc.ExitCode -notin @(0, 3010)) { throw "vs_buildtools.exe exited $($proc.ExitCode)" }; `
    Remove-Item 'C:\vs_buildtools.exe'

# CARGO_HOME and the target dir sit outside C:\src on purpose: the source is a
# bind mount of the host worktree, and a container writing into its target/
# would fight the host's own cargo over the same directory. Both are named
# volumes at run time (ci/windows/run.sh), which is what stands in for
# Swatinem/rust-cache here.
ENV RUSTUP_HOME=C:\rustup `
    CARGO_HOME=C:\cargo `
    CARGO_TARGET_DIR=C:\target `
    CARGO_INCREMENTAL=0

RUN Invoke-WebRequest -UseBasicParsing 'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe' -OutFile 'C:\rustup-init.exe'; `
    $proc = Start-Process -FilePath 'C:\rustup-init.exe' -Wait -PassThru -ArgumentList `
        '-y', '--no-modify-path', '--profile', 'minimal', `
        '--default-toolchain', 'stable', '--component', 'clippy'; `
    if ($proc.ExitCode -ne 0) { throw "rustup-init.exe exited $($proc.ExitCode)" }; `
    Remove-Item 'C:\rustup-init.exe'

# C:\cargo\bin goes on PATH in entrypoint.cmd, not here. `ENV PATH=...;${PATH}`
# looks right and is a trap: servercore declares no environment at all in its
# image config, so ${PATH} expands to nothing and the result is an image-level
# PATH of exactly "C:\cargo\bin;" that *overrides* the real one the container
# gets from the registry. System32 disappears with it, and the first symptom is
# cmd.exe reporting that 'powershell' is not recognized.

COPY entrypoint.cmd C:/entrypoint.cmd
COPY ci.ps1 C:/ci.ps1

WORKDIR C:\src

# Two layers of cmd.exe, and both are needed. CreateProcess cannot launch a
# .cmd directly, so the exec form has to name cmd.exe itself; entrypoint.cmd
# then sources vcvars64 into the environment the real command inherits.
ENTRYPOINT ["cmd", "/S", "/C", "C:\\entrypoint.cmd"]
CMD ["powershell", "-NoProfile", "-NoLogo", "-ExecutionPolicy", "Bypass", "-File", "C:\\ci.ps1"]
