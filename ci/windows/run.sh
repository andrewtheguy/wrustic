#!/usr/bin/env bash
#
# Run the Windows CI steps from WSL on this machine.
#
# This is a wrapper. The runner is ci/windows/run.ps1, which executes on the
# Windows side; everything about images, isolation and volumes lives there, so
# there is one implementation rather than two that drift. What is genuinely
# WSL-specific stays here: finding a Windows path for the source, and staging a
# copy when there isn't one.
#
# Windows containers never run inside WSL — WSL2 is a Linux VM with no Windows
# kernel to share — so the daemon is always the Windows host's. This reaches it
# through interop rather than a TCP socket, which avoids publishing an
# unauthenticated root-equivalent endpoint; with bridged WSL networking
# (`localhost` here is not the Windows host) it would have to go to the LAN to
# be reachable at all.
#
#   ./ci/windows/run.sh            # build the image if needed, then run CI
#   ./ci/windows/run.sh build      # rebuild the image
#   ./ci/windows/run.sh shell      # interactive cmd.exe in the CI environment
#   ./ci/windows/run.sh clean      # drop the cargo/target cache volumes
#   ./ci/windows/run.sh doctor     # check the setup, change nothing
#
# See docs/windows-container-ci.md for host setup.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd "${here}/../.." && pwd)"
command="${1:-ci}"

info() {
    printf '[winci] %s\n' "$*"
}

fail() {
    printf '[winci] ERROR: %s\n' "$*" >&2
    exit 1
}

# Interop executables inherit the caller's working directory, and a WSL-native
# cwd has no Windows path — which makes them warn and land in C:\Windows.
interop_cwd="/"
[[ -d /mnt/c ]] && interop_cwd="/mnt/c"

powershell_bin="$(command -v powershell.exe || true)"
if [[ -z "$powershell_bin" ]]; then
    powershell_bin="/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
fi
[[ -x "$powershell_bin" ]] ||
    fail "powershell.exe not found; is WSL interop enabled?"

# The daemon binds the source by Windows path, so the tree has to live on a
# drive Windows can name. A WSL-native checkout gets copied to the Windows side
# rather than mounted: \\wsl.localhost\... is not a valid bind mount source.
source_dir="$project_root"
if [[ "$project_root" != /mnt/[a-z]/* ]]; then
    stage_root="$(cd "$interop_cwd" && wslpath -u "$(cmd.exe /c 'echo %LOCALAPPDATA%' 2>/dev/null | tr -d '\r')")" ||
        fail "could not locate the Windows LOCALAPPDATA directory"
    stage="${stage_root}/Temp/wrustic-winci-src"
    # The staging path is derived from an interop call, and the tar branch below
    # deletes it outright. Check it still looks like the path this script builds
    # before handing it to rm -rf.
    [[ "$stage" == */Temp/wrustic-winci-src ]] ||
        fail "refusing to clear an unexpected staging path: ${stage}"

    info "checkout is on the WSL filesystem, which a Windows container cannot bind-mount"
    info "staging a copy at ${stage}"
    if command -v rsync >/dev/null 2>&1; then
        # --no-perms/--no-owner/--no-group: the destination is a DrvFs mount of
        # an NTFS volume and carries no Unix metadata; without these rsync
        # fails setting modes it cannot set.
        mkdir -p "$stage"
        rsync -rlt --delete --no-perms --no-owner --no-group \
            --exclude '/target/' --exclude '/tmp/' "${project_root}/" "${stage}/"
    else
        # rsync's --delete has no tar equivalent, so extracting over a previous
        # staging would keep files that have since been deleted from the
        # checkout — and they would be compiled. Start empty instead; this
        # branch copies the whole tree either way, so nothing is lost by it.
        rm -rf "$stage"
        mkdir -p "$stage"
        tar -C "$project_root" --exclude=./target --exclude=./tmp -cf - . | tar -C "$stage" -xf -
    fi
    source_dir="$stage"
fi

source_win="$(cd "$interop_cwd" && wslpath -w "$source_dir")"

cd "$interop_cwd"
exec "$powershell_bin" -NoProfile -ExecutionPolicy Bypass \
    -File "${source_win}\\ci\\windows\\run.ps1" -Command "$command"
