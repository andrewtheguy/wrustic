#!/usr/bin/env bash
#
# Run the Windows CI steps against *this* working tree, on a remote Windows
# machine. This half runs on Linux or macOS, where the source lives;
# ci/windows/run.ps1 is the half that runs over there.
#
#   WRUSTIC_WINCI_HOST=andrew@desktop-vnvgdaf ./ci/windows/remote.sh
#   WRUSTIC_WINCI_HOST=andrew@10.22.33.20     ./ci/windows/remote.sh shell
#
# The ssh target is Windows itself, not its WSL instance: the container daemon
# is a Windows service and run.ps1 is a Windows script, so WSL would only be a
# hop that has to be undone at the other end.
#
# The tree is copied rather than fetched from git on purpose — the reason to
# run this instead of pushing a branch is to test what you have in front of
# you, uncommitted changes included. To test a *pushed* branch, skip this
# script:
#
#   ssh $WRUSTIC_WINCI_HOST "cd C:\ci-workspaces\wrustic && git fetch origin && ^
#       git checkout -q <branch> && powershell -File ci\windows\run.ps1"

set -euo pipefail

HOST="${WRUSTIC_WINCI_HOST:-}"
# Extra ssh flags, word-split: an identity file, a port, a jump host.
#   WRUSTIC_WINCI_SSH_OPTS="-i ~/.ssh/winci -p 2222"
SSH_OPTS="${WRUSTIC_WINCI_SSH_OPTS:-}"
# A Windows path, because everything at the far end is Windows. Backslashes are
# avoided so the same string survives both cmd.exe and tar; Windows accepts
# forward slashes everywhere that matters here.
REMOTE_DIR="${WRUSTIC_WINCI_REMOTE_DIR:-C:/ci-workspaces/wrustic}"

command="${1:-ci}"
project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

info() {
    printf '[winci-remote] %s\n' "$*"
}

fail() {
    printf '[winci-remote] ERROR: %s\n' "$*" >&2
    exit 1
}

[[ -n "$HOST" ]] ||
    fail "set WRUSTIC_WINCI_HOST to the ssh target of the Windows box, e.g. andrew@10.22.33.20"

# tar rather than rsync: Windows has no rsync, and bsdtar ships in System32 as
# tar.exe, so this needs nothing installed at either end. The whole tree goes
# every time, which is fine for a repo this size and avoids the question of
# what a partial sync left behind.
#
# The remote command is run through cmd.exe — OpenSSH's default shell on
# Windows — and deliberately not PowerShell: PowerShell treats a native
# command's stdin as text and re-encodes it, which corrupts the archive.
# Arrays, expanded with the ${a[@]+"${a[@]}"} guard rather than plain
# "${a[@]}": macOS still ships bash 3.2, where expanding an empty array under
# `set -u` is an unbound-variable error.
ssh_opts=()
[[ -n "$SSH_OPTS" ]] && read -r -a ssh_opts <<< "$SSH_OPTS"

remote_ssh() {
    ssh ${ssh_opts[@]+"${ssh_opts[@]}"} "$HOST" "$@"
}

info "copying $(basename "$project_root") to ${HOST}:${REMOTE_DIR}"
remote_ssh "if not exist \"${REMOTE_DIR//\//\\}\" mkdir \"${REMOTE_DIR//\//\\}\""

tar -C "$project_root" \
    --exclude=./target --exclude=./tmp --exclude=./.git \
    -czf - . |
    remote_ssh "tar -xzf - -C \"${REMOTE_DIR}\""

info "running 'run.ps1 ${command}' on ${HOST}"

tty_flag=()
[[ "$command" == "shell" ]] && tty_flag=(-t)

exec ssh ${ssh_opts[@]+"${ssh_opts[@]}"} ${tty_flag[@]+"${tty_flag[@]}"} "$HOST" \
    "powershell -NoProfile -ExecutionPolicy Bypass -File \"${REMOTE_DIR}/ci/windows/run.ps1\" -Command ${command}"
