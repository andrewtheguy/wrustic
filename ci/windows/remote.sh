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
# script and drive a real checkout on the host instead. It needs its own
# directory: REMOTE_DIR has no .git (excluded below) and is replaced outright
# on every run, so a clone left there would be deleted.
#
#   ssh $WRUSTIC_WINCI_HOST "cd C:\ci-workspaces\wrustic-git && git fetch origin && ^
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

# Extract into a staging directory and swap it in only once tar has finished.
# Unpacking straight onto the workspace has two failure modes: a transfer that
# dies half way leaves a tree that is neither the old one nor the new one and
# still builds, and tar has no --delete, so a file removed here would linger
# there and keep getting compiled. Staging makes the workspace change in one
# rename instead of over the length of the transfer.
#
# Nothing under REMOTE_DIR has to survive the swap. The cargo registry and the
# target directory are docker named volumes, not subdirectories of the
# workspace, so the caches are untouched by replacing it.
stage_dir="${REMOTE_DIR}.staging-$$"
stage_win="${stage_dir//\//\\}"
remote_win="${REMOTE_DIR//\//\\}"

drop_stage() {
    remote_ssh "if exist \"${stage_win}\" rmdir /s /q \"${stage_win}\"" >/dev/null 2>&1 || true
}

info "copying $(basename "$project_root") to ${HOST}:${REMOTE_DIR}"

# Until the swap lands, any exit — including the tar pipeline failing under
# `set -e` — leaves a staging directory behind on the remote unless this does
# something about it.
trap drop_stage EXIT
remote_ssh "mkdir \"${stage_win}\""

tar -C "$project_root" \
    --exclude=./target --exclude=./tmp --exclude=./.git \
    -czf - . |
    remote_ssh "tar -xzf - -C \"${stage_dir}\""

remote_ssh "if exist \"${remote_win}\" rmdir /s /q \"${remote_win}\""
remote_ssh "move \"${stage_win}\" \"${remote_win}\" >nul"
trap - EXIT

info "running 'run.ps1 ${command}' on ${HOST}"

tty_flag=()
[[ "$command" == "shell" ]] && tty_flag=(-t)

exec ssh ${ssh_opts[@]+"${ssh_opts[@]}"} ${tty_flag[@]+"${tty_flag[@]}"} "$HOST" \
    "powershell -NoProfile -ExecutionPolicy Bypass -File \"${REMOTE_DIR}/ci/windows/run.ps1\" -Command ${command}"
