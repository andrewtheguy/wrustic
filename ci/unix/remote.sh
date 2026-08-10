#!/usr/bin/env bash
# Run the Unix CI steps against *this* working tree on a remote Unix machine.
#
#   ci/unix/remote.sh <host>              # clippy, test, release-profile build
#   ci/unix/remote.sh <host> shell        # interactive shell in the workspace
#   ci/unix/remote.sh <host> doctor       # report on the machine, change nothing
#   ci/unix/remote.sh <host> clean        # drop the machine's cargo target cache
#
# <host> is an ssh alias; 'macvm' (macOS arm64) and 'workstation-wsl' (Debian
# amd64) are the two boxes this was set up against, and any Unix machine with
# rustup, a C toolchain and — on Linux — libdbus, pkg-config and smbclient
# works the same way. ci/unix/ci.sh is the half that runs over there; it picks
# the platform's release features itself. This is ci/windows/remote.ps1 with
# the Windows constraints removed: the remote shell is a real POSIX shell, so
# paths are quoted instead of being restricted, and symlinks unpack fine.
#
# The tree is copied rather than fetched from git on purpose — the reason to
# run this instead of pushing a branch is to test what you have in front of
# you, uncommitted changes included.
#
# The staging area defaults to codes/staging-area under the remote login
# user's home; override with WRUSTIC_UNIXCI_STAGING (an absolute remote path).
# Inside it: wrustic/ is the workspace and is replaced on every run;
# cargo-target/ is CARGO_TARGET_DIR and survives it, which is what makes a
# warm run fast; wrustic.lock/ is the run lock.
set -euo pipefail

usage() { echo "usage: $0 <ssh-host> [ci|shell|doctor|clean]" >&2; exit 2; }

target=${1:-} && [ -n "$target" ] || usage
command=${2:-ci}
case $command in ci|shell|doctor|clean) ;; *) usage ;; esac

info() { echo "[unixci] $*"; }

if [ -n "${WRUSTIC_UNIXCI_STAGING:-}" ]; then
    staging=$WRUSTIC_UNIXCI_STAGING
else
    staging="$(ssh "$target" 'printf %s "$HOME"')/codes/staging-area"
fi

# Every remote line below is a string handed to the login shell on the far
# end, with these paths spliced in between single quotes, and two of them are
# rm -rf. Take only an absolute path of plain characters, at least two
# components deep so no expansion of it can name a filesystem root — the same
# stance as Assert-RemotePath in the Windows driver.
if ! [[ $staging =~ ^(/[A-Za-z0-9._-]+){2,}$ && $staging != *..* ]]; then
    echo "the staging area must be an absolute path of letters, digits, _ . - at least two components deep, with no trailing slash; got: $staging" >&2
    exit 2
fi

workspace=$staging/wrustic
target_dir=$staging/cargo-target
lock=$staging/wrustic.lock
project_root=$(cd "$(dirname "$0")/../.." && pwd)

# rustup's bin dir is not on a non-interactive ssh session's PATH; every probe
# and ci.sh itself compensate the same way.
remote_path='export PATH="$HOME/.cargo/bin:$PATH";'

case $command in
    doctor)
        info "checking $target"
        ssh "$target" "$remote_path
            uname -sm
            rustc --version || true
            cargo --version || true
            cargo clippy --version || true
            cc --version 2>&1 | head -1 || true
            if [ \"\$(uname -s)\" = Linux ]; then
                pkg-config --exists dbus-1 && echo 'libdbus: present' || echo 'libdbus: MISSING (apt-get install libdbus-1-dev pkg-config)'
                command -v smbclient >/dev/null && echo 'smbclient: present' || echo 'smbclient: missing (six tests will skip themselves)'
            fi
            ls -d '$staging' || true"
        exit 0
        ;;
    clean)
        info "dropping $target_dir on $target"
        ssh "$target" "rm -rf '$target_dir'"
        info 'done'
        exit 0
        ;;
esac

archive=$(mktemp -t wrustic-unixci).tgz
# Per-run, so two invocations cannot land on each other's upload in the shared
# login home directory.
remote_archive="wrustic-unixci-src-$$.tgz"

# The workspace and the cargo target directory are single, fixed and shared by
# design. It also means a second run starting mid-build would rm -rf the tree
# the first one is compiling. Claim the workspace first: mkdir on an existing
# directory fails, and fails atomically, which is all a lock has to do.
if ! ssh "$target" "mkdir -p '$staging' && mkdir '$lock'"; then
    echo "$target is busy: $lock already exists. Either another run holds the workspace, or one died holding it — clear it with: ssh $target rmdir '$lock'" >&2
    exit 1
fi

cleanup() {
    rm -f "$archive"
    # Don't leave a copy of the source tree in the login home dir, and never
    # leave the lock behind — a stale one blocks every later run.
    ssh "$target" "rm -f '$remote_archive'; rmdir '$lock'" >/dev/null 2>&1 || true
}
trap cleanup EXIT

info "packing $(basename "$project_root")"
# -L for parity with the Windows driver: what lands on the far end is the same
# tree either way, symlinks resolved.
tar -C "$project_root" -L --exclude=./target --exclude=./tmp --exclude=./.git \
    -czf "$archive" .

info "copying to $target:$workspace"
scp -q "$archive" "$target:$remote_archive"

# Replace the workspace outright. tar has no --delete, so unpacking over the
# old tree would leave a file deleted here still sitting there, still getting
# compiled. The cargo target directory lives outside the workspace, so the
# build cache survives this.
ssh "$target" "rm -rf '$workspace' && mkdir -p '$workspace' && tar -xzf '$remote_archive' -C '$workspace'"

if [ "$command" = shell ]; then
    info "opening a shell on $target at $workspace"
    ssh -t "$target" "cd '$workspace' && exec \$SHELL -l"
    exit 0
fi

info "running ci.sh on $target"
ssh "$target" "$remote_path cd '$workspace' && CARGO_TARGET_DIR='$target_dir' ./ci/unix/ci.sh"
