#!/usr/bin/env bash
# The steps from .github/workflows/unix-ci.yml, in the same order, with the
# same flags, plus a release-profile build. When this file and that workflow
# disagree, the workflow is right and this is stale — it exists to say what CI
# will say before CI is asked.
#
# This runs natively on whatever Unix machine it is invoked on: a CI box (see
# ci/unix/remote.sh) or a dev machine. It installs nothing and changes no
# machine state, so running it locally is safe — the build dependencies the
# workflow apt-gets on Linux (libdbus, pkg-config, smbclient) are assumed
# present; `remote.sh doctor` checks for them.
set -euo pipefail

# Invoked over ssh the working directory is the login user's home, not the
# checkout, so anchor to the repo root this script sits in. A non-interactive
# ssh shell also skips the profile that puts rustup's bin dir on PATH.
cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$PATH"

step() {
    local name=$1; shift
    echo ''
    echo "== $name =="
    echo "   cargo $*"
    cargo "$@"
}

echo '== toolchain =='
rustc --version
cargo --version
cargo clippy --version
[ -n "${CARGO_TARGET_DIR:-}" ] && echo "   CARGO_TARGET_DIR=$CARGO_TARGET_DIR"

step 'Clippy' clippy --all-features --all-targets -- -D warnings

# The live tests (#[ignore]) need a restic binary / S3 server / OS credential
# store and stay out of CI; everything else runs. The six smbclient tests skip
# themselves where the client is not installed, same as on the macOS runner.
step 'Test' test --all-features

# Not a unix-ci.yml step — it tracks this platform's row of release.yml, so it
# also proves the binary users download still builds: macos-arm64 ships with
# `keychain`, the Linux rows ship with no features (see the matrix comments
# there for why). A string expanded unquoted, not an array — macOS's bash 3.2
# treats an empty array as unset under `set -u`.
release_features=''
release_os=Linux
if [ "$(uname -s)" = Darwin ]; then
    release_features='--features keychain'
    release_os=macOS
fi
# shellcheck disable=SC2086
step "Release build (same features as the shipped $release_os binary)" \
    build --release $release_features

echo ''
echo 'all steps passed'
