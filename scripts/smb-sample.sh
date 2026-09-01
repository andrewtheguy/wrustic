#!/usr/bin/env bash
#
# Build and serve a sample restic snapshot over SMB, for testing the read-only
# SMB server (src/smb/, docs/smb.md) against real clients.
#
# The fixture lives under tmp/ and is not tracked, so `seed` rebuilds it from
# nothing. Everything here is reproducible on a fresh clone.

set -euo pipefail

REPOSITORY_PASSWORD="testpass"
SMB_PORT="${SMB_PORT:-4456}"
SMB_SECONDS="${SMB_SECONDS:-1200}"
SHARE_PASSWORD="${WRUSTIC_SMB_SHARE_PASSWORD:-hunter2}"
SHARE_USER="wrustic"

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
sample="${project_root}/tmp/smb-sample"
repository="${sample}/repo"
source_tree="${sample}/source"
snapshot_file="${sample}/snapshot-id.txt"
mountpoint="${sample}/mnt"
tool_dir="${project_root}/tmp/tools"

info() {
    printf '[smb-sample] %s\n' "$*"
}

fail() {
    printf '[smb-sample] ERROR: %s\n' "$*" >&2
    exit 1
}

if ! [[ "$SMB_PORT" =~ ^[0-9]+$ ]] || (( SMB_PORT < 1 || SMB_PORT > 65535 )); then
    fail "SMB_PORT must be an integer from 1 through 65535"
fi
if (( SMB_PORT < 1024 )); then
    fail "SMB_PORT must be >= 1024; a privileged port would need the whole cargo test run under sudo"
fi

usage() {
    cat <<'EOF'
Usage: ./scripts/smb-sample.sh COMMAND

Commands:
  seed      Build the sample source tree and back it up to a fresh repository
  serve     Serve the seeded snapshot over SMB until it times out or Ctrl-C
  verify    Mount the running share, compare every file, check writes fail
            (Linux only; needs sudo and the cifs-utils package)
  run       seed, then serve

Environment:
  SMB_PORT                     listen port                     (default 4456)
  SMB_SECONDS                  how long `serve` stays up       (default 1200)
  WRUSTIC_SMB_SHARE_PASSWORD   share password                  (default hunter2)
  SMB_BIND_ALL=1               listen on every interface, not just loopback
  SMB_LOG=1                    trace every SMB command to stderr

`serve` runs the `dev smb-serve` harness, which exists only in a
`--features dev-harness` build: the only shipped way to share a snapshot is `s`
in the TUI, which is bound to that screen and to loopback. A long-lived server
and a non-loopback bind are testing affordances and stay out of the binary
users get.

Mount from another machine (after `serve` with SMB_BIND_ALL=1). Each prompts for
the password rather than taking it on the command line, where every process on
the machine could read it:
  Linux    sudo mount -t cifs -o port=4456,vers=2.1,username=wrustic,ro //<host>/snap /mnt
  macOS    mount_smbfs //wrustic@<host>:4456/snap /Volumes/snap
  Windows  net use Z: \\<host>\snap * /user:wrustic /TCPPORT:4456
EOF
}

find_restic() {
    if [[ -n "${RESTIC_BIN:-}" ]]; then
        printf '%s\n' "$RESTIC_BIN"
    elif [[ -x "${tool_dir}/restic" ]]; then
        printf '%s\n' "${tool_dir}/restic"
    elif command -v restic >/dev/null 2>&1; then
        command -v restic
    else
        fail "restic is required to create the repository; set RESTIC_BIN or put restic on PATH"
    fi
}

run_restic() {
    local restic_binary="$1"
    shift
    # Password over stdin, never argv — the same rule src/restic.rs follows.
    printf '%s\n' "$REPOSITORY_PASSWORD" |
        "$restic_binary" --repo "$repository" --password-file /dev/stdin "$@"
}

# A tree chosen to exercise the parts of the protocol that broke during
# development: each entry below earns its place.
build_source_tree() {
    rm -rf "$source_tree"
    mkdir -p "$source_tree"/{docs,media,nested/deeper,many}

    printf 'hello from a restic snapshot\n' >"${source_tree}/docs/readme.txt"
    # Zero-length: READ must report end-of-file rather than a short read.
    : >"${source_tree}/docs/empty.txt"
    printf 'a file with spaces in its name\n' >"${source_tree}/docs/file with spaces.txt"
    # Non-ASCII: names cross the UTF-8 to UTF-16LE boundary in both directions.
    printf 'unicode filename test\n' >"${source_tree}/docs/naïve-日本語.txt"
    # ~19 KB, so a read spans more than one response buffer.
    for i in $(seq 1 2000); do printf 'line %s\n' "$i"; done >"${source_tree}/docs/many-lines.txt"
    # Symlink: appears as an empty regular file over SMB — a known limitation,
    # kept here so a regression that panics instead is caught.
    ln -sf ../docs/readme.txt "${source_tree}/docs/link-to-readme"

    # 5 MB spans several restic blobs and several 1 MiB READs, which is what
    # catches an offset bug at a blob boundary.
    head -c 5000000 /dev/urandom >"${source_tree}/media/big-random.bin"
    # Highly deduplicated, so most reads come from one repeated blob.
    head -c 1500000 /dev/zero >"${source_tree}/media/sparse-ish.bin"

    printf 'deeply nested\n' >"${source_tree}/nested/deeper/deep.txt"

    # 120 entries forces QUERY_DIRECTORY to page rather than answering at once.
    for i in $(seq -w 1 120); do
        printf 'file %s\n' "$((10#$i))" >"${source_tree}/many/f${i}.txt"
    done
}

seed_repository() {
    local restic_binary
    restic_binary="$(find_restic)"

    info "building the sample source tree"
    build_source_tree

    info "creating a fresh repository at ${repository}"
    rm -rf "$repository"
    mkdir -p "$repository"
    run_restic "$restic_binary" init >/dev/null

    info "backing up the source tree"
    run_restic "$restic_binary" backup --tag smb-sample "$source_tree" >/dev/null

    # --json so the id is parsed from a documented field rather than scraped
    # out of human-readable output.
    run_restic "$restic_binary" snapshots --json |
        grep -o '"id":"[0-9a-f]\{64\}"' | tail -1 | cut -d'"' -f4 >"$snapshot_file"

    local snapshot
    snapshot="$(cat "$snapshot_file")"
    [[ -n "$snapshot" ]] || fail "could not determine the snapshot id"
    info "seeded snapshot ${snapshot:0:8} ($(find "$source_tree" -type f | wc -l) files)"
}

serve_snapshot() {
    [[ -f "$snapshot_file" ]] || fail "no snapshot yet; run ./scripts/smb-sample.sh seed"

    cd "$project_root"
    # Everything through the environment, never argv, so no password is visible
    # to other processes on the machine.
    local snapshot
    snapshot="$(cat "$snapshot_file")"
    export WRUSTIC_SMB_REPO="$repository"
    export WRUSTIC_SMB_PASSWORD="$REPOSITORY_PASSWORD"
    export WRUSTIC_SMB_SNAPSHOT="$snapshot"
    export WRUSTIC_SMB_PORT="$SMB_PORT"
    export WRUSTIC_SMB_SECONDS="$SMB_SECONDS"
    export WRUSTIC_SMB_SHARE_PASSWORD="$SHARE_PASSWORD"
    # Plain `if`, not `[[ ]] && export`: under `set -e` a false test as the
    # left side of && makes the whole line non-zero, which is a footgun worth
    # not relying on.
    if [[ -n "${SMB_BIND_ALL:-}" ]]; then
        export WRUSTIC_SMB_BIND_ALL=1
    fi
    if [[ -n "${SMB_LOG:-}" ]]; then
        export WRUSTIC_SMB_LOG=1
    fi

    info "serving on port ${SMB_PORT} for ${SMB_SECONDS}s (Ctrl-C to stop early)"
    exec cargo run --all-features -- dev smb-serve
}

verify_mount() {
    [[ "$(uname -s)" == "Linux" ]] || fail "verify is Linux-only; mount by hand on macOS or Windows"
    # mount.cifs lives in /sbin or /usr/sbin, which are not on a normal user's
    # PATH even though `sudo mount -t cifs` finds it fine.
    command -v mount.cifs >/dev/null 2>&1 ||
        [[ -x /sbin/mount.cifs || -x /usr/sbin/mount.cifs ]] ||
        fail "mount.cifs is missing; install cifs-utils"
    [[ -d "$source_tree" ]] || fail "no source tree yet; run ./scripts/smb-sample.sh seed"

    mkdir -p "$mountpoint"
    # Always leave the mountpoint clean, including when a comparison below fails.
    trap 'sudo umount "$mountpoint" 2>/dev/null || sudo umount -l "$mountpoint" 2>/dev/null || true; rmdir "$mountpoint" 2>/dev/null || true' EXIT

    # Deliberately not `ro`. With it the mount is read-only because *we asked*
    # for that, and the checks below would prove nothing about the share. Without
    # it the mount comes up rw and everything read-only about it comes from the
    # server's own advertisement.
    info "mounting //127.0.0.1/snap on ${mountpoint} (rw, so read-only comes from the server)"
    sudo mount -t cifs \
        -o "port=${SMB_PORT},vers=2.1,username=${SHARE_USER},password=${SHARE_PASSWORD},uid=$(id -u),gid=$(id -g)" \
        //127.0.0.1/snap "$mountpoint" ||
        fail "mount failed; is ./scripts/smb-sample.sh serve running? (sudo dmesg | tail says more)"

    # The symlink is excluded: SMB2 without POSIX extensions cannot represent
    # one, so it arrives as an empty file. That is the documented limitation,
    # not a mismatch worth failing on.
    info "comparing every file against the source tree"
    diff \
        <(cd "${mountpoint}${source_tree}" && find . -type f ! -name link-to-readme -exec sha256sum {} \; | sort) \
        <(cd "$source_tree" && find . -type f ! -name link-to-readme -exec sha256sum {} \; | sort) ||
        fail "mounted contents differ from the source tree"
    # Counts the compared set, not everything visible: the symlink shows up as a
    # regular file over SMB and is excluded above, so counting `-type f` on the
    # mount would claim one more file than was actually checked.
    info "all $(find "$source_tree" -type f ! -name link-to-readme | wc -l) files are byte-identical"

    info "checking that writes are refused"
    ! touch "${mountpoint}${source_tree}/should-not-exist" 2>/dev/null ||
        fail "a write succeeded on a read-only share"
    ! mkdir "${mountpoint}${source_tree}/should-not-exist" 2>/dev/null ||
        fail "mkdir succeeded on a read-only share"
    ! rm -f "${mountpoint}${source_tree}/docs/readme.txt" 2>/dev/null ||
        fail "delete succeeded on a read-only share"
    info "writes are refused through the mount"

    # Those three prove the client refuses, not that the server does. cifs.ko
    # reads FILE_READ_ONLY_VOLUME off FileFsAttributeInformation and stops there
    # — it never sends a write-intent CREATE, so ACCESS_DENIED and
    # MEDIA_WRITE_PROTECTED are unreachable through a kernel mount. smbclient
    # has no such shortcut and asks anyway, which is the only way to see the
    # server's own refusal from here.
    if command -v smbclient >/dev/null 2>&1; then
        info "checking that the server itself refuses a write"
        local payload="${sample}/payload.txt"
        printf 'should not land\n' >"$payload"
        local out
        out="$(smbclient "//127.0.0.1/snap" -p "$SMB_PORT" \
            -U "${SHARE_USER}%${SHARE_PASSWORD}" \
            --option='client min protocol=SMB2_10' \
            --option='client max protocol=SMB2_10' \
            -c "put \"${payload}\" payload.txt" 2>&1 || true)"
        rm -f "$payload"
        case "$out" in
            *NT_STATUS_MEDIA_WRITE_PROTECTED* | *NT_STATUS_ACCESS_DENIED*)
                info "the server refuses writes at the protocol level"
                ;;
            *)
                fail "the server did not refuse a write with a read-only status: ${out}"
                ;;
        esac
    else
        info "smbclient is not installed; skipping the server-side write check"
    fi

    info "reported size: $(df -h "$mountpoint" | awk 'NR == 2 { print $2 }')"
    info "verify passed"
}

command="${1:-}"
case "$command" in
    seed)
        seed_repository
        info "now run: ./scripts/smb-sample.sh serve"
        ;;
    serve)
        serve_snapshot
        ;;
    verify)
        verify_mount
        ;;
    run)
        seed_repository
        serve_snapshot
        ;;
    -h | --help | help)
        usage
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
