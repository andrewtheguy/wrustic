#!/usr/bin/env bash

set -euo pipefail

SILO_ACCESS_KEY="wrustic-it"
SILO_SECRET_KEY="wrustic-it-secret"
SILO_REGION="us-east-1"
SILO_BUCKET="wrustic-it"
RESTIC_REPOSITORY_PASSWORD="silo-repository-password"
SILO_S3_PORT="${SILO_S3_PORT:-9000}"

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
runtime="${project_root}/tmp/silo-e2e/runtime"
tool_dir="${project_root}/tmp/tools"

info() {
    printf '[silo-e2e] %s\n' "$*"
}

fail() {
    printf '[silo-e2e] ERROR: %s\n' "$*" >&2
    exit 1
}

[[ "$SILO_S3_PORT" =~ ^[0-9]+$ ]] &&
    (( SILO_S3_PORT >= 1 && SILO_S3_PORT <= 65535 )) ||
    fail "SILO_S3_PORT must be an integer from 1 through 65535"

usage() {
    cat <<'EOF'
Usage: ./scripts/silo-e2e.sh COMMAND

Commands:
  seed    Initialize a fresh restic repository and create two snapshots
  test    Run wrustic's ignored live Silo integration test
  run     Seed and test, leaving the independently managed server running

Start a fresh server in another terminal with:
  ./scripts/silo-test-server.sh --reset

Set SILO_S3_PORT on both commands to use a port other than 9000.
EOF
}

require_running_server() {
    command -v curl >/dev/null 2>&1 || fail "curl is required to probe Silo"
    # Silo is a MinIO fork and keeps MinIO's wire surface, health path included.
    curl --fail --silent --output /dev/null \
        "http://127.0.0.1:${SILO_S3_PORT}/minio/health/live" ||
        fail "Silo is not running; start ./scripts/silo-test-server.sh in another terminal"
}

find_restic() {
    if [[ -n "${RESTIC_BIN:-}" ]]; then
        printf '%s\n' "$RESTIC_BIN"
    elif [[ -x "${tool_dir}/restic" ]]; then
        printf '%s\n' "${tool_dir}/restic"
    elif command -v restic >/dev/null 2>&1; then
        command -v restic
    else
        fail "restic >= 0.19.1 is required; set RESTIC_BIN or put restic on PATH"
    fi
}

require_restic_0191() {
    local binary="$1"
    local version major minor patch

    version="$("$binary" version | awk 'NR == 1 { print $2 }')"
    [[ "$version" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+) ]] ||
        fail "could not parse restic version: ${version}"
    major="${BASH_REMATCH[1]}"
    minor="${BASH_REMATCH[2]}"
    patch="${BASH_REMATCH[3]}"

    if (( major == 0 && (minor < 19 || (minor == 19 && patch < 1)) )); then
        fail "restic ${version} is too old; restic >= 0.19.1 is required"
    fi
}

run_restic() {
    local restic_binary="$1"
    shift
    local repository="s3:http://127.0.0.1:${SILO_S3_PORT}/${SILO_BUCKET}/repository"

    printf '%s\n' "$RESTIC_REPOSITORY_PASSWORD" |
        AWS_ACCESS_KEY_ID="$SILO_ACCESS_KEY" \
            AWS_SECRET_ACCESS_KEY="$SILO_SECRET_KEY" \
            AWS_DEFAULT_REGION="$SILO_REGION" \
            "$restic_binary" \
            --repo "$repository" \
            --password-file /dev/stdin \
            "$@"
}

seed_repository() {
    require_running_server
    local restic_binary source
    restic_binary="$(find_restic)"
    require_restic_0191 "$restic_binary"
    source="${runtime}/source"
    mkdir -p "${source}/nested"

    # `init` creates the bucket as well: Silo, like MinIO, has none until a
    # client makes one, and restic's S3 backend does that on init.
    info "seeding a fresh restic repository through Silo S3"
    printf 'hello from Silo S3 integration, revision 1\n' >"${source}/hello.txt"
    printf '{"backend":"silo","revision":1}\n' >"${source}/nested/metadata.json"
    run_restic "$restic_binary" init
    run_restic "$restic_binary" backup --tag silo-e2e "$source"

    printf 'hello from Silo S3 integration, revision 2\n' >"${source}/hello.txt"
    printf 'added in revision 2\n' >"${source}/nested/second.txt"
    run_restic "$restic_binary" backup --tag silo-e2e-second "$source"
}

run_test() {
    require_running_server
    info "running the live wrustic Silo S3 integration test"
    WRUSTIC_SILO_ENDPOINT="http://127.0.0.1:${SILO_S3_PORT}" \
        cargo test --manifest-path "${project_root}/Cargo.toml" --all-features \
        repo::tests::live_silo_s3_profile_reads_seeded_repository \
        -- --ignored --nocapture
}

command="${1:-}"
case "$command" in
    seed)
        seed_repository
        ;;
    test)
        run_test
        ;;
    run)
        seed_repository
        run_test
        info "Silo S3 end-to-end test passed; standalone server remains running"
        ;;
    -h | --help | help)
        usage
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
