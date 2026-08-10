#!/usr/bin/env bash

set -euo pipefail

# Silo (https://github.com/pgsty/silo) is a MinIO fork, so it bootstraps in
# one command: a data directory, the root credentials in the environment, and
# nothing else — no config file, no cluster secret, no key or bucket
# provisioning step. The bucket is created by `restic init` in silo-e2e.sh.
# The wire and configuration surfaces are still MinIO's, which is why the
# environment variables and the health endpoint below say `MINIO`/`minio`.
SILO_RELEASE="RELEASE.2026-08-06T00-00-00Z"
SILO_VERSION="20260806000000.0.0"
# SHA-256 of the official linux archives for the release above.
SILO_SHA256_AMD64="d63d57cc7f0535e1aa116f9e5f42117dbfc4f63492da692b64d3ba6ded30e574"
SILO_SHA256_ARM64="4389413672d8b2681130a2e518ae6609406671e0f0a5d34934c20701078ee1ad"
SILO_S3_PORT="${SILO_S3_PORT:-9000}"
SILO_ACCESS_KEY="wrustic-it"
SILO_SECRET_KEY="wrustic-it-secret"
SILO_REGION="us-east-1"

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
runtime="${project_root}/tmp/silo-e2e/runtime"
silo_binary="${SILO_BIN:-${project_root}/tmp/tools/silo-${SILO_VERSION}}"

fail() {
    printf '[silo-server] ERROR: %s\n' "$*" >&2
    exit 1
}

[[ "$SILO_S3_PORT" =~ ^[0-9]+$ ]] &&
    (( SILO_S3_PORT >= 1 && SILO_S3_PORT <= 65535 )) ||
    fail "SILO_S3_PORT must be an integer from 1 through 65535"

if [[ "${1:-}" == "--reset" ]]; then
    # This is an intentionally disposable path under the project-local tmp directory.
    rm -rf "$runtime"
elif (( $# != 0 )); then
    fail "usage: $0 [--reset]"
fi

if [[ ! -x "$silo_binary" ]]; then
    [[ "$(uname -s)" == "Linux" ]] ||
        fail "set SILO_BIN to a Silo ${SILO_RELEASE} binary"
    case "$(uname -m)" in
        x86_64) arch="amd64"; expected_sha256="$SILO_SHA256_AMD64" ;;
        aarch64 | arm64) arch="arm64"; expected_sha256="$SILO_SHA256_ARM64" ;;
        *) fail "set SILO_BIN to a Silo ${SILO_RELEASE} binary" ;;
    esac
    command -v curl >/dev/null 2>&1 || fail "curl is required to download Silo"
    command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required to verify Silo"
    command -v tar >/dev/null 2>&1 || fail "tar is required to unpack Silo"
    mkdir -p "$(dirname "$silo_binary")"
    archive="${silo_binary}.tar.gz"
    printf '[silo-server] downloading Silo %s (linux/%s)\n' "$SILO_RELEASE" "$arch"
    curl --fail --location --silent --show-error \
        --output "$archive" \
        "https://github.com/pgsty/silo/releases/download/${SILO_RELEASE}/silo_${SILO_VERSION}_linux_${arch}.tar.gz"
    actual_sha256="$(sha256sum "$archive" | awk '{ print $1 }')"
    if [[ "$actual_sha256" != "$expected_sha256" ]]; then
        rm -f "$archive"
        fail "Silo download checksum mismatch: expected ${expected_sha256}, got ${actual_sha256}"
    fi
    # The archive carries the server as a bare `silo` at its root.
    tar -xzf "$archive" -O silo >"${silo_binary}.download"
    rm -f "$archive"
    chmod +x "${silo_binary}.download"
    mv "${silo_binary}.download" "$silo_binary"
fi

mkdir -p "${runtime}/data"

printf '[silo-server] S3 endpoint: http://127.0.0.1:%s\n' "$SILO_S3_PORT"
printf '[silo-server] press Ctrl-C to stop Silo\n'
exec env \
    MINIO_ROOT_USER="$SILO_ACCESS_KEY" \
    MINIO_ROOT_PASSWORD="$SILO_SECRET_KEY" \
    MINIO_REGION="$SILO_REGION" \
    "$silo_binary" server "${runtime}/data" \
    --address "127.0.0.1:${SILO_S3_PORT}" --quiet
