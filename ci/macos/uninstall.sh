#!/bin/bash
# Uninstaller for the macOS package (wrustic-macos-arm64.pkg, built by the
# "Build the Linux .deb / macOS .pkg" step of .github/workflows/release.yml).
#
# macOS has no package manager to ask, so removal is the pkg's payload undone
# by hand: the package installs /opt/wrustic (wrustic plus the pinned restic in
# its restic/ subdirectory) and its postinstall symlinks /usr/local/bin/wrustic
# at it. Those two paths and the receipt are the whole footprint — the package
# ships program files only, so nothing under a user's profile is touched by
# installing, and nothing there is touched by uninstalling either unless
# --purge asks for it.
#
# A copy of this script is installed at /opt/wrustic/uninstall.sh, so a machine
# with wrustic on it can uninstall without fetching anything.
#
# bash, not sh, and no bash-4 constructs: this has to run on the bash 3.2 that
# ships with macOS.
set -euo pipefail

INSTALL_ROOT=/opt/wrustic
SYMLINK=/usr/local/bin/wrustic
PKG_ID=com.andrewtheguy.wrustic
KEYCHAIN_SERVICE=wrustic

purge=0
dry_run=0

usage() {
    cat <<USAGE
usage: sudo $0 [--purge] [--dry-run]

Removes what wrustic-macos-arm64.pkg installed:
  $INSTALL_ROOT           program files (wrustic + the pinned restic)
  $SYMLINK      symlink, removed only if it still points into $INSTALL_ROOT
  $PKG_ID   installer receipt

  --purge     also delete this user's wrustic data: the config directory
              (~/Library/Application Support/wrustic), the restic cache
              wrustic keeps for itself (~/Library/Caches/wrustic), and any
              passphrases saved in the login keychain. Backup repositories
              are never touched.
  --dry-run   print what would be removed and change nothing.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --purge) purge=1 ;;
        --dry-run) dry_run=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

if [ "$(uname -s)" != Darwin ]; then
    echo "this uninstaller is for macOS; on Linux use apt/dnf to remove the package" >&2
    exit 1
fi

# Everything below writes under /opt and /usr/local. Fail on the check rather
# than on the first rm, so a non-root run says what is wrong instead of leaving
# a half-removed install behind.
if [ "$(id -u)" -ne 0 ] && [ "$dry_run" -eq 0 ]; then
    echo "must run as root: sudo $0 $*" >&2
    exit 1
fi

# One place that decides whether an action happens, so --dry-run cannot drift
# out of step with what a real run does.
run() {
    if [ "$dry_run" -eq 1 ]; then
        echo "would run: $*"
    else
        "$@"
    fi
}

# Progress narration for a real run. A dry run says the same thing in the
# "would run:" lines, and printing both makes it read as if it had happened.
say() {
    [ "$dry_run" -eq 1 ] || echo "$@"
}

removed_anything=0

# The symlink is the one path shared with the rest of the system: /usr/local/bin
# belongs to everything else installed there too. Remove it only while it is
# still the symlink this package made — if it has been replaced by another
# wrustic (a source build, a second install location), that is not ours to
# delete.
if [ -L "$SYMLINK" ]; then
    target=$(readlink "$SYMLINK")
    if [ "$target" = "$INSTALL_ROOT/wrustic" ]; then
        say "removing $SYMLINK"
        run rm -f "$SYMLINK"
        removed_anything=1
    else
        echo "leaving $SYMLINK alone: it points at $target, not $INSTALL_ROOT/wrustic"
    fi
elif [ -e "$SYMLINK" ]; then
    echo "leaving $SYMLINK alone: it is a regular file, not this package's symlink"
fi

if [ -d "$INSTALL_ROOT" ]; then
    say "removing $INSTALL_ROOT"
    # This script is installed inside the directory it is deleting. On macOS an
    # unlinked file a running process still has open stays readable, and bash
    # has already read the whole script by the time it gets here, so removing
    # the tree out from under it is safe.
    run rm -rf "$INSTALL_ROOT"
    removed_anything=1
else
    echo "$INSTALL_ROOT is already gone"
fi

# The receipt is what `pkgutil --pkgs` and a reinstall consult; leaving it
# behind claims files that no longer exist.
if pkgutil --pkg-info "$PKG_ID" >/dev/null 2>&1; then
    say "forgetting the $PKG_ID receipt"
    run pkgutil --forget "$PKG_ID"
    removed_anything=1
else
    echo "no $PKG_ID receipt to forget"
fi

if [ "$purge" -eq 1 ]; then
    # Under sudo the invoking user is who owns the data worth deleting; root's
    # own ~/Library is not where wrustic wrote anything. Ask directory services
    # for the home rather than expanding ~user, which bash 3.2 will not do for
    # a variable.
    user=${SUDO_USER:-$(id -un)}
    home=$(dscl . -read "/Users/$user" NFSHomeDirectory 2>/dev/null | sed 's/^NFSHomeDirectory: //') || home=
    if [ -z "$home" ] || [ ! -d "$home" ]; then
        echo "could not resolve a home directory for $user; skipping --purge" >&2
        exit 1
    fi

    for dir in "$home/Library/Application Support/wrustic" "$home/Library/Caches/wrustic"; do
        if [ -d "$dir" ]; then
            say "removing $dir"
            run rm -rf "$dir"
        else
            echo "$dir is already gone"
        fi
    done
    # A config directory chosen with -d/--config-dir or WRUSTIC_CONFIG_DIR is
    # not derivable from here — say so rather than silently leaving it.
    echo "note: a config directory set with -d/--config-dir or WRUSTIC_CONFIG_DIR is not removed"

    # Saved passphrases are generic-password items under the "wrustic" service,
    # one per profile, in the invoking user's login keychain — which is why
    # this drops back to that user instead of deleting as root. `security`
    # deletes one item per call, so loop until it reports no more; the counter
    # is a backstop against a delete that keeps succeeding without emptying.
    say "removing saved passphrases from ${user}'s login keychain"
    deleted=0
    while [ "$deleted" -lt 200 ]; do
        if [ "$dry_run" -eq 1 ]; then
            echo "would run: sudo -u $user security delete-generic-password -s $KEYCHAIN_SERVICE"
            break
        fi
        if sudo -u "$user" security delete-generic-password -s "$KEYCHAIN_SERVICE" >/dev/null 2>&1; then
            deleted=$((deleted + 1))
        else
            break
        fi
    done
    if [ "$dry_run" -eq 0 ]; then
        if [ "$deleted" -gt 0 ]; then
            echo "  deleted $deleted keychain item(s)"
        else
            # A locked keychain fails the same way an empty one does, and the
            # difference matters: one means nothing to do, the other means the
            # passphrases are still there.
            echo "  none deleted — either none were saved, or the login keychain"
            echo "  is locked. To check: security find-generic-password -s $KEYCHAIN_SERVICE"
        fi
    fi
fi

echo ''
if [ "$dry_run" -eq 1 ]; then
    echo 'dry run: nothing was changed'
elif [ "$removed_anything" -eq 1 ]; then
    echo 'wrustic uninstalled'
else
    echo 'nothing to uninstall: no wrustic package was installed'
fi
