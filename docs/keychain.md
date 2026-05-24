# Keychain integration

wrustic can optionally store the config passphrase in the OS keychain so
subsequent launches unlock automatically without prompting.

## Compile-time feature

Keychain support is behind the `keychain` Cargo feature and is **not enabled by
default**. The prebuilt macOS binary ships with it; the Linux binaries do not.

```sh
cargo build --release --features keychain
```

### Why not enabled on Linux by default

Linux is frequently used headless (servers, containers, SSH sessions) where no
keyring daemon is available. The underlying `keyring` crate talks to D-Bus
secret-service (GNOME Keyring, KDE Wallet), which requires:

- `libdbus-1-dev` at **build time**
- A running secret-service daemon at **runtime**

Neither is present on a typical headless host. Rather than shipping a dependency
that silently fails for most Linux deployments, the feature is opt-in.

To build with keychain on a Linux desktop:

```sh
sudo apt install libdbus-1-dev pkg-config   # build deps
cargo build --release --features keychain
```

A running GNOME Keyring or KDE Wallet is required at runtime.

## Runtime flag

Even when the binary is compiled with the `keychain` feature, you can disable
it at runtime:

```sh
wrustic --no-keychain
```

This gives the same plain terminal passphrase flow as a binary built without
the feature — no keychain reads, no "save to keychain" checkbox. Useful for
simpler setup or environments where the keyring daemon is unavailable.

## How it works

When keychain is enabled and the user chooses the terminal auth method:

- **Setup**: after entering and confirming the passphrase, a checkbox
  (`[x] Save passphrase to keychain`) lets the user opt in to storing it.
  The passphrase is saved under service `wrustic` with the instance name as
  the account identifier.

- **Unlock**: wrustic first tries to read the passphrase from the keychain.
  If found, it skips the input screen and proceeds directly to key derivation.
  If not found (or if the keychain is unavailable), it falls back to the
  manual passphrase entry screen, which also offers a checkbox to save for
  next time.

- **Wrong passphrase in keychain**: if the stored passphrase no longer matches
  (e.g. changed via browser mode), HMAC verification fails and the user is
  shown the manual entry screen with an error message.

## Supported backends

The `keyring` crate selects the backend by platform:

| Platform | Backend |
|----------|---------|
| macOS    | macOS Keychain (Security.framework) |
| Linux    | D-Bus secret-service (GNOME Keyring / KDE Wallet) |
