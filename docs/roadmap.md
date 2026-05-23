# Roadmap

## Passphrase from stdin

Accept the passphrase via stdin (e.g. piped from a secret manager or script) so wrustic can be used non-interactively in headless environments without relying on the browser-based auth ceremony.

**Priority:** High

## Keychain support

Integrate with OS keychain (e.g. macOS Keychain, GNOME Keyring, Windows Credential Manager) to store and retrieve the passphrase automatically.

**Priority:** Low — wrustic often runs in headless environments where keychain is unavailable, and the browser auth flow already covers interactive use cases.
