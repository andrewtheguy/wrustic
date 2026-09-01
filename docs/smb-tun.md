# Serving the snapshot share on port 445 (Windows)

`--smb-tun` serves the snapshot share on SMB's standard port. That buys two
things, and neither is a legacy concern alone:

- **A real UNC path.** `\\169.254.255.1\snap` works in Explorer's address bar
  and in any program that takes a UNC path, not only as a mapped drive letter.
  No UNC syntax can carry a port, so the standard port is the *only* way to get
  one — including on Windows 11 24H2, where `net use /TCPPORT:` does reach a
  custom port, but only ever as a mapped drive.
- **Windows before 11 24H2.** Those builds speak to no port but 445, so the
  default `--smb-port 4456` share is unreachable from them at all. This is the
  only way they mount a snapshot.

Windows-only, off by default, and only present in builds compiled with
`--features smb-tun`. Nothing about it is configurable from the config file.

    cargo build --release --features smb-tun
    wrustic --smb-tun

The transport itself — a Wintun adapter plus a userspace TCP stack, so port 445
is claimed in a stack Windows does not arbitrate — is `smbanything_core`'s tun
module (wrustic's `smb-tun` feature enables the crate's `tun` feature). The
full design is documented in
[smbanything's docs/smb-tun.md](https://github.com/andrewtheguy/smbanything/blob/main/docs/smb-tun.md):
why no normal socket can bind 445 on Windows (`srvnet.sys` holds a system-wide
exclusive reservation), the two-/32 link-local routing trick, why a crash or
`taskkill /F` leaves no stale adapter or route behind (measured, not assumed),
and the vendored Wintun driver's provenance and hash pinning.

## What wrustic adds

- **Requirements.** Administrator rights (creating a network adapter always
  needs them) and two host routes, `169.254.255.1/32` and `169.254.255.2/32`,
  for exactly as long as the share screen is open. `--smb-tun-ip <IPv4>` moves
  the pair — the next address up goes on the adapter — and wrustic refuses to
  start the share if either exact address is already owned by the machine.
- **The shipped driver.** `wintun-amd64.dll` (signed by WireGuard LLC) is
  vendored in `vendor/wintun/` and shipped by the Windows installer into the
  install directory next to `wrustic.exe`; `smbanything_core` loads it from
  there and refuses any copy that is not byte-for-byte the driver it pins. For
  a source build, copy `vendor/wintun/wintun-amd64.dll` next to the built
  executable. The `vendored_driver_matches_the_digest_core_will_load` test in
  `src/smb/mod.rs` checks wrustic's vendored copy against that same pin, so a
  driver update that touches one side and not the other fails the build.
  Wintun's *Prebuilt Binaries License* §3(d) permits redistribution alongside
  software that uses it only through the documented API;
  `vendor/wintun/LICENSE.txt` is the copy that governs it.

## Tests

    cargo test --features smb-tun tun_mount_on_the_standard_port -- --ignored

Mounts `\\169.254.255.1\snap` for real, reads a file, lists a directory, and asserts
that the host's own `0.0.0.0:445` listener is still there afterwards. Ignored by
default because it needs administrator rights and creates an adapter. Since the
driver is loaded from next to the running executable, copy
`vendor/wintun/wintun-amd64.dll` into the test binary's directory
(`target/debug/deps/`) first — the error message names the path it looked at.

`smb_manual_tun` holds a share open so an external client can be pointed at it:

    cargo test --features smb-tun smb_manual_tun -- --ignored --nocapture
