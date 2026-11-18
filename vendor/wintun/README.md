# Vendored Wintun driver

`wintun-amd64.dll` is the driver the `smb-tun` transport loads from next to the
wrustic executable. The Windows installer stages it there; for a source build,
copy it next to the built binary yourself.

| | |
| --- | --- |
| Version | Wintun 0.14.1 |
| Source | `wintun-0.14.1.zip` from <https://www.wintun.net/builds/>, file `bin/amd64/wintun.dll` |
| Archive SHA-256 | `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` (matches the value published on wintun.net) |
| This file's SHA-256 | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` |
| Authenticode | Valid — `CN=WireGuard LLC, O=WireGuard LLC, L=Boulder, S=Colorado, C=US`, thumbprint `DF98E075A012ED8C86FBCF14854B8F9555CB3D45` |

`smbanything_core` loads it by full path from beside the executable and does
not check its contents, so the digests above are the record of what was
vendored.

To update: download the new archive, confirm its SHA2-256 against wintun.net,
confirm the Authenticode signature on the extracted DLL, then replace this file
and the digests above. See `docs/smb-tun.md`.

`LICENSE.txt` is the Wintun *Prebuilt Binaries License*. §3(d) permits
redistribution alongside software that uses the driver only through the
documented API, which is all wrustic does.
