# Serving the snapshot share on port 445 (Windows)

`--smb-tun` serves the snapshot share on SMB's standard port so it mounts as a
plain UNC path — `\\10.99.0.1\snap` works in Explorer's address bar and in any
program that takes a UNC path, not only as a mapped drive letter.

Windows-only, off by default, and only present in builds compiled with
`--features smb-tun`. Nothing about it is configurable from the config file.

    cargo build --release --features smb-tun
    wrustic --smb-tun

## Why a normal socket cannot do this

Port 445 cannot be bound through the Windows socket layer at all. `srvnet.sys`
holds it as an exclusive, system-wide reservation, so a bind fails with
`WSAEACCES` rather than the `WSAEADDRINUSE` you would expect — on `127.0.0.1`
and on every other local address alike.

Measured on Windows 11 (build 26200), in order of increasing desperation:

| Attempt | Result |
| --- | --- |
| Bind `127.0.0.1:445` | `AccessDenied` |
| Add an interface and bind its address | `AccessDenied` — the reservation is not per-interface |
| Unbind `ms_server` ("File and Printer Sharing") from an adapter | `AccessDenied` — no effect |
| Stop the `LanmanServer` service | `AccessDenied` — `srvnet.sys` stays loaded and keeps the port |
| Stop `srvnet.sys` itself | **Frees 445** — and takes all host file sharing with it |

Only the last one works, and paying for a snapshot browser by disabling the
machine's file sharing is a bad trade. The service dependency chain explains the
rest: `LanmanServer` → `srv2` → `srvnet`, and only the leaf owns the socket.

## What it does instead

The same thing a VM guest or a WireGuard peer does — it terminates the
connection in a TCP/IP stack that is not Windows'. A Wintun adapter provides an
L3 device; [smoltcp](https://docs.rs/smoltcp) provides the stack. Windows never
sees a socket bound to 445, so there is nothing for `srvnet` to arbitrate, and
host file sharing is untouched for the share's whole lifetime.

The routing trick that makes it work, and the part that is easy to get wrong:

- the **adapter** is assigned the subnet's *second* address (`10.99.0.2`);
- wrustic answers for the *first* (`10.99.0.1`), which is assigned to **nothing**.

Windows sees an on-link route for the subnet and pushes packets for `.1` out
through the tun ring. Assign `.1` to the adapter instead and Windows treats it
as a local address, loops the traffic back internally, and the port reservation
applies again — the exact failure the design exists to avoid.

The SMB protocol code is deliberately untouched by all of this. smoltcp
terminates the connection and proxies it to the ordinary loopback listener
`smb::start` already creates, so the async server, its tests and its wire
handling never learn a tun exists. The extra loopback hop costs a memcpy per
buffer, which is nothing next to a repository read.

## Requirements and side effects

- **Administrator rights**, because creating a network adapter always requires
  them. Nothing else needs elevation, and no existing service, binding or
  adapter is modified.
- **A routed subnet.** While a share is open, `10.99.0.0/24` routes to the tun
  adapter. Change it with `--smb-tun-subnet 192.168.77.0/30` if that collides
  with a network the machine already uses; wrustic refuses to start if a more
  specific route for the range already exists (`GetBestRoute2`).
- **Nothing persists.** Dropping the share removes the adapter, and with it the
  address and the route.

`/30` is the smallest usable subnet: the transport needs two addresses in one
subnet, so a `/31` has no room for both, and a `/32` assigns a single address
and creates no subnet route at all.

## The embedded driver

`wintun.dll` (427 KB, signed by WireGuard LLC) is embedded with `include_bytes!`
from `vendor/wintun/`, and written to the config directory on first use so
wrustic stays a single binary. The Wintun *Prebuilt Binaries License* §3(d)
permits redistribution alongside software that uses it only through the
documented API, which is all `src/smb/tun.rs` does. `vendor/wintun/LICENSE.txt`
is the copy that governs it.

This is why the feature is off by default: it embeds a driver in the binary and
only earns its keep if you actually want UNC paths.

## Tests

    cargo test --features smb-tun tun_mount_on_the_standard_port -- --ignored

Mounts `\\10.99.0.1\snap` for real, reads a file, lists a directory, and asserts
that the host's own `0.0.0.0:445` listener is still there afterwards. Ignored by
default because it needs administrator rights and creates an adapter.

`smb_manual_tun` holds a share open so an external client can be pointed at it:

    cargo test --features smb-tun smb_manual_tun -- --ignored --nocapture

One trap worth knowing, because it cost 272 seconds a run before it was
understood: `net use \\host\share /delete` against an address with **no route**
blocks for a full TCP timeout. List mappings first and only delete when one
exists.

## Known limitations

- The poll loop polls rather than waiting on an event, because no single wait
  primitive spans both the wintun ring and the loopback sockets without
  `WSAEventSelect` plumbing. It sleeps 1 ms while a mount is live and 20 ms when
  idle. Measured cost is not visible next to repository reads — a mount, a file
  read and a directory listing are all well under 250 ms — but this is the first
  place to look if throughput ever matters.
- MTU is left at Wintun's default 1500. Raising it would cut per-packet overhead
  on bulk reads, but the wintun crate only sets the adapter MTU by shelling out
  to `netsh`.
- IPv4 only.
