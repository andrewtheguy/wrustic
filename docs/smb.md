# SMB snapshot sharing

wrustic can export one snapshot as a read-only SMB share, so a whole backup
mounts as a filesystem instead of being browsed a file at a time. Press `s` on
the snapshot list.

The server is hand-rolled — `src/smb/`, no SMB crate — because the read-only
half of SMB 2.1 against an immutable snapshot is small: no write path, no
file locking, no cache invalidation, no oplocks worth honouring.

At the repository level the share is not lock-free: "immutable" only holds
while nothing prunes the repo, so for its whole lifetime the share holds
restic's non-exclusive lock — the same one `restic mount` takes. Concurrent
backups keep working; a concurrent `restic prune`/`forget` is refused with
restic's ordinary "repository is already locked" error until the share screen
closes, and conversely a running prune stops the share from starting (the
share screen then offers `u` to remove stale locks and retry). If the lock
cannot be refreshed for 22.5 minutes (restic's refreshability rule — e.g.
the backend became unreachable), the server shuts itself down rather than
keep serving a repo other processes may now treat as unlocked. Details in
[locking.md](locking.md).

## Using it

`s` on the snapshot list starts a server on `127.0.0.1:4456` and shows the
username, the generated password, and a ready mount command for each platform.
Leaving the screen stops the server (releasing the repository lock) and breaks
any mount using it. `--smb-port <N>` picks a different port.

That is the entire user-facing surface. There is deliberately no `serve`
subcommand: a share is scoped to the screen that created it and is always
loopback, so the share cannot outlive the UI that is telling you it exists.
Everything a manual cross-platform test needs — a long-lived server, a
non-loopback bind — lives in the test harness instead, see
[Testing against a real client](#testing-against-a-real-client).

## Mounting

Every one of these prompts for the password rather than taking it on the command
line, where it would be readable by any process on the machine for as long as the
mount command ran — and would sit in shell history afterwards. Type in the
password shown on the share screen when asked.

```sh
# Linux — mount.cifs prompts for the password
sudo mount -t cifs -o port=4456,vers=2.1,username=wrustic,ro,uid=$(id -u),gid=$(id -g) \
    //127.0.0.1/snap /mnt/snap

# macOS
mount_smbfs //wrustic@127.0.0.1:4456/snap /Volumes/snap
```

```bat
:: Windows 11 24H2 or newer — * makes net use prompt
net use Z: \\127.0.0.1\snap * /user:wrustic /TCPPORT:4456
```

Windows needs **no client-side policy changes**. Sessions are authenticated and
signed, so `EnableInsecureGuestLogons` and `RequireSecuritySignature` stay at
their secure defaults.

### Older Windows

Windows builds before 11 24H2 can only reach port 445, which wrustic will not
take: 445 is a privileged port, and binding it means either running the whole
TUI as root or colliding with the system's own SMB service. On those builds,
use the per-file HTTP share (`s` on a file's details screen) instead. Pointing
port 445 at wrustic with a port-forwarding rule works, but it is a local
networking workaround, not something this project sets up or supports.

## Security

**Every client authenticates.** NTLMv2 (MS-NLMP) with a per-server random
password; there is no guest path. All three client platforms support NTLMv2 and
Windows accepts nothing less, so a second unauthenticated path would only
weaken the first one.

**Every message is signed.** HMAC-SHA256 over each PDU. Unsigned messages on an
authenticated session are rejected rather than skipped — accepting them would
make signing trivially bypassable. `SIGNING_REQUIRED` is advertised alongside
`SIGNING_ENABLED`, without which a client is free to sign the handshake and then
stop.

**Nothing is encrypted.** SMB 3.x encryption is not implemented. Signing stops
tampering, not reading. This is why the shipped binary only ever binds loopback:
on a real interface, anyone on the network can read file contents in transit.
Reaching another machine is possible only from the test harness, deliberately —
see [Testing against a real client](#testing-against-a-real-client).

**Writes are impossible, and also refused.** There is no code that could write
to a repository from this module. On top of that, the protocol layer refuses
write access bits (`ACCESS_DENIED`), write dispositions and `DELETE_ON_CLOSE`
(`MEDIA_WRITE_PROTECTED`), so a client sees "read-only filesystem" at the point
it asks rather than an error partway through.

## Scope

SMB **2.1 only** (`0x0210`). Deliberate: 2.1 is the newest dialect that avoids
pre-auth integrity hashes, negotiate contexts, AES-CMAC signing and AES-GCM
encryption — a large amount of cryptographic machinery for a loopback share of
an immutable tree. A client opening with an SMB1 `SMB_COM_NEGOTIATE` (macOS and
Windows both do) gets the SMB2 wildcard dialect `0x02FF` back and retries as
SMB2.

Implemented: NEGOTIATE, SESSION_SETUP, TREE_CONNECT/DISCONNECT, CREATE, CLOSE,
READ, QUERY_DIRECTORY, QUERY_INFO, LOGOFF, ECHO. Compound requests
(`NextCommand`) and credit-based flow control are handled. Everything else is
refused with a specific NTSTATUS.

### Known limitations

- **Symlinks, devices, FIFOs and sockets appear as empty regular files.** SMB2
  without POSIX extensions has only "file" and "directory", and restic stores no
  content for a symlink, so the target is not reachable through the share.
  Regular files and directories round-trip exactly.
- **No reparse points, no extended attributes, no alternate data streams.**
- **One snapshot per server.** The share is bound at startup.

## Module map

| file | what it holds |
|------|---------------|
| `mod.rs` | server entry, accept loop, compound dispatch, tracing |
| `wire.rs` | bounds-checked `Reader`/`Writer`, NetBIOS framing, UTF-16LE |
| `proto.rs` | SMB2 header codec, NTSTATUS / command / access-mask tables |
| `session.rs` | NEGOTIATE, SESSION_SETUP, TREE_CONNECT, SPNEGO framing |
| `ntlm.rs` | NTLMv2 challenge/response, session key derivation |
| `sign.rs` | HMAC-SHA256 signing and verification over compound chains |
| `path.rs` | the trust boundary — SMB path parsing and rejection |
| `backing.rs` | the `Backing`/`FileReader` seam over `rustic_core::vfs` |
| `info.rs` | MS-FSCC info-class encoders |
| `files.rs` | CREATE / CLOSE / READ / QUERY_DIRECTORY / QUERY_INFO, handle table |

`Backing` is a trait so the byte-exact encoders can be tested against an
in-memory tree without a restic repository. `SnapshotBacking` is the real
implementation, over a `Repository<IndexedFullStatus>` opened once at startup —
a snapshot is immutable, so concurrent readers need no coordination beyond an
`Arc`.

## Testing against a real client

The TUI share dies when you leave the screen, which is right for a feature and
useless for validating against macOS or Windows — you need the server up while
you walk over to another machine. `scripts/smb-sample.sh` is that harness, and
it builds its own fixture, so this works on a fresh clone:

```sh
./scripts/smb-sample.sh seed            # build a sample tree, back it up
./scripts/smb-sample.sh serve           # serve it (add SMB_BIND_ALL=1 for other machines)
./scripts/smb-sample.sh verify          # in another terminal: mount, diff, check writes fail
```

`seed` builds a tree chosen for the parts of the protocol that broke during
development: a zero-length file, names with spaces and non-ASCII, a 5 MB file
spanning several blobs and READs, a 120-entry directory that forces
QUERY_DIRECTORY to page, and a symlink for the known limitation below. `verify`
compares every file by sha256 against the source, then checks that `touch`,
`mkdir` and `rm` are all refused.

`serve` runs `smb_manual_snapshot`, an `#[ignore]`d test in `src/smb/mod.rs`
that starts the same server and holds it open for `SMB_SECONDS` (default 1200)
— bounded rather than infinite so a forgotten server does not hold the port for
ever. Knobs: `SMB_PORT`, `SMB_SECONDS`, `WRUSTIC_SMB_SHARE_PASSWORD`,
`SMB_BIND_ALL`, `SMB_LOG`. Everything reaches the server through the
environment, never argv, where a password would be readable by every process on
the machine — the same rule `src/restic.rs` follows for the restic CLI.

`SMB_BIND_ALL` is the only way to reach a non-loopback interface, and it exists
only here. Nothing is encrypted, so an all-interfaces share exposes file
contents to anyone on the network: a testing affordance on a trusted network,
not something the shipped binary offers.

`smb_manual_server` is the same idea over an in-memory tree, for protocol work
that needs no repository at all.

## When a mount fails

Client-side errors are close to useless: Linux reports a bare `-EIO` or
`-EINVAL`, macOS times out with no message, Windows gives a generic system
error. The server is the only place that can see which command was rejected and
why, so set `WRUSTIC_SMB_LOG=1` and it traces every command to stderr:

```
[smb] SMB1 multi-protocol NEGOTIATE -> SMB2 wildcard 0x02ff
[smb] client offers dialects [0202, 0210, 0300, 0302, 0311]
[smb] NEGOTIATE -> SUCCESS (94 bytes)
[smb] SESSION_SETUP -> MORE_PROCESSING_REQUIRED (147 bytes)
[smb] SESSION_SETUP -> SUCCESS (17 bytes)
[smb] TREE_CONNECT -> SUCCESS (16 bytes)
```

Rejections name the command and the reason:

```
[smb] dropping connection: CREATE arrived unsigned
[smb] dropping connection: READ signature mismatch
[smb] SESSION_SETUP -> LOGON_FAILURE          <- wrong username or password
```

On Linux, `sudo dmesg | tail` adds cifs.ko's own complaint, which is often more
specific than the mount error.

Worth knowing: unit tests and `smbclient` both passed while several real
protocol bugs were live. Every one was found by a real kernel or OS client.
Treat "the tests pass" as necessary and not sufficient here, and mount from all
three platforms before believing a protocol change.
