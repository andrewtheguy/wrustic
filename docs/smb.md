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
username, the generated password, and ready mount instructions for each platform.
Leaving the screen stops the server (releasing the repository lock) and breaks
any mount using it. `--smb-port <N>` picks a different port.

The share root contains a single directory named with the snapshot's short id
— restic's standard 8-hex-char form, so the name pastes straight into restic
commands — and the snapshot's tree lives inside it. The share name and mount
commands stay fixed (`\\127.0.0.1\snap`, fstab-safe), while the mount's
contents, and anything copied out of it, say which snapshot they came from.

## Mounting

Every one of these prompts for the password rather than taking it on the command
line, where it would be readable by any process on the machine for as long as the
mount command ran — and would sit in shell history afterwards. Type in the
password shown on the share screen when asked.

```sh
# Linux — mount.cifs prompts for the password
sudo mount -t cifs -o port=4456,vers=2.1,username=wrustic,ro,uid=$(id -u),gid=$(id -g),file_mode=0444,dir_mode=0555 \
    //127.0.0.1/snap /mnt/snap
```

On macOS, use Finder → Go → Connect to Server (⌘K) and enter

```
smb://wrustic@127.0.0.1:4456/snap
```

Finder pre-fills the username from the URL and prompts for the password. Enter
the whole path including `/snap`: connecting to `smb://127.0.0.1:4456` alone
and expecting a share to pick from does not work on macOS, whatever the server
answers — see [macOS only ever enumerates the standard
port](#macos-only-ever-enumerates-the-standard-port).

```bat
:: Windows 11 24H2 or newer — * makes net use prompt
net use Z: \\127.0.0.1\snap * /user:wrustic /TCPPORT:4456
```

That gets a mapped drive and nothing else. A UNC path has no syntax for a port,
so `\\127.0.0.1\snap` on its own goes to 445 and never reaches this share — in
Explorer's address bar, in a file dialog, or anywhere else a program takes a UNC
string. For a path those accept, serve the standard port with
[`--smb-tun`](smb-tun.md).

Windows needs **no client-side policy changes**. Sessions are authenticated and
signed, so `EnableInsecureGuestLogons` and `RequireSecuritySignature` stay at
their secure defaults.

### Permissions: readable by everyone, executable by no one

On Linux, every file mounts as `0444` and every directory as `0555` —
readable and listable by any local user, writable and runnable by none. Windows
has no POSIX mode to set; there the same intent is carried by the read-only
attribute and the server-side execute refusal below. A share is a way to
*browse* a snapshot, not to restore one from: symlinks, devices and modes are
already lost on the way through SMB 2.1 (see [Known
limitations](#known-limitations)), so a tree copied out of a mount is not a
faithful restore however it is executed. Use `restic restore` for that.

The mode itself is a client-side setting there, because SMB 2.1 carries no
POSIX mode: `file_mode=`/`dir_mode=` on Linux, which is why the command above
passes them. A Finder mount has no equivalent, and dropping the options does
not open the share up to writes either — every write is refused by the server
regardless — it only makes the client display a mode the server never claimed,
typically `0555` from the kernel's own default with the read-only attribute
applied.

The execute bit is enforced server-side, though, since Windows checks it there:
a CREATE naming a file and asking for `FILE_EXECUTE` (which is how Windows
activates an image) is answered `ACCESS_DENIED`, so a binary in a snapshot
cannot be launched from a mapped drive. The same bit on a *directory* means
`FILE_TRAVERSE` and is granted — without it a client cannot descend.

### Older Windows, and UNC paths

Windows builds before 11 24H2 can only reach port 445, which wrustic will not
bind: 445 is a privileged port, and taking it means either running the whole
TUI as root or colliding with the system's own SMB service.

[`--smb-tun`](smb-tun.md) reaches the standard port without binding it,
by terminating the connection in its own TCP/IP stack on a private adapter. It
is the answer for these builds, and equally for anyone on 24H2 who wants a UNC
path rather than a drive letter — the two reasons are independent. Windows-only,
and only in builds compiled with `--features smb-tun`.

Failing that, use the per-file HTTP share (`s` on a file's details screen).
Pointing port 445 at wrustic with a port-forwarding rule works too, but it is a
local networking workaround, not something this project sets up or supports.

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

`SMB2 WRITE` has exactly one destination that is not an outright refusal: the
`srvsvc` pipe on the IPC$ tree, where a client writes the DCE/RPC request that
asks what shares exist (see [Share enumeration](#share-enumeration)). It lands
in a bounded in-memory buffer, is gated on the tree being IPC$ *and* the pipe
having been opened, and has no path to a snapshot — the disk tree still has no
writable route at all. The "impossible" half of the guarantee is unchanged;
only "every WRITE is refused" needed qualifying.

## Share enumeration

A client that knows the full path has always worked — `\\host\snap`,
`smb://host/snap`. A client asked to *list* what the server offers had nothing
to go on, because IPC$ was accepted (macOS connects to it during mount) but
answered `NOT_SUPPORTED` to every command, so the `srvsvc` pipe could never be
opened. In Explorer that was typing `\\host\` and waiting; in Finder it was
connecting to `smb://host` and being offered no share to pick, leaving the user
to reach the mount point by hand. Explorer is answered now. Finder is answered
only on port 445, for a client-side reason covered
[below](#macos-only-ever-enumerates-the-standard-port).

`srvsvc.rs` answers the one call that question needs: **NetrShareEnum**
(opnum 15), info level 1, over DCE/RPC on the pipe. Windows carries RPC with
`FSCTL_PIPE_TRANSCEIVE`; other clients use a WRITE/READ pair — both are
supported, and a Windows `net view` was observed using both in one exchange.

Everything else — every other opnum, every other interface — gets a DCE/RPC
fault. That is a well-formed "no" a client acts on, as opposed to silence,
which makes it retry and stall. This is not an RPC stack; it is the smallest
thing that answers "what shares do you have?" truthfully.

One thing enumeration does *not* fix: an **unauthenticated** `net view` still
takes tens of seconds before it gets anywhere, because Windows spends that time
on credential negotiation before it sends a single byte we would see. Measured
on the same build, authenticated enumeration takes ~70 ms and lists the share;
unauthenticated took 18.9 s. That wait is the client's, not the server's.

### macOS only ever enumerates the standard port

Finder lists this share when it is served on 445 and never otherwise, and the
reason is entirely client-side. Connect to `smb://127.0.0.1:4456` and the
negotiate, the NTLM sign-on and the `IPC$` TREE_CONNECT all succeed on that
port — and then macOS opens a **second TCP connection** for the `srvsvc` call,
to `127.0.0.1:445`, and when that is refused to `127.0.0.1:139`. The port the
URL was reached on is not carried into that step. Both connections are refused,
`smbutil view` reports `unable to list resources: Broken pipe`, and the server
log shows the IPC$ tree connected and disconnected again with nothing in
between:

```
[smb 20:51:35.636] conn 1: TREE_CONNECT -> SUCCESS (16 bytes)
[smb 20:51:35.795] conn 1: TREE_DISCONNECT -> SUCCESS (4 bytes)
[smb 20:51:35.796] conn 1: LOGOFF -> SUCCESS (4 bytes)
```

That trace reads exactly like a server that gave up half way through a tree it
had just accepted, which is why it is written down here: the 159 ms gap is the
client failing to reach two ports this server was never on. Nothing in
`srvsvc.rs` participates — the client never gets as far as opening the pipe.
The same build served on 445 instead (as root, which is precisely what wrustic
will not do) lists `snap` in ~60 ms, over `CREATE srvsvc` and two
`FSCTL_PIPE_TRANSCEIVE`s carried on the connection that was already open.

`smbutil view` and Finder's own browsing both go through
`SMBClient.framework`, so this is not a quirk of the command-line tool, and an
already-mounted share on the custom port does not prime it either — the
enumeration redials regardless of what is mounted. Mounting is unaffected,
because that whole exchange stays on the connection the URL opened:
`smb://wrustic@127.0.0.1:4456/snap` mounts, lists and reads normally. That is
why the share screen prints the full path and not the server on its own.
Measured against macOS 26.6 (Darwin 25.6.0).

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
- **A filename SMB2 cannot express is listed with its offending characters
  replaced by U+FFFD, and cannot be opened.** SMB2 filenames carry no path
  separator; macOS filenames may contain a backslash. Substituting is not
  cosmetic caution — the Windows redirector answers a listing that carries one
  by discarding the *whole response*, so one such file would hide every other
  file in its directory.

## Module map

| file | what it holds |
|------|---------------|
| `mod.rs` | server entry, accept loop, compound dispatch, tracing |
| `wire.rs` | bounds-checked `Reader`/`Writer`, NetBIOS framing, UTF-16LE |
| `proto.rs` | SMB2 header codec, NTSTATUS / command / access-mask tables |
| `session.rs` | NEGOTIATE, SESSION_SETUP, TREE_CONNECT, SPNEGO framing |
| `ntlm.rs` | NTLMv2 challenge/response, session key derivation |
| `sign.rs` | HMAC-SHA256 signing and verification over compound chains |
| `srvsvc.rs` | share enumeration: the IPC$ `srvsvc` pipe, DCE/RPC, NetrShareEnum |
| `path.rs` | the trust boundary — SMB path parsing and rejection |
| `name.rs` | filenames as restic quotes them, and back |
| `backing.rs` | the `Backing`/`FileReader` seam over the repository |
| `info.rs` | MS-FSCC info-class encoders |
| `files.rs` | CREATE / CLOSE / READ / QUERY_DIRECTORY / QUERY_INFO, handle table |

`Backing` is a trait so the byte-exact encoders can be tested against an
in-memory tree without a restic repository. `SnapshotBacking` is the real
implementation, over a `Repository<IndexedFullStatus>` opened once at startup —
a snapshot is immutable, so concurrent readers need no coordination beyond an
`Arc`.

### Filenames

restic stores every node name **quoted**, Go `strconv.Quote` style: a real EN
SPACE becomes a six-character unicode escape, a real backslash is doubled, a
byte that is not UTF-8 becomes a hex escape (restic `internal/data/node.go`).
Consumers have to undo that, and `rustic_core::repofile::Node::name()` does —
except on Windows, where its `unescape_filename` is the identity function. So
the share reads `Node.name`, the raw stored string, and decodes it itself in
`name.rs`; the result is the same on every platform, which the accessor is not.

This is not a display nicety. The quoted form of an ordinary macOS filename
contains a backslash, and one backslash in a directory listing makes a Windows
client discard the entire response — the directory reads as "not accessible"
with every file in it gone.

Paths are resolved by walking trees (`SnapshotBacking::lookup`) rather than
through `rustic_core::vfs`, whose entry points take a `std::path::Path` and
split it with `Path::components`. On Windows that treats a backslash as a
separator, so a quoted name can never survive the trip and every file with one
would be unreachable. A component is matched against both the quoted spelling
and the literal one: a repository written by rustic on Windows stores names
unquoted, so both occur, and neither can be told from the other without looking.

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
[smb 04:35:34.087] conn 1: connected from 127.0.0.1:45456
[smb 04:35:34.090] conn 1: client offers dialects [0202, 0210, 0300, 0302, 0311]
[smb 04:35:34.090] conn 1: NEGOTIATE -> SUCCESS (94 bytes)
[smb 04:35:34.092] conn 1: SESSION_SETUP -> MORE_PROCESSING_REQUIRED (147 bytes)
[smb 04:35:34.093] conn 1: SESSION_SETUP -> SUCCESS (17 bytes)
[smb 04:35:34.093] conn 1: TREE_CONNECT -> SUCCESS (16 bytes)
[smb 04:35:34.094] conn 2: connected from 127.0.0.1:60874
[smb 04:35:34.094] conn 1: CREATE "docs\readme.txt" access 0x00120089
[smb 04:35:34.095] conn 1: CREATE -> SUCCESS (88 bytes)
```

**Every line names its connection**, because a client opens several per mount
and spreads work across them. Without the id, a failure on one connection sits
between two successes on another and reads as a server that intermittently
refuses things — the trace above is four concurrent connections from one
`smbclient` run. CREATE also logs the path and the requested access mask, since
"CREATE -> ACCESS_DENIED" alone does not say which path, or what it asked for.
The timestamp separates a burst from a slow retry loop: the same number of
failures means different things at 10 ms apart and at 10 minutes apart.

Rejections name the command and the reason:

```
[smb 04:41:02.310] conn 3: dropping: CREATE arrived unsigned
[smb 04:41:02.311] conn 3: dropping: READ signature mismatch
[smb 04:41:07.884] conn 4: SESSION_SETUP: user "andrew" (domain "") is not "wrustic"
[smb 04:41:07.902] conn 4: SESSION_SETUP: wrong password for user "wrustic"
[smb 04:41:07.915] conn 4: SESSION_SETUP: anonymous logon refused
[smb 04:41:09.006] conn 5: stat "\Users\andrew\Documents" failed: <the repository error>
```

A name the share had to alter to put it on the wire says so, once per listing
that contains it:

```
[smb 04:41:11.220] conn 5: listing "od\\d" as "od\u{fffd}d": SMB filenames cannot hold a separator
```

A logon failure names the identity that was offered, never the response or the
key. That distinction is the whole point: a burst of `LOGON_FAILURE` naming
*someone else's* username is Windows trying the interactive user against a
server it has no stored credential for, while a burst naming `wrustic` with the
wrong password is a **saved credential from an earlier run** — the share
password is generated fresh each time the server starts, so a client that ticked
"remember" replays one that will never work again. Clear it and re-map:

```bat
cmdkey /list | findstr <server>
cmdkey /delete:<server>
net use * /delete
```

A connection is dropped after five consecutive refusals (`MAX_FAILED_LOGONS`).
One real client sent the same stale password 84 times on a single connection,
which buries the connection that is actually failing. Dropping locks nothing
out — the client may reconnect immediately — it just stops one socket being used
as a retry loop.

Across the whole server, 1000 refusals with **no successful logon in between**
(`MAX_SERVER_LOGON_FAILURES`) stop the share: every further logon is refused
from that moment, including the correct password, and the share screen reports
it and releases the repository lock on its next poll. The number is deliberately
far above anything a working setup produces — a client replaying a credential
that went stale across a restart is normal here, and one was seen producing 85
refusals in a single browsing session — and any successful logon resets it, so a
working mount holds it at zero indefinitely. Only a client that never
authenticates can walk it to the limit.

This is defence in depth, not the defence: the password is ~94 bits over a
loopback socket, so guessing it is not the threat model. It exists so a server
left running cannot be ground against indefinitely, and so its owner is told.

The `stat`/`list`/`open` lines exist because a repository error and a genuinely
missing path return the same NTSTATUS — a client can do nothing different with
them — so without the trace a cold pack or a backend hiccup is indistinguishable
from "that folder is not in this snapshot", right down to the wording the client
shows.

On Linux, `sudo dmesg | tail` adds cifs.ko's own complaint, which is often more
specific than the mount error.

Worth knowing: unit tests and `smbclient` both passed while several real
protocol bugs were live. Every one was found by a real kernel or OS client.
Treat "the tests pass" as necessary and not sufficient here, and mount from all
three platforms before believing a protocol change.
