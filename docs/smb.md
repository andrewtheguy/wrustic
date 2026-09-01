# SMB snapshot sharing

wrustic can export one snapshot as a read-only SMB share, so a whole backup
mounts as a filesystem instead of being browsed a file at a time. Press `s` on
the snapshot list.

The SMB 2.1 server itself lives in the shared `smbanything_core` crate
(the [smbanything](https://github.com/andrewtheguy/smbanything) project) —
protocol scope, security model (NTLMv2, mandatory signing, no encryption,
writes refused), share enumeration, module map and trace format are documented
in its [docs/smb.md](https://github.com/andrewtheguy/smbanything/blob/main/docs/smb.md).
What lives in this repository (`src/smb/`) is the restic-specific side:
`backing.rs` (the `SnapshotBacking` that walks repository trees), `name.rs`
(restic's filename quoting, below), and `start_snapshot_share`, which ties the
server's lifetime to restic's repository lock.

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
answers — Finder only ever enumerates shares on the standard port, a
client-side behaviour measured and written down in
[smbanything's docs/smb.md](https://github.com/andrewtheguy/smbanything/blob/main/docs/smb.md#macos-only-ever-enumerates-the-standard-port).

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

## Known limitations

- **Symlinks, devices, FIFOs and sockets appear as empty regular files.** SMB2
  without POSIX extensions has only "file" and "directory", and restic stores no
  content for a symlink, so the target is not reachable through the share.
  Regular files and directories round-trip exactly.
- **One snapshot per server.** The share is bound at startup.
- **A filename SMB2 cannot express is listed with its offending characters
  replaced by U+FFFD, and cannot be opened.** SMB2 filenames carry no path
  separator; macOS filenames may contain a backslash. Substituting is not
  cosmetic caution — the Windows redirector answers a listing that carries one
  by discarding the *whole response*, so one such file would hide every other
  file in its directory.

## Filenames

restic stores every node name **quoted**, Go `strconv.Quote` style: a real EN
SPACE becomes a six-character unicode escape, a real backslash is doubled, a
byte that is not UTF-8 becomes a hex escape (restic `internal/data/node.go`).
Consumers have to undo that, and `rustic_core::repofile::Node::name()` does —
except on Windows, where its `unescape_filename` is the identity function. So
the share reads `Node.name`, the raw stored string, and decodes it itself in
`src/smb/name.rs`; the result is the same on every platform, which the
accessor is not.

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
QUERY_DIRECTORY to page, and a symlink for the known limitation above. `verify`
compares every file by sha256 against the source, then checks that `touch`,
`mkdir` and `rm` are all refused.

`serve` runs `dev smb-serve`, a harness in `src/devharness.rs` built only with
`--features dev-harness`, which starts the same server and holds it open for
`SMB_SECONDS` (default 1200)
— bounded rather than infinite so a forgotten server does not hold the port for
ever. Knobs: `SMB_PORT`, `SMB_SECONDS`, `WRUSTIC_SMB_SHARE_PASSWORD`,
`SMB_BIND_ALL`, `SMB_LOG`. Everything reaches the server through the
environment, never argv, where a password would be readable by every process on
the machine — the same rule `src/restic.rs` follows for the restic CLI.

`SMB_BIND_ALL` is the only way to reach a non-loopback interface, and it exists
only here. Nothing is encrypted, so an all-interfaces share exposes file
contents to anyone on the network: a testing affordance on a trusted network,
not something the shipped binary offers.

## When a mount fails

Set `WRUSTIC_SMB_LOG=1` and the server traces every command to stderr — the
full trace format, what each line means, and how to read a burst of logon
failures (usually a saved credential from an earlier run replaying a password
that was regenerated) are documented in
[smbanything's docs/smb.md](https://github.com/andrewtheguy/smbanything/blob/main/docs/smb.md#when-a-mount-fails).

Two lines are specific to the snapshot backing:

```
[smb 04:41:09.006] conn 5: stat "\Users\andrew\Documents" failed: <the repository error>
[smb 04:41:11.220] conn 5: listing "od\\d" as "od\u{fffd}d": SMB filenames cannot hold a separator
```

The first exists because a repository error and a genuinely missing path return
the same NTSTATUS — without the trace a cold pack or a backend hiccup is
indistinguishable from "that folder is not in this snapshot". The second says,
once per listing that contains it, that a name had to be altered to be put on
the wire at all.

When the whole-server logon limit trips (1000 refusals with no success in
between), the share screen reports it and releases the repository lock on its
next poll.
