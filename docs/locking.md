# Native writes with restic-compatible locking

Decision record + design for evolving wrustic from "reads native, writes
shell out to restic" into a tool that performs write operations natively
via rustic_core while safely coexisting with concurrent `restic`
processes on the same repository. The alternative considered — abandoning
this repo in favor of resterm (a pure restic-CLI wrapper) — is rejected:
rustic_core's native reads are significantly more performant, and the
locking problem turns out to be solvable.

All restic facts below were verified against the restic 0.19.1 source
(`internal/restic/lock.go`, `internal/repository/lock.go`,
`cmd/restic/lock.go`, `doc/design.rst`). rustic_core facts were verified
against rustic_core 0.14.0 as pinned in `Cargo.lock`.

## The problem

rustic_core 0.14.0 is completely lock-oblivious. Its `FileType` enum has
no `Lock` variant, so the crate cannot even address a repository's
`locks/` directory — it cannot create, read, refresh, or honor restic
lock files. Every write API it exposes (`delete_snapshots`, `backup`,
`prune`, …) will happily run while a restic process holds an exclusive
lock, and conversely a concurrent `restic prune` sees no lock from a
rustic_core write in progress. Mixing the two tools on one repo without
extra work risks corruption.

restic, on the other hand, has a well-defined cooperative locking
protocol, and any process that speaks it — writes valid lock files,
checks for conflicting ones — participates in restic's own safety
guarantees. wrustic will implement that protocol itself.

## restic's locking model (restic 0.19.1)

### Lock files

- Stored under `locks/` in the repo. Content is JSON:
  `{time, exclusive, hostname, username, pid, uid, gid}`
  (`internal/restic/lock.go:31-43`).
- Encoded like any "unpacked" repo file: JSON → zstd (repo v2) →
  encrypted with the repo master key (AES-256-CTR + Poly1305-AES MAC).
  Filename = SHA-256 of the final ciphertext.
- **A garbage/unreadable lock file makes restic fail hard** ("Fatal: …
  `unlock --remove-all`"), so wrustic's lock files must be properly
  encrypted, never placeholder bytes.

### Semantics

- **Non-exclusive ("append") lock**: holder promises to only *add* files
  and relies on nobody deleting or rewriting anything. Many may coexist —
  concurrent backups are explicitly by design (`doc/design.rst:598-609`).
- **Exclusive lock**: holder may delete/rewrite; conflicts with all other
  locks.
- Acquisition protocol (`lock.go:105-141`): list + read all existing
  locks (0-byte files ignored as interrupted uploads) → conflict check →
  write own lock file → wait 200 ms (`waitBeforeLockCheck`) → re-check;
  on conflict, remove own lock and fail with "repository is already
  locked".
- Conflict rules: creating non-exclusive conflicts only with an existing
  exclusive lock; creating exclusive conflicts with any lock.
- **Refresh**: every 5 min the holder writes a *new* lock file and
  deletes the old one (the filename changes each refresh). If a lock
  cannot be refreshed within 22.5 min (`StaleLockTimeout − 1.5 ×
  refreshInterval`), restic aborts the running operation.
- **Staleness**: another process considers a lock stale when its
  timestamp is older than 30 min (`StaleLockTimeout`), or when it was
  created on the *same host* and the PID no longer exists.
- restic 0.19 **never auto-removes stale locks during acquisition** —
  only `restic unlock` does. A crashed holder therefore blocks everyone
  until an unlock is run (this is why wrustic's `u` shortcut exists).
- `--retry-lock` (default 0 = fail fast) makes restic poll with backoff
  instead of erroring on conflict.

### ⚠ The SIGHUP probe

restic's same-host staleness check probes the lock-holder PID by sending
it **SIGHUP** (`internal/restic/lock_unix.go`), and restic installs a
SIGHUP-ignore handler so its own processes survive the probe. The default
action for SIGHUP is process termination — so if wrustic holds a lock and
someone runs `restic unlock` on the same host, restic would *kill the
wrustic TUI*. wrustic must ignore SIGHUP while it holds any lock (and
restore the default disposition afterwards, so closing the terminal still
terminates the app normally).

Windows has no SIGHUP: restic probes liveness with `OpenProcess` there
(`internal/restic/lock_windows.go`) and writes uid/gid 0 into its lock
files (no numeric user IDs on Windows). wrustic's Windows build mirrors
both — OpenProcess for the same-host staleness probe, uid/gid 0 in the
locks it writes, and no signal handling at all.

### Per-command lock usage (restic 0.19.1)

| Lock taken | Commands |
|---|---|
| non-exclusive | backup, copy (destination side), key add, restore, mount, ls, snapshots, stats, find, diff, dump, cat, list, key list |
| **exclusive** | forget (even without `--prune`), prune, tag, key remove/passwd, check, repair index/packs/snapshots, migrate, recover, rewrite `--forget` |
| none | unlock, init, self-update |

`--no-lock` is honored only by read commands (and `check`); forget/prune
refuse it outright. The read/append distinction in the source is a TODO —
both map to non-exclusive today.

## What writes wrustic can safely support

(For the user-facing summary of which workflows use the restic CLI today
vs. by plan, see [restic-usage.md](restic-usage.md); these tables are the
safety rationale behind that split.)

Restic's own table above *is* the safety map. Tiered by lock type, with
each operation's implementation status (see Phases below for the history).
Implemented today: **forget / delete snapshots** (`repo::delete_snapshot`,
the TUI delete flow), **tag edits** (`repo::edit_snapshot_tags`,
the TUI's `t` action — see "Native tag edits" below), **snapshot merge**
(`repo::merge_snapshots`, the TUI's `M` action — see "Native snapshot
merge" below), the **snapshot SMB
share** (a long-running *read* under the same non-exclusive lock
`restic mount` takes — see "Long-running reads" below), and — outside
these tables because it takes no lock — **unlock** (`repo::unlock`,
native stale-lock removal behind the TUI's `u` shortcut, plus the
pre-spawn unstick in `restic::run_unsticking_locks`). Prune is *not*
native: the TUI's `p` action shells out to `restic prune` through the
spawn harness (Tier 3 below).

**Tier 1 — non-exclusive lock (coexists with running restic backups):**

| Operation | rustic_core API | Status | Why safe |
|---|---|---|---|
| backup | `Repository::backup` | not planned — stays on the restic CLI | pure append: packs → index → snapshot, the ordering the design doc requires for concurrent-append safety |
| copy into repo | `Repository::copy` (dest side) | not planned | append-only |
| key add | `Repository::add_key` | not planned | writes one new key file |
| merge snapshots | `Repository::merge_trees` + a wrustic-written snapshot file | **implemented** — `repo::merge_snapshots` (phase 6) | pure append: tree packs → index → snapshot; reads no file content and deletes nothing |

**Tier 2 — exclusive lock (blocks restic while held; fully safe):**

| Operation | rustic_core API | Status |
|---|---|---|
| forget / delete snapshots | `delete_snapshots` | **implemented** — `repo::delete_snapshot` (phase 2) |
| tag edits | raw JSON via `cat_file` + own envelope (see below) | **implemented** — `repo::edit_snapshot_tags` (phase 5) |
| description edits | `save_snapshots` + `delete_snapshots` | not planned — `description` is rustic-only; restic silently drops it on any rewrite, so wrustic only implements what both tools share |
| key remove | `delete_key` | not planned |

These have tiny critical sections (seconds); a concurrent restic command
gets the ordinary "repository is already locked" error it is designed to
handle.

**Native tag edits (implemented — phase 5, `repo::edit_snapshot_tags`,
the TUI's `t` on the snapshot list):** what `restic tag` does, verified
against restic 0.19.1 (`cmd/restic/cmd_tag.go`), and what wrustic
mimics. Tags only — description edits are out of scope because
`description` is a rustic-only field restic cannot preserve (see the
round-trip bullet below); wrustic implements only features common to
both tools:

- restic takes the **exclusive** lock (`openWithExclusiveLock`) even
  though the edit only touches snapshot files, and resolves the target
  snapshots *under* the lock. wrustic does the same — the snapshot is
  re-read after acquiring the lock, exactly like `repo::delete_snapshot`
  does, because the row the TUI shows was read lock-free and may have
  been retagged or deleted in the meantime (a retag changes the snapshot
  id, so a stale id fails cleanly instead of editing the wrong file).
- Edit semantics: `time` is preserved; `original` is set to the pre-edit
  id if not already set ("retain the original snapshot id over all tag
  changes"); the **new snapshot file is written first, then the old one
  deleted** (restic's `SaveSnapshot` → `RemoveUnpacked` order), so there
  is never a moment where the snapshot doesn't exist. The write is one
  request, and one that reports an error is looked for in the repository
  before the edit gives up (`lock::write_unpacked`): a new file the
  server stored without answering is the new snapshot, not a duplicate
  left beside the old one. Between those two
  steps wrustic re-reads the new file through rustic_core's decrypt path
  and compares it byte-for-byte — an envelope bug aborts before anything
  is deleted. Snapshot files are not indexed, so nothing else needs
  rebuilding; the critical section is sub-second. An unchanged tag set
  is a no-op (no rewrite, id kept) — compared as a *set*, because restic
  attaches no meaning to tag order and rustic_core models tags as a
  `BTreeSet`, so wrustic's display (and editor prefill) is always
  sorted; an order-sensitive check would rewrite untouched snapshots.
  (restic's own `tag --set` rewrites unconditionally; wrustic is
  deliberately stricter.)
- Cross-tool field round-trip (restic 0.19.1 `internal/data/snapshot.go`
  vs rustic_core 0.14.0 `SnapshotFile`): `description` (and `label`,
  `delete`) are rustic-only — restic ignores them on read and silently
  drops them when *it* rewrites the snapshot (`restic tag`/`rewrite`
  round-trip through Go structs that don't have the fields). This is why
  description edits are out of scope: the field cannot survive a mixed
  restic/wrustic workflow. Mirror image: rustic_core's `SnapshotFile`
  has no `excludes` field, so a round-trip through the typed
  `save_snapshots` API would silently drop `excludes` from a
  `restic backup --exclude` snapshot. That is why the implementation
  does **not** use the typed API: it edits the raw snapshot JSON —
  `Repository::cat_file(FileType::Snapshot, …)` under the lock, a
  `serde_json::Value` mutation touching only `tags`/`original`
  (`preserve_order` keeps the layout), sealed and written through
  wrustic's own unpacked-file envelope (`RepoCrypto` + the lock module's
  backends pointed at `snapshots/`). Every field wrustic doesn't touch —
  `excludes` included, unknown future fields too — keeps its value and
  position (reserializing may normalize JSON formatting details, such as
  Go's `\u003c` HTML escaping of `<`, but drops and reorders nothing).
  Verified live end to end:
  `live_native_tag_edit_interop_with_restic` (restic sees the new tags,
  `excludes` intact, `original` set; `restic check --read-data` passes;
  restic can itself retag the rewritten snapshot).

**Native snapshot merge (implemented — phase 6, `repo::merge_snapshots`,
the TUI's `M` on the snapshot list and the headless `wrustic merge`):** two
snapshots become one new
snapshot holding the files of both — the way to add a file or directory to
an existing snapshot without reading the rest of it again: back up only
the addition, then merge. It is a tool for special cases like that one,
not a step of ordinary backups. A regular `restic backup` of the whole
path set already yields a complete snapshot and stores nothing twice, and
nothing about it calls for a merge; merging two full backups of one
directory is possible but rarely what is wanted, since the result is the
union — a file deleted between the two is back in it. restic has no merge
command, so unlike every
other native write there is no restic behaviour to mirror, only restic's
rules to stay inside. That is also why this one is in scope while
description edits are not: a description is a *field* restic cannot keep,
whereas a merge is an *operation* restic lacks whose result is ordinary
restic-format data — trees, an index entry, a snapshot file — that restic
lists, restores, checks, forgets and prunes like any other.

- **Lock: non-exclusive**, the one `restic backup` takes, because a merge
  is the same kind of write — it adds tree packs, index files and one
  snapshot, and removes or rewrites nothing. So it runs alongside running
  backups and alongside wrustic's own SMB share (no up-front refusal like
  delete, tag edit and prune get), while forget, prune and tag edits block
  it and are blocked by it. A merge that also deleted its sources would
  need the exclusive lock; it deliberately does not — the sources stay, and
  `d` removes them afterwards.
- **Order**: open → lock → load the index → resolve both snapshots, the
  same as the SMB share, so nothing the merge reads can be pruned
  underneath it. Writing follows restic's append order — `merge_trees`
  finishes its packs and index before it returns, and the snapshot file is
  written last — so the snapshot never names a blob that is not indexed.
  `RepoLock::poisoned()` is checked between the two: a lock that went
  unrefreshed past restic's cutoff means a prune may have run, and the
  snapshot is then not written (the orphaned trees go with the next prune).
  That check alone would come too late for what `merge_trees` itself
  writes: it stores packs, then the index files naming them, and returns
  only when done — a prune that got in after the lock was lost deletes
  packs no index names yet, and the index written afterwards names
  deleted packs. So the repository is opened on gated backends
  (`lock::gate_writes`): every write rustic_core makes is refused once the
  lock is poisoned, and a file whose write returned after the lock went
  bad is removed again and the write reported as failed, which fails
  `merge_trees`. What stays was written under a lock that had been healthy
  all along. Three more things the gate is for:
  - *Ending the writes.* rustic_core's packer stores packs on threads it
    waits for only when it finishes normally; after an error return they
    may still be writing a pack and the index entry for it. So the gate is
    closed (`WriteGate::close`) as soon as `merge_trees` returns, and by a
    guard on every other way out: closing waits for the writes under way
    and refuses any that follow, and only then is the lock given up.
  - *Saying what could not be taken back.* A write that reports an error
    may have been stored all the same, so with the lock lost the file is
    removed either way; and a removal that fails counts as done only if a
    listing shows the file is not there. An index file that is still
    there is named in the merge's error instead of the usual "the next
    prune removes the trees" — it may name packs a prune deleted, and has
    to be removed by hand. (A stale index entry does not spread by
    itself: checked against restic 0.19.1, whose prune rebuilt the index
    without an entry for an unused pack that no longer existed.)
  - *Not giving up on an index a server may still store.* A REST or S3
    server can store a file after its write was reported as failed (see
    the snapshot write below). For a pack that is waste the next prune
    collects. An index that turns up after a prune names packs that are
    gone. So once an attempt at an index is open — it failed in a way
    that leaves the server free to complete it — a failure is not passed
    on at once: the gate reads the index back and counts it as stored if
    it is what was written. A refusal after an open attempt is what
    rest-server answers once that attempt has arrived, and reading the
    index back shows it. If the index is not there and the latest answer
    was a refusal, the failure is passed on — a server that says no goes
    on saying it; otherwise the index is written again, five seconds
    apart, until it is stored, refused, the lock is lost, or the merge
    is stopped (Ctrl+C). An index given up with an attempt still open is
    named in the merge's error like one that could not be removed.
    Which failures leave an attempt open is the backend's to say
    (`repo::data_write_can_land_later`): none of a local repository's,
    and of a server's all but its own refusal.
  - *One request per attempt.* That count holds only if every attempt is
    the gate's own. Both remote backends retry a request by themselves —
    rustic_backend's REST backend, and opendal's retry layer under the S3
    one — and report only the last attempt: a refusal can then stand for
    a write whose first attempt the server still holds, and so can a
    success
    (`rustic_rest_write_hides_an_open_attempt_unless_it_makes_only_one`,
    `s3_backend::tests::a_write_is_one_put_and_reports_that_puts_outcome`).
    So the gate writes everything but packs through the same repository
    opened without retries (`RequestPolicy::ONE_ATTEMPT`), where a call
    is one request and its outcome that request's, and does the trying
    again itself. Packs keep the backend's retries: one that arrives late
    is waste. The lock backends make one request per write for the same
    reason (`LockBackend::write`), the S3 one through an operator without
    the retry layer.
  The lock is checked once more when the snapshot write has returned
  (`RepoLock::write_unpacked_while_held`), because the write itself can
  outlast the lock: restic gets out of this by cancelling the backend
  request when its lock goes bad, and wrustic's backends cannot be
  cancelled, nor do they bound a write to the 7.5 minutes that separate a
  poisoned lock from a stale one — a local write blocks as long as the
  filesystem does, S3 has a stall timeout but no total, only
  REST gives up after 30 seconds. A lock still healthy after the write
  was refreshed in time throughout (poisoning latches), so no prune can
  have started before the snapshot existed; a poisoned one means the
  snapshot may name pruned trees, and it is removed again and the merge
  reported as failed. The snapshot's name is the hash of what is written,
  so it is known before the write, and a write that reports an error is
  treated as possibly stored — a timeout after the server committed —
  whatever the lock's health. It is checked against the repository
  first: a snapshot that is there as written, under a healthy lock, is
  published and reported as that; one that is not is written again,
  since a write that then succeeds settles it whatever became of the
  earlier ones.
  How often it is written again depends on what a failed write leaves
  behind. A server that has taken a write in full stores it whether or
  not the client is still waiting: rest-server reads the body and goes
  on to sync and rename without looking at the connection again, and
  answers a removal sent in between with success, there being nothing to
  remove yet. No call from the client cancels such a write or waits for
  it, so for the REST and S3 backends a failed write followed by a
  successful removal can still be published later
  (`LockBackend::failed_write_can_land_later`; false for a local
  repository, where the write is this process's own system calls).
  Giving up on such a write would release the lock with the write still
  to come: a prune could then delete the merged trees, and the snapshot
  that turns up afterwards would name them. Under the lock a late write
  does no harm, so a write that failed without the server's answer is
  not given up on while the lock is healthy — the merge checks the
  repository and writes again, five seconds apart, until the snapshot is
  stored or the lock is lost (the lock is asked again right before each
  attempt, so none starts under a lost one). With the repository out of
  reach that is the 22.5 minutes the lock takes to turn bad.
  A failure that is final ends the attempts once a second one has been
  made and the snapshot is not in the repository, with the file removed
  and the error passed on, naming it. That is any failure of a local
  write, and a server's own no (`lock::server_refused`): an HTTP answer
  in the 400s or 507. A
  server that refuses the snapshot goes on refusing it while the lock is
  refreshed without trouble, and must not keep the merge and its lock. A
  timeout, a broken connection or an answer in the 500s is no refusal:
  the first two leave open what the server did with a body it had, and a
  proxy answers 502 or 504 for a server still at work. On S3 the line is
  the one opendal draws between errors worth trying again — no answer,
  429, 499, 500, 502, 503, 504 — and the rest: it has a kind of its own
  for few answers and files a full disk or a rejected request under the
  same kind as a broken connection, so the kind does not tell
  (`s3_backend::tests::every_answer_that_turns_a_put_down_is_a_refusal`).
  A refusal ends the attempts after one that may still land, too:
  waiting would not get a refused write stored, and the repository has
  been looked at first, since the refusal can be about the earlier write
  having arrived. The earlier attempt is then still open, and the error
  says so.
  That leaves a write that keeps failing without an answer while the
  lock stays healthy, which nothing would end. No request a client can
  send completes, cancels or fences a write a server holds — rest-server
  never looks at the connection again once it has the body, and restic's
  own retry of a failed save is in the same position — so there is no
  point at which giving up becomes safe by itself, and a retry limit
  would only pick an arbitrary one. The merge therefore runs on a worker
  thread, the merging screen shows which file is being retried, and
  Ctrl+C stops it (`lock::WriteRetries`): no write is begun after that
  and none is tried again, while one under way is waited for. The reads
  of the source and merged trees ask for the stop as well; `merge_trees`
  itself reads on until it has a write to make. The app going away while
  the worker runs — the terminal gone, an error out of the main loop —
  does the same and waits for the worker, so the process does not exit
  under a merge with its lock in place and a write in flight.
  The headless `wrustic merge` (`automation::run_merge`) has no screen to
  press Ctrl+C on, so the stop is the signal: SIGINT and SIGTERM — on
  Windows the console's control events — are caught for the length of the
  command and stop the merge the same way, where they would otherwise kill
  the process with its lock file in the repository. SIGHUP is not among
  them: it stays with the lock module, which ignores it while a lock is
  held.
  Where the attempts end with one of them still open — the lock lost, a
  refusal, or the merge stopped — the write is abandoned unsettled, and
  the error
  does not pretend otherwise: it says the snapshot may still turn up and
  is to be removed if it does — it would by then name trees that a prune
  is free to delete. The same goes for a snapshot removed again because
  it did not read back as written.
  A merge that succeeds can leave an attempt open as well: an earlier
  one still held by the server after a later one stored the file, the
  snapshot or an index. Every attempt writes the same file under the
  same name, so it changes nothing when it lands — unless the file was
  removed in the meantime, which it then brings back: the snapshot file
  after the merged snapshot was deleted, an index file after a prune.
  Keeping the merged snapshot does not guard the index: a prune rewrites
  index files and repacks packs whether or not a snapshot still uses
  what is in them, so the index that comes back can name packs that are
  gone.
  That cannot be prevented from here either, so it is said: the notice
  after such a merge says that a late write is possible and points here
  (headless: `late_write_possible` in the JSON result, and a warning on
  stderr).
  A merge that fails after storing an index that way says it in its
  error — its packs are what the next prune removes.
  Until the server has had time to finish what it took, put off pruning
  and anything else that rewrites the index (`restic prune`, `forget
  --prune`, `repair index`), and deleting the merged snapshot. A `restic
  check` that comes out clean settles nothing if it ran after such a
  prune and before the request arrived: run it again later. Where it
  reports that the index names packs missing from the repository,
  `restic repair index` rebuilds the index from the packs that are
  there.
- **Trees** go through rustic_core's `Repository::merge_trees`: entries are
  matched by path from the root, an entry only one snapshot has is taken
  as is, directories are merged recursively, and where the same path
  differs the entry with the newer mtime wins (`last_modified_node`). No
  file content is read or stored again.
- **The snapshot file is wrustic's own**, written through the same
  unpacked-file envelope as a tag edit and read back through rustic_core
  before the call returns — a snapshot that cannot be read back, or does
  not read back as written, is removed again, and the error says whether
  the removal worked. rustic_core's `merge_snapshots` is not used: it
  stamps the *merging* machine's hostname and user, and keeps nested paths
  apart (`/data` + `/data/extra`), and restic picks a backup's parent by
  exact hostname and path set — so the next `restic backup /data` would
  not find the merged snapshot and would read every file again. The file
  is built field by field in restic's layout
  (`repo::merged_snapshot_json`):
  - `username`, `uid`, `gid` — the newest source's, copied as stored.
  - `hostname` — the sources' own when they share one, which is what lets
    that host's next backup find the merged snapshot. Sources of several
    hosts get a name made of all of them, sorted and joined with `+`
    (`repo::merged_hostname`; a source without a hostname counts as
    `unknown`, and if a source really is called that, the merged
    snapshot gets no hostname rather than that host's own): such a merge
    holds another machine's files, and a backup
    that took it for its parent would compare its own files against
    those. The name shows in restic and wrustic where the snapshot came
    from, and is nobody's, so neither host's backups look for it. That is
    a convention, not a barrier — `restic backup --host alpha+beta` on
    the same paths does take the merge for its parent, as does a backup
    whose `--group-by` leaves the host out. Leaving the hostname out
    altogether would close the first of those (every backup has some
    hostname; restic 0.19.1 records the machine's own for an empty
    `--host`), and was passed over because the snapshot would then show
    no host anywhere. So restic's choice of a parent — the latest
    snapshot with the backup's host and exact path set, unless
    `--parent`, `--force` or another `--group-by` changes that — falls
    on the merged snapshot for sources of one host only.
  - `time` — the newest source's plus one nanosecond, in the same UTC
    offset (`repo::just_after`). The merged snapshot is as recent as its
    newest data, and has to be strictly the latest: restic takes the latest
    matching snapshot as a backup's parent and leaves a tie to chance, and
    the newest source matches as well whenever its paths are the merged
    ones (two backups of one directory). With the source's own time, the
    next backup sometimes picked the source and read again what only the
    merge held.
  - `paths` — every source's paths, with a path that lies inside another
    folded into it (`repo::merged_paths`; whole components, Unix and
    Windows separators), which is what makes the path set that of a
    backup of the outer directory. A path is folded only where the trees
    are laid out as the paths say (`repo::tree_holds_path`): restic
    stores a target given as a relative path under that relative path
    while recording its absolute one (`cd /data && restic backup extra`
    records `/data/extra` and stores `/extra`; checked against restic
    0.19.1), so its files were not merged into the directory its path
    names. Such a path is listed beside the other, and the merged
    snapshot does not pass for a backup of the one directory. The same
    goes for every path of a source whose tree holds anything outside
    its paths (`repo::tree_keeps_to_paths`) — a merge that kept such a
    path apart is one: its `/extra` at the root is no part of `/data`,
    whatever `/data/extra` leads to. Names in a
    tree are compared as restic means them, with its quoting undone, and
    a network share is one directory under its whole name
    (`\\nas\share`), as restic stores a volume. The
    confirmation screen shows the folded set from the paths alone — the
    trees are read only under the lock — and says next to it that a
    nested path may stay.
  - `tags` — the union.
  - `program_version` — `wrustic <version>`.
  - `summary` — the fields restic and rustic_core share, totals being
    those of the merged tree.
  - `parent`, `original`, `excludes` — left out. They describe one backup
    run, and the merged snapshot is the product of several.
- **Metadata is best effort: what `merge_trees` cannot keep is left out
  and reported.** `merge_trees` reads every directory of every source into
  rustic_core's typed `Node` and writes it back from there, and that type
  has no field for restic's `generic_attributes` (Windows creation time,
  file attributes, security descriptors) — the tree-level twin of the
  `excludes` problem that made tag edits a raw-JSON rewrite. rustic_core
  offers no way to write a tree blob except through that type, so the
  merge cannot be made lossless the same way. It goes ahead: everything
  the type does hold (names, content, sizes, times, modes, owners, links,
  extended attributes) is carried over, and **a merged snapshot of
  restic-on-Windows backups has no Windows attributes** — a restore from
  it brings back the files without them. The sources keep theirs, and the
  merge does not delete the sources. So that this is never silent, every
  tree the sources reach is read raw and each node round-tripped through
  the typed `Node` (`repo::scan_source_trees`); the fields that
  held something and do not come back are returned with the new snapshot's
  id, and the TUI names them in its notice. The check is the round trip
  itself rather than a list of field names, so it stays right when
  rustic_core learns a field.
- **Two things `merge_trees` gets wrong for restic are refused**, each
  before any snapshot is written and with the paths named. Neither can be
  put right from here — that would mean writing tree blobs, which
  rustic_core offers no way to do — and neither shows in the sources
  alone, since it depends on which entries meet in the merged tree. So the
  merged tree is read back and checked (`repo::merged_tree_defect`), which
  takes a second repository handle with a fresh index and is therefore
  done only when the scan of the sources found what makes it possible: a
  quoted name, or a file with more than one link.
  - *Order.* restic keeps a directory's entries sorted by name and relies
    on it. It stores a name as Go's `strconv.Quote` writes it, so a name
    with a quote, a backslash, a control character or bytes that are not
    UTF-8 is stored quoted — and `merge_trees` merges two directories in
    the order of the stored form, which is not the order of the names
    (`"a` sorts before `A`, the stored `\"a` after it). Directories restic
    wrote are then not in the order the merge assumes: an entry both
    sources hold comes out twice, the older copy last, and a restore
    writes the older over the newer — or the entries come out in an order
    restic does not keep. `restic check` accepts both. The merge is
    refused when a merged directory is not strictly in restic's order.
  - *Hardlinks.* restic rebuilds hardlinks on restore from each file's
    recorded device and inode: of the files with more than one link that
    share the pair it writes the first, and it makes every other file with
    that pair a hardlink to it, whatever link count that file records
    itself. `merge_trees` passes the pair on untouched, which is right
    within a source and usually right across them — but two sources can
    record one pair on different content: an inode rewritten or reused
    between the two backups under another path (a directory renamed and a
    file in it changed in place is enough; so is a file that lost its
    other link, was moved and rewritten), or two filesystems that were
    given the same device number. restic restores such a merged snapshot
    with every one of those files holding the first one's bytes. The
    merge is refused when a file's content differs from that of a
    multi-link file with its device and inode — or its permissions,
    owner (by number and by name), modification time or extended
    attributes (as a set, whatever order they are listed in) do: restic
    links the
    paths and then puts each one's recorded metadata back, and an inode
    has one of each, so of two that differ only the last applied
    survives. Change times are not compared, since no restore sets
    them, and neither are access times, which restic does put back but
    does not record alike for the links of one file: they are its
    modification time unless the backup ran with `--with-atime`, and
    then reading one link moves the time the next is recorded with,
    wherever restic cannot open the file without touching it (a file
    of another owner, any file outside Linux). A `--with-atime` backup
    of `/usr/bin` by restic 0.19.1 recorded two access times for four
    of its seven hardlinked files; restoring it keeps one of each, as
    restoring a merge does, and holding the merge to more would refuse
    snapshots restic wrote. Two backups of one
    directory with a hardlinked file changed in between differ in the
    sources and merge fine, both links coming from the newer.
    Files of different sources that share the pair and agree in all of
    this are merged as they are, and restic restores them as hardlinks
    of one file. That is right when they are one file, seen by two
    backups — a link added since the first, a `--link-dest` generation
    backed up on its own — and wrong for two files that only look like
    it: copies on a cloned filesystem, say, where numbers, bytes and
    times all match. The restore then has every byte and attribute
    right and one inode where there were two, which shows when one of
    them is changed in place. A snapshot does not record enough to tell
    the two cases apart, and refusing what cannot be proven would
    refuse the first; keeping them apart takes separate identities per
    source (docs/roadmap.md, "Lossless snapshot merge").
    Between hosts there is no first case: the device and inode numbers
    of one machine say nothing about another's, and two machines set up
    alike hand out the same ones. So when the sources' hostnames differ,
    a group of files restic would link has to be one that a single
    source records as it is — every path of it, under that device and
    inode — and a group made of two sources' files is refused
    (`repo::cross_host_link_defect`).
- **How much is rewritten depends on the timezone.** rustic_core renders
  node times with the local zone's offset. Where that is what the trees
  already hold, a directory only one source has serializes back to the
  same bytes and its blob is reused, so only the directories both sources
  pass through are written. Where it is not — snapshots from a machine in
  another zone, or wrustic running in UTC, which rustic_core writes as
  `+00:00` where restic writes `Z` — every directory of every source is
  written again: the same instants, a full second copy of the directory
  metadata (never of file content). Correct either way, and restic reads
  both; it is a cost, and the reason a merge reads every directory.

Verified live end to end: `live_native_merge_interop_with_restic` (restic
backs up a directory and then one new subdirectory of it; after the merge
restic lists the merged snapshot under the directory's path alone, with
the newer source's time and host and both tags, walks every file of both
through it, and passes `check --read-data`; the next `restic backup` of
the directory names the merged snapshot as its parent and finds nothing
new or changed), `live_native_merge_restores_hardlinks_with_restic`
(`restic restore` of a merged snapshot brings back the hardlink groups of
both sources as separate groups with their own bytes; the renamed-and-
rewritten pair, which restic restores as four links to one file when
merged regardless, and the file that fell to one link before it was moved
and rewritten are refused before a snapshot is written — the trees the
attempt stored stay unreferenced, for the next prune to reclaim) and
`live_native_merge_quoted_names_and_parent_with_restic` (a directory
holding `"a` and `A` merged with a later backup of `A` is refused; `"a`
and `b`, which sort one way either way, merge and restore byte for byte;
after two backups of one directory are merged, restic lists the merged
snapshot as strictly the latest and takes it as the next backup's parent;
a merge of one directory's backups as two hosts is listed as `alpha+beta`,
the next backup as either host takes that host's own last backup, and a
backup with an empty `--host` gets the machine's name and does not take
it either).

**Long-running reads — non-exclusive lock (implemented):** the snapshot
SMB share (`smb::ShareServer::share_snapshot`). Reads take no lock in wrustic's
other flows because they are short and restic tolerates concurrent
readers, but a share can stay mounted for hours, and "snapshots are
immutable" only holds while nothing prunes — so the share does what
`restic mount` does (`cmd_mount.go` → `openWithReadLock`): it holds a
non-exclusive lock for its lifetime, refreshed every 5 minutes. The
acquisition order in `repo::open_indexed_full_shared_lock` is open →
lock → load index, restic's order, so the served index can never
reference packs a concurrent prune deleted. Concurrent backups coexist;
prune/forget get "repository is already locked" until the snapshot leaves
the share. The lock belongs to the shared snapshot, not the SMB server: a
server with nothing shared holds no lock, and swapping in another snapshot
acquires the new lock before releasing the old. rustic's own webdav/mount is lock-free (rustic_core cannot even
address `locks/`) and was deliberately not followed here — lock-free
serving is exactly what breaks coexistence with restic.

Because this is wrustic's first *long-running* lock, it also implements
restic's refreshability-abort rule (`refreshabilityTimeout`,
`internal/repository/lock.go`): if the lock has not been successfully
refreshed for 22.5 min (StaleLockTimeout − 1.5 × refresh interval),
`RepoLock::poisoned()` latches true — other processes are about to judge
the lock stale and may remove it. The share itself asks on every request and
every read (`RepoLock::health()`, a probe that does not own the lock), so the
snapshot's folder leaves the share and its open files stop reading at once,
however busy the TUI is; the README stays. The TUI then catches up (it polls
once a second while the SMB server is on, whatever screen is up), releases
the lock and says why. Poisoning is a latch, set by whichever comes first —
the check, or the refresher when a refresh succeeds after the timeout ran
out — so a refresh ending an outage nobody was watching does not resurrect
trust either: an unlock + prune may have happened in the gap.

**Tier 3 — stays on the restic CLI indefinitely:** prune, repair index,
migrate. Prune is technically possible under an exclusive lock, but
rustic_core's prune semantics differ from restic's (two-phase delete with
23 h `keep_delete` and a rustic-only `packs_to_delete` index extension
restic cannot see; `keep_pack` defaults to 0 so concurrently-written
packs get no grace period), and mixing two prune implementations on one
repo is where the real blast radius lives — so the TUI's `p` action runs
`restic prune` through the spawn harness in `src/restic.rs` instead
(`restic::run_unsticking_locks_streaming`). Repair index and migrate are
rare, hand-run recovery/upgrade operations with no TUI action; the user
runs them with restic outside the app.

## wrustic lock module design

### Crypto

`Repository::key()` is public in rustic_core 0.14.0 and returns
`MasterKey`, whose fields are public raw key material
(`repofile/keyfile.rs:350`): `encrypt` (32-byte AES-256 key) and `mac.k`
/ `mac.r` (Poly1305-AES MAC keys). rustic_core's own
`encrypt_data`/`decrypt_data` are `pub(crate)` and not reachable, so
wrustic implements the small envelope itself (in `src/lock.rs`, using the
same `aes256ctr_poly1305aes` crate rustic_core uses — no hand-rolled
primitives):

- encrypted file = `nonce(16) ‖ AES-256-CTR(ciphertext) ‖ Poly1305-AES tag(16)`
  (tag over the ciphertext, mask = AES(k, nonce))
- repo v2: plaintext is `0x02 ‖ zstd(JSON)`; repo v1: raw JSON —
  distinguished on read by the first decrypted byte, exactly like
  rustic_core's `backend/decrypt.rs`

An alternative — carrying a cargo `[patch]` fork of rustic_core that adds
`FileType::Lock` — was considered and rejected: the envelope is ~60
lines, while a fork is a standing maintenance cost.

### Backend access to `locks/`

rustic_backend's backends are `FileType`-addressed and can't reach
`locks/`, so wrustic carries a tiny `LockBackend` abstraction (list /
read / write / delete a lock file) with one impl per profile type:

- **local**: `std::fs` on `<repo>/locks/` (write-then-rename so other
  processes never observe a partial lock file)
- **REST**: direct HTTP against the rest-server lock endpoints
  (`GET /locks/` list — API v2 with a v1 fallback —,
  `GET|POST|DELETE /locks/<id>`), same credentials as the profile
- **S3**: a small opendal S3 client dedicated to `locks/`
  (`src/s3_backend.rs`). Repository *data* on S3 goes through wrustic's
  own `S3DataBackend` in the same file — a read/write rustic_core backend
  over `opendal-service-s3`, sharing its operator construction with the
  lock client. It replaced rustic_backend's generic opendal backend,
  whose all-services feature pulled in ~150 crates wrustic never uses.

### Protocol implementation

A `RepoLock` guard type that mirrors restic exactly:

1. acquire (shared or exclusive): conflict-check → write own lock →
   sleep 200 ms → re-check (excluding own file) → on conflict delete own
   lock and return a typed `AlreadyLocked` error carrying the holder's
   hostname/PID/age
2. background refresh every 5 min (write new file, delete old); if
   refresh has not succeeded for 22.5 min, `poisoned()` latches true so
   the owning operation aborts (implemented; the SMB share is its first
   consumer)
3. `Drop` deletes the lock file (best effort) and restores SIGHUP
   disposition
4. staleness evaluation (30 min age, or same-host + dead PID via
   `kill(pid, 0)` — *not* SIGHUP; existence-checking is enough and never
   harms an innocent process) for display and for native unlock
5. native unlock = remove stale locks only (mirrors `restic unlock`
   without `--remove-all`)

### Test coverage of the "writes are locked" rule

The per-operation live tests below prove interop with restic, but they need
a restic binary and are `#[ignore]`d, so on their own they let a dropped
`acquire_exclusive` through a plain `cargo test`. That rule is therefore also
enforced by tests with no external dependency:
`delete_snapshot_takes_the_exclusive_lock` and
`edit_snapshot_tags_takes_the_exclusive_lock` each plant a live **non-exclusive** lock —
the one a concurrent `restic backup` or a running share holds — and assert
the operation fails with restic's lock error. Since a non-exclusive lock
never blocks another non-exclusive acquisition, only an *exclusive*
acquisition can fail against it, so a lock that was dropped **or merely
downgraded** fails the test. Comparing every repository file except `locks/`
either side of the blocked attempt proves the refusal landed before the first
write rather than midway through, and the lock count afterwards proves both
that a failed acquisition cleans up after itself and that a successful
operation releases on return.

`merge_snapshots_combines_trees_under_the_shared_lock` is the same idea
turned around for the one native write that must take the *non-exclusive*
lock: a planted **exclusive** lock has to block the merge with the
repository fingerprint unchanged — a merge that took no lock would sail
past it — and a planted non-exclusive one has to let it through, which a
merge that asked for the exclusive lock would trip over. It goes on to
check the result: every file of both sources, each conflict won by the
newer mtime whichever snapshot it came from, nothing that existed before
changed or removed. `app::tests::a_merge_runs_while_a_snapshot_of_the_repository_is_shared`
runs it against the SMB share's real lock.
`lock::tests::a_file_whose_write_outlasted_the_lock_is_taken_back` covers
the publication rule: a write that only returns once the lock has gone
unrefreshed past the cutoff comes back as an error with the file removed,
and an already poisoned lock writes nothing.
`lock::tests::gated_writes_stop_when_the_lock_is_lost` does the same for
what rustic_core writes through the gate: an index whose write outlasted
the lock does not stay, and nothing is written after it.
`a_failed_write_past_the_lock_is_reconciled`,
`a_write_reported_as_failed_but_stored_counts_as_published`,
`a_failed_write_the_server_still_holds_is_retried_while_the_lock_holds`,
`a_write_the_server_refuses_is_given_up`,
`an_index_write_the_server_may_still_complete_is_not_given_up` and
`an_index_that_could_not_be_taken_back_is_reported` cover a write that
reports failure for a file it stored, one the server is still holding —
retried under a healthy lock until the file is there, and reported as
possibly still to come once the lock is lost or the retrying stopped —
one the server refuses, which ends the attempts and reports any that is
still open
(`only_the_servers_no_counts_as_a_refusal`,
`rest_write_that_timed_out_is_stored_after_its_removal`,
`rustic_rest_write_hides_an_open_attempt_unless_it_makes_only_one`,
`s3_backend::tests::a_write_is_one_put_and_reports_that_puts_outcome` and
`s3_backend::tests::every_answer_that_turns_a_put_down_is_a_refusal`
show what the real backends' errors count as, against servers that hold
a write and store it after the client has given up, and
`the_gate_writes_all_but_packs_through_the_backend_that_does_not_retry`
that the attempts counted are all there are), a removal that
fails, and
`closing_the_gate_waits_for_writes_and_refuses_later_ones` that the gate
does not close over a write under way. These tests lose the lock at a
point they choose (`LockHealth::expire_for_tests`, inside the backend's
write) on a lock with restic's real timing, so a slow scheduler cannot
lose it for them early.

`shared_open_holds_the_append_lock_for_the_handle_lifetime` covers the other
direction: the guard `open_indexed_full_shared_lock` hands back is held for
as long as the repository handle lives, tolerates a second append lock, and
blocks native writes until it drops —
`smb::tests::snapshot_share_holds_restics_append_lock` checks the same
properties through the share itself.

These fixtures are built in-process with rustic_core's `init`/`backup`
(`src/testrepo.rs`, `#[cfg(test)]`), which is what frees them from the restic
binary; `init`/`backup` remain non-features of wrustic itself (Tier 1 above).
Because restic's key file is
scrypt-derived, every repository open runs a full KDF — unoptimised that is
~10 s per open, so `Cargo.toml` raises `opt-level` for the scrypt crates in
the dev profile only.

## Phases

1. **Lock module** — DONE (`src/lock.rs` + `LockBackend` impls in
   `src/lock.rs`/`src/s3_backend.rs`). Unit tests cover the envelope,
   restic's JSON schema, conflict rules, staleness, the refresh cycle
   (via a test-only shortened interval: new file appears, old removed,
   never zero locks), the grace-window back-off (a competing lock planted
   between write and re-check makes acquisition remove its own lock and
   fail), simultaneous two-thread acquisition (never two holders, no
   orphaned lock files), SIGHUP disposition (ignored while any lock is
   held — the process survives a raised SIGHUP — restored after the last
   release), and `RestLockBackend` against an in-process rest-server mock
   (API v2 list with sizes, v1 name-array fallback, 404 semantics, basic
   auth on every request). Because signal disposition is process-global,
   every test that acquires a `RepoLock` serializes on
   `lock::test_acquire_guard()`. Live tests (`cargo test -- --ignored`):
   `live_native_lock_and_delete_interop_with_restic` proves interop from
   restic's side — `restic forget` is blocked by our exclusive lock with
   "already locked" (so restic lists *and decrypts* our lock files), and
   `restic unlock` leaves our fresh lock in place — and
   `live_silo_s3_lock_backend_cycle` runs the raw file ops plus the
   full acquire/conflict/release/stale-removal protocol against a real
   Silo S3 server (`scripts/silo-test-server.sh`). `scripts/silo-e2e.sh
   test` runs only the repository read test, so run this one — and
   `s3_backend::tests::live_silo_s3_data_backend_read_write_cycle` —
   directly. Both default to `http://127.0.0.1:9000`; a server started
   on another `SILO_S3_PORT` needs `WRUSTIC_SILO_ENDPOINT` set to match:
   `WRUSTIC_SILO_ENDPOINT=http://127.0.0.1:$SILO_S3_PORT cargo test
   --all-features live_silo -- --ignored`.
2. **Native forget/delete** — DONE. The delete flow's `restic forget`
   subprocess became `Repository::delete_snapshots` under a native
   exclusive lock (`repo::delete_snapshot`), and the `u` shortcut's
   `restic unlock` became native stale-lock removal (`repo::unlock`).
   The restic/rustic metadata cross-check and `restic snapshots --json`
   fetch went away with it; the only feature that still needs the restic
   binary is the TUI's prune action (`p` on the Snapshots screen).
   `src/restic.rs` is the secure spawn harness (stdin-piped
   password, env-var credentials, resterm's launch semantics including
   its private cache directory) that the prune flow and the live tests
   use to drive restic. Before spawning a lock-taking command,
   `restic::run_unsticking_locks` performs restic's acquisition conflict
   check natively: the subcommand maps to the lock restic takes for it
   (the per-command table above) and `lock::check_blocking_locks`
   evaluates the repo's lock files under restic's rules without writing
   one. Only when blocked does it run restic's own `unlock` through the
   same harness — not native stale-lock removal, which serves the native
   flows — and re-check; a live lock fails the re-check and its holder
   details are surfaced without spawning restic. restic's own in-process
   check at startup remains the authoritative gate against races.
3. **SMB share under a non-exclusive lock** — DONE. The snapshot SMB
   server holds the lock `restic mount` takes for as long as a snapshot
   is shared (see "Long-running reads" above). This brought the
   refreshability-abort rule with it: `RepoLock::poisoned()` implements
   restic's 22.5-minute cutoff; the share checks it on every request, and
   the main loop polls it once a second while the server is on to release
   the lock and report it. Verified
   live against restic 0.19.1: `restic forget` is blocked by the share's
   lock with the ordinary "already locked" message naming our PID,
   `restic snapshots` coexists, and `restic unlock` leaves the fresh lock
   in place (and its SIGHUP probe doesn't kill the process). On a lock
   conflict when sharing a snapshot, the share screen offers `u` — native
   stale-lock removal, then retry. wrustic's own delete, tag edit and prune
   on a repository with a shared snapshot are refused up front — matched by
   the repository's own id, whatever profile reaches it — since `u` cannot
   remove a lock this process holds live.
4. **Prune through the harness** — DONE. The TUI's prune action runs
   `restic prune` via `restic::run_unsticking_locks_streaming`: version
   detection first (restic ≥ 0.19, the bundled `restic/restic(.exe)` under
   the executable's directory — the only path ever run, PATH included in
   neither), then the native unstick pre-check
   from phase 2, then a streaming spawn whose stdout lines feed the
   running screen live and whose PID a `ChildTracker` records so Ctrl+C
   can interrupt it (SIGINT on Unix — restic catches it and removes its
   lock; termination on Windows, whose leftover lock names a dead PID
   and is removed as stale by the next run's pre-check). A native prune
   via rustic_core was tried and reverted — mixing rustic's prune
   semantics with restic's on one repository is the blast radius Tier 3
   exists to avoid, so prune stays a shell-out.
5. **Native tag edits** — DONE (`repo::edit_snapshot_tags`, the TUI's
   `t` on the snapshot list; see "Native tag edits" above for the full
   design). The exclusive lock, resolve-under-lock, `original`
   retention, and write-verify-then-delete ordering all mirror restic;
   the rewrite goes through raw JSON so restic-only fields like
   `excludes` survive. A lock conflict offers `u` (native stale-lock
   removal) and retries the same edit, like the delete flow. Description
   edits are out of scope (rustic-only field, not restic-preservable).
   Native backup / copy / key management, formerly this phase, were
   dropped from the plan — the restic CLI keeps them.

6. **Native snapshot merge** — DONE (`repo::merge_snapshots`, the TUI's
   `M` on the snapshot list and the headless `wrustic merge`; see "Native
   snapshot merge" above for the full design). The first native write under the *non-exclusive* lock,
   and the first with no restic command behind it. The backup that
   produces the snapshot to merge in stays on the restic CLI; the two are
   independent — nothing is lost if the merge never runs. A lock conflict
   offers `u` and retries the same merge.

Non-goals: native backup, copy, and key management (the restic CLI
keeps them; the Tier 1 rows above remain as the safety map should that
ever change), native prune/repair/migrate (Tier 3), multi-host
clock-skew mitigation beyond what restic itself does, and any
restic < 0.19 compatibility.
