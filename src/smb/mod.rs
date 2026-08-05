// A read-only SMB 2.1 server for a single restic snapshot.
//
// Why this exists: a snapshot is immutable, so exporting one over a real
// network filesystem needs no invalidation, no locking and no write path. That
// makes a read-only server small enough to hand-roll, and a mounted filesystem
// is far more useful than a download link for browsing a backup.
//
// Scope, deliberately: SMB 2.1 only, guest sessions only, no signing, no
// encryption, loopback only. That combination is what Linux (cifs.ko) and macOS
// (smbfs) accept without credentials, and what Windows 11 24H2 refuses — see
// docs for the reasoning. Every write command is refused at the protocol level
// in addition to there being no code that could perform one.
//
// Mount it with:
//   Linux  sudo mount -t cifs -o port=<p>,vers=2.1,sec=none,guest,ro \
//                     //127.0.0.1/snap /mnt
//   macOS  mount_smbfs //guest@127.0.0.1:<p>/snap /Volumes/snap

// Nothing calls into this module yet — it is wired to the TUI once the file
// commands land. The constant tables in `proto` are also deliberately complete
// rather than trimmed to current use, because a half-populated NTSTATUS list is
// how you end up inventing a wrong status code under pressure. Drop this allow
// once the module is reachable, and take seriously whatever it then reports.
#![allow(dead_code)]

mod backing;
mod files;
mod info;
mod path;
mod proto;
mod session;
mod wire;

use std::net::TcpListener as StdTcpListener;
use std::sync::Arc;
use std::thread;
use std::time::SystemTime;

use anyhow::{Result, anyhow};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::config::Profile;
use crate::local_server;
use crate::repo::open_indexed_full;
use backing::{Backing, SnapshotBacking};
use files::Handles;
use proto::{HEADER_LEN, Header, NEXT_COMMAND_OFFSET, cmd, status, write_error_body};
use session::{SessionState, TreeKind};
use wire::{MAX_INBOUND_MESSAGE, NBSS_HEADER_LEN, Reader, Writer, nbss_header, nbss_len};

/// Upper bound on credits granted per request. Credits are SMB2's flow control:
/// each one lets the client keep one more request in flight. Granting too few
/// stalls the client outright, so we are generous — the ceiling exists only to
/// keep a client from claiming an unbounded window.
const MAX_CREDITS: u16 = 512;

/// The share name clients connect to: `\\127.0.0.1\snap`.
pub(crate) const DEFAULT_SHARE_NAME: &str = "snap";

/// Immutable per-server state shared by every connection.
struct Ctx {
    share_name: String,
    /// What the share serves. Shared across connections; a snapshot is
    /// immutable, so concurrent readers need no coordination beyond this Arc.
    backing: Arc<dyn Backing>,
    /// Reported as the volume serial number. Clients key their metadata caches
    /// on it, so it must be stable for the server's lifetime and differ between
    /// servers.
    volume_serial: u32,
    /// Identifies this server instance in NEGOTIATE. Random per start, as the
    /// spec requires it be stable for a server's lifetime and distinct between
    /// servers.
    server_guid: [u8; 16],
    boot_time: SystemTime,
}

pub(crate) struct SmbHandle {
    pub(crate) port: u16,
    pub(crate) share_name: String,
    shutdown_tx: Option<oneshot::Sender<()>>,
    join_handle: Option<thread::JoinHandle<()>>,
}

impl SmbHandle {
    /// UNC path for a Linux `mount -t cifs`.
    pub(crate) fn unc(&self) -> String {
        format!(r"\\127.0.0.1\{}", self.share_name)
    }

    pub(crate) fn stop(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(jh) = self.join_handle.take() {
            let _ = jh.join();
        }
    }
}

impl Drop for SmbHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Start the server on `port` (0 picks an ephemeral one), bound to loopback
/// only. Binding happens synchronously so that a port conflict is reported to
/// the caller rather than swallowed by the server thread.
pub(crate) fn start(
    port: u16,
    share_name: impl Into<String>,
    backing: Arc<dyn Backing>,
) -> Result<SmbHandle> {
    let listeners_std = local_server::bind_localhost(port)?;
    let bound_port = listeners_std
        .first()
        .ok_or_else(|| anyhow!("bind_localhost returned no listeners"))?
        .local_addr()
        .map_err(|e| anyhow!("read bound listener address: {e}"))?
        .port();

    let share_name = share_name.into();
    let ctx = Arc::new(Ctx {
        share_name: share_name.clone(),
        backing,
        volume_serial: rand::random::<u32>(),
        server_guid: rand::random::<[u8; 16]>(),
        boot_time: SystemTime::now(),
    });

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let join = thread::Builder::new()
        .name(format!("wrustic-smb-{bound_port}"))
        .spawn(move || {
            // Multi-thread rather than current-thread: repository reads are
            // blocking, and `block_in_place` (below) requires a runtime that can
            // hand the reactor to another worker while one is stalled on a
            // backend fetch.
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_io()
                .enable_time()
                .build()
            {
                Ok(rt) => rt,
                Err(_) => return,
            };
            rt.block_on(async move {
                accept_loop(listeners_std, ctx, shutdown_rx).await;
            });
        })
        .map_err(|e| anyhow!("spawning smb thread: {e}"))?;

    Ok(SmbHandle {
        port: bound_port,
        share_name,
        shutdown_tx: Some(shutdown_tx),
        join_handle: Some(join),
    })
}

/// Serve one snapshot from `profile`'s repository.
///
/// The repository is opened synchronously, before the listener thread starts,
/// so a bad passphrase or an unreachable backend is reported to the caller
/// rather than surfacing later as a mount that connects and then fails.
pub(crate) fn start_snapshot_share(
    port: u16,
    profile: &Profile,
    snapshot_id: &str,
) -> Result<SmbHandle> {
    let repo = Arc::new(open_indexed_full(profile)?);
    let snap = repo
        .get_snapshot_from_str(snapshot_id, |_| true)
        .map_err(|e| anyhow!("looking up snapshot `{snapshot_id}`: {e}"))?;

    // Label the volume with the short snapshot id, so a client that has several
    // of these mounted can tell them apart.
    let hex = snap.id.to_hex();
    let label = format!("snap-{}", &hex.as_str()[..8.min(hex.as_str().len())]);
    // restic records the snapshot's byte count at backup time; using it avoids
    // a recursive walk and is exact.
    let total_size = snap.summary.as_ref().map(|s| s.total_bytes_processed);
    let backing = SnapshotBacking::new(repo, snap.tree, label, total_size)?;

    start(port, DEFAULT_SHARE_NAME, Arc::new(backing))
}

async fn accept_loop(
    listeners_std: Vec<StdTcpListener>,
    ctx: Arc<Ctx>,
    shutdown_rx: oneshot::Receiver<()>,
) {
    for listener_std in listeners_std {
        let listener = match TcpListener::from_std(listener_std) {
            Ok(l) => l,
            Err(_) => continue,
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            loop {
                let stream = match listener.accept().await {
                    Ok((s, _)) => s,
                    Err(_) => continue,
                };
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    // Nagle hurts here: SMB2 is request/response with small
                    // headers, and the client is on loopback.
                    let _ = stream.set_nodelay(true);
                    serve_connection(stream, ctx).await;
                });
            }
        });
    }

    let _ = shutdown_rx.await;
}

async fn serve_connection(mut stream: tokio::net::TcpStream, ctx: Arc<Ctx>) {
    let mut conn = Conn::new(ctx);
    let mut nb = [0u8; NBSS_HEADER_LEN];
    loop {
        if stream.read_exact(&mut nb).await.is_err() {
            return;
        }
        let len = nbss_len(&nb);
        if len == 0 {
            // Zero-length NetBIOS message: a keepalive. Nothing to answer.
            continue;
        }
        if len > MAX_INBOUND_MESSAGE {
            return;
        }
        let mut msg = vec![0u8; len];
        if stream.read_exact(&mut msg).await.is_err() {
            return;
        }
        // The file handlers call into the repository, which blocks — on a cache
        // miss that is an S3 round trip. `block_in_place` moves the reactor to
        // another worker for the duration instead of stalling every other
        // connection on this one. It is applied here, at the single call site,
        // rather than inside the handlers, so the protocol code stays sync and
        // directly unit-testable without a runtime.
        let Some(resp) = tokio::task::block_in_place(|| conn.handle_message(&msg)) else {
            // Unparseable, or an SMB1 negotiate. Dropping the connection is the
            // correct answer: clients retry as SMB2.
            return;
        };
        if resp.is_empty() {
            // CANCEL is answered with silence.
            continue;
        }
        if stream.write_all(&nbss_header(resp.len())).await.is_err() {
            return;
        }
        if stream.write_all(&resp).await.is_err() {
            return;
        }
    }
}

/// A successful response: body plus any header fields the handler needs to
/// override. Most commands echo the request's session and tree ids, but
/// SESSION_SETUP and TREE_CONNECT report ids the request could not have known.
struct Reply {
    status: u32,
    body: Vec<u8>,
    session_id: Option<u64>,
    tree_id: Option<u32>,
}

impl Reply {
    fn ok(body: Vec<u8>) -> Self {
        Self {
            status: status::SUCCESS,
            body,
            session_id: None,
            tree_id: None,
        }
    }

    fn status(mut self, status: u32) -> Self {
        self.status = status;
        self
    }

    fn session(mut self, session_id: u64) -> Self {
        self.session_id = Some(session_id);
        self
    }

    fn tree(mut self, tree_id: u32) -> Self {
        self.tree_id = Some(tree_id);
        self
    }
}

/// Per-connection protocol state.
struct Conn {
    ctx: Arc<Ctx>,
    state: SessionState,
    /// Open handles are per-connection: SMB2 file ids are scoped to the
    /// connection that created them and do not survive a reconnect.
    handles: Handles,
}

impl Conn {
    fn new(ctx: Arc<Ctx>) -> Self {
        Self {
            ctx,
            state: SessionState::default(),
            handles: Handles::default(),
        }
    }

    /// Process one NetBIOS message, which may carry several compounded SMB2
    /// requests chained by `NextCommand`. Returns the assembled response, an
    /// empty vector if the message warrants no reply, or `None` to drop the
    /// connection.
    fn handle_message(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
        let mut out = Writer::with_capacity(msg.len().max(256));
        let mut offset = 0usize;
        let mut first = true;

        loop {
            let chunk = msg.get(offset..)?;
            let mut r = Reader::new(chunk);
            let hdr = Header::parse(&mut r).ok()?;

            let next = hdr.next_command as usize;
            // A request runs to the next chained command, or to the end.
            let end = if next == 0 {
                chunk.len()
            } else {
                if next < HEADER_LEN || next > chunk.len() {
                    return None;
                }
                next
            };
            let body = chunk.get(HEADER_LEN..end)?;
            let is_only = first && next == 0;

            let start = out.len();
            match self.execute(&hdr, body, chunk, is_only) {
                Some(Ok(reply)) => {
                    hdr.write_response(
                        &mut out,
                        reply.status,
                        grant_credits(&hdr),
                        reply.session_id.unwrap_or(hdr.session_id),
                        reply.tree_id.unwrap_or(hdr.tree_id),
                    );
                    out.bytes(&reply.body);
                }
                Some(Err(st)) => {
                    hdr.write_response(
                        &mut out,
                        st,
                        grant_credits(&hdr),
                        hdr.session_id,
                        hdr.tree_id,
                    );
                    write_error_body(&mut out);
                }
                // No response at all (CANCEL). Only reachable when this is the
                // sole request, so the chain bookkeeping below is unaffected.
                None => {}
            }

            if next == 0 {
                break;
            }
            // Each compounded response starts on an 8-byte boundary, and its
            // NextCommand holds the distance to the one that follows.
            out.align_to(8);
            let this_len = (out.len() - start) as u32;
            out.patch_u32(start + NEXT_COMMAND_OFFSET, this_len);

            offset += next;
            first = false;
            if offset >= msg.len() {
                break;
            }
        }

        Some(out.into_vec())
    }

    /// Run one request. `message` is the slice this request's offsets are
    /// relative to — its own header, not the whole compound message.
    fn execute(
        &mut self,
        hdr: &Header,
        body: &[u8],
        message: &[u8],
        is_only: bool,
    ) -> Option<Result<Reply, u32>> {
        // Anything except NEGOTIATE and SESSION_SETUP needs a live session.
        // Skipping this check would let an unauthenticated peer reach the file
        // handlers, which is the whole reason a session exists.
        let needs_session = !matches!(hdr.command, cmd::NEGOTIATE | cmd::SESSION_SETUP);
        if needs_session && (!self.state.authenticated || hdr.session_id != self.state.session_id) {
            return Some(Err(status::USER_SESSION_DELETED));
        }

        let result = match hdr.command {
            cmd::NEGOTIATE => session::negotiate(
                body,
                &self.ctx.server_guid,
                self.ctx.boot_time,
                &mut self.state,
            )
            .map(Reply::ok),

            cmd::SESSION_SETUP => {
                session::session_setup(body, message, &mut self.state).map(|(st, b)| {
                    // Both legs must carry the server-assigned session id: the
                    // client reads it off the first response and uses it from
                    // then on.
                    Reply::ok(b).status(st).session(self.state.session_id)
                })
            }

            cmd::LOGOFF => {
                self.state.authenticated = false;
                self.state.session_id = 0;
                Ok(Reply::ok(session::simple_ack()))
            }

            cmd::TREE_CONNECT => {
                session::tree_connect(body, message, &self.ctx.share_name, &mut self.state)
                    .map(|(b, _kind, tree_id)| Reply::ok(b).tree(tree_id))
            }

            cmd::TREE_DISCONNECT => {
                if self.tree_kind(hdr.tree_id).is_none() {
                    Err(status::NETWORK_NAME_DELETED)
                } else {
                    if self.state.disk_tree_id == Some(hdr.tree_id) {
                        self.state.disk_tree_id = None;
                    }
                    if self.state.ipc_tree_id == Some(hdr.tree_id) {
                        self.state.ipc_tree_id = None;
                    }
                    Ok(Reply::ok(session::simple_ack()))
                }
            }

            cmd::ECHO => Ok(Reply::ok(session::simple_ack())),

            // CANCEL has no response. Answering it would desynchronise the
            // client's message-id tracking.
            cmd::CANCEL if is_only => return None,
            cmd::CANCEL => Err(status::NOT_SUPPORTED),

            // Every mutating command, refused at the protocol level so a client
            // learns the share is read-only from the operation itself rather
            // than from a confusing failure further along.
            cmd::WRITE | cmd::SET_INFO | cmd::FLUSH => Err(status::MEDIA_WRITE_PROTECTED),

            // File commands. All of them need the disk tree: reaching them
            // through IPC$, or through a tree id that was never connected, is
            // refused before any path is resolved.
            cmd::CREATE
            | cmd::CLOSE
            | cmd::READ
            | cmd::QUERY_DIRECTORY
            | cmd::QUERY_INFO => match self.tree_kind(hdr.tree_id) {
                Some(TreeKind::Disk) => self.file_command(hdr, body, message),
                Some(TreeKind::Ipc) => Err(status::NOT_SUPPORTED),
                None => Err(status::NETWORK_NAME_DELETED),
            },

            // IOCTL is refused wholesale. macOS probes FSCTL_DFS_GET_REFERRALS
            // and a couple of others during mount; NOT_SUPPORTED is the answer
            // that makes a client move on, and never implementing one keeps the
            // FSCTL surface at zero.
            cmd::IOCTL => Err(status::NOT_SUPPORTED),

            // Byte-range locks on immutable data protect nothing, and there is
            // nothing to notify about in a snapshot that cannot change.
            cmd::LOCK | cmd::CHANGE_NOTIFY | cmd::OPLOCK_BREAK => Err(status::NOT_SUPPORTED),

            _ => Err(status::NOT_SUPPORTED),
        };

        Some(result)
    }

    /// Dispatch to the file handlers. Split out so the tree check above stays
    /// legible and so every one of these shares a single entry point.
    fn file_command(&mut self, hdr: &Header, body: &[u8], message: &[u8]) -> Result<Reply, u32> {
        let backing = self.ctx.backing.as_ref();
        match hdr.command {
            cmd::CREATE => {
                files::create(body, message, backing, &mut self.handles).map(Reply::ok)
            }
            cmd::CLOSE => files::close(body, &mut self.handles).map(Reply::ok),
            cmd::READ => files::read(body, backing, &mut self.handles).map(Reply::ok),
            cmd::QUERY_DIRECTORY => files::query_directory(
                body,
                message,
                backing,
                &mut self.handles,
                self.ctx.boot_time,
            )
            .map(Reply::ok),
            cmd::QUERY_INFO => files::query_info(
                body,
                backing,
                &self.handles,
                self.ctx.boot_time,
                self.ctx.volume_serial,
            )
            .map(Reply::ok),
            _ => Err(status::NOT_SUPPORTED),
        }
    }

    fn tree_kind(&self, tree_id: u32) -> Option<TreeKind> {
        if self.state.disk_tree_id == Some(tree_id) {
            Some(TreeKind::Disk)
        } else if self.state.ipc_tree_id == Some(tree_id) {
            Some(TreeKind::Ipc)
        } else {
            None
        }
    }
}

/// Grant what the client asked for, never zero (which would deadlock it) and
/// never more than our ceiling.
fn grant_credits(hdr: &Header) -> u16 {
    hdr.credits.clamp(1, MAX_CREDITS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use backing::test_support::MemBacking;
    use wire::utf16le;

    /// A small tree the end-to-end tests can list and read.
    fn test_backing() -> Arc<dyn Backing> {
        Arc::new(
            MemBacking::new()
                .with_dir("docs")
                .with_file("docs\\readme.txt", b"hello from a snapshot\n")
                .with_file("docs\\notes.md", b"# notes\n")
                .with_file("data.bin", &[0xAB; 9000]),
        )
    }

    fn ctx() -> Arc<Ctx> {
        Arc::new(Ctx {
            share_name: DEFAULT_SHARE_NAME.to_string(),
            backing: test_backing(),
            volume_serial: 0x1234_5678,
            server_guid: [7u8; 16],
            boot_time: SystemTime::UNIX_EPOCH,
        })
    }

    /// Build one SMB2 request message: header followed by `body`.
    fn request(command: u16, session_id: u64, tree_id: u32, body: &[u8]) -> Vec<u8> {
        request_with(command, session_id, tree_id, body, 0, 0)
    }

    fn request_with(
        command: u16,
        session_id: u64,
        tree_id: u32,
        body: &[u8],
        next_command: u32,
        flags: u32,
    ) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&proto::SMB2_MAGIC);
        w.u16(HEADER_LEN as u16);
        w.u16(1); // CreditCharge
        w.u32(0); // Status
        w.u16(command);
        w.u16(64); // CreditRequest
        w.u32(flags);
        w.u32(next_command);
        w.u64(1); // MessageId
        w.u32(0); // Reserved
        w.u32(tree_id);
        w.u64(session_id);
        w.zeros(16); // Signature
        w.bytes(body);
        w.into_vec()
    }

    fn negotiate_body(dialects: &[u16]) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(36);
        w.u16(dialects.len() as u16);
        w.u16(0);
        w.u16(0);
        w.u32(0);
        w.zeros(16);
        w.u64(0);
        for d in dialects {
            w.u16(*d);
        }
        w.into_vec()
    }

    fn session_setup_body(msg_type: u32) -> Vec<u8> {
        let mut token = Vec::new();
        token.extend_from_slice(b"NTLMSSP\0");
        token.extend_from_slice(&msg_type.to_le_bytes());
        token.extend_from_slice(&[0u8; 32]);

        let mut w = Writer::new();
        w.u16(25);
        w.u8(0);
        w.u8(0);
        w.u32(0);
        w.u32(0);
        w.u16((HEADER_LEN + 24) as u16);
        w.u16(token.len() as u16);
        w.u64(0);
        w.bytes(&token);
        w.into_vec()
    }

    fn tree_connect_body(path: &str) -> Vec<u8> {
        let encoded = utf16le(path);
        let mut w = Writer::new();
        w.u16(9);
        w.u16(0);
        w.u16((HEADER_LEN + 8) as u16);
        w.u16(encoded.len() as u16);
        w.bytes(&encoded);
        w.into_vec()
    }

    fn parse_response(resp: &[u8]) -> Header {
        Header::parse(&mut Reader::new(resp)).expect("response header parses")
    }

    /// Drive a connection through negotiate + both session-setup legs,
    /// returning the connection and its session id.
    fn connected() -> (Conn, u64) {
        let mut conn = Conn::new(ctx());

        let resp = conn
            .handle_message(&request(cmd::NEGOTIATE, 0, 0, &negotiate_body(&[0x0210, 0x0311])))
            .expect("negotiate answered");
        assert_eq!(parse_response(&resp).status, status::SUCCESS);

        let resp = conn
            .handle_message(&request(cmd::SESSION_SETUP, 0, 0, &session_setup_body(1)))
            .expect("session setup leg one answered");
        let h = parse_response(&resp);
        assert_eq!(h.status, status::MORE_PROCESSING_REQUIRED);
        let session_id = h.session_id;

        let resp = conn
            .handle_message(&request(
                cmd::SESSION_SETUP,
                session_id,
                0,
                &session_setup_body(3),
            ))
            .expect("session setup leg two answered");
        assert_eq!(parse_response(&resp).status, status::SUCCESS);

        (conn, session_id)
    }

    #[test]
    fn full_handshake_reaches_a_connected_tree() {
        let (mut conn, session_id) = connected();
        let resp = conn
            .handle_message(&request(
                cmd::TREE_CONNECT,
                session_id,
                0,
                &tree_connect_body(r"\\127.0.0.1\snap"),
            ))
            .expect("tree connect answered");
        let h = parse_response(&resp);
        assert_eq!(h.status, status::SUCCESS);
        assert_ne!(h.tree_id, 0);
    }

    #[test]
    fn commands_before_authentication_are_refused() {
        let mut conn = Conn::new(ctx());
        let resp = conn
            .handle_message(&request(cmd::TREE_CONNECT, 0, 0, &tree_connect_body("snap")))
            .expect("answered");
        assert_eq!(parse_response(&resp).status, status::USER_SESSION_DELETED);
    }

    #[test]
    fn a_forged_session_id_is_refused() {
        let (mut conn, session_id) = connected();
        let resp = conn
            .handle_message(&request(
                cmd::TREE_CONNECT,
                session_id ^ 0xFFFF,
                0,
                &tree_connect_body(r"\\127.0.0.1\snap"),
            ))
            .expect("answered");
        assert_eq!(parse_response(&resp).status, status::USER_SESSION_DELETED);
    }

    #[test]
    fn write_commands_report_a_write_protected_medium() {
        let (mut conn, session_id) = connected();
        for command in [cmd::WRITE, cmd::SET_INFO, cmd::FLUSH] {
            let resp = conn
                .handle_message(&request(command, session_id, 0, &[0u8; 8]))
                .expect("answered");
            assert_eq!(
                parse_response(&resp).status,
                status::MEDIA_WRITE_PROTECTED,
                "command {}",
                cmd::name(command)
            );
        }
    }

    #[test]
    fn logoff_invalidates_the_session() {
        let (mut conn, session_id) = connected();
        let resp = conn
            .handle_message(&request(cmd::LOGOFF, session_id, 0, &[4, 0, 0, 0]))
            .expect("answered");
        assert_eq!(parse_response(&resp).status, status::SUCCESS);

        let resp = conn
            .handle_message(&request(cmd::ECHO, session_id, 0, &[4, 0, 0, 0]))
            .expect("answered");
        assert_eq!(parse_response(&resp).status, status::USER_SESSION_DELETED);
    }

    #[test]
    fn cancel_alone_produces_no_response() {
        let (mut conn, session_id) = connected();
        let resp = conn
            .handle_message(&request(cmd::CANCEL, session_id, 0, &[4, 0, 0, 0]))
            .expect("connection stays open");
        assert!(resp.is_empty(), "CANCEL is answered with silence");
    }

    #[test]
    fn an_smb1_negotiate_drops_the_connection() {
        let mut conn = Conn::new(ctx());
        let mut msg = request(cmd::NEGOTIATE, 0, 0, &negotiate_body(&[0x0210]));
        msg[0] = 0xFF; // \xFFSMB — the SMB1 magic
        assert!(conn.handle_message(&msg).is_none());
    }

    #[test]
    fn a_truncated_message_drops_the_connection() {
        let mut conn = Conn::new(ctx());
        let msg = request(cmd::NEGOTIATE, 0, 0, &negotiate_body(&[0x0210]));
        assert!(conn.handle_message(&msg[..HEADER_LEN - 1]).is_none());
    }

    #[test]
    fn compounded_requests_produce_a_chained_response() {
        let (mut conn, session_id) = connected();

        // Two ECHOs in one message: the first chains to the second.
        let echo_body = [4u8, 0, 0, 0];
        let mut first = request_with(
            cmd::ECHO,
            session_id,
            0,
            &echo_body,
            0,
            0,
        );
        // Pad the first request to an 8-byte boundary and point NextCommand at
        // the second, exactly as a client does.
        while !first.len().is_multiple_of(8) {
            first.push(0);
        }
        let next_command = first.len() as u32;
        first[NEXT_COMMAND_OFFSET..NEXT_COMMAND_OFFSET + 4]
            .copy_from_slice(&next_command.to_le_bytes());
        let second = request_with(
            cmd::ECHO,
            session_id,
            0,
            &echo_body,
            0,
            proto::flags::RELATED_OPERATIONS,
        );
        let mut msg = first;
        msg.extend_from_slice(&second);

        let resp = conn.handle_message(&msg).expect("answered");

        let h1 = parse_response(&resp);
        assert_eq!(h1.status, status::SUCCESS);
        assert_ne!(h1.next_command, 0, "first response must chain");
        assert!(
            h1.next_command.is_multiple_of(8),
            "chained responses start on an 8-byte boundary, got {}",
            h1.next_command
        );

        let h2 = parse_response(&resp[h1.next_command as usize..]);
        assert_eq!(h2.status, status::SUCCESS);
        assert_eq!(h2.next_command, 0, "last response terminates the chain");
        assert_eq!(
            h2.flags & proto::flags::RELATED_OPERATIONS,
            proto::flags::RELATED_OPERATIONS,
            "RELATED_OPERATIONS is echoed so the client can match the chain"
        );
    }

    #[test]
    fn a_compound_chain_pointing_out_of_bounds_drops_the_connection() {
        let (mut conn, session_id) = connected();
        let msg = request_with(cmd::ECHO, session_id, 0, &[4, 0, 0, 0], 0xFFFF, 0);
        assert!(conn.handle_message(&msg).is_none());
    }

    #[test]
    fn credits_are_granted_within_bounds() {
        let mut hdr = Header::parse(&mut Reader::new(&request(cmd::ECHO, 1, 0, &[]))).unwrap();
        hdr.credits = 0;
        assert_eq!(grant_credits(&hdr), 1, "zero credits would stall the client");
        hdr.credits = 10_000;
        assert_eq!(grant_credits(&hdr), MAX_CREDITS);
        hdr.credits = 64;
        assert_eq!(grant_credits(&hdr), 64);
    }

    #[test]
    fn tree_disconnect_releases_the_tree() {
        let (mut conn, session_id) = connected();
        let resp = conn
            .handle_message(&request(
                cmd::TREE_CONNECT,
                session_id,
                0,
                &tree_connect_body(r"\\127.0.0.1\snap"),
            ))
            .unwrap();
        let tree_id = parse_response(&resp).tree_id;

        let resp = conn
            .handle_message(&request(
                cmd::TREE_DISCONNECT,
                session_id,
                tree_id,
                &[4, 0, 0, 0],
            ))
            .unwrap();
        assert_eq!(parse_response(&resp).status, status::SUCCESS);

        let resp = conn
            .handle_message(&request(
                cmd::TREE_DISCONNECT,
                session_id,
                tree_id,
                &[4, 0, 0, 0],
            ))
            .unwrap();
        assert_eq!(parse_response(&resp).status, status::NETWORK_NAME_DELETED);
    }

    #[test]
    fn server_starts_on_an_ephemeral_port_and_stops() {
        let handle = start(0, DEFAULT_SHARE_NAME, test_backing()).expect("server starts");
        assert_ne!(handle.port, 0);
        assert_eq!(handle.unc(), r"\\127.0.0.1\snap");
        handle.stop();
    }

    /// End-to-end handshake against a real SMB client. Unit tests can only
    /// confirm the bytes match our reading of the spec; this confirms they
    /// match what a client actually accepts, which is the part that matters.
    ///
    /// Skipped when smbclient is not installed rather than failing, so the
    /// suite still runs on a machine without Samba's client tools.
    #[test]
    fn smbclient_completes_the_handshake() {
        use std::process::Command;

        if Command::new("smbclient").arg("--version").output().is_err() {
            eprintln!("skipping: smbclient is not installed");
            return;
        }

        let handle = start(0, DEFAULT_SHARE_NAME, test_backing()).expect("server starts");
        let target = format!("//127.0.0.1/{}", handle.share_name);

        let out = Command::new("smbclient")
            .arg(&target)
            .args(["-p", &handle.port.to_string()])
            .arg("-N") // no password: guest
            // Pin the client to 2.1 so a dialect mismatch shows up here as a
            // clear failure rather than as a confusing later error.
            .arg("--option=client min protocol=SMB2_10")
            .arg("--option=client max protocol=SMB2_10")
            .args(["-c", "quit"])
            .output()
            .expect("smbclient runs");

        handle.stop();

        assert!(
            out.status.success(),
            "smbclient failed to connect\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }

    /// Run one smbclient command against a fresh server, returning its stdout.
    /// Returns None when smbclient is not installed.
    fn smbclient(command: &str) -> Option<String> {
        use std::process::Command;

        if Command::new("smbclient").arg("--version").output().is_err() {
            eprintln!("skipping: smbclient is not installed");
            return None;
        }

        let handle = start(0, DEFAULT_SHARE_NAME, test_backing()).expect("server starts");
        let target = format!("//127.0.0.1/{}", handle.share_name);
        let out = Command::new("smbclient")
            .arg(&target)
            .args(["-p", &handle.port.to_string()])
            .arg("-N")
            .arg("--option=client min protocol=SMB2_10")
            .arg("--option=client max protocol=SMB2_10")
            .args(["-c", command])
            .output()
            .expect("smbclient runs");
        handle.stop();

        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(
            out.status.success(),
            "smbclient `{command}` failed\nstdout: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&out.stderr),
        );
        Some(stdout)
    }

    /// Hold a server open on a fixed port so an external client can be pointed
    /// at it. Run with: cargo test --all-features smb_manual_server -- --ignored --nocapture
    #[test]
    #[ignore]
    fn smb_manual_server() {
        let port: u16 = std::env::var("WRUSTIC_SMB_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4455);
        let handle = start(port, DEFAULT_SHARE_NAME, test_backing()).expect("server starts");
        eprintln!("serving \\\\127.0.0.1\\snap on port {}", handle.port);
        std::thread::sleep(std::time::Duration::from_secs(120));
        handle.stop();
    }

    /// Serve a real restic snapshot, for validating the `SnapshotBacking` path
    /// against a live client. Driven by environment variables so it needs no
    /// wrustic config:
    ///
    ///   WRUSTIC_SMB_REPO=<path> WRUSTIC_SMB_PASSWORD=<pw> WRUSTIC_SMB_SNAPSHOT=<id> \
    ///     cargo test --all-features smb_manual_snapshot -- --ignored --nocapture
    #[test]
    #[ignore]
    fn smb_manual_snapshot() {
        let repo = std::env::var("WRUSTIC_SMB_REPO").expect("WRUSTIC_SMB_REPO");
        let password = std::env::var("WRUSTIC_SMB_PASSWORD").expect("WRUSTIC_SMB_PASSWORD");
        let snapshot = std::env::var("WRUSTIC_SMB_SNAPSHOT").expect("WRUSTIC_SMB_SNAPSHOT");
        let port: u16 = std::env::var("WRUSTIC_SMB_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4456);

        let profile = Profile::Local {
            password,
            local_path: repo,
        };
        let handle =
            start_snapshot_share(port, &profile, &snapshot).expect("snapshot share starts");
        eprintln!("serving snapshot {snapshot} on port {}", handle.port);
        std::thread::sleep(std::time::Duration::from_secs(120));
        handle.stop();
    }

    #[test]
    fn smbclient_lists_the_share_root() {
        let Some(out) = smbclient("ls") else { return };
        assert!(out.contains("docs"), "missing directory in listing:\n{out}");
        assert!(out.contains("data.bin"), "missing file in listing:\n{out}");
        // The size column must reflect the real file size.
        assert!(out.contains("9000"), "wrong size reported:\n{out}");
    }

    #[test]
    fn smbclient_lists_a_subdirectory() {
        let Some(out) = smbclient("cd docs; ls") else {
            return;
        };
        assert!(out.contains("readme.txt"), "missing entry:\n{out}");
        assert!(out.contains("notes.md"), "missing entry:\n{out}");
    }

    #[test]
    fn smbclient_reads_file_content() {
        let dir = tempdir_path("smb-read");
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let dest = dir.join("readme.txt");
        let Some(_) = smbclient(&format!(
            "get docs\\readme.txt {}",
            dest.display()
        )) else {
            return;
        };
        let got = std::fs::read(&dest).expect("downloaded file exists");
        assert_eq!(
            got, b"hello from a snapshot\n",
            "content read over SMB must match the source"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn smbclient_refuses_to_write() {
        use std::process::Command;

        if Command::new("smbclient").arg("--version").output().is_err() {
            return;
        }
        let handle = start(0, DEFAULT_SHARE_NAME, test_backing()).expect("server starts");
        let target = format!("//127.0.0.1/{}", handle.share_name);

        let src = tempdir_path("smb-write");
        std::fs::create_dir_all(&src).expect("scratch dir");
        let file = src.join("payload.txt");
        std::fs::write(&file, b"should not land").expect("write scratch file");

        let out = Command::new("smbclient")
            .arg(&target)
            .args(["-p", &handle.port.to_string()])
            .arg("-N")
            .arg("--option=client min protocol=SMB2_10")
            .arg("--option=client max protocol=SMB2_10")
            .args(["-c", &format!("put {} payload.txt", file.display())])
            .output()
            .expect("smbclient runs");
        handle.stop();
        let _ = std::fs::remove_dir_all(&src);

        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            combined.contains("NT_STATUS_MEDIA_WRITE_PROTECTED")
                || combined.contains("NT_STATUS_ACCESS_DENIED"),
            "a write must be refused with a read-only status, got:\n{combined}"
        );
    }

    fn tempdir_path(tag: &str) -> std::path::PathBuf {
        // Per the project convention, scratch data lives under tmp/.
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tmp")
            .join(format!("{tag}-{}", std::process::id()))
    }
}
