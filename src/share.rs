// A one-file, signed-URL localhost downloader bound to the File Details
// screen. Each ShareHandle owns a Tokio runtime on its own OS thread, a
// hyper http1 listener on 127.0.0.1:<port>, and a Repository opened with the
// full blob index/cache. The server serves only the (snap_id, tree_id, name)
// it was started with — never anything else — so a URL minted for file A can
// never be replayed against a server later started for file B.

use std::convert::Infallible;
use std::io;
use std::io::Read;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context as TaskContext, Poll};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow, bail};
use bytes::Bytes;
use hmac::{Hmac, Mac};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::{Body, Frame};
use hyper::header::{CONTENT_DISPOSITION, CONTENT_TYPE, HeaderValue, LOCATION};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustic_core::{IndexedFullStatus, Repository, TreeId};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

use crate::config::Profile;
use crate::repo::{open_indexed_full, stream_file_content};

type HmacSha256 = Hmac<Sha256>;

pub(crate) const SHARE_TTL: Duration = Duration::from_secs(3600);

// What a share server is bound to: a single file inside a snapshot. Grouped
// so callers don't pass five strings positionally.
#[derive(Clone)]
pub(crate) struct ShareTarget {
    pub(crate) snap_id: String,
    pub(crate) tree_id: TreeId,
    pub(crate) name: String,
    pub(crate) display_path: String,
}

pub(crate) struct ShareHandle {
    pub(crate) port: u16,
    pub(crate) url: String,
    // Short alias: http://127.0.0.1:<port>/s/<short_id>. The server holds
    // <short_id> in-memory and 302-redirects it to the current long URL.
    // The short id is freshly generated on every `start` call, so stopping
    // and restarting (toggle 's' twice) gives a brand-new short URL.
    pub(crate) short_url: String,
    pub(crate) exp_unix: u64,
    snap_id: String,
    tree_id: TreeId,
    name: String,
    signing_key: [u8; 32],
    // Shared with the server task so `regenerate` updates the redirect
    // target without having to restart the server. Stored as a path-only
    // form (`/dl?...`) so the redirect doesn't pin a host:port.
    long_path_cell: Arc<RwLock<String>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    join_handle: Option<thread::JoinHandle<()>>,
}

impl ShareHandle {
    pub(crate) fn regenerate(&mut self, ttl: Duration) {
        let (url, path, exp) = build_signed_url(
            self.port,
            &self.snap_id,
            self.tree_id,
            &self.name,
            ttl,
            &self.signing_key,
        );
        if let Ok(mut w) = self.long_path_cell.write() {
            *w = path;
        }
        self.url = url;
        self.exp_unix = exp;
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

impl Drop for ShareHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

pub(crate) fn derive_signing_key(identity_path: &Path) -> Result<[u8; 32]> {
    let bytes = std::fs::read(identity_path)
        .map_err(|e| anyhow!("reading {}: {e}", identity_path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hasher.finalize().into())
}

// 16 hex chars (64 bits) of randomness for the short URL id. Read from
// /dev/urandom so we never collide with a previous run's id and don't have
// to guess at the OS rng story. Falls back to mixing process id + nanos if
// /dev/urandom isn't readable, which is good enough for a localhost alias
// that's only meant to deter someone shoulder-surfing the terminal.
fn random_short_id() -> String {
    let mut buf = [0u8; 8];
    let filled = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok();
    if !filled {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        let mix = (nanos as u64) ^ ((pid as u64) << 32);
        buf.copy_from_slice(&mix.to_le_bytes());
    }
    hex_encode(&buf)
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

fn canonical_message(snap: &str, tree_hex: &str, name: &str, exp: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(snap.len() + tree_hex.len() + name.len() + 32);
    msg.extend_from_slice(b"v1\n");
    msg.extend_from_slice(snap.as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(tree_hex.as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(name.as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(exp.to_string().as_bytes());
    msg
}

fn compute_sig(key: &[u8; 32], snap: &str, tree_hex: &str, name: &str, exp: u64) -> String {
    // HMAC::new_from_slice accepts any key length and returns Result solely
    // to be future-compatible; for HMAC-SHA256 with a fixed 32-byte key it
    // never fails.
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&canonical_message(snap, tree_hex, name, exp));
    hex_encode(&mac.finalize().into_bytes())
}

// Returns (absolute_url, relative_path, exp). The absolute form is for human
// display ("here is the URL you can paste into a browser"); the relative
// form (`/dl?...`) is what the short-URL handler emits as the redirect
// `Location` so the browser stays on whatever host:port it dialed in on.
pub(crate) fn build_signed_url(
    port: u16,
    snap_id: &str,
    tree_id: TreeId,
    name: &str,
    ttl: Duration,
    key: &[u8; 32],
) -> (String, String, u64) {
    let exp = (SystemTime::now() + ttl)
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let tree_hex = tree_id.to_hex().as_str().to_string();
    let sig = compute_sig(key, snap_id, &tree_hex, name, exp);
    let qs: String = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("snap", snap_id)
        .append_pair("tree", &tree_hex)
        .append_pair("name", name)
        .append_pair("exp", &exp.to_string())
        .append_pair("sig", &sig)
        .finish();
    let path = format!("/dl?{qs}");
    (format!("http://127.0.0.1:{port}{path}"), path, exp)
}

struct Ctx {
    repo: Arc<Repository<IndexedFullStatus>>,
    key: [u8; 32],
    snap_id: String,
    tree_hex: String,
    tree_id: TreeId,
    name: String,
    display_path: String,
    short_id: String,
    // Current path+query for the long URL — read on every /s/<id> redirect.
    // Mutated by ShareHandle::regenerate from outside the server thread.
    // Path-only (no scheme/host/port) so the redirect stays same-origin.
    long_path: Arc<RwLock<String>>,
}

pub(crate) fn start(
    port: u16,
    profile: Profile,
    key: [u8; 32],
    target: ShareTarget,
    ttl: Duration,
) -> Result<ShareHandle> {
    let ShareTarget {
        snap_id,
        tree_id,
        name,
        display_path,
    } = target;
    if snap_id.len() != 64 || !snap_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("expected a full 64-char hex snapshot id, got `{snap_id}`");
    }
    let tree_hex = tree_id.to_hex().as_str().to_string();
    if tree_hex.len() != 64 || !tree_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("invalid TreeId hex: `{tree_hex}`");
    }

    // Bind synchronously so EADDRINUSE/permission errors surface before we
    // spin up a runtime. Hand the listener to tokio after.
    let listener_std = std::net::TcpListener::bind(("127.0.0.1", port))
        .map_err(|e| anyhow!("bind 127.0.0.1:{port}: {e}"))?;
    listener_std
        .set_nonblocking(true)
        .map_err(|e| anyhow!("set_nonblocking: {e}"))?;

    let repo = open_indexed_full(&profile)?;

    let (url, path, exp) = build_signed_url(port, &snap_id, tree_id, &name, ttl, &key);
    let short_id = random_short_id();
    let short_url = format!("http://127.0.0.1:{port}/s/{short_id}");
    let long_path_cell = Arc::new(RwLock::new(path));

    let ctx = Arc::new(Ctx {
        repo: Arc::new(repo),
        key,
        snap_id: snap_id.clone(),
        tree_hex: tree_hex.clone(),
        tree_id,
        name: name.clone(),
        display_path,
        short_id,
        long_path: long_path_cell.clone(),
    });

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let thread_ctx = ctx.clone();
    let join = thread::Builder::new()
        .name(format!("wrustic-share-{port}"))
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
            {
                Ok(rt) => rt,
                Err(_) => return,
            };
            rt.block_on(async move {
                let listener = match TcpListener::from_std(listener_std) {
                    Ok(l) => l,
                    Err(_) => return,
                };
                accept_loop(listener, thread_ctx, shutdown_rx).await;
            });
        })
        .map_err(|e| anyhow!("spawning share thread: {e}"))?;

    Ok(ShareHandle {
        port,
        url,
        short_url,
        exp_unix: exp,
        snap_id,
        tree_id,
        name,
        signing_key: key,
        long_path_cell,
        shutdown_tx: Some(shutdown_tx),
        join_handle: Some(join),
    })
}

async fn accept_loop(
    listener: TcpListener,
    ctx: Arc<Ctx>,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            res = listener.accept() => {
                let stream = match res {
                    Ok((s, _)) => s,
                    Err(_) => continue,
                };
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req| handle(req, ctx.clone()));
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, svc)
                        .await;
                });
            }
        }
    }
}

type RespBody = BoxBody<Bytes, io::Error>;

fn err_resp(status: StatusCode, msg: &'static str) -> Response<RespBody> {
    let body = Full::new(Bytes::from_static(msg.as_bytes()))
        .map_err(|never: Infallible| match never {})
        .boxed();
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    resp
}

async fn handle(
    req: Request<hyper::body::Incoming>,
    ctx: Arc<Ctx>,
) -> Result<Response<RespBody>, Infallible> {
    if req.method() != Method::GET {
        return Ok(err_resp(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"));
    }

    // Short-URL redirect: /s/<short_id> -> 302 to the current long URL.
    // The short id is fixed for the server's lifetime; the redirect target
    // is read fresh on each request so `regenerate` is picked up
    // immediately.
    if let Some(rest) = req.uri().path().strip_prefix("/s/") {
        if rest == ctx.short_id {
            // Path-relative Location so the browser keeps its current
            // host:port. Avoids surprises if someone reaches the server
            // via a different name (loopback alias, ssh -L tunnel, etc.).
            let target = ctx.long_path.read().map(|s| s.clone()).unwrap_or_default();
            let mut resp = Response::new(
                Full::new(Bytes::from_static(b""))
                    .map_err(|never: Infallible| match never {})
                    .boxed(),
            );
            *resp.status_mut() = StatusCode::FOUND;
            if let Ok(v) = HeaderValue::from_str(&target) {
                resp.headers_mut().insert(LOCATION, v);
            }
            return Ok(resp);
        }
        return Ok(err_resp(StatusCode::NOT_FOUND, "no such short id"));
    }

    if req.uri().path() != "/dl" {
        return Ok(err_resp(StatusCode::NOT_FOUND, "not found"));
    }

    let q = req.uri().query().unwrap_or("");
    let mut snap = None;
    let mut tree = None;
    let mut name = None;
    let mut exp_s = None;
    let mut sig = None;
    for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
        match k.as_ref() {
            "snap" => snap = Some(v.into_owned()),
            "tree" => tree = Some(v.into_owned()),
            "name" => name = Some(v.into_owned()),
            "exp" => exp_s = Some(v.into_owned()),
            "sig" => sig = Some(v.into_owned()),
            _ => {}
        }
    }
    let (Some(snap), Some(tree), Some(name), Some(exp_s), Some(sig)) =
        (snap, tree, name, exp_s, sig)
    else {
        return Ok(err_resp(StatusCode::BAD_REQUEST, "missing query parameters"));
    };

    // Cross-check the URL's identifiers against the server's bound values
    // before any crypto work. Identical 404 message regardless of which field
    // mismatched, so we don't leak which one's wrong.
    if snap != ctx.snap_id || tree != ctx.tree_hex || name != ctx.name {
        return Ok(err_resp(StatusCode::NOT_FOUND, "no such file"));
    }

    let Ok(exp) = exp_s.parse::<u64>() else {
        return Ok(err_resp(StatusCode::BAD_REQUEST, "bad exp"));
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX);
    if now > exp {
        return Ok(err_resp(StatusCode::FORBIDDEN, "expired"));
    }

    let Some(sig_bytes) = hex_decode(&sig) else {
        return Ok(err_resp(StatusCode::FORBIDDEN, "invalid signature"));
    };
    let mut mac = HmacSha256::new_from_slice(&ctx.key).expect("any-length");
    mac.update(&canonical_message(&snap, &tree, &name, exp));
    if mac.verify_slice(&sig_bytes).is_err() {
        return Ok(err_resp(StatusCode::FORBIDDEN, "invalid signature"));
    }

    // rustic_core's read path is synchronous; hand it to spawn_blocking and
    // stream bytes back through an mpsc into a custom Body impl below.
    let (tx, rx) = mpsc::channel::<io::Result<Bytes>>(8);
    let repo = ctx.repo.clone();
    let tree_id = ctx.tree_id;
    let bound_name = ctx.name.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(e) = stream_file_content(&repo, tree_id, &bound_name, &tx) {
            let _ = tx.blocking_send(Err(io::Error::other(format!("{e:#}"))));
        }
    });

    let body = ChannelBody { rx, done: false }.boxed();
    let mut resp = Response::new(body);
    resp.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    let filename = sanitize_filename(basename(&ctx.display_path));
    let disp = format!("attachment; filename=\"{filename}\"");
    if let Ok(v) = HeaderValue::from_str(&disp) {
        resp.headers_mut().insert(CONTENT_DISPOSITION, v);
    }
    Ok(resp)
}

// Custom hyper Body that polls a tokio mpsc receiver. Avoids pulling in
// async-stream or tokio-stream just for this one bridge.
struct ChannelBody {
    rx: mpsc::Receiver<io::Result<Bytes>>,
    done: bool,
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.done {
            return Poll::Ready(None);
        }
        match self.rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                self.done = true;
                Poll::Ready(None)
            }
            Poll::Ready(Some(Ok(b))) => Poll::Ready(Some(Ok(Frame::data(b)))),
            Poll::Ready(Some(Err(e))) => {
                self.done = true;
                Poll::Ready(Some(Err(e)))
            }
        }
    }
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

// Keep only printable ASCII without quotes or control bytes — anything else
// gets dropped so the Content-Disposition header can't be broken or used to
// smuggle CRLF. Browsers will fall back to the URL/UA defaults if filename is
// empty.
fn sanitize_filename(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|c| c.is_ascii() && !c.is_ascii_control() && *c != '"' && *c != '\\')
        .collect();
    if cleaned.is_empty() {
        "download".to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn hex_roundtrip() {
        let bytes = [0u8, 1, 2, 0xff, 0x10, 0xab];
        let hex = hex_encode(&bytes);
        assert_eq!(hex, "000102ff10ab");
        assert_eq!(hex_decode(&hex).unwrap(), bytes);
    }

    #[test]
    fn hex_decode_rejects_odd_length() {
        assert!(hex_decode("abc").is_none());
    }

    #[test]
    fn hex_decode_rejects_non_hex() {
        assert!(hex_decode("zz").is_none());
    }

    #[test]
    fn sig_changes_per_inputs() {
        let k = key();
        let a = compute_sig(&k, "snap-a", "tree-a", "file-a", 123);
        let b = compute_sig(&k, "snap-a", "tree-a", "file-b", 123);
        let c = compute_sig(&k, "snap-a", "tree-b", "file-a", 123);
        let d = compute_sig(&k, "snap-b", "tree-a", "file-a", 123);
        let e = compute_sig(&k, "snap-a", "tree-a", "file-a", 124);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_ne!(a, e);
    }

    #[test]
    fn sig_verify_round_trip() {
        let k = key();
        let exp = 1_700_000_000u64;
        let sig = compute_sig(&k, "snap", "tree", "name", exp);
        let sig_bytes = hex_decode(&sig).unwrap();
        let mut mac = HmacSha256::new_from_slice(&k).unwrap();
        mac.update(&canonical_message("snap", "tree", "name", exp));
        assert!(mac.verify_slice(&sig_bytes).is_ok());
    }

    #[test]
    fn sig_verify_rejects_tampered_byte() {
        let k = key();
        let exp = 1_700_000_000u64;
        let sig = compute_sig(&k, "snap", "tree", "name", exp);
        let mut bytes = hex_decode(&sig).unwrap();
        bytes[0] ^= 0x01;
        let mut mac = HmacSha256::new_from_slice(&k).unwrap();
        mac.update(&canonical_message("snap", "tree", "name", exp));
        assert!(mac.verify_slice(&bytes).is_err());
    }

    #[test]
    fn sig_verify_rejects_wrong_name() {
        let k = key();
        let exp = 1_700_000_000u64;
        // URL minted with name=A but server bound to name=B verifies B's message.
        let sig = compute_sig(&k, "snap", "tree", "nameA", exp);
        let sig_bytes = hex_decode(&sig).unwrap();
        let mut mac = HmacSha256::new_from_slice(&k).unwrap();
        mac.update(&canonical_message("snap", "tree", "nameB", exp));
        assert!(mac.verify_slice(&sig_bytes).is_err());
    }

    #[test]
    fn derive_signing_key_is_stable() {
        let dir = std::path::PathBuf::from("tmp").join(format!(
            "share-derive-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("age.key");
        std::fs::write(&p, b"some-identity-bytes\nAGE-SECRET-KEY-...\n").unwrap();
        let a = derive_signing_key(&p).unwrap();
        let b = derive_signing_key(&p).unwrap();
        assert_eq!(a, b);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sanitize_filename_strips_unsafe() {
        assert_eq!(sanitize_filename("ok.txt"), "ok.txt");
        assert_eq!(sanitize_filename("bad\"name\r\n.txt"), "badname.txt");
        assert_eq!(sanitize_filename(""), "download");
        // Non-ASCII gets stripped; if nothing survives we fall back.
        assert_eq!(sanitize_filename("日本語"), "download");
    }

    #[test]
    fn basename_picks_tail() {
        assert_eq!(basename("foo/bar/baz.txt"), "baz.txt");
        assert_eq!(basename("just-a-name"), "just-a-name");
        assert_eq!(basename(""), "");
    }

    // End-to-end smoke test against a real local restic repo prepared under
    // tmp/share-test (see the CLI commands in the implementation log).
    // Marked #[ignore] so `cargo test` doesn't depend on the fixture; run
    // explicitly with `cargo test share::tests::e2e -- --ignored`.
    #[test]
    #[ignore]
    fn e2e_serves_and_validates_signed_url() {
        use std::io::{Read, Write};
        use std::net::TcpStream;

        // Find the latest snapshot id (64-hex) and the file's parent tree id
        // by walking the repo via rustic_core, so this test isn't tied to a
        // specific snapshot id that's only known after `restic backup`.
        let profile = Profile::Local {
            password: "sandbox".into(),
            local_path: "tmp/share-test/restic-repo".into(),
        };
        let repo = crate::repo::open_indexed(&profile).expect("open repo");
        let snaps = repo.get_all_snapshots().expect("list snapshots");
        let snap = snaps.last().expect("at least one snapshot");
        let snap_id = snap.id.to_hex().as_str().to_string();

        // Walk to the tree containing `greeting.txt`. The backup put files
        // under `source/`, so the path is `/source/greeting.txt`. Resolve
        // the parent tree id by descending into `source`.
        let root_tree = snap.tree;
        let root_rows = repo.get_tree(&root_tree).expect("root tree");
        let source_node = root_rows
            .nodes
            .iter()
            .find(|n| n.name().to_string_lossy() == "source")
            .expect("source dir node");
        let source_tree = source_node.subtree.expect("source has subtree");

        // Free up our `repo` handle — share::start opens its own with the
        // full index. (Otherwise both repos would scribble on the same cache
        // dir; rustic_core is fine with concurrent opens, but we don't need
        // two here.)
        drop(repo);

        let target = ShareTarget {
            snap_id: snap_id.clone(),
            tree_id: source_tree,
            name: "greeting.txt".into(),
            display_path: "/source/greeting.txt".into(),
        };

        // Bind to an ephemeral port instead of 7834 so this test can run
        // alongside a real wrustic instance.
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let id_path = std::path::PathBuf::from("tmp/share-test/wrustic-sandbox/age.key");
        // Test runs against any 32-byte signing key; fabricate one here
        // rather than rely on a real age.key being present.
        let key = [0x77u8; 32];
        let _ = id_path; // silence if unused

        let handle = start(port, profile, key, target, SHARE_TTL).expect("start server");

        // Issue a raw HTTP/1.0 GET (no need to pull in a client) and pull
        // the body until EOF.
        let url = handle.url.clone();
        let qs = url.split_once('?').unwrap().1;
        let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        write!(sock, "GET /dl?{qs} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n").unwrap();
        let mut resp = Vec::new();
        sock.read_to_end(&mut resp).unwrap();
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(
            resp_str.starts_with("HTTP/1.0 200") || resp_str.starts_with("HTTP/1.1 200"),
            "got: {resp_str}"
        );
        let body_start = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let body = &resp[body_start..];
        assert_eq!(body, b"hello signed-url world\n");

        // Tamper the sig: flip the first hex char. Must come back 403.
        let mut bad_qs = qs.to_string();
        let sig_pos = bad_qs.find("sig=").unwrap() + 4;
        let ch = bad_qs.as_bytes()[sig_pos];
        let flipped = if ch == b'0' { '1' } else { '0' };
        bad_qs.replace_range(sig_pos..sig_pos + 1, &flipped.to_string());
        let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(sock, "GET /dl?{bad_qs} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n").unwrap();
        let mut resp = Vec::new();
        sock.read_to_end(&mut resp).unwrap();
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(
            resp_str.starts_with("HTTP/1.0 403") || resp_str.starts_with("HTTP/1.1 403"),
            "got: {resp_str}"
        );

        // Cross-check: replace `name` in URL with a different filename. Server
        // is bound to greeting.txt; this must come back 404 before HMAC.
        let alt_qs = qs.replace("name=greeting.txt", "name=other.txt");
        let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(sock, "GET /dl?{alt_qs} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n").unwrap();
        let mut resp = Vec::new();
        sock.read_to_end(&mut resp).unwrap();
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(
            resp_str.starts_with("HTTP/1.0 404") || resp_str.starts_with("HTTP/1.1 404"),
            "got: {resp_str}"
        );

        // Short URL: GET /s/<id> should 302 with Location = the long URL.
        let short_path = handle.short_url.rsplit_once('/').unwrap().1.to_string();
        let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(
            sock,
            "GET /s/{short_path} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n"
        )
        .unwrap();
        let mut resp = Vec::new();
        sock.read_to_end(&mut resp).unwrap();
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(
            resp_str.starts_with("HTTP/1.0 302") || resp_str.starts_with("HTTP/1.1 302"),
            "got: {resp_str}"
        );
        let loc = resp_str
            .lines()
            .find_map(|l| l.strip_prefix("location: "))
            .or_else(|| resp_str.lines().find_map(|l| l.strip_prefix("Location: ")))
            .expect("Location header");
        // Path-relative redirect: no scheme/host/port in the Location.
        assert!(
            loc.trim().starts_with("/dl?"),
            "Location should be path-relative, got: {loc}"
        );
        assert!(handle.url.ends_with(loc.trim()), "long URL should end with the redirect path");

        // Unknown short id: 404.
        let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(sock, "GET /s/deadbeef HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n").unwrap();
        let mut resp = Vec::new();
        sock.read_to_end(&mut resp).unwrap();
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(
            resp_str.starts_with("HTTP/1.0 404") || resp_str.starts_with("HTTP/1.1 404"),
            "got: {resp_str}"
        );

        handle.stop();

        // After stop, the port should be unbound. Connect attempts fail.
        let res = TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            std::time::Duration::from_millis(500),
        );
        assert!(res.is_err(), "server should be stopped");
    }
}
