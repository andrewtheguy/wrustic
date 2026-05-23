// Experimental: passkey-derived encryption ceremony, served as a localhost
// http page that the user opens in a browser. Mirrors the share.rs pattern
// (hyper on 127.0.0.1, ephemeral OS thread + tokio runtime, RAII handle).
// Unlike share, this is bidirectional: the browser POSTs the WebAuthn PRF
// output back to us, and we forward it through an mpsc to the App.

use std::convert::Infallible;
use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc as std_mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE, HeaderValue};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::config::PasskeyMeta;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PasskeyPhase {
    Setup,
    Unlock,
}

/// Hard wall-clock cap on a single passkey ceremony — if the user leaves the
/// browser tab open for this long the server still answers but with 403 on
/// every route, and the TUI surfaces an "expired" line. Kept separate from
/// the share dialog's TTL because the threat models differ (share serves
/// snapshot bytes, passkey gates the entire config decryption).
pub(crate) const PASSKEY_TTL: Duration = Duration::from_secs(30 * 60);

/// Wrong-setup-code budget for the Setup phase. The auth-key URL already
/// authenticates the caller, so this isn't anti-brute-force entropy — it's
/// a kill-switch so a typo'd code doesn't tie up the ceremony forever, and
/// a hostile script that somehow holds the URL can't grind through the
/// code space under the 30-minute TTL. Five strikes is forgiving for
/// human typos and combined with the ~56^6 ≈ 3·10^10 code space leaves
/// the guess probability well under 1e-9.
const MAX_SETUP_CODE_ATTEMPTS: u32 = 5;

/// Alphabet for the Setup-confirmation code. Excludes the well-known
/// confusables (0/O/o, 1/I/l/L) but keeps both cases of every other
/// letter, so the displayed code is case-sensitive and the user must
/// type it as printed. Symbols `-` and `=` are unshifted on US ANSI
/// and visible (no period — too small to spot reliably). Total 56
/// characters → 56^6 ≈ 3·10^10 code space.
const SETUP_CODE_ALPHABET: &[u8] =
    b"23456789ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz-=";
const SETUP_CODE_LEN: usize = 6;

/// Result handed back to App when the browser completes the ceremony.
/// The 32-byte key is the WebAuthn PRF output (used as the AEAD key in
/// `Cipher::Passkey`); `new_meta` is `Some` only on Setup so the App can
/// stash the credential id + salt into the next `config::save`.
///
/// The channel only ever carries success; browser-side errors surface as
/// HTTP error responses on the same page so the user can retry, and don't
/// need a separate App-side error path.
pub(crate) struct PasskeyOutcome {
    pub(crate) key: [u8; 32],
    pub(crate) new_meta: Option<PasskeyMeta>,
}

pub(crate) struct PasskeyHandle {
    /// The only URL that does anything — `http://localhost:<port>/auth/<key>`.
    /// `<key>` is a 64-bit random hex id; the server treats every other path
    /// (including bare `/`) as 404, so the URL itself is the capability.
    pub(crate) short_url: String,
    /// 6-digit code printed on the TUI that the user must echo into the
    /// browser to accept Setup. `Some` only when `phase == Setup`; on
    /// Unlock the existing `[passkey]` block + AEAD tag are the gate, so
    /// no second factor is needed.
    pub(crate) setup_code: Option<String>,
    pub(crate) phase: PasskeyPhase,
    pub(crate) rx: std_mpsc::Receiver<PasskeyOutcome>,
    /// Wall-clock instant at which the server stops accepting any route
    /// (returns 403 for everything). Surfaced to the TUI so a stale screen
    /// can show an "expired" line without polling the server.
    pub(crate) deadline: Instant,
    shutdown_tx: Option<oneshot::Sender<()>>,
    join_handle: Option<thread::JoinHandle<()>>,
}

impl PasskeyHandle {
    pub(crate) fn stop(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(jh) = self.join_handle.take() {
            let _ = jh.join();
        }
    }

    pub(crate) fn is_expired(&self) -> bool {
        Instant::now() >= self.deadline
    }
}

impl Drop for PasskeyHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

// 16 hex chars (64 bits) of randomness for the short URL id, same as share.rs.
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
    let mut s = String::with_capacity(16);
    use std::fmt::Write;
    for b in &buf {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

/// 6-character Setup-confirmation code drawn from SETUP_CODE_ALPHABET.
/// Each character is `byte % 33`, with a negligible modulo bias (≈ 1/256
/// per character — irrelevant for an intent-confirmation token). The
/// fallback path (no /dev/urandom) is intentionally weak; it just keeps
/// the function infallible.
fn random_setup_code() -> String {
    let mut buf = [0u8; SETUP_CODE_LEN];
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
        let mix_bytes = mix.to_le_bytes();
        for (i, slot) in buf.iter_mut().enumerate() {
            *slot = mix_bytes[i % mix_bytes.len()];
        }
    }
    let n = SETUP_CODE_ALPHABET.len();
    buf.iter()
        .map(|b| SETUP_CODE_ALPHABET[(*b as usize) % n] as char)
        .collect()
}

fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| anyhow!("opening /dev/urandom: {e}"))?;
    f.read_exact(&mut buf)
        .map_err(|e| anyhow!("reading /dev/urandom: {e}"))?;
    Ok(buf)
}

struct Ctx {
    phase: PasskeyPhase,
    short_id: String,
    // PRF salt presented to the browser. Newly generated on Setup; loaded
    // from the embedded [passkey] block on Unlock.
    prf_salt_b64: String,
    // Credential id presented to the browser on Unlock so it knows which
    // passkey to use. Empty on Setup (the browser is creating one).
    credential_id_b64: String,
    // 6-digit Setup-confirmation code. Some on Setup, None on Unlock. The
    // browser must echo it back in POST /api/setup, otherwise the call is
    // rejected (no key delivered, no [passkey] block written).
    setup_code: Option<String>,
    // Setup-code wrong-attempt counter. Crossing MAX_SETUP_CODE_ATTEMPTS
    // flips `killed`, which makes every subsequent route 403 like an
    // expired ceremony — the user has to quit + relaunch.
    setup_code_attempts: AtomicU32,
    // Tripped after too many wrong setup codes. Treated by the route
    // dispatcher as equivalent to the deadline having passed.
    killed: AtomicBool,
    // Send the PRF output (or an error) back to the App, exactly once.
    outcome_tx: std::sync::Mutex<Option<std_mpsc::Sender<PasskeyOutcome>>>,
    // Wall-clock cap. Once now >= deadline, every route returns 403.
    deadline: Instant,
}

impl Ctx {
    fn deliver(&self, outcome: PasskeyOutcome) -> Result<(), &'static str> {
        let mut guard = self.outcome_tx.lock().unwrap();
        match guard.take() {
            Some(tx) => {
                let _ = tx.send(outcome);
                Ok(())
            }
            None => Err("already delivered"),
        }
    }
}

pub(crate) fn start(
    port: u16,
    phase: PasskeyPhase,
    existing: Option<PasskeyMeta>,
) -> Result<PasskeyHandle> {
    // Shares the localhost port with the file-share dialog (see app.rs::
    // server_port). The two flows can't be active simultaneously, so a
    // single port is fine and avoids a second knob.
    let listener_std = std::net::TcpListener::bind(("127.0.0.1", port))
        .map_err(|e| anyhow!("bind 127.0.0.1:{port}: {e}"))?;
    listener_std
        .set_nonblocking(true)
        .map_err(|e| anyhow!("set_nonblocking: {e}"))?;

    let (prf_salt_b64, credential_id_b64) = match phase {
        PasskeyPhase::Setup => {
            // Fresh 16-byte salt; the browser will use this same value on
            // every subsequent unlock so PRF outputs match.
            let salt = random_bytes(16)?;
            (BASE64.encode(&salt), String::new())
        }
        PasskeyPhase::Unlock => {
            let meta = existing
                .ok_or_else(|| anyhow!("unlock phase requires existing passkey metadata"))?;
            (meta.prf_salt, meta.credential_id)
        }
    };

    let short_id = random_short_id();
    // User-facing host is `localhost` (better browser/authenticator
    // compatibility); the listener binds to 127.0.0.1 above. The 64-bit
    // hex `short_id` is the actual auth credential — every route below
    // `/auth/<short_id>` is gated by a constant-time compare against it,
    // and anything outside that prefix gets a flat 404.
    let short_url = format!("http://localhost:{port}/auth/{short_id}");

    // Setup-only intent-confirmation code: TUI prints it, browser must echo
    // it back on POST /api/setup. The auth-key URL is enough for *access*
    // but doesn't prove the user-at-terminal actively wanted to create or
    // import a passkey right now; this does.
    let setup_code = match phase {
        PasskeyPhase::Setup => Some(random_setup_code()),
        PasskeyPhase::Unlock => None,
    };

    let (outcome_tx, outcome_rx) = std_mpsc::channel::<PasskeyOutcome>();
    let deadline = Instant::now() + PASSKEY_TTL;

    let ctx = Arc::new(Ctx {
        phase,
        short_id,
        prf_salt_b64,
        credential_id_b64,
        setup_code: setup_code.clone(),
        setup_code_attempts: AtomicU32::new(0),
        killed: AtomicBool::new(false),
        outcome_tx: std::sync::Mutex::new(Some(outcome_tx)),
        deadline,
    });

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let thread_ctx = ctx.clone();
    let join = thread::Builder::new()
        .name(format!("wrustic-passkey-{port}"))
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
        .map_err(|e| anyhow!("spawning passkey thread: {e}"))?;

    Ok(PasskeyHandle {
        short_url,
        setup_code,
        phase,
        rx: outcome_rx,
        deadline,
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

type RespBody = BoxBody<Bytes, std::io::Error>;

fn full_resp(status: StatusCode, ct: &'static str, body: Vec<u8>) -> Response<RespBody> {
    let body = Full::new(Bytes::from(body))
        .map_err(|never: Infallible| match never {})
        .boxed();
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    resp.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(ct));
    resp.headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn text(status: StatusCode, msg: &str) -> Response<RespBody> {
    full_resp(status, "text/plain; charset=utf-8", msg.as_bytes().to_vec())
}

fn json_ok() -> Response<RespBody> {
    full_resp(StatusCode::OK, "application/json", b"{\"ok\":true}".to_vec())
}

async fn handle(
    req: Request<hyper::body::Incoming>,
    ctx: Arc<Ctx>,
) -> Result<Response<RespBody>, Infallible> {
    // Security gate: the entire server lives under /auth/<short_id>. The
    // 64-bit hex short_id is the actual auth credential — without it,
    // every path (including bare `/`) is a flat 404. No info leakage to
    // a port scanner, no /api/* reachable without first knowing the id.
    let path = req.uri().path().to_string();
    let Some(suffix) = path.strip_prefix("/auth/") else {
        return Ok(text(StatusCode::NOT_FOUND, "not found"));
    };
    let (key, rest) = match suffix.find('/') {
        Some(i) => (&suffix[..i], &suffix[i..]),
        None => (suffix, ""),
    };
    if !ct_eq(key.as_bytes(), ctx.short_id.as_bytes()) {
        return Ok(text(StatusCode::NOT_FOUND, "not found"));
    }

    // Auth-key check passes — this is a legitimate caller (the browser the
    // user pasted the URL into). Only now do we surface the expiry message,
    // so an unkeyed scanner can't distinguish "running" from "expired".
    //
    // Safety-net expiry: after PASSKEY_TTL the server keeps accepting
    // connections (so a stale browser tab gets a clear error instead of a
    // confusing "connection refused") but every keyed route 403s. The TUI
    // checks the same deadline via PasskeyHandle::is_expired() and shows
    // a matching message — no flow rework, the user just quits + restarts.
    // `killed` short-circuits the same way after too many wrong setup codes.
    if ctx.killed.load(Ordering::Relaxed) || Instant::now() >= ctx.deadline {
        return Ok(text(
            StatusCode::FORBIDDEN,
            "Passkey ceremony expired or cancelled. \
             Quit wrustic in the terminal and relaunch to start a new ceremony.",
        ));
    }

    let method = req.method().clone();
    match (method, rest) {
        (Method::GET, "") | (Method::GET, "/") => Ok(full_resp(
            StatusCode::OK,
            "text/html; charset=utf-8",
            render_html(&ctx).into_bytes(),
        )),
        (Method::POST, "/api/check-code") if ctx.phase == PasskeyPhase::Setup => {
            Ok(handle_check_setup_code(req, ctx).await)
        }
        (Method::POST, "/api/setup") if ctx.phase == PasskeyPhase::Setup => {
            Ok(handle_setup(req, ctx).await)
        }
        (Method::POST, "/api/unlock") if ctx.phase == PasskeyPhase::Unlock => {
            Ok(handle_unlock(req, ctx).await)
        }
        _ => Ok(text(StatusCode::NOT_FOUND, "not found")),
    }
}

/// Constant-time bytewise compare. The short_id is only 64 bits and the
/// server is on localhost, so the practical timing-attack surface is zero;
/// this is hygiene so a future change (e.g. binding to a non-loopback iface)
/// can't accidentally turn into a timing oracle.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

#[derive(Deserialize)]
struct SetupBody {
    credential_id: String,
    prf: String,
    /// 6-digit code printed on the TUI; the user types it in the browser
    /// before either "Create new passkey" or "Use existing passkey" can
    /// complete. Compared constant-time against `ctx.setup_code`.
    setup_code: String,
}

#[derive(Deserialize)]
struct UnlockBody {
    prf: String,
}

async fn read_body(req: Request<hyper::body::Incoming>) -> Result<Vec<u8>, std::io::Error> {
    let collected = req
        .into_body()
        .collect()
        .await
        .map_err(|e| std::io::Error::other(format!("reading body: {e}")))?;
    Ok(collected.to_bytes().to_vec())
}

fn decode_prf(b64: &str) -> Result<[u8; 32], String> {
    let raw = BASE64.decode(b64).map_err(|e| format!("invalid base64 prf: {e}"))?;
    if raw.len() != 32 {
        return Err(format!(
            "expected 32-byte PRF output, got {} bytes",
            raw.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// Result of a setup-code gate check.
enum CodeCheck {
    /// Code matched — caller may proceed.
    Ok,
    /// Code didn't match (or wasn't initialized). The pre-built response
    /// already encodes the right status, message, and any kill-switch
    /// side effects the caller should surface unchanged.
    Wrong(Response<RespBody>),
}

/// Shared setup-code gate, used by both the precheck endpoint and the
/// actual `/api/setup` route. The check is intentionally symmetric: a
/// wrong code consumes a strike either way, and exhausting the strike
/// budget trips the same `killed` flag the expiry net uses. Doing the
/// expensive WebAuthn ceremony before this check is precisely what we
/// want to avoid, hence the precheck endpoint.
fn check_setup_code(ctx: &Arc<Ctx>, submitted_raw: &str) -> CodeCheck {
    let expected = match ctx.setup_code.as_deref() {
        Some(c) => c,
        // Shouldn't happen: Setup phase always mints a code. Treat a None
        // expected code as an internal error rather than auto-accept.
        None => {
            return CodeCheck::Wrong(text(
                StatusCode::INTERNAL_SERVER_ERROR,
                "setup code not initialized",
            ));
        }
    };
    // Normalize incoming code: strip whitespace only. Case is part of
    // the code (the alphabet has both upper and lower case letters) so
    // we compare the bytes verbatim. ct_eq runs in constant time over
    // the resulting buffers; the whitespace strip operates on attacker-
    // supplied bytes only and doesn't leak anything about the secret.
    let submitted: String = submitted_raw
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if !ct_eq(submitted.as_bytes(), expected.as_bytes()) {
        let prev = ctx.setup_code_attempts.fetch_add(1, Ordering::Relaxed);
        let used = prev + 1;
        if used >= MAX_SETUP_CODE_ATTEMPTS {
            ctx.killed.store(true, Ordering::Relaxed);
            return CodeCheck::Wrong(text(
                StatusCode::FORBIDDEN,
                "Too many wrong setup codes. Ceremony cancelled — quit wrustic and relaunch.",
            ));
        }
        let remaining = MAX_SETUP_CODE_ATTEMPTS - used;
        return CodeCheck::Wrong(text(
            StatusCode::UNAUTHORIZED,
            &format!(
                "Wrong setup code. {remaining} attempt(s) left before the ceremony is cancelled."
            ),
        ));
    }
    CodeCheck::Ok
}

#[derive(Deserialize)]
struct CheckCodeBody {
    setup_code: String,
}

/// Pre-flight setup-code check: lets the browser surface a "wrong code"
/// error *before* invoking `navigator.credentials.create()` / `.get()`,
/// so a typo doesn't waste an authenticator prompt. No outcome is ever
/// delivered through this route — it only succeeds or fails. The actual
/// outcome delivery happens through `/api/setup` after the WebAuthn
/// ceremony, where the same code is re-checked (defense-in-depth: the
/// server doesn't trust "I pre-checked it" claims).
async fn handle_check_setup_code(
    req: Request<hyper::body::Incoming>,
    ctx: Arc<Ctx>,
) -> Response<RespBody> {
    let body = match read_body(req).await {
        Ok(b) => b,
        Err(e) => return text(StatusCode::BAD_REQUEST, &format!("body read: {e}")),
    };
    let parsed: CheckCodeBody = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return text(StatusCode::BAD_REQUEST, &format!("invalid JSON: {e}")),
    };
    match check_setup_code(&ctx, &parsed.setup_code) {
        CodeCheck::Ok => json_ok(),
        CodeCheck::Wrong(resp) => resp,
    }
}

async fn handle_setup(req: Request<hyper::body::Incoming>, ctx: Arc<Ctx>) -> Response<RespBody> {
    let body = match read_body(req).await {
        Ok(b) => b,
        Err(e) => return text(StatusCode::BAD_REQUEST, &format!("body read: {e}")),
    };
    let parsed: SetupBody = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return text(StatusCode::BAD_REQUEST, &format!("invalid JSON: {e}")),
    };
    // Setup-code gate: re-checked even though the browser is expected to
    // have already pre-flighted the same code via /api/check-code. The
    // server doesn't trust the client; both routes share `check_setup_code`
    // so a wrong code through either path consumes a strike from the same
    // counter, and exhausting them trips the same `killed` flag.
    match check_setup_code(&ctx, &parsed.setup_code) {
        CodeCheck::Ok => {}
        CodeCheck::Wrong(resp) => return resp,
    }
    if parsed.credential_id.is_empty() {
        return text(StatusCode::BAD_REQUEST, "credential_id required");
    }
    let key = match decode_prf(&parsed.prf) {
        Ok(k) => k,
        Err(e) => return text(StatusCode::BAD_REQUEST, &e),
    };
    let meta = PasskeyMeta {
        credential_id: parsed.credential_id,
        prf_salt: ctx.prf_salt_b64.clone(),
    };
    let outcome = PasskeyOutcome { key, new_meta: Some(meta) };
    if ctx.deliver(outcome).is_err() {
        return text(StatusCode::CONFLICT, "passkey already provided this session");
    }
    json_ok()
}

async fn handle_unlock(req: Request<hyper::body::Incoming>, ctx: Arc<Ctx>) -> Response<RespBody> {
    let body = match read_body(req).await {
        Ok(b) => b,
        Err(e) => return text(StatusCode::BAD_REQUEST, &format!("body read: {e}")),
    };
    let parsed: UnlockBody = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return text(StatusCode::BAD_REQUEST, &format!("invalid JSON: {e}")),
    };
    let key = match decode_prf(&parsed.prf) {
        Ok(k) => k,
        Err(e) => return text(StatusCode::BAD_REQUEST, &e),
    };
    let outcome = PasskeyOutcome { key, new_meta: None };
    if ctx.deliver(outcome).is_err() {
        return text(StatusCode::CONFLICT, "passkey already provided this session");
    }
    json_ok()
}

// Single-page HTML + inline JS. No external assets; the browser's built-in
// WebAuthn API does all the crypto work. The page checks navigator support
// up front and surfaces a clear error if PRF isn't returned (older browsers
// or authenticators).
fn render_html(ctx: &Ctx) -> String {
    let heading = match ctx.phase {
        PasskeyPhase::Setup => "Set up a passkey for wrustic",
        PasskeyPhase::Unlock => "Unlock wrustic with your passkey",
    };
    let explanation = match ctx.phase {
        PasskeyPhase::Setup => {
            "Choose either to create a new passkey on this device, or to use \
             an existing passkey already known to this browser (e.g. one synced \
             from another device via your password manager). wrustic uses the \
             WebAuthn PRF extension to derive an encryption key from whichever \
             passkey you pick — the key itself never leaves your device."
        }
        PasskeyPhase::Unlock => {
            "Your browser will prompt for the passkey you set up earlier. \
             wrustic re-derives the encryption key from the same passkey to \
             decrypt your config."
        }
    };
    // Setup phase shows two buttons (create vs. use existing); unlock shows
    // a single one. Each button id is wired to its own handler below, so
    // adding more options later is just another id+handler pair. The
    // "Use existing passkey" path carries a disclaimer so the user
    // understands it starts a fresh encrypted store under a new salt and
    // won't decrypt an existing wrustic config from another machine.
    // Setup-only: a 6-character code input the user must echo from the
    // TUI. Alphabet matches SETUP_CODE_ALPHABET (digits 2-9, A-Z and a-z
    // each minus I/L/O / i/l/o, plus `-` and `=`). Case-sensitive — no
    // text-transform / autocapitalize tweaks. Both Create and Use
    // Existing flows read the same input and send it along with the
    // WebAuthn result. No code on Unlock — the existing `[passkey]`
    // block + AEAD tag already prove the user knows the passkey.
    let setup_code_html = match ctx.phase {
        PasskeyPhase::Setup => {
            "<p>\
              <label for=\"setup-code\">\
                <strong>Setup code</strong> (printed in your wrustic terminal, \
                copy it exactly — letter case matters):\
              </label>\
              <br>\
              <input id=\"setup-code\" type=\"text\" autocomplete=\"off\" \
                     spellcheck=\"false\" autocapitalize=\"none\" \
                     maxlength=\"6\" \
                     pattern=\"[2-9A-HJKMNP-Za-hjkmnp-z=\\-]{6}\" \
                     style=\"font-size:1.2rem;width:8rem;\
                            font-family:ui-monospace,monospace;padding:0.4rem;\" \
                     placeholder=\"abcdef\">\
            </p>"
        }
        PasskeyPhase::Unlock => "",
    };
    let buttons_html = match ctx.phase {
        PasskeyPhase::Setup => {
            "<p>\
              <button id=\"go-create\">Create new passkey</button>\
              <button id=\"go-import\" style=\"margin-left:0.5rem\">Use existing passkey</button>\
            </p>\
            <div class=\"hint\">\
              <strong>About \"Use existing passkey\":</strong> picks a passkey already known to this \
              browser (e.g. one synced from another device via your password manager) and starts a \
              <em>fresh</em> wrustic config encrypted under that passkey plus a newly generated salt. \
              <br><br>\
              It will <strong>not</strong> decrypt an existing wrustic config you set up on another \
              machine — the salt would differ. To open an existing config from another machine, quit \
              wrustic, copy that machine's <code>config.toml</code> into this config dir, then relaunch \
              — the Unlock flow will use the salt embedded in the file.\
            </div>"
        }
        PasskeyPhase::Unlock => "<p><button id=\"go-unlock\">Unlock</button></p>",
    };

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>wrustic passkey</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 40rem; margin: 3rem auto; padding: 0 1rem; color: #222; }}
  h1 {{ font-size: 1.4rem; }}
  p  {{ line-height: 1.5; }}
  button {{ font-size: 1rem; padding: 0.5rem 1rem; cursor: pointer; }}
  #status {{ margin-top: 1rem; padding: 0.75rem; border-radius: 4px; font-family: ui-monospace, monospace; white-space: pre-wrap; }}
  .ok   {{ background: #e6ffed; color: #006400; }}
  .err  {{ background: #ffecec; color: #800; }}
  .note {{ background: #f6f6f6; color: #444; }}
  .hint {{ background: #fff7e0; color: #664d03; border-left: 3px solid #d4a017; padding: 0.65rem 0.9rem; margin-top: 0.5rem; line-height: 1.5; border-radius: 3px; }}
  .hint strong {{ color: #5a3d00; }}
  small {{ color: #666; }}
</style>
</head>
<body>
<h1>{heading}</h1>
<p>{explanation}</p>
{setup_code_html}
{buttons_html}
<div id="status" class="note">Click a button above to begin.</div>
<p><small>This page is served by the wrustic process on localhost. You can close it when finished.</small></p>
<script>
const PRF_SALT_B64 = {prf_salt_js};
const CRED_ID_B64 = {cred_id_js};
// The page itself is served at /auth/<key>, so derive the API prefix from
// the browser's own URL — no template substitution needed, and the entire
// ceremony stays scoped to this one keyed path. The trailing-slash strip
// lets the user accept either /auth/<key> or /auth/<key>/.
const API_BASE = window.location.pathname.replace(/\/$/, "");

function b64ToBytes(b64) {{
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}}
function bytesToB64(bytes) {{
  let bin = "";
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin);
}}
function setStatus(text, kind) {{
  const el = document.getElementById("status");
  el.textContent = text;
  el.className = kind || "note";
}}

// Setup phase only: read the 6-character code the user typed from the
// TUI. Throws early (before any authenticator prompt) if it's missing
// or the wrong shape. Case-sensitive: the alphabet includes both upper
// and lower case letters, so the server compares the bytes verbatim.
// We do strip whitespace so a stray space doesn't blow the compare.
function readSetupCode() {{
  const el = document.getElementById("setup-code");
  if (!el) return null;
  const code = (el.value || "").replace(/\s+/g, "");
  if (!/^[2-9A-HJKMNP-Za-hjkmnp-z=\-]{{6}}$/.test(code)) {{
    throw new Error("Enter the 6-character setup code from your wrustic terminal (letter case matters).");
  }}
  return code;
}}

// Pre-flight the setup code with the server before doing anything that
// requires user interaction (i.e. the authenticator prompt). On wrong
// code the user gets the server's error message immediately, with no
// authenticator dance to back out of. On match this returns silently
// and the caller proceeds. The server re-validates the same code on
// /api/setup as belt-and-braces.
async function precheckSetupCode(code) {{
  const r = await fetch(API_BASE + "/api/check-code", {{
    method: "POST",
    headers: {{ "Content-Type": "application/json" }},
    body: JSON.stringify({{ setup_code: code }})
  }});
  if (!r.ok) throw new Error("Server: " + (await r.text()));
}}

// Create a brand-new passkey on this device and use its PRF output as the
// encryption key. Some platform authenticators don't return PRF during
// create(), so we fall back to a follow-up get() with the same credential.
async function doCreate() {{
  // Validate the setup code first — bail before triggering an
  // authenticator prompt. Client-side regex check first, then a server
  // round-trip so a wrong code surfaces immediately (instead of after
  // the user has authenticated and we're committing the result).
  const setupCode = readSetupCode();
  await precheckSetupCode(setupCode);
  const prfSalt = b64ToBytes(PRF_SALT_B64);
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const cred = await navigator.credentials.create({{
    publicKey: {{
      rp: {{ name: "wrustic" }},
      user: {{ id: userId, name: "wrustic", displayName: "wrustic" }},
      challenge,
      pubKeyCredParams: [
        {{ type: "public-key", alg: -7 }},
        {{ type: "public-key", alg: -257 }}
      ],
      authenticatorSelection: {{
        residentKey: "preferred",
        userVerification: "preferred"
      }},
      extensions: {{ prf: {{ eval: {{ first: prfSalt }} }} }}
    }}
  }});
  if (!cred) throw new Error("Authenticator did not return a credential");
  const credId = new Uint8Array(cred.rawId);
  let prf = cred.getClientExtensionResults().prf;
  let prfOutput = prf && prf.results && prf.results.first;
  if (!prfOutput) {{
    const challenge2 = crypto.getRandomValues(new Uint8Array(32));
    const assert = await navigator.credentials.get({{
      publicKey: {{
        challenge: challenge2,
        allowCredentials: [{{ type: "public-key", id: credId }}],
        userVerification: "preferred",
        extensions: {{ prf: {{ eval: {{ first: prfSalt }} }} }}
      }}
    }});
    prf = assert.getClientExtensionResults().prf;
    prfOutput = prf && prf.results && prf.results.first;
  }}
  if (!prfOutput) {{
    throw new Error("Authenticator did not return a PRF output. wrustic's experimental passkey mode requires WebAuthn PRF (hmac-secret) support.");
  }}
  await postSetup(credId, prfOutput, setupCode);
}}

// Reuse an existing passkey already known to the browser (e.g. synced via
// the user's password manager). No `allowCredentials` so the browser shows
// the user every passkey valid for this origin and they pick one.
async function doImportExisting() {{
  // Validate the setup code first — same reasoning as doCreate().
  const setupCode = readSetupCode();
  await precheckSetupCode(setupCode);
  const prfSalt = b64ToBytes(PRF_SALT_B64);
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const assert = await navigator.credentials.get({{
    publicKey: {{
      challenge,
      userVerification: "preferred",
      extensions: {{ prf: {{ eval: {{ first: prfSalt }} }} }}
    }}
  }});
  if (!assert) throw new Error("Authenticator did not return a credential");
  const credId = new Uint8Array(assert.rawId);
  const prf = assert.getClientExtensionResults().prf;
  const prfOutput = prf && prf.results && prf.results.first;
  if (!prfOutput) {{
    throw new Error("The selected passkey did not return a PRF output. wrustic requires a passkey created with WebAuthn PRF (hmac-secret) support.");
  }}
  await postSetup(credId, prfOutput, setupCode);
}}

async function postSetup(credId, prfOutput, setupCode) {{
  const r = await fetch(API_BASE + "/api/setup", {{
    method: "POST",
    headers: {{ "Content-Type": "application/json" }},
    body: JSON.stringify({{
      credential_id: bytesToB64(credId),
      prf: bytesToB64(prfOutput),
      setup_code: setupCode
    }})
  }});
  if (!r.ok) throw new Error("Server: " + (await r.text()));
}}

async function doUnlock() {{
  const prfSalt = b64ToBytes(PRF_SALT_B64);
  const credId = b64ToBytes(CRED_ID_B64);
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const assert = await navigator.credentials.get({{
    publicKey: {{
      challenge,
      allowCredentials: [{{ type: "public-key", id: credId }}],
      userVerification: "preferred",
      extensions: {{ prf: {{ eval: {{ first: prfSalt }} }} }}
    }}
  }});
  const prf = assert.getClientExtensionResults().prf;
  const prfOutput = prf && prf.results && prf.results.first;
  if (!prfOutput) {{
    throw new Error("Authenticator did not return a PRF output. The passkey may have been created without PRF support.");
  }}
  const r = await fetch(API_BASE + "/api/unlock", {{
    method: "POST",
    headers: {{ "Content-Type": "application/json" }},
    body: JSON.stringify({{ prf: bytesToB64(prfOutput) }})
  }});
  if (!r.ok) throw new Error("Server: " + (await r.text()));
}}

// After a successful ceremony the server has already received what it
// needs; a second click would just hit /api/setup or /api/unlock again
// (server returns 409 "already provided this session") and risk the user
// re-prompting the authenticator for no reason. Visually disable every
// button so the page reads as terminal-state.
function disableAllCtas() {{
  document.querySelectorAll("button").forEach(b => {{
    b.disabled = true;
    b.style.opacity = "0.5";
    b.style.cursor = "not-allowed";
  }});
}}

function wireButton(id, fn) {{
  const el = document.getElementById(id);
  if (!el) return;
  el.addEventListener("click", async () => {{
    if (!window.PublicKeyCredential) {{
      setStatus("This browser does not support WebAuthn.", "err");
      return;
    }}
    setStatus("Waiting for the authenticator…", "note");
    try {{
      await fn();
      setStatus("Done. You can close this tab and return to the wrustic terminal.", "ok");
      disableAllCtas();
    }} catch (e) {{
      setStatus("Error: " + (e && e.message ? e.message : e), "err");
    }}
  }});
}}
wireButton("go-create", doCreate);
wireButton("go-import", doImportExisting);
wireButton("go-unlock", doUnlock);
</script>
</body>
</html>
"#,
        heading = heading,
        explanation = explanation,
        setup_code_html = setup_code_html,
        buttons_html = buttons_html,
        prf_salt_js = json_string(&ctx.prf_salt_b64),
        cred_id_js = json_string(&ctx.credential_id_b64),
    )
}

// Minimal JSON string escaper for embedding ASCII base64/short identifiers
// into inline JS. Only escapes the characters that matter for the contexts
// we use (strings without control bytes or unicode).
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write;
                write!(out, "\\u{:04x}", c as u32).unwrap();
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Derive an HMAC-SHA256 signing key (32 bytes) from arbitrary input bytes.
/// Used for the share dialog in passkey mode — share.rs's HMAC signing key
/// is normally derived from the age.key file; in passkey mode we don't have
/// one, so we hash the PRF output instead.
pub(crate) fn derive_share_signing_key(seed: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"wrustic-share-v1\0");
    hasher.update(seed);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_string_escapes_quotes_and_backslashes() {
        assert_eq!(json_string("abc"), "\"abc\"");
        assert_eq!(json_string("a\"b"), "\"a\\\"b\"");
        assert_eq!(json_string("a\\b"), "\"a\\\\b\"");
        assert_eq!(json_string("a\nb"), "\"a\\nb\"");
    }

    #[test]
    fn derive_share_key_is_stable() {
        let a = derive_share_signing_key(&[0x11u8; 32]);
        let b = derive_share_signing_key(&[0x11u8; 32]);
        let c = derive_share_signing_key(&[0x22u8; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn decode_prf_rejects_wrong_length() {
        assert!(decode_prf("AAAA").is_err());
        // 32 bytes encoded in base64 is 44 chars; 16 bytes is 24 chars.
        let short = BASE64.encode([0u8; 16]);
        assert!(decode_prf(&short).is_err());
        let exact = BASE64.encode([0u8; 32]);
        assert!(decode_prf(&exact).is_ok());
    }

    fn test_ctx(phase: PasskeyPhase, setup_code: Option<&str>) -> Ctx {
        Ctx {
            phase,
            short_id: "abc123".into(),
            prf_salt_b64: "U0FMVA==".into(),
            credential_id_b64: match phase {
                PasskeyPhase::Unlock => "Q1JFRA==".into(),
                PasskeyPhase::Setup => String::new(),
            },
            setup_code: setup_code.map(|s| s.into()),
            setup_code_attempts: AtomicU32::new(0),
            killed: AtomicBool::new(false),
            outcome_tx: std::sync::Mutex::new(None),
            deadline: Instant::now() + PASSKEY_TTL,
        }
    }

    #[test]
    fn html_setup_offers_create_and_import_buttons() {
        let ctx = test_ctx(PasskeyPhase::Setup, Some("AB-23K"));
        let html = render_html(&ctx);
        assert!(html.contains("Set up a passkey"));
        assert!(html.contains("U0FMVA=="));
        assert!(html.contains(r#"id="go-create""#));
        assert!(html.contains(r#"id="go-import""#));
        assert!(!html.contains(r#"id="go-unlock""#));
        // The disclaimer for "Use existing passkey" must be present in
        // Setup so the user knows the new salt won't match another
        // machine's config.
        assert!(html.contains("Use existing passkey"));
        assert!(html.contains("class=\"hint\""));
        assert!(html.contains("salt would differ"));
        assert!(html.contains("config.toml"));
        // Success must disable all CTAs so the user can't re-trigger.
        assert!(html.contains("disableAllCtas"));
        // Setup-code input must be present in Setup phase.
        assert!(html.contains(r#"id="setup-code""#));
        assert!(html.contains("Setup code"));
    }

    #[test]
    fn html_unlock_offers_only_unlock_button() {
        let ctx = test_ctx(PasskeyPhase::Unlock, None);
        let html = render_html(&ctx);
        assert!(html.contains("Unlock wrustic"));
        assert!(html.contains("Q1JFRA=="));
        assert!(html.contains(r#"id="go-unlock""#));
        assert!(!html.contains(r#"id="go-create""#));
        assert!(!html.contains(r#"id="go-import""#));
        // Disclaimer is Setup-only.
        assert!(!html.contains("class=\"hint\""));
        // Setup-code input must not appear in Unlock phase.
        assert!(!html.contains(r#"id="setup-code""#));
    }

    #[test]
    fn setup_code_alphabet_is_unambiguous() {
        // Generated codes must only use SETUP_CODE_ALPHABET characters.
        for _ in 0..32 {
            let code = random_setup_code();
            assert_eq!(code.chars().count(), SETUP_CODE_LEN);
            for c in code.chars() {
                assert!(
                    SETUP_CODE_ALPHABET.contains(&(c as u8)),
                    "char {c:?} not in alphabet"
                );
            }
        }
        // Sanity-check the alphabet excludes the well-known confusables
        // and the period (replaced by `=` because periods read poorly in
        // a TUI font).
        let bad = b"01ILOilo.";
        for b in bad {
            assert!(
                !SETUP_CODE_ALPHABET.contains(b),
                "alphabet should not contain {:?}",
                *b as char
            );
        }
        // Spot-check that both `-` and `=` made it in (the symbol set is
        // exactly these two).
        assert!(SETUP_CODE_ALPHABET.contains(&b'-'));
        assert!(SETUP_CODE_ALPHABET.contains(&b'='));
        // And that both upper and lower case made it in.
        assert!(SETUP_CODE_ALPHABET.contains(&b'A'));
        assert!(SETUP_CODE_ALPHABET.contains(&b'a'));
        assert!(SETUP_CODE_ALPHABET.contains(&b'Z'));
        assert!(SETUP_CODE_ALPHABET.contains(&b'z'));
    }

    fn assert_send<T: Send>() {}

    #[test]
    fn handle_is_send() {
        // PasskeyHandle crosses thread boundaries (held inside App).
        assert_send::<PasskeyHandle>();
    }

    // The HTTP route guard at the top of handle() is the one-liner
    // `Instant::now() >= ctx.deadline`. We don't fabricate a hyper
    // Incoming body for an integration test; instead verify the same
    // predicate via PasskeyHandle::is_expired(), and trust the guard.
    #[test]
    fn is_expired_predicate() {
        // Mock a handle with an already-past deadline. The other fields
        // need to be valid enough to construct PasskeyHandle.
        let (_tx, rx) = std_mpsc::channel::<PasskeyOutcome>();
        let (shutdown_tx, _shutdown_rx) = oneshot::channel::<()>();
        let h = PasskeyHandle {
            short_url: String::new(),
            setup_code: None,
            phase: PasskeyPhase::Setup,
            rx,
            deadline: Instant::now() - Duration::from_secs(1),
            shutdown_tx: Some(shutdown_tx),
            join_handle: None,
        };
        assert!(h.is_expired());

        let (_tx, rx) = std_mpsc::channel::<PasskeyOutcome>();
        let (shutdown_tx, _shutdown_rx) = oneshot::channel::<()>();
        let h2 = PasskeyHandle {
            short_url: String::new(),
            setup_code: None,
            phase: PasskeyPhase::Setup,
            rx,
            deadline: Instant::now() + Duration::from_secs(60),
            shutdown_tx: Some(shutdown_tx),
            join_handle: None,
        };
        assert!(!h2.is_expired());
    }

    #[test]
    fn ct_eq_basics() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(!ct_eq(b"", b"x"));
    }

    /// Bind to an ephemeral port to avoid colliding with anything on 7834
    /// while the test runs.
    fn ephemeral_port() -> u16 {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        port
    }

    /// Send a raw HTTP/1.0 request (forces connection-close, so
    /// `read_to_end` won't hang) and return the full response as a string.
    fn raw_request(port: u16, method: &str, path: &str) -> String {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let req = format!(
            "{method} {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n"
        );
        sock.write_all(req.as_bytes()).unwrap();
        let mut resp = Vec::new();
        sock.read_to_end(&mut resp).unwrap();
        String::from_utf8_lossy(&resp).into_owned()
    }

    /// Variant of `raw_request` that ships a JSON body.
    fn raw_post_json(port: u16, path: &str, body: &str) -> String {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let req = format!(
            "POST {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {len}\r\n\r\n{body}",
            len = body.len(),
            body = body,
        );
        sock.write_all(req.as_bytes()).unwrap();
        let mut resp = Vec::new();
        sock.read_to_end(&mut resp).unwrap();
        String::from_utf8_lossy(&resp).into_owned()
    }

    /// Pull the 16-hex auth key out of the handle's `http://localhost:<port>/auth/<key>` URL.
    fn key_from_handle(h: &PasskeyHandle) -> String {
        h.short_url.rsplit('/').next().unwrap().to_string()
    }

    /// End-to-end check that the only reachable surface is `/auth/<key>` and
    /// its `/api/*` children. Everything else — bare `/`, wrong key, right
    /// key + wrong path, the old unkeyed `/api/*` routes — must 404. The
    /// keyed root must serve 200 + HTML.
    #[test]
    fn routing_only_serves_under_correct_auth_key() {
        let port = ephemeral_port();
        let handle = start(port, PasskeyPhase::Setup, None).expect("start server");
        let key = key_from_handle(&handle);

        // Unkeyed paths — every shape gets the same flat 404.
        for (m, p) in [
            ("GET", "/"),
            ("GET", "/auth"),
            ("GET", "/auth/"),
            ("GET", "/auth/deadbeefdeadbeef"),
            ("GET", "/api/setup"),
            ("POST", "/api/setup"),
            ("POST", "/api/unlock"),
            ("POST", "/auth/deadbeefdeadbeef/api/setup"),
        ] {
            let r = raw_request(port, m, p);
            assert!(r.contains(" 404 "), "expected 404 for {m} {p}, got:\n{r}");
        }

        // Wrong-key prefixes never reveal whether the API exists: they 404
        // before even hitting the dispatch table (so an attacker can't
        // distinguish "wrong key" from "wrong route"). We assert no 302 / 200
        // ever leaks out for a bad key.
        let r = raw_request(port, "GET", "/auth/deadbeefdeadbeef");
        assert!(!r.contains(" 200 "), "wrong key must not 200");
        assert!(!r.contains(" 302 "), "wrong key must not redirect");

        // Correct key, root → 200 + the inline HTML.
        let keyed = format!("/auth/{key}");
        let r = raw_request(port, "GET", &keyed);
        assert!(r.contains(" 200 "), "GET {keyed} should 200, got:\n{r}");
        assert!(
            r.contains("<!doctype html>") || r.contains("<!DOCTYPE html>"),
            "should contain HTML doctype"
        );
        // The HTML must carry the per-page Setup markers (we started in Setup
        // phase) so we know we're actually serving the ceremony page.
        assert!(r.contains(r#"id="go-create""#));

        // Correct key with a trailing slash also reaches the HTML (the JS
        // strips the trailing slash too).
        let keyed_slash = format!("/auth/{key}/");
        let r = raw_request(port, "GET", &keyed_slash);
        assert!(r.contains(" 200 "), "GET {keyed_slash} should 200, got:\n{r}");

        // Correct key + an unknown subpath still 404s.
        let r = raw_request(port, "GET", &format!("/auth/{key}/whatever"));
        assert!(r.contains(" 404 "));

        // /api/setup is the right phase route, but Setup expects a body —
        // we send Content-Length: 0, so the JSON parser inside handle_setup
        // will reject with 400. The point of this assertion is just that
        // the gate forwarded the request (i.e. we got past the 404 wall).
        let r = raw_request(port, "POST", &format!("/auth/{key}/api/setup"));
        assert!(
            r.contains(" 400 ") || r.contains(" 200 "),
            "POST {key}/api/setup should reach the handler (400 from empty body), got:\n{r}"
        );

        handle.stop();
    }

    /// 32-byte base64 PRF that's well-formed enough to pass `decode_prf`
    /// — used as filler so the test reaches the setup_code branch.
    fn dummy_prf_b64() -> String {
        BASE64.encode([0u8; 32])
    }

    #[test]
    fn setup_code_wrong_returns_401_and_doesnt_deliver() {
        let port = ephemeral_port();
        let handle = start(port, PasskeyPhase::Setup, None).expect("start server");
        let key = key_from_handle(&handle);
        let setup_code = handle.setup_code.clone().expect("Setup phase mints a code");
        let path = format!("/auth/{key}/api/setup");
        let prf = dummy_prf_b64();

        // Wrong code: deliberately mutate the real one so it stays in the
        // alphabet but differs. Flip the first character to the next one
        // in the alphabet (wrapping).
        let mut bad_chars: Vec<u8> = setup_code.as_bytes().to_vec();
        let pos = SETUP_CODE_ALPHABET
            .iter()
            .position(|&b| b == bad_chars[0])
            .unwrap();
        bad_chars[0] = SETUP_CODE_ALPHABET[(pos + 1) % SETUP_CODE_ALPHABET.len()];
        let bad = String::from_utf8(bad_chars).unwrap();

        let body = format!(
            r#"{{"credential_id":"Y3JlZA==","prf":"{prf}","setup_code":"{bad}"}}"#
        );
        let r = raw_post_json(port, &path, &body);
        assert!(r.contains(" 401 "), "wrong code should 401, got:\n{r}");
        assert!(r.to_lowercase().contains("setup code"));

        // No outcome should have been delivered — try_recv must be empty.
        match handle.rx.try_recv() {
            Err(std_mpsc::TryRecvError::Empty) => {}
            Ok(_) => panic!("no outcome should be delivered on wrong code"),
            Err(other) => panic!("unexpected channel state: {other:?}"),
        }
        handle.stop();
    }

    #[test]
    fn setup_code_correct_reaches_outcome_delivery() {
        let port = ephemeral_port();
        let handle = start(port, PasskeyPhase::Setup, None).expect("start server");
        let key = key_from_handle(&handle);
        let setup_code = handle.setup_code.clone().expect("Setup phase mints a code");
        let path = format!("/auth/{key}/api/setup");
        let prf = dummy_prf_b64();

        let body = format!(
            r#"{{"credential_id":"Y3JlZA==","prf":"{prf}","setup_code":"{setup_code}"}}"#
        );
        let r = raw_post_json(port, &path, &body);
        // Right code + well-formed body → 200 and outcome delivered.
        assert!(r.contains(" 200 "), "correct code should 200, got:\n{r}");

        let outcome = handle.rx.recv_timeout(Duration::from_secs(2)).expect("outcome");
        assert_eq!(outcome.key, [0u8; 32]);
        assert!(outcome.new_meta.is_some());
        handle.stop();
    }

    #[test]
    fn setup_code_accepts_whitespace_padding() {
        let port = ephemeral_port();
        let handle = start(port, PasskeyPhase::Setup, None).expect("start server");
        let key = key_from_handle(&handle);
        let setup_code = handle.setup_code.clone().unwrap();
        let path = format!("/auth/{key}/api/setup");
        let prf = dummy_prf_b64();

        // Pad with whitespace — server strips it before comparing. Case
        // is *not* normalized (the alphabet has both upper and lower)
        // so we keep the code byte-identical otherwise.
        let munged: String = format!(" {setup_code} ");
        let body = format!(
            r#"{{"credential_id":"Y3JlZA==","prf":"{prf}","setup_code":"{munged}"}}"#
        );
        let r = raw_post_json(port, &path, &body);
        assert!(
            r.contains(" 200 "),
            "whitespace-tolerant compare should accept, got:\n{r}"
        );
        let outcome = handle.rx.recv_timeout(Duration::from_secs(2)).expect("outcome");
        assert!(outcome.new_meta.is_some());
        handle.stop();
    }

    #[test]
    fn setup_code_case_mismatch_is_rejected() {
        // A code typed with the wrong case should NOT be accepted — the
        // alphabet treats upper and lower as distinct.
        let port = ephemeral_port();
        let handle = start(port, PasskeyPhase::Setup, None).expect("start server");
        let key = key_from_handle(&handle);
        let setup_code = handle.setup_code.clone().unwrap();
        let path = format!("/auth/{key}/api/setup");
        let prf = dummy_prf_b64();

        // Build a flipped-case version of the real code. If the code has
        // no letters (purely digits and symbols), skip the assertion —
        // there's nothing to flip.
        let flipped: String = setup_code
            .chars()
            .map(|c| {
                if c.is_ascii_uppercase() {
                    c.to_ascii_lowercase()
                } else if c.is_ascii_lowercase() {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect();
        if flipped == setup_code {
            // No letters in the code; the case-mismatch test isn't
            // meaningful. Skip cleanly.
            handle.stop();
            return;
        }

        let body = format!(
            r#"{{"credential_id":"Y3JlZA==","prf":"{prf}","setup_code":"{flipped}"}}"#
        );
        let r = raw_post_json(port, &path, &body);
        assert!(r.contains(" 401 "), "case-flipped code should 401, got:\n{r}");
        handle.stop();
    }

    #[test]
    fn precheck_accepts_correct_code_without_delivering_outcome() {
        let port = ephemeral_port();
        let handle = start(port, PasskeyPhase::Setup, None).expect("start server");
        let key = key_from_handle(&handle);
        let setup_code = handle.setup_code.clone().unwrap();
        let path = format!("/auth/{key}/api/check-code");

        let body = format!(r#"{{"setup_code":"{setup_code}"}}"#);
        let r = raw_post_json(port, &path, &body);
        assert!(r.contains(" 200 "), "correct code should 200, got:\n{r}");

        // Precheck must NOT deliver an outcome — that only happens via
        // /api/setup after the WebAuthn dance.
        match handle.rx.try_recv() {
            Err(std_mpsc::TryRecvError::Empty) => {}
            Ok(_) => panic!("precheck must not deliver an outcome"),
            Err(other) => panic!("unexpected channel state: {other:?}"),
        }
        handle.stop();
    }

    #[test]
    fn precheck_wrong_code_returns_401() {
        let port = ephemeral_port();
        let handle = start(port, PasskeyPhase::Setup, None).expect("start server");
        let key = key_from_handle(&handle);
        let real = handle.setup_code.clone().unwrap();
        let path = format!("/auth/{key}/api/check-code");

        // Flip first character to a different valid-alphabet char.
        let mut bad_chars: Vec<u8> = real.as_bytes().to_vec();
        let pos = SETUP_CODE_ALPHABET
            .iter()
            .position(|&b| b == bad_chars[0])
            .unwrap();
        bad_chars[0] = SETUP_CODE_ALPHABET[(pos + 1) % SETUP_CODE_ALPHABET.len()];
        let bad = String::from_utf8(bad_chars).unwrap();

        let body = format!(r#"{{"setup_code":"{bad}"}}"#);
        let r = raw_post_json(port, &path, &body);
        assert!(r.contains(" 401 "), "wrong precheck should 401, got:\n{r}");
        handle.stop();
    }

    #[test]
    fn precheck_strikes_share_counter_with_setup() {
        // Mixed sequence: 4 wrong prechecks plus 1 wrong setup should
        // total 5 strikes and trip the kill switch. This pins down that
        // both routes consume from the same `setup_code_attempts`
        // counter — important so an attacker can't double the budget by
        // alternating endpoints.
        let port = ephemeral_port();
        let handle = start(port, PasskeyPhase::Setup, None).expect("start server");
        let key = key_from_handle(&handle);
        let real = handle.setup_code.clone().unwrap();
        let prf = dummy_prf_b64();

        let mut wrong = "------".to_string();
        if wrong == real {
            wrong = "======".into();
        }

        // 4 wrong prechecks.
        for _ in 0..4 {
            let body = format!(r#"{{"setup_code":"{wrong}"}}"#);
            let r = raw_post_json(port, &format!("/auth/{key}/api/check-code"), &body);
            assert!(r.contains(" 401 "), "precheck strike should 401, got:\n{r}");
        }

        // 5th strike via /api/setup must trip the kill switch.
        let body = format!(
            r#"{{"credential_id":"Y3JlZA==","prf":"{prf}","setup_code":"{wrong}"}}"#
        );
        let r = raw_post_json(port, &format!("/auth/{key}/api/setup"), &body);
        assert!(r.contains(" 403 "), "5th strike should 403, got:\n{r}");

        // And subsequent requests of any shape stay 403.
        let r = raw_post_json(
            port,
            &format!("/auth/{key}/api/check-code"),
            &format!(r#"{{"setup_code":"{real}"}}"#),
        );
        assert!(r.contains(" 403 "), "post-kill precheck must 403, got:\n{r}");

        handle.stop();
    }

    #[test]
    fn precheck_unavailable_in_unlock_phase() {
        // Unlock has no setup code, so the precheck route must not
        // exist for it (would 404 just like any non-Setup endpoint).
        let port = ephemeral_port();
        let meta = PasskeyMeta {
            credential_id: "Y3JlZA==".into(),
            prf_salt: "U0FMVA==".into(),
        };
        let handle =
            start(port, PasskeyPhase::Unlock, Some(meta)).expect("start unlock server");
        let key = key_from_handle(&handle);
        let r = raw_post_json(
            port,
            &format!("/auth/{key}/api/check-code"),
            r#"{"setup_code":"Ab2Rt="}"#,
        );
        assert!(r.contains(" 404 "), "precheck must 404 in Unlock, got:\n{r}");
        handle.stop();
    }

    #[test]
    fn setup_code_five_strikes_kills_ceremony() {
        let port = ephemeral_port();
        let handle = start(port, PasskeyPhase::Setup, None).expect("start server");
        let key = key_from_handle(&handle);
        let real = handle.setup_code.clone().unwrap();
        let path = format!("/auth/{key}/api/setup");
        let prf = dummy_prf_b64();

        // Use a wrong code that is guaranteed not to equal the real one.
        // Both "------" and "======" are 6-char strings of in-alphabet
        // chars; the real code colliding with either is overwhelmingly
        // unlikely, but be defensive and rotate.
        let mut wrong = "------".to_string();
        if wrong == real {
            wrong = "======".into();
        }

        for i in 1..=MAX_SETUP_CODE_ATTEMPTS {
            let body = format!(
                r#"{{"credential_id":"Y3JlZA==","prf":"{prf}","setup_code":"{wrong}"}}"#
            );
            let r = raw_post_json(port, &path, &body);
            if i < MAX_SETUP_CODE_ATTEMPTS {
                assert!(r.contains(" 401 "), "strike {i} should 401, got:\n{r}");
            } else {
                assert!(r.contains(" 403 "), "final strike should 403, got:\n{r}");
            }
        }

        // After the kill switch trips, every subsequent request (even
        // through the right key) must 403 from the expiry/killed guard.
        let r = raw_request(port, "GET", &format!("/auth/{key}"));
        assert!(r.contains(" 403 "), "post-kill requests must 403, got:\n{r}");

        // Even the correct code is no longer accepted.
        let body = format!(
            r#"{{"credential_id":"Y3JlZA==","prf":"{prf}","setup_code":"{real}"}}"#
        );
        let r = raw_post_json(port, &path, &body);
        assert!(r.contains(" 403 "), "correct code post-kill must 403, got:\n{r}");

        handle.stop();
    }
}
