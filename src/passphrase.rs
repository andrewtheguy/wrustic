use std::convert::Infallible;
use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc as std_mpsc;
use std::thread;
use std::time::{Duration, Instant};

use aes_gcm::{Aes256Gcm, Nonce, aead::Aead, KeyInit as AesKeyInit};
use anyhow::{Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use bytes::Bytes;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE, HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use sha2::Sha256;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

use crate::config::PassphraseMeta;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PassphrasePhase {
    Setup,
    Unlock,
}

pub(crate) const PASSPHRASE_TTL: Duration = Duration::from_secs(30 * 60);

const MAX_SETUP_CODE_ATTEMPTS: u32 = 5;
const SETUP_CODE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";
const SETUP_CODE_LEN: usize = 6;

pub(crate) struct PassphraseOutcome {
    pub(crate) key: [u8; 32],
    pub(crate) new_meta: Option<PassphraseMeta>,
}

pub(crate) struct PassphraseHandle {
    pub(crate) short_url: String,
    pub(crate) setup_code: Option<String>,
    pub(crate) phase: PassphrasePhase,
    pub(crate) rx: std_mpsc::Receiver<PassphraseOutcome>,
    pub(crate) deadline: Instant,
    #[allow(dead_code)]
    pub(crate) transport_public_b64: String,
    shutdown_tx: Option<oneshot::Sender<()>>,
    join_handle: Option<thread::JoinHandle<()>>,
}

impl PassphraseHandle {
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

impl Drop for PassphraseHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

fn random_short_id() -> Result<String> {
    let buf = random_bytes(8)?;
    let mut s = String::with_capacity(16);
    use std::fmt::Write;
    for b in &buf {
        write!(s, "{b:02x}").unwrap();
    }
    Ok(s)
}

fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| anyhow!("opening /dev/urandom: {e}"))?;
    f.read_exact(&mut buf)
        .map_err(|e| anyhow!("reading /dev/urandom: {e}"))?;
    Ok(buf)
}

fn random_setup_code() -> String {
    let mut buf = [0u8; SETUP_CODE_LEN];
    let filled = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok();
    if !filled {
        use std::time::{SystemTime, UNIX_EPOCH};
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

const TRANSPORT_HKDF_INFO: &[u8] = b"wrustic-passphrase-transport-v1";
const TRANSPORT_NONCE_LEN: usize = 12;

struct ServerTransport {
    private: X25519Secret,
    public_b64: String,
}

impl ServerTransport {
    fn generate() -> Result<Self> {
        let bytes = random_bytes(32)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let private = X25519Secret::from(arr);
        let public = X25519Public::from(&private);
        let public_b64 = BASE64.encode(public.as_bytes());
        Ok(Self { private, public_b64 })
    }

    fn decrypt(&self, env: &Envelope) -> Result<Vec<u8>, EnvelopeError> {
        let client_pub_bytes = BASE64
            .decode(&env.client_pub)
            .map_err(|_| EnvelopeError::BadBase64("client_pub"))?;
        let client_pub_arr: [u8; 32] = client_pub_bytes
            .as_slice()
            .try_into()
            .map_err(|_| EnvelopeError::BadLength("client_pub", 32))?;
        let client_pub = X25519Public::from(client_pub_arr);
        let shared = self.private.diffie_hellman(&client_pub);
        let hkdf = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut key = [0u8; 32];
        hkdf.expand(TRANSPORT_HKDF_INFO, &mut key)
            .map_err(|_| EnvelopeError::Hkdf)?;
        let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&key));
        let nonce_bytes = BASE64
            .decode(&env.nonce)
            .map_err(|_| EnvelopeError::BadBase64("nonce"))?;
        if nonce_bytes.len() != TRANSPORT_NONCE_LEN {
            return Err(EnvelopeError::BadLength("nonce", TRANSPORT_NONCE_LEN));
        }
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = BASE64
            .decode(&env.ciphertext)
            .map_err(|_| EnvelopeError::BadBase64("ciphertext"))?;
        cipher
            .decrypt(nonce, ct.as_ref())
            .map_err(|_| EnvelopeError::Aead)
    }
}

#[derive(Deserialize)]
struct Envelope {
    client_pub: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Debug)]
enum EnvelopeError {
    BadBase64(&'static str),
    BadLength(&'static str, usize),
    Hkdf,
    Aead,
}

impl EnvelopeError {
    fn http_response(&self) -> Response<RespBody> {
        let msg = match self {
            EnvelopeError::BadBase64(field) => {
                format!("{field}: invalid base64")
            }
            EnvelopeError::BadLength(field, expected) => {
                format!("{field}: expected {expected} bytes")
            }
            EnvelopeError::Hkdf => "transport key derivation failed".into(),
            EnvelopeError::Aead => "transport decrypt failed (wrong key or tampered ciphertext)".into(),
        };
        text(StatusCode::BAD_REQUEST, &msg)
    }
}

struct Ctx {
    phase: PassphrasePhase,
    short_id: String,
    path_prefix: &'static str,
    subdomain: String,
    salt_b64: String,
    expected_subdomain_sig: Option<String>,
    expected_host: String,
    setup_code: Option<String>,
    setup_code_attempts: AtomicU32,
    killed: AtomicBool,
    outcome_tx: std::sync::Mutex<Option<std_mpsc::Sender<PassphraseOutcome>>>,
    deadline: Instant,
    transport: ServerTransport,
    script_nonce: String,
}

impl Ctx {
    fn deliver(&self, outcome: PassphraseOutcome) -> Result<(), &'static str> {
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
    phase: PassphrasePhase,
    existing: Option<PassphraseMeta>,
    subdomain: &str,
) -> Result<PassphraseHandle> {
    let listener_std = std::net::TcpListener::bind(("127.0.0.1", port))
        .map_err(|e| anyhow!("bind 127.0.0.1:{port}: {e}"))?;
    listener_std
        .set_nonblocking(true)
        .map_err(|e| anyhow!("set_nonblocking: {e}"))?;

    let (salt_b64, expected_subdomain_sig) = match phase {
        PassphrasePhase::Setup => {
            let salt = random_bytes(32)?;
            (BASE64.encode(&salt), None)
        }
        PassphrasePhase::Unlock => {
            let meta = existing
                .ok_or_else(|| anyhow!("unlock phase requires existing passphrase metadata"))?;
            (meta.salt, Some(meta.subdomain_sig))
        }
    };

    let short_id = random_short_id()?;
    let path_prefix = match phase {
        PassphrasePhase::Setup => "setup",
        PassphrasePhase::Unlock => "auth",
    };
    let short_url = format!("http://{subdomain}.wrustic.localhost:{port}/{path_prefix}/{short_id}");

    let setup_code = match phase {
        PassphrasePhase::Setup => Some(random_setup_code()),
        PassphrasePhase::Unlock => None,
    };

    let (outcome_tx, outcome_rx) = std_mpsc::channel::<PassphraseOutcome>();
    let deadline = Instant::now() + PASSPHRASE_TTL;
    let transport = ServerTransport::generate()?;
    let script_nonce = BASE64.encode(random_bytes(16)?);

    let expected_host = format!("{subdomain}.wrustic.localhost");

    let ctx = Arc::new(Ctx {
        phase,
        short_id,
        path_prefix,
        subdomain: subdomain.to_string(),
        salt_b64,
        expected_subdomain_sig,
        expected_host,
        setup_code: setup_code.clone(),
        setup_code_attempts: AtomicU32::new(0),
        killed: AtomicBool::new(false),
        outcome_tx: std::sync::Mutex::new(Some(outcome_tx)),
        deadline,
        transport,
        script_nonce,
    });

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let thread_ctx = ctx.clone();
    let join = thread::Builder::new()
        .name(format!("wrustic-passphrase-{port}"))
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
        .map_err(|e| anyhow!("spawning passphrase thread: {e}"))?;

    let transport_public_b64 = ctx.transport.public_b64.clone();
    Ok(PassphraseHandle {
        short_url,
        setup_code,
        phase,
        rx: outcome_rx,
        deadline,
        transport_public_b64,
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

fn html_resp(ctx: &Ctx) -> Response<RespBody> {
    let mut resp = full_resp(
        StatusCode::OK,
        "text/html; charset=utf-8",
        render_html(ctx).into_bytes(),
    );
    let csp = format!(
        "default-src 'none'; \
         script-src 'nonce-{nonce}'; \
         style-src 'unsafe-inline'; \
         connect-src 'self'; \
         base-uri 'none'; \
         form-action 'none'; \
         frame-ancestors 'none'",
        nonce = ctx.script_nonce,
    );
    resp.headers_mut().insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_str(&csp).expect("CSP header is valid ASCII"),
    );
    resp.headers_mut().insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    resp
}

fn extract_host(req: &Request<hyper::body::Incoming>) -> Option<&str> {
    req.headers()
        .get(hyper::header::HOST)?
        .to_str()
        .ok()
}

fn host_matches(raw: &str, expected: &str) -> bool {
    let hostname = raw.split(':').next().unwrap_or(raw).trim();
    hostname.eq_ignore_ascii_case(expected)
}

async fn handle(
    req: Request<hyper::body::Incoming>,
    ctx: Arc<Ctx>,
) -> Result<Response<RespBody>, Infallible> {
    match extract_host(&req) {
        Some(raw) if host_matches(raw, &ctx.expected_host) => {}
        _ => return Ok(text(StatusCode::NOT_FOUND, "not found")),
    }

    let path = req.uri().path().to_string();
    let expected_prefix = format!("/{}/", ctx.path_prefix);
    let Some(suffix) = path.strip_prefix(&expected_prefix) else {
        return Ok(text(StatusCode::NOT_FOUND, "not found"));
    };
    let (key, rest) = match suffix.find('/') {
        Some(i) => (&suffix[..i], &suffix[i..]),
        None => (suffix, ""),
    };
    if !ct_eq(key.as_bytes(), ctx.short_id.as_bytes()) {
        return Ok(text(StatusCode::NOT_FOUND, "not found"));
    }

    if ctx.killed.load(Ordering::Relaxed) || Instant::now() >= ctx.deadline {
        return Ok(text(
            StatusCode::FORBIDDEN,
            "Passphrase ceremony expired or cancelled. \
             Quit wrustic in the terminal and relaunch to start a new ceremony.",
        ));
    }

    let method = req.method().clone();
    match (method, rest) {
        (Method::GET, "") | (Method::GET, "/") => Ok(html_resp(&ctx)),
        (Method::POST, "/api/check-code") if matches!(ctx.phase, PassphrasePhase::Setup) => {
            Ok(handle_check_setup_code(req, ctx).await)
        }
        (Method::POST, "/api/setup") if ctx.phase == PassphrasePhase::Setup => {
            Ok(handle_setup(req, ctx).await)
        }
        (Method::POST, "/api/unlock") if ctx.phase == PassphrasePhase::Unlock => {
            Ok(handle_unlock(req, ctx).await)
        }
        _ => Ok(text(StatusCode::NOT_FOUND, "not found")),
    }
}

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

struct SetupBody {
    setup_code: String,
    subdomain_sig: [u8; 32],
    config_key: [u8; 32],
}

struct UnlockBody {
    config_key: [u8; 32],
}

async fn read_body(req: Request<hyper::body::Incoming>) -> Result<Vec<u8>, std::io::Error> {
    let collected = req
        .into_body()
        .collect()
        .await
        .map_err(|e| std::io::Error::other(format!("reading body: {e}")))?;
    Ok(collected.to_bytes().to_vec())
}

async fn read_and_decrypt(
    req: Request<hyper::body::Incoming>,
    ctx: &Arc<Ctx>,
) -> Result<Vec<u8>, Response<RespBody>> {
    let body = read_body(req)
        .await
        .map_err(|e| text(StatusCode::BAD_REQUEST, &format!("body read: {e}")))?;
    let env: Envelope = serde_json::from_slice(&body)
        .map_err(|e| text(StatusCode::BAD_REQUEST, &format!("invalid envelope JSON: {e}")))?;
    ctx.transport.decrypt(&env).map_err(|e| e.http_response())
}

fn decode_config_key(raw: &[u8]) -> Result<[u8; 32], String> {
    if raw.len() != 32 {
        return Err(format!(
            "expected 32-byte config key, got {} bytes",
            raw.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    Ok(out)
}

fn parse_setup_body(inner: &[u8]) -> Result<SetupBody, String> {
    // v1: version(1) + code_len(1) + code(N) + subdomain_sig(32) + config_key(32)
    if inner.len() < 1 + 1 + 32 + 32 {
        return Err(format!("setup payload too short: {} bytes", inner.len()));
    }
    if inner[0] != 1 {
        return Err(format!("unsupported setup payload version {}", inner[0]));
    }
    let code_len = inner[1] as usize;
    let expected = 1 + 1 + code_len + 32 + 32;
    if inner.len() != expected {
        return Err(format!(
            "setup payload size mismatch: expected {expected}, got {}",
            inner.len()
        ));
    }
    let mut pos = 2;
    let setup_code = String::from_utf8(inner[pos..pos + code_len].to_vec())
        .map_err(|e| format!("setup code is not UTF-8: {e}"))?;
    pos += code_len;
    let mut subdomain_sig = [0u8; 32];
    subdomain_sig.copy_from_slice(&inner[pos..pos + 32]);
    pos += 32;
    let config_key = decode_config_key(&inner[pos..])?;
    Ok(SetupBody {
        setup_code,
        subdomain_sig,
        config_key,
    })
}

fn parse_unlock_body(inner: &[u8]) -> Result<UnlockBody, String> {
    Ok(UnlockBody {
        config_key: decode_config_key(inner)?,
    })
}

fn verify_subdomain_sig(subdomain: &str, key: &[u8; 32], expected_sig_b64: &str) -> bool {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(subdomain.as_bytes());
    let computed = mac.finalize().into_bytes();
    let expected = match BASE64.decode(expected_sig_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    ct_eq(&computed, &expected)
}

enum CodeCheck {
    Ok,
    Wrong(Response<RespBody>),
}

fn check_setup_code(ctx: &Arc<Ctx>, submitted_raw: &str) -> CodeCheck {
    let expected = match ctx.setup_code.as_deref() {
        Some(c) => c,
        None => {
            return CodeCheck::Wrong(text(
                StatusCode::INTERNAL_SERVER_ERROR,
                "setup code not initialized",
            ));
        }
    };
    let submitted: String = submitted_raw
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(|c| c.to_uppercase())
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

async fn handle_check_setup_code(
    req: Request<hyper::body::Incoming>,
    ctx: Arc<Ctx>,
) -> Response<RespBody> {
    let inner = match read_and_decrypt(req, &ctx).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let parsed: CheckCodeBody = match serde_json::from_slice(&inner) {
        Ok(v) => v,
        Err(e) => return text(StatusCode::BAD_REQUEST, &format!("invalid JSON: {e}")),
    };
    match check_setup_code(&ctx, &parsed.setup_code) {
        CodeCheck::Ok => json_ok(),
        CodeCheck::Wrong(resp) => resp,
    }
}

async fn handle_setup(req: Request<hyper::body::Incoming>, ctx: Arc<Ctx>) -> Response<RespBody> {
    let inner = match read_and_decrypt(req, &ctx).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let parsed = match parse_setup_body(&inner) {
        Ok(v) => v,
        Err(e) => return text(StatusCode::BAD_REQUEST, &format!("invalid setup payload: {e}")),
    };
    match check_setup_code(&ctx, &parsed.setup_code) {
        CodeCheck::Ok => {}
        CodeCheck::Wrong(resp) => return resp,
    }
    let meta = PassphraseMeta {
        subdomain: ctx.subdomain.clone(),
        subdomain_sig: BASE64.encode(parsed.subdomain_sig),
        salt: ctx.salt_b64.clone(),
    };
    let outcome = PassphraseOutcome {
        key: parsed.config_key,
        new_meta: Some(meta),
    };
    if ctx.deliver(outcome).is_err() {
        return text(StatusCode::CONFLICT, "passphrase already provided this session");
    }
    json_ok()
}

async fn handle_unlock(req: Request<hyper::body::Incoming>, ctx: Arc<Ctx>) -> Response<RespBody> {
    let inner = match read_and_decrypt(req, &ctx).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let parsed = match parse_unlock_body(&inner) {
        Ok(v) => v,
        Err(e) => return text(StatusCode::BAD_REQUEST, &format!("invalid unlock payload: {e}")),
    };
    if let Some(expected_sig) = &ctx.expected_subdomain_sig
        && !verify_subdomain_sig(&ctx.subdomain, &parsed.config_key, expected_sig)
    {
        return text(
            StatusCode::UNAUTHORIZED,
            "Wrong passphrase. The subdomain signature did not match.",
        );
    }
    let outcome = PassphraseOutcome {
        key: parsed.config_key,
        new_meta: None,
    };
    if ctx.deliver(outcome).is_err() {
        return text(StatusCode::CONFLICT, "passphrase already provided this session");
    }
    json_ok()
}

fn render_html(ctx: &Ctx) -> String {
    let (heading, heading_style) = match ctx.phase {
        PassphrasePhase::Setup => (
            "Set up passphrase encryption for wrustic",
            "border-left:4px solid #d4a017;padding-left:0.6rem;color:#5a3d00;",
        ),
        PassphrasePhase::Unlock => (
            "Unlock wrustic with your passphrase",
            "border-left:4px solid #2563eb;padding-left:0.6rem;color:#1e40af;",
        ),
    };
    let explanation = match ctx.phase {
        PassphrasePhase::Setup => {
            "Enter a strong passphrase to encrypt your wrustic config. \
             The passphrase is used to derive an encryption key via PBKDF2 \
             in this browser — it is never sent to the server in plaintext."
        }
        PassphrasePhase::Unlock => {
            "Enter the passphrase you set up earlier to decrypt your config."
        }
    };
    let setup_code_html = match ctx.phase {
        PassphrasePhase::Setup => {
            "<p>\
              <label for=\"setup-code\">\
                <strong>Setup code</strong> (printed in your wrustic terminal):\
              </label>\
              <br>\
              <input id=\"setup-code\" type=\"text\" autocomplete=\"off\" \
                     spellcheck=\"false\" autocapitalize=\"characters\" \
                     maxlength=\"6\" \
                     pattern=\"[2-9A-HJKMNP-Za-hjkmnp-z]{6}\" \
                     style=\"font-size:1.2rem;width:8rem;\
                            font-family:ui-monospace,monospace;padding:0.4rem;\
                            text-transform:uppercase;\" \
                     placeholder=\"ABCDEF\">\
            </p>"
        }
        PassphrasePhase::Unlock => "",
    };
    let form_html = match ctx.phase {
        PassphrasePhase::Setup => {
            "<p>\
              <label for=\"passphrase\"><strong>Passphrase</strong></label><br>\
              <input id=\"passphrase\" type=\"password\" autocomplete=\"off\" \
                     style=\"font-size:1rem;width:20rem;padding:0.4rem;\" \
                     placeholder=\"Enter passphrase\">\
            </p>\
            <p>\
              <label for=\"passphrase-confirm\"><strong>Confirm passphrase</strong></label><br>\
              <input id=\"passphrase-confirm\" type=\"password\" autocomplete=\"off\" \
                     style=\"font-size:1rem;width:20rem;padding:0.4rem;\" \
                     placeholder=\"Repeat passphrase\">\
            </p>\
            <p id=\"complexity-hint\" class=\"hint\">\
              <strong>Requirements:</strong> at least 12 characters, including uppercase, \
              lowercase, a digit, and a special character.\
            </p>\
            <p><button id=\"go-setup\">Set passphrase</button></p>"
        }
        PassphrasePhase::Unlock => {
            "<p>\
              <label for=\"passphrase\"><strong>Passphrase</strong></label><br>\
              <input id=\"passphrase\" type=\"password\" autocomplete=\"off\" \
                     style=\"font-size:1rem;width:20rem;padding:0.4rem;\" \
                     placeholder=\"Enter passphrase\">\
            </p>\
            <p><button id=\"go-unlock\">Unlock</button></p>"
        }
    };

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>wrustic passphrase</title>
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
<h1 style="{heading_style}">{heading}</h1>
<div id="status" class="note">Ready. Use the controls below to begin.</div>
<p>{explanation}</p>
{setup_code_html}
{form_html}
<p><small>This page is served by the wrustic process on localhost. You can close it when finished.</small></p>
<script nonce="{script_nonce_attr}">
const SALT_B64 = {salt_js};
const SUBDOMAIN = {subdomain_js};
const SERVER_PUB_B64 = {server_pub_js};
const TRANSPORT_HKDF_INFO = new TextEncoder().encode("wrustic-passphrase-transport-v1");
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
function zeroBytes(bytes) {{
  if (bytes && typeof bytes.fill === "function") bytes.fill(0);
}}

async function importServerPub() {{
  return crypto.subtle.importKey(
    "raw", b64ToBytes(SERVER_PUB_B64),
    {{ name: "X25519" }}, false, []
  );
}}

async function deriveTransportKey(serverPub) {{
  const clientPair = await crypto.subtle.generateKey(
    {{ name: "X25519" }}, false, ["deriveBits", "deriveKey"]
  );
  const sharedKey = await crypto.subtle.deriveKey(
    {{ name: "X25519", public: serverPub }},
    clientPair.privateKey,
    {{ name: "HKDF" }},
    false,
    ["deriveKey"]
  );
  const aesKey = await crypto.subtle.deriveKey(
    {{ name: "HKDF", hash: "SHA-256",
       salt: new Uint8Array(0), info: TRANSPORT_HKDF_INFO }},
    sharedKey,
    {{ name: "AES-GCM", length: 256 }},
    false,
    ["encrypt"]
  );
  const clientPubBytes = new Uint8Array(
    await crypto.subtle.exportKey("raw", clientPair.publicKey)
  );
  return {{ aesKey, clientPubBytes }};
}}

async function encryptBytes(plaintext) {{
  const serverPub = await importServerPub();
  const {{ aesKey, clientPubBytes }} = await deriveTransportKey(serverPub);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    {{ name: "AES-GCM", iv: nonce }},
    aesKey, plaintext
  ));
  return {{
    client_pub: bytesToB64(clientPubBytes),
    nonce: bytesToB64(nonce),
    ciphertext: bytesToB64(ct)
  }};
}}

async function postEncryptedEnvelope(path, envelope) {{
  const r = await fetch(API_BASE + path, {{
    method: "POST",
    headers: {{ "Content-Type": "application/json" }},
    body: JSON.stringify(envelope)
  }});
  if (!r.ok) throw new Error("Server: " + (await r.text()));
  return r;
}}
async function postEncryptedBytes(path, plaintext) {{
  return postEncryptedEnvelope(path, await encryptBytes(plaintext));
}}

async function deriveKey(passphrase) {{
  const enc = new TextEncoder();
  const saltBytes = b64ToBytes(SALT_B64);
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(passphrase), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {{ name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations: 600000 }},
    keyMaterial, 256
  );
  return new Uint8Array(bits);
}}

async function computeSubdomainSig(derivedKey) {{
  const enc = new TextEncoder();
  const hmacKey = await crypto.subtle.importKey(
    "raw", derivedKey, {{ name: "HMAC", hash: "SHA-256" }}, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", hmacKey, enc.encode(SUBDOMAIN));
  return new Uint8Array(sig);
}}

function checkComplexity(pp) {{
  if (pp.length < 12) return "Must be at least 12 characters.";
  if (!/[a-z]/.test(pp)) return "Must contain a lowercase letter.";
  if (!/[A-Z]/.test(pp)) return "Must contain an uppercase letter.";
  if (!/[0-9]/.test(pp)) return "Must contain a digit.";
  if (!/[^a-zA-Z0-9]/.test(pp)) return "Must contain a special character.";
  return null;
}}

function readSetupCode() {{
  const el = document.getElementById("setup-code");
  if (!el) return null;
  const code = (el.value || "").replace(/\s+/g, "").toUpperCase();
  if (!/^[2-9A-HJKMNP-Z]{{6}}$/.test(code)) {{
    throw new Error("Enter the 6-character setup code from your wrustic terminal (letters A-Z and digits 2-9, no 0/1/I/L/O).");
  }}
  return code;
}}

async function encryptJson(payload) {{
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  try {{
    return await encryptBytes(plaintext);
  }} finally {{
    zeroBytes(plaintext);
  }}
}}
async function postEncryptedJson(path, payload) {{
  return postEncryptedEnvelope(path, await encryptJson(payload));
}}

async function precheckSetupCode(code) {{
  await postEncryptedJson("/api/check-code", {{ setup_code: code }});
}}

async function doSetup() {{
  const setupCode = readSetupCode();
  await precheckSetupCode(setupCode);
  const pp = document.getElementById("passphrase").value;
  const pp2 = document.getElementById("passphrase-confirm").value;
  const err = checkComplexity(pp);
  if (err) throw new Error(err);
  if (pp !== pp2) throw new Error("Passphrases do not match.");
  setStatus("Deriving key (this may take a moment)…", "note");
  const configKey = await deriveKey(pp);
  const sig = await computeSubdomainSig(configKey);
  const codeBytes = new TextEncoder().encode(setupCode);
  const payload = new Uint8Array(1 + 1 + codeBytes.length + 32 + 32);
  let p = 0;
  payload[p++] = 1;
  payload[p++] = codeBytes.length;
  payload.set(codeBytes, p); p += codeBytes.length;
  payload.set(sig, p); p += 32;
  payload.set(configKey, p);
  try {{
    await postEncryptedBytes("/api/setup", payload);
  }} finally {{
    zeroBytes(configKey);
    zeroBytes(sig);
    zeroBytes(payload);
    zeroBytes(codeBytes);
  }}
}}

async function doUnlock() {{
  const pp = document.getElementById("passphrase").value;
  if (!pp) throw new Error("Enter your passphrase.");
  setStatus("Deriving key (this may take a moment)…", "note");
  const configKey = await deriveKey(pp);
  try {{
    await postEncryptedBytes("/api/unlock", configKey);
  }} finally {{
    zeroBytes(configKey);
  }}
}}

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
    setStatus("Working…", "note");
    try {{
      await fn();
      setStatus("Done. You can close this tab and return to the wrustic terminal.", "ok");
      disableAllCtas();
    }} catch (e) {{
      setStatus("Error: " + (e && e.message ? e.message : e), "err");
    }}
  }});
}}
wireButton("go-setup", doSetup);
wireButton("go-unlock", doUnlock);
</script>
</body>
</html>
"#,
        heading = heading,
        heading_style = heading_style,
        explanation = explanation,
        setup_code_html = setup_code_html,
        form_html = form_html,
        script_nonce_attr = html_attr(&ctx.script_nonce),
        salt_js = json_string(&ctx.salt_b64),
        subdomain_js = json_string(&ctx.subdomain),
        server_pub_js = json_string(&ctx.transport.public_b64),
    )
}

fn html_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c => out.push(c),
        }
    }
    out
}

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
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
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
        assert_eq!(
            json_string("</script><script>alert(1)</script>"),
            "\"\\u003c/script\\u003e\\u003cscript\\u003ealert(1)\\u003c/script\\u003e\""
        );
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
    fn decode_config_key_rejects_wrong_length() {
        assert!(decode_config_key(&[]).is_err());
        assert!(decode_config_key(&[0u8; 16]).is_err());
        assert!(decode_config_key(&[0u8; 32]).is_ok());
    }

    #[test]
    fn parse_setup_body_valid() {
        let code = b"AB23KM";
        let mut payload = vec![1u8, code.len() as u8];
        payload.extend_from_slice(code);
        payload.extend_from_slice(&[0xAAu8; 32]);
        payload.extend_from_slice(&[0xBBu8; 32]);
        let body = parse_setup_body(&payload).unwrap();
        assert_eq!(body.setup_code, "AB23KM");
        assert_eq!(body.subdomain_sig, [0xAA; 32]);
        assert_eq!(body.config_key, [0xBB; 32]);
    }

    #[test]
    fn parse_setup_body_wrong_size() {
        assert!(parse_setup_body(&[1u8; 3]).is_err());
        assert!(parse_setup_body(&[]).is_err());
    }

    #[test]
    fn parse_setup_body_wrong_version() {
        let mut payload = vec![2u8, 0];
        payload.extend_from_slice(&[0u8; 64]);
        assert!(parse_setup_body(&payload).is_err());
    }

    #[test]
    fn verify_subdomain_sig_correct() {
        let key = [0x42u8; 32];
        let subdomain = "mysite";
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(subdomain.as_bytes());
        let sig = BASE64.encode(mac.finalize().into_bytes());
        assert!(verify_subdomain_sig(subdomain, &key, &sig));
    }

    #[test]
    fn verify_subdomain_sig_wrong_key() {
        let key = [0x42u8; 32];
        let subdomain = "mysite";
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(subdomain.as_bytes());
        let sig = BASE64.encode(mac.finalize().into_bytes());
        let wrong_key = [0x43u8; 32];
        assert!(!verify_subdomain_sig(subdomain, &wrong_key, &sig));
    }

    #[test]
    fn verify_subdomain_sig_wrong_subdomain() {
        let key = [0x42u8; 32];
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(b"mysite");
        let sig = BASE64.encode(mac.finalize().into_bytes());
        assert!(!verify_subdomain_sig("other", &key, &sig));
    }

    fn test_ctx(phase: PassphrasePhase) -> Ctx {
        let sig = if phase == PassphrasePhase::Unlock {
            let key = [0x42u8; 32];
            let mut mac = HmacSha256::new_from_slice(&key).unwrap();
            mac.update(b"testsite");
            Some(BASE64.encode(mac.finalize().into_bytes()))
        } else {
            None
        };
        Ctx {
            phase,
            short_id: "abc123".into(),
            path_prefix: match phase {
                PassphrasePhase::Setup => "setup",
                PassphrasePhase::Unlock => "auth",
            },
            subdomain: "testsite".into(),
            salt_b64: "U0FMVA==".into(),
            expected_subdomain_sig: sig,
            expected_host: "testsite.wrustic.localhost".into(),
            setup_code: match phase {
                PassphrasePhase::Setup => Some("AB23KM".into()),
                PassphrasePhase::Unlock => None,
            },
            setup_code_attempts: AtomicU32::new(0),
            killed: AtomicBool::new(false),
            outcome_tx: std::sync::Mutex::new(None),
            deadline: Instant::now() + PASSPHRASE_TTL,
            transport: ServerTransport::generate().expect("/dev/urandom"),
            script_nonce: "testnonce".into(),
        }
    }

    #[test]
    fn html_setup_shows_passphrase_form() {
        let ctx = test_ctx(PassphrasePhase::Setup);
        let html = render_html(&ctx);
        assert!(html.contains("Set up passphrase encryption"));
        assert!(html.contains(r#"id="passphrase""#));
        assert!(html.contains(r#"id="passphrase-confirm""#));
        assert!(html.contains(r#"id="go-setup""#));
        assert!(!html.contains(r#"id="go-unlock""#));
        assert!(html.contains("at least 12 characters"));
        assert!(html.contains("PBKDF2"));
        assert!(html.contains(r#"id="setup-code""#));
        assert!(html.contains("Setup code"));
        assert!(html.contains("precheckSetupCode"));
    }

    #[test]
    fn html_unlock_shows_passphrase_form() {
        let ctx = test_ctx(PassphrasePhase::Unlock);
        let html = render_html(&ctx);
        assert!(html.contains("Unlock wrustic"));
        assert!(html.contains(r#"id="passphrase""#));
        assert!(!html.contains(r#"id="passphrase-confirm""#));
        assert!(html.contains(r#"id="go-unlock""#));
        assert!(!html.contains(r#"id="go-setup""#));
        assert!(!html.contains(r#"id="setup-code""#));
    }

    #[test]
    fn html_embeds_salt_and_subdomain() {
        let ctx = test_ctx(PassphrasePhase::Setup);
        let html = render_html(&ctx);
        assert!(html.contains("U0FMVA=="));
        assert!(html.contains("testsite"));
        assert!(html.contains("disableAllCtas"));
    }

    fn assert_send<T: Send>() {}

    #[test]
    fn handle_is_send() {
        assert_send::<PassphraseHandle>();
    }

    #[test]
    fn is_expired_predicate() {
        let (_tx, rx) = std_mpsc::channel::<PassphraseOutcome>();
        let (shutdown_tx, _shutdown_rx) = oneshot::channel::<()>();
        let h = PassphraseHandle {
            short_url: String::new(),
            setup_code: None,
            phase: PassphrasePhase::Setup,
            rx,
            deadline: Instant::now() - Duration::from_secs(1),
            transport_public_b64: String::new(),
            shutdown_tx: Some(shutdown_tx),
            join_handle: None,
        };
        assert!(h.is_expired());

        let (_tx, rx) = std_mpsc::channel::<PassphraseOutcome>();
        let (shutdown_tx, _shutdown_rx) = oneshot::channel::<()>();
        let h2 = PassphraseHandle {
            short_url: String::new(),
            setup_code: None,
            phase: PassphrasePhase::Setup,
            rx,
            deadline: Instant::now() + Duration::from_secs(60),
            transport_public_b64: String::new(),
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

    fn ephemeral_port() -> u16 {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        port
    }

    fn raw_request_host(port: u16, method: &str, path: &str, host: &str) -> String {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let req = format!(
            "{method} {path} HTTP/1.0\r\nHost: {host}\r\nContent-Length: 0\r\n\r\n"
        );
        sock.write_all(req.as_bytes()).unwrap();
        let mut resp = Vec::new();
        sock.read_to_end(&mut resp).unwrap();
        String::from_utf8_lossy(&resp).into_owned()
    }

    fn raw_request(port: u16, method: &str, path: &str) -> String {
        raw_request_host(port, method, path, "testsite.wrustic.localhost")
    }

    fn raw_post_json_host(port: u16, path: &str, body: &str, host: &str) -> String {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let req = format!(
            "POST {path} HTTP/1.0\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\n\r\n{body}",
            len = body.len(),
            body = body,
        );
        sock.write_all(req.as_bytes()).unwrap();
        let mut resp = Vec::new();
        sock.read_to_end(&mut resp).unwrap();
        String::from_utf8_lossy(&resp).into_owned()
    }

    fn raw_post_json(port: u16, path: &str, body: &str) -> String {
        raw_post_json_host(port, path, body, "testsite.wrustic.localhost")
    }

    fn key_from_handle(h: &PassphraseHandle) -> String {
        h.short_url.rsplit('/').next().unwrap().to_string()
    }

    fn encrypt_envelope_bytes(server_pub_b64: &str, plaintext: &[u8]) -> String {
        let server_pub_bytes = BASE64.decode(server_pub_b64).expect("server pub b64");
        let server_pub_arr: [u8; 32] = server_pub_bytes.as_slice().try_into().unwrap();
        let server_pub = X25519Public::from(server_pub_arr);

        let mut client_priv_bytes = [0u8; 32];
        let mut f = std::fs::File::open("/dev/urandom").unwrap();
        f.read_exact(&mut client_priv_bytes).unwrap();
        let client_priv = X25519Secret::from(client_priv_bytes);
        let client_pub = X25519Public::from(&client_priv);
        let shared = client_priv.diffie_hellman(&server_pub);

        let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut key = [0u8; 32];
        hk.expand(TRANSPORT_HKDF_INFO, &mut key).unwrap();
        let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&key));

        let mut nonce_bytes = [0u8; TRANSPORT_NONCE_LEN];
        f.read_exact(&mut nonce_bytes).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher.encrypt(nonce, plaintext).unwrap();

        format!(
            r#"{{"client_pub":"{cpb}","nonce":"{nb}","ciphertext":"{ctb}"}}"#,
            cpb = BASE64.encode(client_pub.as_bytes()),
            nb = BASE64.encode(nonce_bytes),
            ctb = BASE64.encode(&ct),
        )
    }

    fn encrypted_post_bytes(port: u16, server_pub_b64: &str, path: &str, plaintext: &[u8], host: &str) -> String {
        let body = encrypt_envelope_bytes(server_pub_b64, plaintext);
        raw_post_json_host(port, path, &body, host)
    }

    fn setup_payload(setup_code: &str, subdomain_sig: &[u8; 32], config_key: &[u8; 32]) -> Vec<u8> {
        let code = setup_code.as_bytes();
        let mut out = Vec::with_capacity(2 + code.len() + 64);
        out.push(1);
        out.push(code.len() as u8);
        out.extend_from_slice(code);
        out.extend_from_slice(subdomain_sig);
        out.extend_from_slice(config_key);
        out
    }

    fn compute_hmac(subdomain: &str, key: &[u8; 32]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(subdomain.as_bytes());
        mac.finalize().into_bytes().into()
    }

    #[test]
    fn routing_only_serves_under_correct_key() {
        let port = ephemeral_port();
        let handle = start(port, PassphrasePhase::Setup, None, "testsite").expect("start server");
        let key = key_from_handle(&handle);

        for (m, p) in [
            ("GET", "/"),
            ("GET", "/setup"),
            ("GET", "/setup/"),
            ("GET", "/setup/deadbeefdeadbeef"),
            ("GET", "/auth/deadbeefdeadbeef"),
            ("POST", "/api/setup"),
        ] {
            let r = raw_request(port, m, p);
            assert!(r.contains(" 404 "), "expected 404 for {m} {p}, got:\n{r}");
        }

        let keyed = format!("/setup/{key}");
        let r = raw_request(port, "GET", &keyed);
        assert!(r.contains(" 200 "), "GET {keyed} should 200, got:\n{r}");
        assert!(r.contains("<!doctype html>") || r.contains("<!DOCTYPE html>"));
        assert!(r.contains(r#"id="go-setup""#));
        assert!(r.to_lowercase().contains("content-security-policy:"));

        let keyed_slash = format!("/setup/{key}/");
        let r = raw_request(port, "GET", &keyed_slash);
        assert!(r.contains(" 200 "), "GET {keyed_slash} should 200, got:\n{r}");

        let r = raw_request(port, "GET", &format!("/setup/{key}/whatever"));
        assert!(r.contains(" 404 "));

        handle.stop();
    }

    const MYSITE_HOST: &str = "mysite.wrustic.localhost";

    #[test]
    fn setup_delivers_outcome_with_meta() {
        let port = ephemeral_port();
        let handle = start(port, PassphrasePhase::Setup, None, "mysite").expect("start server");
        let key = key_from_handle(&handle);
        let setup_code = handle.setup_code.clone().expect("Setup phase mints a code");
        let path = format!("/setup/{key}/api/setup");
        let config_key = [0x42u8; 32];
        let sig = compute_hmac("mysite", &config_key);
        let body = setup_payload(&setup_code, &sig, &config_key);
        let r = encrypted_post_bytes(port, &handle.transport_public_b64, &path, &body, MYSITE_HOST);
        assert!(r.contains(" 200 "), "setup should 200, got:\n{r}");

        let outcome = handle.rx.recv_timeout(Duration::from_secs(2)).expect("outcome");
        assert_eq!(outcome.key, config_key);
        let meta = outcome.new_meta.expect("setup must produce meta");
        assert_eq!(meta.subdomain, "mysite");
        handle.stop();
    }

    #[test]
    fn unlock_correct_passphrase_delivers_outcome() {
        let port = ephemeral_port();
        let config_key = [0x42u8; 32];
        let sig = compute_hmac("mysite", &config_key);
        let meta = PassphraseMeta {
            subdomain: "mysite".into(),
            subdomain_sig: BASE64.encode(sig),
            salt: BASE64.encode([0u8; 32]),
        };
        let handle = start(port, PassphrasePhase::Unlock, Some(meta), "mysite").expect("start server");
        let key = key_from_handle(&handle);
        let path = format!("/auth/{key}/api/unlock");
        let r = encrypted_post_bytes(port, &handle.transport_public_b64, &path, &config_key, MYSITE_HOST);
        assert!(r.contains(" 200 "), "unlock should 200, got:\n{r}");

        let outcome = handle.rx.recv_timeout(Duration::from_secs(2)).expect("outcome");
        assert_eq!(outcome.key, config_key);
        assert!(outcome.new_meta.is_none());
        handle.stop();
    }

    #[test]
    fn unlock_wrong_passphrase_returns_401() {
        let port = ephemeral_port();
        let config_key = [0x42u8; 32];
        let sig = compute_hmac("mysite", &config_key);
        let meta = PassphraseMeta {
            subdomain: "mysite".into(),
            subdomain_sig: BASE64.encode(sig),
            salt: BASE64.encode([0u8; 32]),
        };
        let handle = start(port, PassphrasePhase::Unlock, Some(meta), "mysite").expect("start server");
        let key = key_from_handle(&handle);
        let path = format!("/auth/{key}/api/unlock");
        let wrong_key = [0x43u8; 32];
        let r = encrypted_post_bytes(port, &handle.transport_public_b64, &path, &wrong_key, MYSITE_HOST);
        assert!(r.contains(" 401 "), "wrong passphrase should 401, got:\n{r}");
        assert!(r.to_lowercase().contains("wrong passphrase"));

        match handle.rx.try_recv() {
            Err(std_mpsc::TryRecvError::Empty) => {}
            Ok(_) => panic!("no outcome should be delivered on wrong passphrase"),
            Err(other) => panic!("unexpected channel state: {other:?}"),
        }
        handle.stop();
    }

    #[test]
    fn envelope_roundtrips_through_handler() {
        let port = ephemeral_port();
        let config_key = [0x42u8; 32];
        let sig = compute_hmac("mysite", &config_key);
        let meta = PassphraseMeta {
            subdomain: "mysite".into(),
            subdomain_sig: BASE64.encode(sig),
            salt: BASE64.encode([0u8; 32]),
        };
        let handle = start(port, PassphrasePhase::Unlock, Some(meta), "mysite").expect("start server");
        let key = key_from_handle(&handle);
        let r = encrypted_post_bytes(
            port,
            &handle.transport_public_b64,
            &format!("/auth/{key}/api/unlock"),
            &config_key,
            MYSITE_HOST,
        );
        assert!(r.contains(" 200 "), "envelope round-trip should reach handler, got:\n{r}");
        handle.stop();
    }

    #[test]
    fn envelope_with_tampered_ciphertext_is_rejected() {
        let port = ephemeral_port();
        let handle = start(port, PassphrasePhase::Setup, None, "mysite").expect("start server");
        let key = key_from_handle(&handle);

        let setup_code = handle.setup_code.clone().unwrap();
        let config_key = [0u8; 32];
        let sig = compute_hmac("mysite", &config_key);
        let inner = setup_payload(&setup_code, &sig, &config_key);
        let mut env: serde_json::Value =
            serde_json::from_str(&encrypt_envelope_bytes(&handle.transport_public_b64, &inner)).unwrap();
        let ct_b64 = env["ciphertext"].as_str().unwrap().to_string();
        let mut ct_bytes = BASE64.decode(&ct_b64).unwrap();
        ct_bytes[0] ^= 0x01;
        env["ciphertext"] = serde_json::Value::String(BASE64.encode(&ct_bytes));
        let body = serde_json::to_string(&env).unwrap();

        let r = raw_post_json_host(port, &format!("/setup/{key}/api/setup"), &body, MYSITE_HOST);
        assert!(r.contains(" 400 "), "tampered ciphertext should 400, got:\n{r}");
        assert!(r.to_lowercase().contains("transport"));

        handle.stop();
    }

    #[test]
    fn wrong_host_header_is_rejected() {
        let port = ephemeral_port();
        let handle = start(port, PassphrasePhase::Setup, None, "mysite").expect("start server");
        let key = key_from_handle(&handle);

        let r = raw_request_host(port, "GET", &format!("/setup/{key}"), "evil.example.com");
        assert!(r.contains(" 404 "), "wrong Host must 404, got:\n{r}");

        let r = raw_request_host(port, "GET", &format!("/setup/{key}"), "127.0.0.1");
        assert!(r.contains(" 404 "), "bare IP Host must 404, got:\n{r}");

        let r = raw_request_host(port, "GET", &format!("/setup/{key}"), &format!("mysite.wrustic.localhost:{port}"));
        assert!(r.contains(" 200 "), "correct Host with port should 200, got:\n{r}");

        handle.stop();
    }

    #[test]
    fn host_match_is_case_insensitive() {
        let port = ephemeral_port();
        let handle = start(port, PassphrasePhase::Setup, None, "mysite").expect("start server");
        let key = key_from_handle(&handle);

        let r = raw_request_host(port, "GET", &format!("/setup/{key}"), "MYSITE.WRUSTIC.LOCALHOST");
        assert!(r.contains(" 200 "), "uppercase Host should 200, got:\n{r}");

        handle.stop();
    }
}
