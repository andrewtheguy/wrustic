use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc as std_mpsc;
use std::thread;
use std::time::{Duration, Instant};

use aes_gcm::{Aes256Gcm, Nonce, aead::Aead, KeyInit as AesKeyInit};
use anyhow::{Result, anyhow};
use askama::Template;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use bytes::Bytes;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE, HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use scrypt::Params as ScryptParams;
use serde::Deserialize;
use sha2::Sha256;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

use crate::config::PassphraseMeta;
use crate::local_server;

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
const SCRYPT_LOG_N: u8 = 16;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

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

fn random_short_id() -> String {
    let buf: [u8; 8] = rand::random();
    let mut s = String::with_capacity(16);
    use std::fmt::Write;
    for b in &buf {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

fn random_setup_code() -> String {
    use rand::RngExt;
    let n = SETUP_CODE_ALPHABET.len();
    let mut rng = rand::rng();
    (0..SETUP_CODE_LEN)
        .map(|_| SETUP_CODE_ALPHABET[rng.random_range(0..n)] as char)
        .collect()
}

const TRANSPORT_HKDF_INFO: &[u8] = b"wrustic-passphrase-transport-v1";
const TRANSPORT_NONCE_LEN: usize = 12;

struct ServerTransport {
    private: X25519Secret,
    public_b64: String,
}

impl ServerTransport {
    fn generate() -> Self {
        let private = X25519Secret::from(rand::random::<[u8; 32]>());
        let public = X25519Public::from(&private);
        let public_b64 = BASE64.encode(public.as_bytes());
        Self { private, public_b64 }
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
    instance: String,
    salt_b64: String,
    expected_instance_sig: Option<String>,
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
    instance: &str,
) -> Result<PassphraseHandle> {
    let listeners_std = local_server::bind_localhost(port)?;

    let (salt_b64, expected_instance_sig) = match phase {
        PassphrasePhase::Setup => {
            let salt: [u8; 32] = rand::random();
            (BASE64.encode(salt), None)
        }
        PassphrasePhase::Unlock => {
            let meta = existing
                .ok_or_else(|| anyhow!("unlock phase requires existing passphrase metadata"))?;
            (meta.salt, Some(meta.instance_sig))
        }
    };

    let short_id = random_short_id();
    let path_prefix = match phase {
        PassphrasePhase::Setup => "setup",
        PassphrasePhase::Unlock => "auth",
    };
    let short_url = format!("http://{instance}.wrustic.localhost:{port}/{path_prefix}/{short_id}");

    let setup_code = match phase {
        PassphrasePhase::Setup => Some(random_setup_code()),
        PassphrasePhase::Unlock => None,
    };

    let (outcome_tx, outcome_rx) = std_mpsc::channel::<PassphraseOutcome>();
    let deadline = Instant::now() + PASSPHRASE_TTL;
    let transport = ServerTransport::generate();
    let script_nonce = BASE64.encode(rand::random::<[u8; 16]>());

    let expected_host = format!("{instance}.wrustic.localhost");

    let ctx = Arc::new(Ctx {
        phase,
        short_id,
        path_prefix,
        instance: instance.to_string(),
        salt_b64,
        expected_instance_sig,
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
                let mut listeners = Vec::with_capacity(listeners_std.len());
                for listener_std in listeners_std {
                    let listener = match TcpListener::from_std(listener_std) {
                        Ok(l) => l,
                        Err(_) => return,
                    };
                    listeners.push(listener);
                }
                accept_loop(listeners, thread_ctx, shutdown_rx).await;
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
    listeners: Vec<TcpListener>,
    ctx: Arc<Ctx>,
    shutdown_rx: oneshot::Receiver<()>,
) {
    for listener in listeners {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            accept_one(listener, ctx).await;
        });
    }

    let _ = shutdown_rx.await;
}

async fn accept_one(listener: TcpListener, ctx: Arc<Ctx>) {
    loop {
        let stream = match listener.accept().await {
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
    passphrase: String,
}

struct UnlockBody {
    passphrase: String,
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

pub(crate) fn derive_config_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    let params = ScryptParams::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P)
        .map_err(|e| format!("invalid scrypt parameters: {e}"))?;
    scrypt::scrypt(passphrase.as_bytes(), salt, &params, &mut key)
        .map_err(|e| format!("scrypt failed: {e}"))?;
    Ok(key)
}

pub(crate) fn passphrase_policy_error(passphrase: &str) -> Option<&'static str> {
    if passphrase.chars().count() < 12 {
        return Some("Must be at least 12 characters.");
    }
    if !passphrase.chars().any(|c| c.is_ascii_lowercase()) {
        return Some("Must contain a lowercase letter.");
    }
    if !passphrase.chars().any(|c| c.is_ascii_uppercase()) {
        return Some("Must contain an uppercase letter.");
    }
    if !passphrase.chars().any(|c| c.is_ascii_digit()) {
        return Some("Must contain a digit.");
    }
    if !passphrase.chars().any(|c| c.is_ascii_punctuation()) {
        return Some("Must contain a special character.");
    }
    None
}

fn parse_setup_body(inner: &[u8]) -> Result<SetupBody, String> {
    // v1: version(1) + code_len(1) + code(N) + passphrase(remaining)
    if inner.len() < 3 {
        return Err(format!("setup payload too short: {} bytes", inner.len()));
    }
    if inner[0] != 1 {
        return Err(format!("unsupported setup payload version {}", inner[0]));
    }
    let code_len = inner[1] as usize;
    if inner.len() < 2 + code_len + 1 {
        return Err(format!(
            "setup payload too short for code_len={code_len}: {} bytes",
            inner.len()
        ));
    }
    let setup_code = String::from_utf8(inner[2..2 + code_len].to_vec())
        .map_err(|e| format!("setup code is not UTF-8: {e}"))?;
    let passphrase = String::from_utf8(inner[2 + code_len..].to_vec())
        .map_err(|e| format!("passphrase is not UTF-8: {e}"))?;
    if let Some(err) = passphrase_policy_error(&passphrase) {
        return Err(err.into());
    }
    Ok(SetupBody {
        setup_code,
        passphrase,
    })
}

fn parse_unlock_body(inner: &[u8]) -> Result<UnlockBody, String> {
    let passphrase = String::from_utf8(inner.to_vec())
        .map_err(|e| format!("passphrase is not UTF-8: {e}"))?;
    if passphrase.is_empty() {
        return Err("empty passphrase".into());
    }
    Ok(UnlockBody { passphrase })
}

pub(crate) fn verify_instance_sig(instance: &str, key: &[u8; 32], expected_sig_b64: &str) -> bool {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(instance.as_bytes());
    let computed = mac.finalize().into_bytes();
    let expected = match BASE64.decode(expected_sig_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    ct_eq(&computed, &expected)
}

pub(crate) fn compute_instance_sig(instance: &str, key: &[u8; 32]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(instance.as_bytes());
    BASE64.encode(mac.finalize().into_bytes())
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
    let salt = match BASE64.decode(&ctx.salt_b64) {
        Ok(s) => s,
        Err(e) => return text(StatusCode::INTERNAL_SERVER_ERROR, &format!("bad salt: {e}")),
    };
    let config_key = match derive_config_key(&parsed.passphrase, &salt) {
        Ok(k) => k,
        Err(e) => return text(StatusCode::INTERNAL_SERVER_ERROR, &format!("key derivation: {e}")),
    };
    let instance_sig = compute_instance_sig(&ctx.instance, &config_key);
    let meta = PassphraseMeta {
        instance: ctx.instance.clone(),
        instance_sig,
        salt: ctx.salt_b64.clone(),
    };
    let outcome = PassphraseOutcome {
        key: config_key,
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
    let salt = match BASE64.decode(&ctx.salt_b64) {
        Ok(s) => s,
        Err(e) => return text(StatusCode::INTERNAL_SERVER_ERROR, &format!("bad salt: {e}")),
    };
    let config_key = match derive_config_key(&parsed.passphrase, &salt) {
        Ok(k) => k,
        Err(e) => return text(StatusCode::INTERNAL_SERVER_ERROR, &format!("key derivation: {e}")),
    };
    if let Some(expected_sig) = &ctx.expected_instance_sig
        && !verify_instance_sig(&ctx.instance, &config_key, expected_sig)
    {
        return text(
            StatusCode::UNAUTHORIZED,
            "Wrong passphrase. The instance signature did not match.",
        );
    }
    let outcome = PassphraseOutcome {
        key: config_key,
        new_meta: None,
    };
    if ctx.deliver(outcome).is_err() {
        return text(StatusCode::CONFLICT, "passphrase already provided this session");
    }
    json_ok()
}

#[derive(askama::Template)]
#[template(path = "passphrase.html")]
struct PassphraseTemplate {
    is_setup: bool,
    script_nonce: String,
    server_pub_js: String,
    instance: String,
    instance_sig: String,
}

fn render_html(ctx: &Ctx) -> String {
    let tmpl = PassphraseTemplate {
        is_setup: ctx.phase == PassphrasePhase::Setup,
        script_nonce: ctx.script_nonce.clone(),
        server_pub_js: json_string(&ctx.transport.public_b64),
        instance: ctx.instance.clone(),
        instance_sig: ctx.expected_instance_sig.clone().unwrap_or_default(),
    };
    tmpl.render().expect("template rendering failed")
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
    fn parse_setup_body_valid() {
        let code = b"AB23KM";
        let pp = b"MyPass123!xx";
        let mut payload = vec![1u8, code.len() as u8];
        payload.extend_from_slice(code);
        payload.extend_from_slice(pp);
        let body = parse_setup_body(&payload).unwrap();
        assert_eq!(body.setup_code, "AB23KM");
        assert_eq!(body.passphrase, "MyPass123!xx");
    }

    #[test]
    fn parse_setup_body_rejects_empty_passphrase() {
        let code = b"AB23KM";
        let payload = vec![1u8, code.len() as u8, b'A', b'B', b'2', b'3', b'K', b'M'];
        assert!(parse_setup_body(&payload).is_err());
    }

    #[test]
    fn parse_setup_body_enforces_passphrase_policy() {
        for passphrase in [
            "short1!",
            "missingdigit!",
            "missing-special1",
            "MISSINGLOWER1!",
            "missingupper1!",
            "ValidPass123 ",
        ] {
            let payload = setup_payload("AB23KM", passphrase);
            assert!(
                parse_setup_body(&payload).is_err(),
                "passphrase should fail policy: {passphrase}"
            );
        }

        let payload = setup_payload("AB23KM", TEST_PASSPHRASE);
        assert!(parse_setup_body(&payload).is_ok());
    }

    #[test]
    fn parse_setup_body_rejects_empty() {
        assert!(parse_setup_body(&[]).is_err());
    }

    #[test]
    fn parse_setup_body_wrong_version() {
        let mut payload = vec![2u8, 0];
        payload.extend_from_slice(b"somepassphrase");
        assert!(parse_setup_body(&payload).is_err());
    }

    #[test]
    fn verify_instance_sig_correct() {
        let key = [0x42u8; 32];
        let instance = "mysite";
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(instance.as_bytes());
        let sig = BASE64.encode(mac.finalize().into_bytes());
        assert!(verify_instance_sig(instance, &key, &sig));
    }

    #[test]
    fn verify_instance_sig_wrong_key() {
        let key = [0x42u8; 32];
        let instance = "mysite";
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(instance.as_bytes());
        let sig = BASE64.encode(mac.finalize().into_bytes());
        let wrong_key = [0x43u8; 32];
        assert!(!verify_instance_sig(instance, &wrong_key, &sig));
    }

    #[test]
    fn verify_instance_sig_wrong_instance() {
        let key = [0x42u8; 32];
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(b"mysite");
        let sig = BASE64.encode(mac.finalize().into_bytes());
        assert!(!verify_instance_sig("other", &key, &sig));
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
            instance: "testsite".into(),
            salt_b64: "U0FMVA==".into(),
            expected_instance_sig: sig,
            expected_host: "testsite.wrustic.localhost".into(),
            setup_code: match phase {
                PassphrasePhase::Setup => Some("AB23KM".into()),
                PassphrasePhase::Unlock => None,
            },
            setup_code_attempts: AtomicU32::new(0),
            killed: AtomicBool::new(false),
            outcome_tx: std::sync::Mutex::new(None),
            deadline: Instant::now() + PASSPHRASE_TTL,
            transport: ServerTransport::generate(),
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
    fn html_embeds_script() {
        let ctx = test_ctx(PassphrasePhase::Setup);
        let html = render_html(&ctx);
        assert!(html.contains("disableAllCtas"));
        assert!(html.contains("SERVER_PUB_B64"));
        assert!(!html.contains("SALT_B64"));
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
        let listeners = crate::local_server::bind_localhost(0).unwrap();
        let port = listeners[0].local_addr().unwrap().port();
        drop(listeners);
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

    fn key_from_handle(h: &PassphraseHandle) -> String {
        h.short_url.rsplit('/').next().unwrap().to_string()
    }

    fn encrypt_envelope_bytes(server_pub_b64: &str, plaintext: &[u8]) -> String {
        let server_pub_bytes = BASE64.decode(server_pub_b64).expect("server pub b64");
        let server_pub_arr: [u8; 32] = server_pub_bytes.as_slice().try_into().unwrap();
        let server_pub = X25519Public::from(server_pub_arr);

        let client_priv = X25519Secret::from(rand::random::<[u8; 32]>());
        let client_pub = X25519Public::from(&client_priv);
        let shared = client_priv.diffie_hellman(&server_pub);

        let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut key = [0u8; 32];
        hk.expand(TRANSPORT_HKDF_INFO, &mut key).unwrap();
        let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&key));

        let nonce_bytes: [u8; TRANSPORT_NONCE_LEN] = rand::random();
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

    fn setup_payload(setup_code: &str, passphrase: &str) -> Vec<u8> {
        let code = setup_code.as_bytes();
        let pp = passphrase.as_bytes();
        let mut out = Vec::with_capacity(2 + code.len() + pp.len());
        out.push(1);
        out.push(code.len() as u8);
        out.extend_from_slice(code);
        out.extend_from_slice(pp);
        out
    }

    const TEST_PASSPHRASE: &str = "TestPass123!";
    const TEST_SALT: [u8; 32] = [0u8; 32];

    fn test_config_key() -> [u8; 32] {
        derive_config_key(TEST_PASSPHRASE, &TEST_SALT).unwrap()
    }

    fn compute_hmac(instance: &str, key: &[u8; 32]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(instance.as_bytes());
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
        let body = setup_payload(&setup_code, TEST_PASSPHRASE);
        let r = encrypted_post_bytes(port, &handle.transport_public_b64, &path, &body, MYSITE_HOST);
        assert!(r.contains(" 200 "), "setup should 200, got:\n{r}");

        let outcome = handle.rx.recv_timeout(Duration::from_secs(2)).expect("outcome");
        assert_eq!(outcome.key.len(), 32);
        let meta = outcome.new_meta.expect("setup must produce meta");
        assert_eq!(meta.instance, "mysite");
        handle.stop();
    }

    #[test]
    fn unlock_correct_passphrase_delivers_outcome() {
        let port = ephemeral_port();
        let config_key = test_config_key();
        let sig = compute_hmac("mysite", &config_key);
        let meta = PassphraseMeta {
            instance: "mysite".into(),
            instance_sig: BASE64.encode(sig),
            salt: BASE64.encode(TEST_SALT),
        };
        let handle = start(port, PassphrasePhase::Unlock, Some(meta), "mysite").expect("start server");
        let key = key_from_handle(&handle);
        let path = format!("/auth/{key}/api/unlock");
        let r = encrypted_post_bytes(port, &handle.transport_public_b64, &path, TEST_PASSPHRASE.as_bytes(), MYSITE_HOST);
        assert!(r.contains(" 200 "), "unlock should 200, got:\n{r}");

        let outcome = handle.rx.recv_timeout(Duration::from_secs(2)).expect("outcome");
        assert_eq!(outcome.key, config_key);
        assert!(outcome.new_meta.is_none());
        handle.stop();
    }

    #[test]
    fn unlock_wrong_passphrase_returns_401() {
        let port = ephemeral_port();
        let config_key = test_config_key();
        let sig = compute_hmac("mysite", &config_key);
        let meta = PassphraseMeta {
            instance: "mysite".into(),
            instance_sig: BASE64.encode(sig),
            salt: BASE64.encode(TEST_SALT),
        };
        let handle = start(port, PassphrasePhase::Unlock, Some(meta), "mysite").expect("start server");
        let key = key_from_handle(&handle);
        let path = format!("/auth/{key}/api/unlock");
        let r = encrypted_post_bytes(port, &handle.transport_public_b64, &path, b"WrongPass999!", MYSITE_HOST);
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
        let config_key = test_config_key();
        let sig = compute_hmac("mysite", &config_key);
        let meta = PassphraseMeta {
            instance: "mysite".into(),
            instance_sig: BASE64.encode(sig),
            salt: BASE64.encode(TEST_SALT),
        };
        let handle = start(port, PassphrasePhase::Unlock, Some(meta), "mysite").expect("start server");
        let key = key_from_handle(&handle);
        let r = encrypted_post_bytes(
            port,
            &handle.transport_public_b64,
            &format!("/auth/{key}/api/unlock"),
            TEST_PASSPHRASE.as_bytes(),
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
        let inner = setup_payload(&setup_code, TEST_PASSPHRASE);
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
