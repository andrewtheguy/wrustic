// Experimental: passkey-derived encryption ceremony, served as a localhost
// http page that the user opens in a browser. Mirrors the share.rs pattern
// (hyper on 127.0.0.1, ephemeral OS thread + tokio runtime, RAII handle).
// Unlike share, this is bidirectional: the browser POSTs the WebAuthn PRF
// output back to us, and we forward it through an mpsc to the App.

use std::convert::Infallible;
use std::io::Read;
use std::sync::Arc;
use std::sync::mpsc as std_mpsc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE, HeaderValue, LOCATION};
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
    pub(crate) url: String,
    pub(crate) short_url: String,
    pub(crate) phase: PasskeyPhase,
    pub(crate) rx: std_mpsc::Receiver<PasskeyOutcome>,
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
    // Send the PRF output (or an error) back to the App, exactly once.
    outcome_tx: std::sync::Mutex<Option<std_mpsc::Sender<PasskeyOutcome>>>,
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
    // compatibility); the listener binds to 127.0.0.1 above.
    let short_url = format!("http://localhost:{port}/auth/{short_id}");
    let url = format!("http://localhost:{port}/");

    let (outcome_tx, outcome_rx) = std_mpsc::channel::<PasskeyOutcome>();

    let ctx = Arc::new(Ctx {
        phase,
        short_id,
        prf_salt_b64,
        credential_id_b64,
        outcome_tx: std::sync::Mutex::new(Some(outcome_tx)),
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
        url,
        short_url,
        phase,
        rx: outcome_rx,
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
    let path = req.uri().path().to_string();
    let method = req.method().clone();

    // /auth/<short> 302-redirects to / so users can copy a short URL from
    // the TUI and the browser still lands on the ceremony page. (`/auth/`
    // distinguishes the passkey path from the share dialog's `/s/` even
    // though the two flows share the same port and never run together.)
    if method == Method::GET && let Some(rest) = path.strip_prefix("/auth/") {
        if rest == ctx.short_id {
            let body = Full::new(Bytes::from_static(b""))
                .map_err(|never: Infallible| match never {})
                .boxed();
            let mut resp = Response::new(body);
            *resp.status_mut() = StatusCode::FOUND;
            resp.headers_mut()
                .insert(LOCATION, HeaderValue::from_static("/"));
            return Ok(resp);
        }
        return Ok(text(StatusCode::NOT_FOUND, "no such short id"));
    }

    if method == Method::GET && path == "/" {
        return Ok(full_resp(
            StatusCode::OK,
            "text/html; charset=utf-8",
            render_html(&ctx).into_bytes(),
        ));
    }

    if method == Method::POST && path == "/api/setup" && ctx.phase == PasskeyPhase::Setup {
        return Ok(handle_setup(req, ctx).await);
    }

    if method == Method::POST && path == "/api/unlock" && ctx.phase == PasskeyPhase::Unlock {
        return Ok(handle_unlock(req, ctx).await);
    }

    Ok(text(StatusCode::NOT_FOUND, "not found"))
}

#[derive(Deserialize)]
struct SetupBody {
    credential_id: String,
    prf: String,
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

async fn handle_setup(req: Request<hyper::body::Incoming>, ctx: Arc<Ctx>) -> Response<RespBody> {
    let body = match read_body(req).await {
        Ok(b) => b,
        Err(e) => return text(StatusCode::BAD_REQUEST, &format!("body read: {e}")),
    };
    let parsed: SetupBody = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return text(StatusCode::BAD_REQUEST, &format!("invalid JSON: {e}")),
    };
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
{buttons_html}
<div id="status" class="note">Click a button above to begin.</div>
<p><small>This page is served by the wrustic process on localhost. You can close it when finished.</small></p>
<script>
const PRF_SALT_B64 = {prf_salt_js};
const CRED_ID_B64 = {cred_id_js};

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

// Create a brand-new passkey on this device and use its PRF output as the
// encryption key. Some platform authenticators don't return PRF during
// create(), so we fall back to a follow-up get() with the same credential.
async function doCreate() {{
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
  await postSetup(credId, prfOutput);
}}

// Reuse an existing passkey already known to the browser (e.g. synced via
// the user's password manager). No `allowCredentials` so the browser shows
// the user every passkey valid for this origin and they pick one.
async function doImportExisting() {{
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
  await postSetup(credId, prfOutput);
}}

async function postSetup(credId, prfOutput) {{
  const r = await fetch("/api/setup", {{
    method: "POST",
    headers: {{ "Content-Type": "application/json" }},
    body: JSON.stringify({{
      credential_id: bytesToB64(credId),
      prf: bytesToB64(prfOutput)
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
  const r = await fetch("/api/unlock", {{
    method: "POST",
    headers: {{ "Content-Type": "application/json" }},
    body: JSON.stringify({{ prf: bytesToB64(prfOutput) }})
  }});
  if (!r.ok) throw new Error("Server: " + (await r.text()));
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

    #[test]
    fn html_setup_offers_create_and_import_buttons() {
        let ctx = Ctx {
            phase: PasskeyPhase::Setup,
            short_id: "abc123".into(),
            prf_salt_b64: "U0FMVA==".into(),
            credential_id_b64: String::new(),
            outcome_tx: std::sync::Mutex::new(None),
        };
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
    }

    #[test]
    fn html_unlock_offers_only_unlock_button() {
        let ctx = Ctx {
            phase: PasskeyPhase::Unlock,
            short_id: "abc123".into(),
            prf_salt_b64: "U0FMVA==".into(),
            credential_id_b64: "Q1JFRA==".into(),
            outcome_tx: std::sync::Mutex::new(None),
        };
        let html = render_html(&ctx);
        assert!(html.contains("Unlock wrustic"));
        assert!(html.contains("Q1JFRA=="));
        assert!(html.contains(r#"id="go-unlock""#));
        assert!(!html.contains(r#"id="go-create""#));
        assert!(!html.contains(r#"id="go-import""#));
        // Disclaimer is Setup-only.
        assert!(!html.contains("class=\"hint\""));
    }

    fn assert_send<T: Send>() {}

    #[test]
    fn handle_is_send() {
        // PasskeyHandle crosses thread boundaries (held inside App).
        assert_send::<PasskeyHandle>();
    }
}
