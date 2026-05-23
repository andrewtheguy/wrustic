# Encryption

Per-value secret encryption for `config.toml`, plus the passphrase ceremony
server that derives the key.

**Scope: single-user, single-device.** wrustic is a personal tool — one
person, one machine. There is no multi-user threat model, no privilege
separation inside the binary, no defense-in-depth against another local
account on the same machine. Everything below — file permissions,
localhost-only servers, in-memory key handling — is sized for that
scope. If you need a multi-tenant secret store, this isn't it.

One cipher is supported:

| Cipher | Prefix | Algorithm | Key source |
|---|---|---|---|
| `Cipher` | `$WR;1.0;CHACHA20-POLY1305;<instance>;` | ChaCha20-Poly1305 AEAD | scrypt-derived config key from user passphrase, never on disk |

Source of truth: `src/crypto.rs`, `src/config.rs`, `src/passphrase.rs`.

## Why per-value, not whole-file

`config.toml` is encrypted **field by field**, not as one blob. Each secret
field is a single line, base64-after-prefix. The trade-offs:

- Non-secret edits (URLs, paths, bucket names, profile renames) still diff
  cleanly without decrypting anything.
- Adding a new field doesn't force re-encryption of every other field.
- The set of which fields are secret is hardcoded (see
  `config::encrypt_profile_fields`). New backends must opt fields in
  explicitly.

Which fields are encrypted, per backend (`src/config.rs`):

| Backend | Encrypted | Plaintext |
|---|---|---|
| `Local` | `password` | `local_path` |
| `Rest` | `password`, `rest_user`, `rest_password` | `rest_url` |
| `S3` | `password`, `s3_access_key`, `s3_secret_key` | `s3_endpoint`, `s3_bucket`, `s3_region`, `s3_root` |

Empty strings short-circuit: `encrypt_field` returns early on `""` so an
unset `rest_user` stays as `rest_user = ""` in the TOML rather than being
encrypted into noise.

## On-disk schema

```toml
version = 2
cipher  = "passphrase-v1"      # required, no default

[profiles.<name>]
backend  = "local" | "rest" | "s3"
password = "$WR;1.0;CHACHA20-POLY1305;mysite;…"
# plus backend-specific fields (some encrypted, some not — see table above)

[passphrase]
instance     = "<text>"     # DNS-safe instance (max 32 chars)
instance_sig = "<base64>"   # HMAC-SHA256(instance, derived_key)
salt          = "<base64>"   # random 32-byte scrypt salt
```

### Required fields and safety checks

1. **`cipher` is mandatory.** The `Config::cipher` field has no
   `#[serde(default)]`, so a TOML without that key fails to parse — there
   is no silent fallback. The only accepted value is `"passphrase-v1"`
   (constant in `src/config.rs`).
2. **`config::load` validates the marker.** Before any field is decrypted,
   `load` checks the on-disk marker is `"passphrase-v1"`. Mismatch → error.

A *third* implicit check sits at the value level: `Cipher::decrypt` rejects
any value whose prefix isn't `$WR;1.0;CHACHA20-POLY1305;`.

### `[passphrase]` block

```toml
[passphrase]
instance     = "mysite"
instance_sig = "<base64 HMAC-SHA256>"
salt          = "<base64 32-byte salt>"
```

- `instance` is the DNS-safe label chosen by the user at Setup (max 32
  chars, `[a-z0-9]([a-z0-9-]*[a-z0-9])?`). Used to construct the browser
  URL (`http://<instance>.wrustic.localhost:<port>/auth/<key>`).
- `instance_sig` is `HMAC-SHA256(instance, derived_key)`, base64-encoded.
  Verified on Unlock to give a fast "wrong passphrase" error before
  attempting full config decryption.
- `salt` is the random 32-byte scrypt salt, base64-encoded. Generated once
  at Setup; the server uses the same salt on every Unlock so the derived
  key matches.

These fields live inline in `config.toml` so `config::peek` can read them
without decrypting anything — that resolves the chicken-and-egg between
"need the salt for the ceremony" and "need the ceremony to derive the
cipher."

## Atomic save

`config::save` writes `config.toml.tmp` with `mode 0600`, then `rename(2)`s
over `config.toml`. POSIX rename is atomic within a filesystem, so a
process killed mid-save leaves the previous config intact rather than a
truncated one. The temp file is in the same directory as the target so
the rename can't cross filesystems.

`mode 0600` here is mostly convention given the single-user scope — the
practical attacks the encryption is built against involve the file
leaving the device (cloud sync of a config dir, included in a backup,
copied to another machine) rather than another local account reading it
in place. Disk encryption is your responsibility.

## Is `config.toml` safe to back up unencrypted?

**Short answer:** the *secret* fields are safe — they're already AEAD-
encrypted in place. What leaks if the bare file is exposed is the
*shape* of your setup.

The TOML file always exposes, in plaintext:

- The profile names (`[profiles.foo]`, `[profiles.bar]`, …).
- The backend type per profile (`backend = "s3" | "rest" | "local"`).
- All public backend fields: `local_path`, `rest_url`, `s3_endpoint`,
  `s3_bucket`, `s3_region`, `s3_root`.
- Schema metadata: `version`, `cipher` marker.
- The `[passphrase]` block (`instance`, `instance_sig`,
  `salt`). The instance is a user-chosen label; the signature and salt are
  useless without the passphrase.

Everything else (repo passwords, REST user/password, S3 access/secret
keys) sits behind `$WR;1.0;CHACHA20-POLY1305;` and is unreadable without the passphrase.

The key is never on disk; the `[passphrase]` block is metadata, not
material. An attacker with only `config.toml` would need to brute-force
the passphrase through wrustic's scrypt parameters and then pass the
HMAC check.

### What's still in scope for a config-only leak

Even with the secret fields encrypted, an exfiltrated `config.toml`
tells an attacker:

- Which storage backends you use and where (S3 buckets, REST endpoints,
  local paths). That's a target list — they know where to look if they
  later obtain credentials.
- Your profile count and naming conventions.

If that metadata is itself sensitive, treat `config.toml` like any
other secret file and encrypt the backup container.

## Key derivation

The 32-byte AEAD key is derived from the user's passphrase with
**scrypt**. The browser encrypts the passphrase to the localhost server
using the transport envelope described below; the Rust server then derives
the config key:

```
key = scrypt(passphrase, salt, log_n=16, r=8, p=1, len=32)
```

The salt is generated once at Setup (`random_bytes(32)`) and stored in
`[passphrase].salt` so subsequent unlocks regenerate the same key.

The passphrase is not sent in plaintext and is never written to disk. It
does exist in Rust process memory long enough for scrypt to run. The App
keeps only the derived 32-byte config key for the session.

### Instance signature

At Setup, the server computes `HMAC-SHA256(instance, derived_key)` after
scrypt finishes. This is stored in `[passphrase].instance_sig`.

On Unlock, the server re-computes the HMAC from the derived key and
compares (constant-time) against the stored signature. A mismatch means
the passphrase is wrong — the user gets a clear error immediately instead
of a cryptic AEAD tag failure on the first `$WR;1.0;CHACHA20-POLY1305;` value.

### Encrypt / decrypt

```
$WR;1.0;CHACHA20-POLY1305;<instance>;<base64( nonce(12) || ciphertext || tag(16) )>
```

The header fields are semicolon-delimited: app identifier, format
version, algorithm, and the passphrase instance name. The instance is
the same DNS-safe label from the `[passphrase]` block, making each
encrypted value self-documenting about which config it belongs to.

- 12-byte nonce from `OsRng` (chacha20poly1305's `generate_nonce`). Each
  encrypt mints a fresh nonce — there is no nonce reuse window even
  within a single save.
- ChaCha20-Poly1305 with the 32-byte scrypt-derived config key.
- 16-byte Poly1305 tag appended (the AEAD construction does this; the
  encrypted blob's last 16 bytes are the tag).

Decrypt strips the header and instance field, then requires
`len(payload) >= 28` (12 nonce + 16 tag), splits off the nonce, runs
`cipher.decrypt`, returns the UTF-8 plaintext. Tag failure = hard error.

### Why not whole-file passphrase encryption?

The passphrase ceremony is interactive and 30-minute-bounded (see
[Passphrase ceremony server](#passphrase-ceremony-server) below). Whole-file
encryption would force a ceremony for any `peek()` lookup, including the
one needed to decide whether to do a Setup or an Unlock — boot would be
impossible without already having unlocked. Per-value lets the boot code
peek at the `[passphrase]` block first, then pick the right ceremony, then
decrypt everything else with the resulting key.

## Passphrase input

### Two modes: terminal (default) and browser

By default, wrustic prompts for passphrase input directly in the terminal.
Adding `--browser-auth` switches to a browser-based ceremony where the
user enters the passphrase on a localhost page instead.

| Mode | Flag | Setup flow | Unlock flow |
|------|------|-----------|-------------|
| Terminal (default) | (none) | Instance prompt → passphrase + confirm → scrypt | Passphrase prompt → scrypt → HMAC verify |
| Browser | `--browser-auth` | Instance prompt → browser URL + setup code → scrypt | Browser URL → passphrase → scrypt → HMAC verify |

### Terminal passphrase input (default)

**Setup** (`Screen::PassphraseSetup`): after the instance name prompt,
two masked fields — "Passphrase" and "Confirm passphrase" — are shown in
a grouped input. The same passphrase policy from the browser flow applies
(min 12 chars, uppercase, lowercase, digit, special char). On submit,
scrypt runs synchronously on `Screen::PassphraseDerivingKey` (same
pattern as `Screen::Verifying`), the HMAC instance signature is computed,
and the `[passphrase]` block is saved to config.toml.

**Unlock** (`Screen::PassphraseUnlock`): a single masked passphrase
field. On submit, scrypt derives the key with the stored salt, then
`verify_instance_sig` checks the HMAC. On mismatch the error says
"Wrong passphrase (or config.toml was corrupted)." and returns to the
input. On match, the config is decrypted and the app proceeds to Home.

No setup code is used in terminal mode — the passphrase is entered
directly by the user at the terminal.

### Browser passphrase ceremony (`--browser-auth`)

### Runtime shape

Same skeleton as `src/share.rs`:

- One OS thread spawned in `passphrase::start()`, one
  `tokio::runtime::Builder::new_current_thread()` per thread. No shared
  executor, no global runtime.
- Bind on `127.0.0.1:<port>` (the binary's `--port`, default 7834, shared
  with the share dialog because the two flows are never simultaneously
  active). User-facing URL uses `<instance>.wrustic.localhost`.
- Returns a `PassphraseHandle { short_url, setup_code, phase, rx, deadline,
  shutdown_tx, join_handle }` that owns the resources. Drop sends the
  shutdown oneshot; explicit `.stop()` also joins the thread (port
  released by the time it returns).

The handle and the App communicate via `std::sync::mpsc`:
`PassphraseOutcome { key: [u8; 32], new_meta: Option<PassphraseMeta> }`.
The main loop polls `App::try_advance_passphrase()` every 150 ms while
`Screen::PassphraseUrl` is active, so the ceremony can complete without a
keypress. `new_meta` is `Some` only on Setup — Unlock reuses the on-disk
`[passphrase]` block.

### Host header validation

The server validates the `Host` header on every request, matching the
hostname portion (port stripped) case-insensitively against the expected
`<instance>.wrustic.localhost`. Requests with a missing or mismatched
Host header receive a flat 404 — indistinguishable from a wrong auth key.
This mirrors nginx virtual-host matching (hostname only, port ignored)
and prevents DNS rebinding attacks from reaching the ceremony routes.

### Capability URL

The entire server lives under one prefix, chosen by phase:

```
Setup:  http://<instance>.wrustic.localhost:<port>/setup/<short_id>
Unlock: http://<instance>.wrustic.localhost:<port>/auth/<short_id>
```

`<short_id>` is a 16-hex-char (64-bit) random id generated at
`start()`. **It is the auth credential, not a decoration.** Every
request is gated by a constant-time bytewise compare of the URL's key
segment against `ctx.short_id` (`ct_eq` in `src/passphrase.rs`). On
mismatch — including bare `/`, the wrong prefix, the wrong key, or any
unrecognized path — the response is a flat 404, no information leakage.

This mirrors the share dialog's model: the URL is the capability. A
port scanner sees the same 404 wall whether the server is live or
expired.

Routes under the correct prefix + key (any other path still 404s):

| Method + path | Response |
|---|---|
| `GET /<prefix>/<key>` or `/<prefix>/<key>/` | 200 + the inline ceremony HTML |
| `POST /<prefix>/<key>/api/check-code` (Setup phase) | encrypted JSON `{setup_code}` → no outcome |
| `POST /<prefix>/<key>/api/setup` (Setup phase) | encrypted binary `version(1) + code_len(1) + code(N) + passphrase` → derive key and deliver outcome |
| `POST /<prefix>/<key>/api/unlock` (Unlock phase) | encrypted passphrase bytes → derive key and deliver outcome after HMAC verification |

The auth-key check runs **before** the expiry check by design: an
unauthenticated caller never gets to distinguish "running" from
"expired" — both look like 404.

### Two phases: Setup and Unlock (browser mode)

The phase is picked at boot by `config::peek`:

- **No `config.toml` (or no `[passphrase]` block)** →
  `PassphrasePhase::Setup`. The TUI prompts for an instance name on
  `Screen::PassphraseInstancePrompt` (pre-filled with the config dir's
  basename if it's DNS-safe), then launches the ceremony server. The
  browser page renders a passphrase form with two inputs (passphrase +
  confirm), complexity validation, and a setup-code input (see below).
  On submit: the browser posts the setup code and passphrase through the
  encrypted transport. The server enforces the same passphrase policy as
  the page, derives the config key with scrypt, computes the instance
  HMAC signature, and delivers `PassphraseOutcome { key, new_meta:
  Some(PassphraseMeta { instance, instance_sig, salt }) }`. The App
  splices the meta into `self.config.passphrase` and immediately calls
  `config::save` so the `[passphrase]` block lands on disk — next launch
  routes into Unlock.

- **`[passphrase]` block already present** → `PassphrasePhase::Unlock`.
  Server reads the instance, salt, and instance_sig from the stored
  metadata. The browser page renders a single passphrase input. On submit:
  the browser posts the passphrase through the encrypted transport. The
  server derives the key with scrypt using the stored salt, then verifies
  `HMAC-SHA256(instance, derived_key)` against the
  stored `instance_sig` (constant-time). On mismatch → 401 "Wrong
  passphrase", the user can retry. On match → server delivers
  `PassphraseOutcome { key, new_meta: None }`. App uses the key to
  decrypt every `$WR;1.0;CHACHA20-POLY1305;` value in the config. No setup code on Unlock — the
  instance signature verification already gates the path.

### Setup-confirmation code

In addition to the `/auth/<key>` capability URL, the **Setup** phase
prints a 6-character code in the TUI that the user must type into the
browser before the passphrase submission will be accepted. Unlock
has no equivalent — the instance signature verification already gates
that path.

Why this exists: the capability URL is enough for *access control*
(only someone who saw the TUI can reach the ceremony page), but it
doesn't prove the user-at-terminal *intended* to set a passphrase right
now. A pre-loaded browser tab, a stale URL pasted into the wrong window,
or a clipboard timing accident could otherwise drive the ceremony past
the user. The code is an intent-confirmation gesture, like a sudo prompt.

**Alphabet (31 chars).** Uppercase letters and digits only, with the
well-known confusables removed so a misread can't trip a strike:

- Digits `2`–`9` (excludes `0` and `1` — visually collide with `O` and
  `I`/`L`).
- Uppercase `A`–`Z` excluding `I`, `L`, `O`.

Code space: `31^6 ≈ 8.87 × 10^8`. The strike limit (below) caps total
guess probability per ceremony at `MAX_SETUP_CODE_ATTEMPTS / 31^6 ≈
5.6 × 10^-9`.

**Source of truth:** `SETUP_CODE_ALPHABET` and `random_setup_code()`
in `src/passphrase.rs`. The generator uses `rand` to sample each
character uniformly from the alphabet.

**Input handling.** Both the browser and the server normalize the
submitted code by stripping whitespace and uppercasing. The comparison
is constant-time (`ct_eq`). The browser input carries
`autocapitalize="characters"` and `text-transform: uppercase`.

**Pre-flight check.** The browser pre-validates the code with the
server *before* sending the passphrase, via
`POST /setup/<key>/api/check-code` with body `{"setup_code": "..."}`.
This way a wrong code surfaces immediately. The subsequent
`POST /api/setup` re-validates the same code, and both routes share
the same `check_setup_code` helper and the same strike counter.

**Lock-out.** Five wrong codes in one ceremony — counted across
**both** `/api/check-code` and `/api/setup` combined — trip a `killed`
flag on the server's `Ctx`. From that moment forward every keyed route
returns 403; the user has to quit wrustic and relaunch to get a fresh
code.

**Display.** The code is printed tight (no inter-character padding) on
the Passphrase screen when phase is Setup:

```
Setup code (type this in the browser):

    K4M9XR
```

Suppressed when the screen is in its expired state.

### 30-minute expiry net

`PASSPHRASE_TTL = 30 minutes`, captured at `start()` as
`deadline: Instant`. After expiry the server **keeps accepting
connections** (so a stale browser tab gets a clear 403 instead of a
confusing "connection refused"), but every keyed route returns 403.

The TUI checks the same `deadline` via `PassphraseHandle::is_expired()`
and switches the screen to a red "session expired" message. Quit +
relaunch is the only recovery — no flow logic for in-place renewal.

Ordering inside `handle()`:

1. Host header check (404 on miss — DNS rebinding rejected silently).
2. Auth-key check (404 on miss — unauthenticated scanners learn nothing).
3. Killed / expiry check (403 on miss — only legitimate callers ever see
   this).
4. Route dispatch.

### HTML and JS

The ceremony page is an Askama template in `templates/passphrase.html`.
There is no static-file routing; `src/passphrase.rs` renders the template
directly into the response body.

The inline `<script>`:
- Derives `API_BASE` from `window.location.pathname` (with a trailing-
  slash strip) so `fetch` targets stay under `/<prefix>/<key>/api/…`
  without needing the key templated into the HTML.
- On Setup: renders two password inputs (passphrase + confirm), a
  complexity check (min 12 chars, uppercase, lowercase, digit, special
  char), and a setup-code input. The browser checks the code before
  sending the passphrase; the server re-checks both the code and the
  passphrase policy before deriving a key.
- On Unlock: renders a single password input. No complexity check, no
  setup code.
- On Setup: builds a binary payload:
  `version(1) + code_len(1) + code(N) + passphrase`.
- On Unlock: sends the raw passphrase bytes.
- Wraps every `/api/*` POST body in the transport-encryption envelope
  described below.
- Disables all buttons on success so a second click can't re-submit
  (the server would also reject with 409 "already provided this session").
- Zeroes temporary key buffers best-effort via `fill(0)`.

The HTML response carries a per-page CSP nonce:

```
Content-Security-Policy:
  default-src 'none';
  script-src 'nonce-…';
  connect-src 'self';
  base-uri 'none';
  form-action 'none';
  frame-ancestors 'none'
```

Template values embedded in JavaScript strings escape `<`, `>`, `&`, and
the usual JSON string characters so injected constants cannot terminate
the trusted inline script.

### Transport encryption (browser ↔ server)

Even though the ceremony server only binds to `127.0.0.1`, the loopback
interface is not perfectly isolated: another local process running as
root or with `CAP_NET_RAW` can sniff loopback, a malicious browser
extension can read `fetch` request bodies, and devtools-history /
proxy-style inspectors capture full requests. To avoid putting the
passphrase on the wire as plaintext, every `/api/*` POST body is
wrapped in an authenticated encryption envelope under a fresh per-request
key.

**Protocol.** At `start()` the server generates an ephemeral X25519
keypair (`ServerTransport::generate` in `src/passphrase.rs`). The private
half lives in `Ctx` for the ceremony's lifetime; the public half is
base64'd and inlined into the HTML as the JS const `SERVER_PUB_B64`.
For each request the browser generates its own ephemeral X25519 keypair
(`crypto.subtle.generateKey({ name: "X25519" }, false, …)` — private
imported `extractable: false`), does
`ECDH(server_pub, client_priv)` directly into a non-extractable HKDF
`CryptoKey`, runs it through HKDF-SHA256 with empty salt and
`info = b"wrustic-passphrase-transport-v1"` to derive a 32-byte AES-256-GCM
key (`extractable: false`), and encrypts the route body with a random
12-byte nonce. The outer wire format is:

```json
{
  "client_pub": "<base64 32 bytes>",
  "nonce":      "<base64 12 bytes>",
  "ciphertext": "<base64 N+16 bytes — AES-GCM ct||tag>"
}
```

The server runs the mirror routine in `ServerTransport::decrypt`,
checks the GCM tag (so a flipped bit in transit is a hard 400, not a
silent corruption), then hands the inner plaintext to the existing
per-route parser (`CheckCodeBody`, `parse_setup_body`, `parse_unlock_body`).
Response bodies are plaintext on purpose: errors don't carry secrets,
and success bodies only report `{"ok": true}`.

**Non-extractable browser keys.** The client's X25519 private key, the
transport HKDF key, and the transport AES-GCM key are all
`extractable: false`. An attacker inside the ceremony page can still
invoke WebCrypto while the page is alive, but cannot `exportKey` those
values as raw bytes.

**What this doesn't defend against.**
- An attacker who controls the wrustic process itself (they have the
  server private key and receive the passphrase by definition).
- An attacker who can serve their own HTML at `/auth/<key>` (they'd
  already need to be the wrustic server).
- The browser process being compromised (extensions are mitigated
  somewhat by `extractable: false`, but a sufficiently privileged
  extension can still drive the page).

**Browser support.** WebCrypto `X25519` became broadly available in
2025: Chrome 133+, Firefox 130+, Safari 18.4+.

**Algorithm choice.**
- X25519 over P-256 ECDH: smaller key, single fixed curve, faster, no
  parameter-confusion footguns.
- AES-256-GCM over ChaCha20-Poly1305: WebCrypto doesn't expose
  ChaCha20-Poly1305, so AES-GCM is the only AEAD that works on both
  ends without a userland JS implementation. The Rust side pulls
  `aes-gcm = "0.10"` to match.
- Empty HKDF salt: the ECDH shared secret is already uniformly random
  and unique per request; a versioned `info` string handles algorithm
  cutover instead.
- scrypt for key derivation: the KDF runs in Rust, so WebCrypto support no
  longer constrains the algorithm choice. scrypt is memory-hard and is
  already part of the restic/rustic ecosystem. wrustic uses
  `log_n=16, r=8, p=1`, which requires roughly 64 MiB for each password
  guess before the HMAC or AEAD tags can be checked.

**Replay.** Each ceremony has a fresh server keypair (30-min lifespan),
each request a fresh client keypair, so every shared secret is unique
and a captured ciphertext can't be decrypted after the ceremony ends
or replayed against a future one.

**No body-size hiding.** The envelope leaks the inner plaintext length
(approximately ciphertext length minus 16 bytes for the tag). For
passphrase submissions, that means a local observer who can see request
sizes can estimate passphrase length. The passphrase contents remain
encrypted.

### What the server does *not* do

- No persistence of the passphrase or derived key on disk. Only the salt,
  instance, and instance signature are written. The passphrase exists
  transiently while the server derives the key; the 32-byte config key
  lives in the App's memory for the session.
- No CORS / no auth header / no cookies. The capability URL is the
  whole auth surface.

## Share dialog signing key

The share server (`src/share.rs`) signs URLs with HMAC-SHA256 over
`(snap_id, tree_id, name, exp)`. The 32-byte signing key is derived via
`passphrase::derive_share_signing_key(config_key)` — SHA-256 over
`"wrustic-share-v1\0" || config_key`.

Same key per identity (no per-session randomness) → share URLs stay valid
across wrustic restarts within their 1-hour TTL. Different passphrase →
different key, so URLs minted under one passphrase cannot be replayed
against a server started under another.

This signing key is independent of `Cipher`: a tampered URL fails HMAC
verification before the server ever touches a `Cipher::decrypt`.

## Threat model and non-goals

wrustic assumes a single-user, single-device deployment. The encryption
is sized for "the config file leaves the device" scenarios, not for
"there are hostile users on the same device" scenarios.

In scope:
- **Config exfiltration off-device.** A copy of `config.toml` that ends
  up in cloud sync, a generic file-share, a publicly readable backup,
  or a misconfigured snapshot does not by itself leak the secret
  fields. The attacker would need the passphrase (subject to scrypt
  brute-force resistance).
- **Mid-save corruption.** Atomic rename leaves the previous config
  intact even if the process is killed mid-write.

Not in scope:
- **Hostile local accounts on the same machine.** wrustic doesn't
  defend against this — single-user scope.
- **Root / disk-image access.** Anyone with raw disk access or the
  passphrase can decrypt the config. Use full-disk
  encryption if that matters.
- **Memory disclosure** (core dumps, ptrace, swap). Cipher key bytes are
  ordinary heap memory — not `mlock`ed, not zeroized on drop.
- **Repo-level secrecy.** This is about `config.toml`, not about the
  restic repository itself. Restic has its own password (which wrustic
  stores encrypted in the per-profile `password` field) and its own
  at-rest encryption.

For the surrounding system shape (boot flow, the share dialog, the runtime
loop), see [architecture.md](architecture.md).
