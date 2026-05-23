# Encryption

Per-value secret encryption for `config.toml`, plus the passphrase ceremony
server that derives the passphrase-mode key.

**Scope: single-user, single-device.** wrustic is a personal tool — one
person, one machine. There is no multi-user threat model, no privilege
separation inside the binary, no defense-in-depth against another local
account on the same machine. Everything below — file permissions,
localhost-only servers, in-memory key handling — is sized for that
scope. If you need a multi-tenant secret store, this isn't it.

Two ciphers are supported and are deliberately non-interoperable; the one
a config was created with is the one it stays in for its lifetime.

| Cipher | Prefix | Algorithm | Key source | Status |
|---|---|---|---|---|
| `Cipher::Age` | `ageenc:` | age x25519 (single recipient) | `<config-dir>/age.key`, mode 0600 | default |
| `Cipher::Passphrase` | `pkenc:` | ChaCha20-Poly1305 AEAD | PBKDF2-SHA256-derived config key from user passphrase, never on disk | experimental, gated behind `--experimental-passphrase` |

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
cipher  = "age-v1"           # or "passphrase-v1" — required, no default
recipient = "age1…"          # age mode only; omitted in passphrase mode

[profiles.<name>]
backend  = "local" | "rest" | "s3"
password = "ageenc:…"        # or "pkenc:…" depending on mode
# plus backend-specific fields (some encrypted, some not — see table above)

[passphrase]                 # passphrase mode only
subdomain     = "<text>"     # DNS-safe subdomain (max 32 chars)
subdomain_sig = "<base64>"   # HMAC-SHA256(subdomain, derived_key)
salt          = "<base64>"   # random 32-byte PBKDF2 salt
```

### Required fields and cross-mode safety

Two independent safety nets prevent a passphrase config from being opened in
age mode (or vice versa):

1. **`cipher` is mandatory.** The `Config::cipher` field has no
   `#[serde(default)]`, so a TOML without that key fails to parse — there
   is no silent fallback. The accepted values are `"age-v1"` and
   `"passphrase-v1"` (constants in `src/config.rs`).
2. **`config::load` cross-checks the marker against the active `Cipher`.**
   Before any field is decrypted, `load` compares the on-disk marker against
   the `Cipher` variant the caller passed in. Mismatch → error with a hint
   about which flag to add or drop.

A *third* implicit check sits at the value level: `Cipher::decrypt` rejects
any value whose prefix doesn't match the active cipher. So even if both
above were bypassed, a `pkenc:` value would never be fed to age and vice
versa.

### `recipient` field (age mode only)

In age mode `recipient` holds the bech32 public key derived from
`age.key`. `load` checks it matches the identity file's derived recipient
before trusting any encrypted value. This catches the case where the
config and the key file have drifted apart (wrong dir, restored backup
mismatch, etc.).

In passphrase mode the field is omitted (`#[serde(skip_serializing_if =
"Option::is_none")]`) — there is no equivalent public key, and the
subdomain signature plus the AEAD's integrity tag together cover the
"correct key?" check at decrypt time.

### `[passphrase]` block (passphrase mode only)

```toml
[passphrase]
subdomain     = "mysite"
subdomain_sig = "<base64 HMAC-SHA256>"
salt          = "<base64 32-byte salt>"
```

- `subdomain` is the DNS-safe label chosen by the user at Setup (max 32
  chars, `[a-z0-9]([a-z0-9-]*[a-z0-9])?`). Used to construct the browser
  URL (`http://<subdomain>.wrustic.localhost:<port>/auth/<key>`).
- `subdomain_sig` is `HMAC-SHA256(subdomain, derived_key)`, base64-encoded.
  Verified on Unlock to give a fast "wrong passphrase" error before
  attempting full config decryption.
- `salt` is the random 32-byte PBKDF2 salt, base64-encoded. Generated once
  at Setup; the browser uses the same salt on every Unlock so the derived
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
*shape* of your setup, plus, in age mode, the public key needed to
target you.

The TOML file always exposes, in plaintext:

- The profile names (`[profiles.foo]`, `[profiles.bar]`, …).
- The backend type per profile (`backend = "s3" | "rest" | "local"`).
- All public backend fields: `local_path`, `rest_url`, `s3_endpoint`,
  `s3_bucket`, `s3_region`, `s3_root`.
- Schema metadata: `version`, `cipher` marker.
- Age mode: the `recipient` bech32 public key.
- Passphrase mode: the `[passphrase]` block (`subdomain`, `subdomain_sig`,
  `salt`). The subdomain is a user-chosen label; the signature and salt are
  useless without the passphrase.

Everything else (repo passwords, REST user/password, S3 access/secret
keys) sits behind `ageenc:` or `pkenc:` and is unreadable without the
matching key.

### Practical guidance per mode

**Age mode** — backing up *just* `config.toml` is safe in the secrets
sense, but worth noting:

- The `recipient` public key in the file points at the age identity an
  attacker would need to obtain. If they breach the host where
  `age.key` lives, they pair the two and recover everything.
- **Don't back up `age.key` alongside `config.toml` in the same
  unencrypted blob** — that's equivalent to backing up the secrets in
  plaintext. Either keep `age.key` out of the backup, or wrap the backup
  itself in another layer.

**Passphrase mode** — the key is never on disk; the `[passphrase]` block
is metadata, not material. An attacker with only `config.toml` would need
to brute-force the passphrase through 600,000 iterations of PBKDF2 and
then pass the HMAC check.

### What's still in scope for a config-only leak

Even with the secret fields encrypted, an exfiltrated `config.toml`
tells an attacker:

- Which storage backends you use and where (S3 buckets, REST endpoints,
  local paths). That's a target list — they know where to look if they
  later obtain credentials.
- Your profile count and naming conventions.

If that metadata is itself sensitive, treat `config.toml` like any
other secret file and encrypt the backup container.

## age cipher (`Cipher::Age`)

### Identity file format

`age.key` is sops-style: optional `# comment` lines, then exactly one
`AGE-SECRET-KEY-…` line. wrustic refuses files containing two or more
identity lines — keeping the recipient unambiguous matters for the
`recipient` cross-check on load.

`config::generate_identity` writes the file with `O_CREAT|O_EXCL` and
`mode 0600`, so it can't silently overwrite an existing key. The bech32
public key is included as a `# public key: …` comment for human readers.

### Encrypt / decrypt

```
ageenc:<base64( age::encrypt(recipient, plaintext) )>
```

Each value is encrypted independently with `age::encrypt` (single
recipient, no passphrase). The age stream header and AEAD body together
form the base64 payload after the prefix. There is no separate nonce
field because age generates its own internally.

Decrypt is the inverse: strip prefix, base64-decode, `age::decrypt` with
the loaded `Identity`. Failure modes bubble up as `anyhow::Error` and end
up on the boot Error screen.

## Passphrase cipher (`Cipher::Passphrase`)

### Key derivation

The 32-byte AEAD key is derived from the user's passphrase via
**PBKDF2-SHA256** with 600,000 iterations. The derivation runs entirely
in the browser via WebCrypto:

```
key_material = importKey("raw", encode(passphrase), "PBKDF2", false, ["deriveBits"])
key          = PBKDF2(key_material, salt, iterations=600000, hash="SHA-256", len=256)
```

The salt is generated once at Setup (`random_bytes(32)`) and stored in
`[passphrase].salt` so subsequent unlocks regenerate the same key.

The passphrase never leaves the browser. Only the derived 32-byte config
key is exported and sent through the encrypted localhost transport; the
App keeps that key in memory for the session only.

### Subdomain signature

At Setup, the browser also computes `HMAC-SHA256(subdomain, derived_key)`
and sends the 32-byte signature alongside the config key. This is stored
in `[passphrase].subdomain_sig`.

On Unlock, the server re-computes the HMAC from the received key and
compares (constant-time) against the stored signature. A mismatch means
the passphrase is wrong — the user gets a clear error immediately instead
of a cryptic AEAD tag failure on the first `pkenc:` value.

### Encrypt / decrypt

```
pkenc:<base64( nonce(12) || ciphertext || tag(16) )>
```

- 12-byte nonce from `OsRng` (chacha20poly1305's `generate_nonce`). Each
  encrypt mints a fresh nonce — there is no nonce reuse window even
  within a single save.
- ChaCha20-Poly1305 with the 32-byte PBKDF2-derived config key.
- 16-byte Poly1305 tag appended (the AEAD construction does this; the
  encrypted blob's last 16 bytes are the tag).

Decrypt requires `len(payload) >= 28` (12 nonce + 16 tag), splits off the
nonce, runs `cipher.decrypt`, returns the UTF-8 plaintext. Tag failure =
hard error.

### Why not whole-file passphrase encryption?

The passphrase ceremony is interactive and 30-minute-bounded (see
[Passphrase ceremony server](#passphrase-ceremony-server) below). Whole-file
encryption would force a ceremony for any `peek()` lookup, including the
one needed to decide whether to do a Setup or an Unlock — boot would be
impossible without already having unlocked. Per-value lets the boot code
peek at the `[passphrase]` block first, then pick the right ceremony, then
decrypt everything else with the resulting key.

## Passphrase ceremony server

The passphrase-mode AEAD key comes from a browser ceremony where the user
enters their passphrase. wrustic itself can't safely prompt for a
passphrase in the terminal (clipboard attacks, shoulder surfing on a
shared screen session), so `src/passphrase.rs` stands up a small localhost
server, prints the URL in the TUI, and waits for the browser to POST the
derived config key back through an encrypted localhost envelope. This
section covers the server's shape; the cryptographic mechanics are in the
[Passphrase cipher](#passphrase-cipher-cipherpassphrase) section above.

### Gating

Only available when both flags are present:

- `--experimental-passphrase` opts in.
- `--config-dir <path>` must also be passed (no default `~/.config/wrustic`
  fallback while the feature is experimental, so it can't silently
  shadow a real config).

The CLI parser hard-fails if `--experimental-passphrase` is set without
`--config-dir`.

### Runtime shape

Same skeleton as `src/share.rs`:

- One OS thread spawned in `passphrase::start()`, one
  `tokio::runtime::Builder::new_current_thread()` per thread. No shared
  executor, no global runtime.
- Bind on `127.0.0.1:<port>` (the binary's `--port`, default 7834, shared
  with the share dialog because the two flows are never simultaneously
  active). User-facing URL uses `<subdomain>.wrustic.localhost`.
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
`<subdomain>.wrustic.localhost`. Requests with a missing or mismatched
Host header receive a flat 404 — indistinguishable from a wrong auth key.
This mirrors nginx virtual-host matching (hostname only, port ignored)
and prevents DNS rebinding attacks from reaching the ceremony routes.

### Capability URL: only `/auth/<key>/…`

The entire server lives under one prefix:

```
http://<subdomain>.wrustic.localhost:<port>/auth/<short_id>
```

`<short_id>` is a 16-hex-char (64-bit) random id generated at
`start()`. **It is the auth credential, not a decoration.** Every
request is gated by a constant-time bytewise compare of the URL's key
segment against `ctx.short_id` (`ct_eq` in `src/passphrase.rs`). On
mismatch — including bare `/`, `/auth/`, the wrong key, or any path
that doesn't start with `/auth/` — the response is a flat 404, no
information leakage.

This mirrors the share dialog's model: the URL is the capability. A
port scanner sees the same 404 wall whether the server is live or
expired.

Routes under the correct key (any other path under the correct key
still 404s):

| Method + path | Response |
|---|---|
| `GET /auth/<key>` or `/auth/<key>/` | 200 + the inline ceremony HTML |
| `POST /auth/<key>/api/check-code` (Setup phase) | encrypted JSON `{setup_code}` → no outcome |
| `POST /auth/<key>/api/setup` (Setup phase) | encrypted binary `{setup_code, subdomain_sig, config_key}` → deliver outcome |
| `POST /auth/<key>/api/unlock` (Unlock phase) | encrypted 32-byte `config_key` → deliver outcome (after HMAC verification) |

The auth-key check runs **before** the expiry check by design: an
unauthenticated caller never gets to distinguish "running" from
"expired" — both look like 404.

### Two phases: Setup and Unlock

The phase is picked at boot by `config::peek`:

- **No `config.toml` (or no `[passphrase]` block)** →
  `PassphrasePhase::Setup`. The TUI prompts for a subdomain on
  `Screen::PassphraseSubdomainPrompt` (pre-filled with the config dir's
  basename if it's DNS-safe), then launches the ceremony server. The
  browser page renders a passphrase form with two inputs (passphrase +
  confirm), complexity validation, and a setup-code input (see below).
  On submit: the browser derives the key via PBKDF2, computes the
  subdomain HMAC signature, and posts both through the encrypted transport.
  The server delivers `PassphraseOutcome { key, new_meta:
  Some(PassphraseMeta { subdomain, subdomain_sig, salt }) }`. The App
  splices the meta into `self.config.passphrase` and immediately calls
  `config::save` so the `[passphrase]` block lands on disk — next launch
  routes into Unlock.

- **`[passphrase]` block already present** → `PassphrasePhase::Unlock`.
  Server reads the subdomain, salt, and subdomain_sig from the stored
  metadata. The browser page renders a single passphrase input. On submit:
  the browser derives the key via PBKDF2 with the stored salt and posts it.
  The server verifies `HMAC-SHA256(subdomain, received_key)` against the
  stored `subdomain_sig` (constant-time). On mismatch → 401 "Wrong
  passphrase", the user can retry. On match → server delivers
  `PassphraseOutcome { key, new_meta: None }`. App uses the key to
  decrypt every `pkenc:` value in the config. No setup code on Unlock — the
  subdomain signature verification already gates the path.

### Setup-confirmation code

In addition to the `/auth/<key>` capability URL, the **Setup** phase
prints a 6-character code in the TUI that the user must type into the
browser before the passphrase submission will be accepted. Unlock
has no equivalent — the subdomain signature verification already gates
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
in `src/passphrase.rs`. The generator pulls 6 bytes from `/dev/urandom`
and maps each through `byte % 31`.

**Input handling.** Both the browser and the server normalize the
submitted code by stripping whitespace and uppercasing. The comparison
is constant-time (`ct_eq`). The browser input carries
`autocapitalize="characters"` and `text-transform: uppercase`.

**Pre-flight check.** The browser pre-validates the code with the
server *before* prompting for the passphrase, via
`POST /auth/<key>/api/check-code` with body `{"setup_code": "..."}`.
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

The ceremony page is one static `const` string in `src/passphrase.rs`. No
build step, no static-file routing — the response body is a string
literal.

The inline `<script>`:
- Derives `API_BASE` from `window.location.pathname` (with a trailing-
  slash strip) so `fetch` targets stay under `/auth/<key>/api/…`
  without needing the key templated into the HTML.
- On Setup: renders two password inputs (passphrase + confirm), a
  complexity check (min 12 chars, uppercase, lowercase, digit, special
  char), and a setup-code input. The code is pre-flight checked before
  key derivation begins.
- On Unlock: renders a single password input. No complexity check, no
  setup code.
- Derives the config key via WebCrypto PBKDF2 (`deriveBits`, 600K
  iterations, SHA-256).
- On Setup: computes `HMAC-SHA256(subdomain, derived_key)` via WebCrypto
  and builds a binary payload:
  `version(1) + code_len(1) + code(N) + subdomain_sig(32) + config_key(32)`.
- On Unlock: sends the raw 32-byte derived key.
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
the usual JSON string characters so a subdomain such as `</script>`
cannot terminate the trusted inline script.

### Transport encryption (browser ↔ server)

Even though the ceremony server only binds to `127.0.0.1`, the loopback
interface is not perfectly isolated: another local process running as
root or with `CAP_NET_RAW` can sniff loopback, a malicious browser
extension can read `fetch` request bodies, and devtools-history /
proxy-style inspectors capture full requests. To avoid putting the
derived config key on the wire as plaintext, every `/api/*` POST body is
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
and the only success-side leak the threat model worries about is the
derived config key, which lives only in the inbound direction.

**Non-extractable browser keys.** The client's X25519 private key, the
transport HKDF key, and the transport AES-GCM key are all
`extractable: false`. An attacker inside the ceremony page can still
invoke WebCrypto while the page is alive, but cannot `exportKey` those
values as raw bytes.

**What this doesn't defend against.**
- An attacker who controls the wrustic process itself (they have the
  server private key and receive the config key by definition).
- An attacker who can serve their own HTML at `/auth/<key>` (they'd
  already need to be the wrustic server).
- The browser process being compromised (extensions are mitigated
  somewhat by `extractable: false`, but a sufficiently privileged
  extension can still drive the page).

**Browser support.** WebCrypto `X25519` became broadly available in
2025: Chrome 133+, Firefox 130+, Safari 18.4+. PBKDF2 has been
available since much earlier (Chrome 37+, Firefox 34+, Safari 11+).
wrustic's passphrase mode is flagged `--experimental-passphrase` and
targets these versions.

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
- PBKDF2-SHA256 for key derivation: built into WebCrypto (unlike Argon2),
  widely supported, and 600K iterations provides adequate work factor.

**Replay.** Each ceremony has a fresh server keypair (30-min lifespan),
each request a fresh client keypair, so every shared secret is unique
and a captured ciphertext can't be decrypted after the ceremony ends
or replayed against a future one.

**No body-size hiding.** The envelope leaks the inner plaintext length
(≈ ciphertext length minus 16 bytes for the tag). For the routes here
the lengths are essentially fixed and known a priori (a 6-char setup
code, a 32-byte config key, etc.), so padding would add nothing.

### What the server does *not* do

- No persistence of the passphrase or derived key on disk. Only the salt,
  subdomain, and subdomain signature are written. The 32-byte config key
  lives in the App's memory for the session.
- No CORS / no auth header / no cookies. The capability URL is the
  whole auth surface.

## Share dialog signing key

The share server (`src/share.rs`) signs URLs with HMAC-SHA256 over
`(snap_id, tree_id, name, exp)`. The 32-byte signing key is derived from
the active cipher's material:

| Mode | Derivation |
|---|---|
| age | `derive_signing_key(age.key bytes)` — SHA-256 over the raw key file |
| passphrase | `passphrase::derive_share_signing_key(config_key)` — SHA-256 over `"wrustic-share-v1\0" \|\| config_key` |

Same key per identity (no per-session randomness) → share URLs stay valid
across wrustic restarts within their 1-hour TTL. Different identity →
different key, so URLs minted under one identity cannot be replayed
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
  fields. The attacker would need the matching `age.key` (age mode) or
  the passphrase (passphrase mode, subject to PBKDF2 brute-force
  resistance).
- **Cross-config mixing.** Passphrase configs cannot be opened in age mode
  and vice versa; URLs minted under one identity cannot be redeemed
  under another (covered by the share signing key and the AEAD's tag).
- **Mid-save corruption.** Atomic rename leaves the previous config
  intact even if the process is killed mid-write.

Not in scope:
- **Hostile local accounts on the same machine.** wrustic doesn't
  defend against this — single-user scope.
- **Root / disk-image access.** Anyone with raw disk access or with the
  key file / passphrase can decrypt the config. Use full-disk
  encryption if that matters.
- **Memory disclosure** (core dumps, ptrace, swap). Cipher key bytes are
  ordinary heap memory — not `mlock`ed, not zeroized on drop.
- **Repo-level secrecy.** This is about `config.toml`, not about the
  restic repository itself. Restic has its own password (which wrustic
  stores encrypted in the per-profile `password` field) and its own
  at-rest encryption.

For the surrounding system shape (boot flow, the share dialog, the runtime
loop), see [architecture.md](architecture.md).
