# Encryption

Per-value secret encryption for `config.toml`, plus the passkey ceremony
server that derives the passkey-mode key.

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
| `Cipher::Passkey` | `pkenc:` | ChaCha20-Poly1305 AEAD | WebAuthn PRF + HKDF-derived config key, never on disk | experimental, gated behind `--experimental-passkey` |

Source of truth: `src/crypto.rs`, `src/config.rs`, `src/passkey.rs`.

## Why per-value, not whole-file

`config.toml` is encrypted **field by field**, not as one blob. Each secret
field is a single line, base64-after-prefix. The trade-offs:

- ✅ `git diff config.toml` still works for non-secret edits (URLs, paths,
  bucket names, profile renames). Reviewing a config change doesn't require
  decrypting anything.
- ✅ Adding a new field doesn't force a re-encryption of every other field.
- ❌ The set of which fields are secret is hardcoded (see
  `config::encrypt_profile_fields`). New backends must opt fields in
  explicitly — there is no "encrypt everything by default" backstop.

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
cipher  = "age-v1"           # or "passkey-v1" — required, no default
recipient = "age1…"          # age mode only; omitted in passkey mode

[profiles.<name>]
backend  = "local" | "rest" | "s3"
password = "ageenc:…"        # or "pkenc:…" depending on mode
# plus backend-specific fields (some encrypted, some not — see table above)

[passkey]                    # passkey mode only — public WebAuthn identifiers
credential_id = "<base64>"
prf_salt      = "<base64>"
label         = "<text>"     # optional; informational only, not used in key derivation
```

### Required fields and cross-mode safety

Two independent safety nets prevent a passkey config from being opened in
age mode (or vice versa):

1. **`cipher` is mandatory.** The `Config::cipher` field has no
   `#[serde(default)]`, so a TOML without that key fails to parse — there
   is no silent fallback. The accepted values are `"age-v1"` and
   `"passkey-v1"` (constants in `src/config.rs`).
2. **`config::load` cross-checks the marker against the active `Cipher`.**
   Before any field is decrypted, `load` compares the on-disk marker against
   the `Cipher` variant the caller passed in. Mismatch → error with a hint
   about which flag to add or drop. (See `src/config.rs` `load` body.)

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

In passkey mode the field is omitted (`#[serde(skip_serializing_if =
"Option::is_none")]`) — there is no equivalent public key, and the
`[passkey]` block plus the AEAD's integrity tag together cover the
"correct key?" check at decrypt time.

### `[passkey]` block (passkey mode only)

```toml
[passkey]
credential_id = "<base64 raw_id>"
prf_salt      = "<base64 16-byte salt>"
label         = "<text>"          # optional, informational only
```

`credential_id` and `prf_salt` are **public** WebAuthn identifiers — no key
material here. They live inline in `config.toml` (rather than a separate
file) so:

- `config::peek` can read them without decrypting anything, which is what
  lets boot pick Setup vs Unlock before the cipher is even constructed
  (chicken-and-egg: you need the salt to run the ceremony, you need the
  ceremony to derive the cipher).
- Copying `config.toml` between machines that share the same passkey just
  works — the salt rides along.

`label` is the human-readable string the user typed in the Setup(Create)
flow, persisted so the Unlock screen can echo "this config was set up
with passkey label: foo" — useful when the user has several wrustic
passkeys in their password manager. It is **not used in any cryptographic
operation**: the encryption key is
`HMAC(authenticator hmac-secret, prf_salt)` only, and the credential is
addressed by `credential_id`. The authenticator independently stores its
own canonical copy of the label (as the credential's user.name /
user.displayName); the field here is just a wrustic-side mirror so the TUI
doesn't have to ask the authenticator. Absent for Setup(Import) configs
(we never asked the user) and for any configs written before this field
existed.

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
- Passkey mode: the `[passkey]` block (`credential_id`, `prf_salt`, and
  optionally `label`). The two id/salt fields are public WebAuthn
  identifiers — no key material. `label` is the human-readable name the
  user typed at Setup; it is also non-secret (the authenticator stores its
  own copy as `user.name`).

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
  plaintext. The whole point of the encryption falls away. Either keep
  `age.key` out of the backup, or wrap the backup itself in another
  layer (e.g. a passphrase-protected restic backup of the config dir).

**Passkey mode** — safer to back up because the key isn't on disk at
all. The `[passkey]` block is metadata, not material. To restore on
another machine you also need the passkey itself reachable there —
typically via your password manager's passkey sync, or a roaming
hardware authenticator that knows the credential.

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

## Passkey cipher (`Cipher::Passkey`)

### Key derivation

The 32-byte AEAD key is derived from the **WebAuthn PRF extension**
(`hmac-secret`). The browser/authenticator computes a deterministic HMAC
of the credential's secret with a salt we provide, then the ceremony page
imports that PRF output into WebCrypto as a non-extractable HKDF key and
derives the config key with a wrustic-specific label:

```
prf_output = HMAC_credentialSecret(prf_salt)       // computed by authenticator
master     = importKey("HKDF", prf_output, false)  // non-extractable CryptoKey
key        = HKDF-SHA256(master, info="wrustic-passkey-config-v1", len=32)
```

The salt is generated once at Setup (`random_bytes(16)`) and stored in
`[passkey].prf_salt` so subsequent unlocks regenerate the same key.

The authenticator's credential secret never leaves the passkey provider.
The WebAuthn PRF API does expose `prf.results.first` to page JavaScript as
an `ArrayBuffer`; wrustic imports those bytes into non-extractable WebCrypto
key material immediately and zeroes the temporary buffer best-effort. The
raw PRF output is not sent to the Rust process. Only the derived 32-byte
config key is exported at the last moment and sent through the encrypted
localhost transport; the App keeps that key in memory for the session only.

If the same passkey is used with a *different* salt (e.g. someone
manually edits `prf_salt` or copies a config from another machine without
the matching salt), the PRF output differs, ChaCha20-Poly1305's AEAD tag
verification fails on the first decrypt, and the user sees a clear error
on boot rather than silent corruption.

### Encrypt / decrypt

```
pkenc:<base64( nonce(12) || ciphertext || tag(16) )>
```

- 12-byte nonce from `OsRng` (chacha20poly1305's `generate_nonce`). Each
  encrypt mints a fresh nonce — there is no nonce reuse window even
  within a single save.
- ChaCha20-Poly1305 with the 32-byte HKDF-derived passkey config key.
- 16-byte Poly1305 tag appended (the AEAD construction does this; the
  encrypted blob's last 16 bytes are the tag).

Decrypt requires `len(payload) >= 28` (12 nonce + 16 tag), splits off the
nonce, runs `cipher.decrypt`, returns the UTF-8 plaintext. Tag failure =
hard error.

### Why not whole-file passkey encryption?

The passkey ceremony is interactive and 30-minute-bounded (see
[Passkey ceremony server](#passkey-ceremony-server) below). Whole-file
encryption would force a ceremony for any `peek()` lookup, including the
one needed to decide whether to *do* a Setup or an Unlock — boot would be
impossible without already having unlocked. Per-value lets the boot code
peek at the `[passkey]` block first, then pick the right ceremony, then
decrypt everything else with the resulting key.

## Passkey ceremony server

The passkey-mode AEAD key comes from a WebAuthn ceremony run by the
user's browser. wrustic itself can't talk to WebAuthn (it's a terminal
program), so `src/passkey.rs` stands up a small localhost server, prints
the URL in the TUI, and waits for the browser to POST the derived config
key back through an encrypted localhost envelope. This section covers the server's shape; the cryptographic
mechanics are in the [Passkey cipher](#passkey-cipher-cipherpasskey)
section above.

### Gating

Only available when both flags are present:

- `--experimental-passkey` opts in.
- `--config-dir <path>` must also be passed (no default `~/.config/wrustic`
  fallback while the feature is experimental, so it can't silently
  shadow a real config).

The CLI parser hard-fails if `--experimental-passkey` is set without
`--config-dir`.

### Runtime shape

Same skeleton as `src/share.rs`:

- One OS thread spawned in `passkey::start()`, one
  `tokio::runtime::Builder::new_current_thread()` per thread. No shared
  executor, no global runtime.
- Bind on `127.0.0.1:<port>` (the binary's `--port`, default 7834, shared
  with the share dialog because the two flows are never simultaneously
  active). User-facing URL uses `localhost` for browser/authenticator
  compatibility.
- Returns a `PasskeyHandle { short_url, phase, rx, deadline,
  shutdown_tx, join_handle }` that owns the resources. Drop sends the
  shutdown oneshot; explicit `.stop()` also joins the thread (port
  released by the time it returns).

The handle and the App communicate via `std::sync::mpsc`:
`PasskeyOutcome { key: [u8; 32], new_meta: Option<PasskeyMeta> }`. The
main loop polls `App::try_advance_passkey()` every 150 ms while
`Screen::PasskeyUrl` is active (`main.rs:277`), so the ceremony can
complete without a keypress. `new_meta` is `Some` only on Setup —
Unlock reuses the on-disk `[passkey]` block.

### Capability URL: only `/auth/<key>/…`

The entire server lives under one prefix:

```
http://localhost:<port>/auth/<short_id>
```

`<short_id>` is a 16-hex-char (64-bit) random id generated at
`start()`. **It is the auth credential, not a decoration.** Every
request is gated by a constant-time bytewise compare of the URL's key
segment against `ctx.short_id` (`ct_eq` in `src/passkey.rs`). On
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
| `POST /auth/<key>/api/setup` (Setup phase) | encrypted binary `{credential_id, setup_code, config_key}` → deliver outcome |
| `POST /auth/<key>/api/unlock` (Unlock phase) | encrypted 32-byte `config_key` → deliver outcome |

The auth-key check runs **before** the expiry check by design: an
unauthenticated caller never gets to distinguish "running" from
"expired" — both look like 404.

### Two phases: Setup and Unlock

The phase is picked at boot by `config::peek`:

- **No `config.toml` (or no `[passkey]` block)** → `PasskeyPhase::Setup`.
  Before the localhost server is even started, the TUI asks **Create vs.
  Import** on `Screen::PasskeySetupChoice`:

  - **Create** (`PasskeyPhase::Setup(SetupMode::Create)`) — the TUI
    advances to `Screen::PasskeyLabelPrompt` (pre-filled with the config
    dir's basename) and the submitted label is passed into
    `passkey::start(...)`. The label is embedded in the inline JS as a
    const (`USER_LABEL`); the WebAuthn `create()` call uses it as
    `user.name` and `user.displayName`, so the browser's passkey picker
    and the user's password manager label the entry distinctively (e.g.
    "wrustic" RP + "personal" user) instead of N identical "wrustic"
    entries across configs. The label is purely cosmetic — it has no
    role in decryption. wrustic stores a copy in `[passkey].label` only so
    the Unlock screen can remind the user which passkey label to pick; the
    authenticator keeps its own canonical credential metadata.
    The browser page renders a single *Create new passkey* button that
    calls `navigator.credentials.create()` with the PRF extension. Some
    authenticators don't return PRF during `create()`; the page
    transparently falls back to a follow-up `get()` against the
    just-created credential.

  - **Import** (`PasskeyPhase::Setup(SetupMode::Import)`) — the TUI
    skips the label prompt entirely (the existing credential carries
    its own label from creation time) and launches `passkey::start(...)`
    with `user_label = None`. The browser page renders a single *Use
    existing passkey* button that calls `navigator.credentials.get()`
    with no `allowCredentials`, so the browser presents every passkey
    valid for `localhost`. The user picks one, the browser requires user
    verification, and the page derives the key from its PRF using a fresh
    salt. The page carries a disclaimer
    explaining this still creates a *fresh* wrustic config under a new
    salt — it won't open another machine's existing config.

  Splitting the choice onto the TUI means the browser page never offers
  both buttons at once: the user has already committed by the time the
  ceremony page loads, which keeps the page focused on one flow and
  avoids the "label irrelevant to Import" awkwardness of asking for a
  label up front regardless of branch.

  - **Both flows are gated by the Setup-confirmation code** (see
    below). The browser refuses to even prompt the authenticator
    until a valid-shape code is in the input box, and the server
    refuses to deliver the outcome until the code matches.
  - On accepted POST: server delivers
    `PasskeyOutcome { key, new_meta: Some(PasskeyMeta { credential_id,
    prf_salt, label }) }`. The App splices the meta into `self.config.passkey`
    and immediately calls `config::save` so the `[passkey]` block
    lands on disk — next launch routes into Unlock.

- **`[passkey]` block already present** → `PasskeyPhase::Unlock`. Server
  presents the stored `credential_id` + `prf_salt` to the page, the
  browser does `.get()` against that exact credential with user verification
  required, derives the config key, and posts that key through the encrypted
  localhost transport. No setup code on Unlock — the existing `[passkey]`
  block plus the AEAD tag verification at first decrypt already prove the
  user knows the passkey. Server delivers
  `PasskeyOutcome { key, new_meta: None }`. App uses the key to
  decrypt every `pkenc:` value in the config.

### Setup-confirmation code

In addition to the `/auth/<key>` capability URL, the **Setup** phase
prints a 6-character code in the TUI that the user must type into the
browser before either Create or Use Existing will be accepted. Unlock
has no equivalent — the existing `[passkey]` block + AEAD already gate
that path.

Why this exists: the capability URL is enough for *access control*
(only someone who saw the TUI can reach the ceremony page), but it
doesn't prove the user-at-terminal *intended* to create or import a
passkey right now. A pre-loaded browser tab, a stale URL pasted into
the wrong window, or a clipboard timing accident could otherwise drive
the ceremony past the user. The code is an intent-confirmation
gesture, like a sudo prompt: "I see this number on my terminal right
now, here it is."

**Alphabet (31 chars).** Uppercase letters and digits only, with the
well-known confusables removed so a misread can't trip a strike:

- Digits `2`–`9` (excludes `0` and `1` — visually collide with `O` and
  `I`/`L`).
- Uppercase `A`–`Z` excluding `I`, `L`, `O`.

Code space: `31^6 ≈ 8.87 × 10^8`. Guess probability per attempt:
`~1.13 × 10^-9`. The strike limit (below) caps total guess probability
per ceremony at `MAX_SETUP_CODE_ATTEMPTS / 31^6 ≈ 5.6 × 10^-9` — still
many orders of magnitude below anything that would justify a longer
code or a wider alphabet for an intent-confirmation token.

**Source of truth:** `SETUP_CODE_ALPHABET` and `random_setup_code()`
in `src/passkey.rs`. The generator pulls 6 bytes from `/dev/urandom`
and maps each through `byte % 31`; the resulting modulo bias is well
below any security-relevant threshold for an intent-confirmation
token.

**Input handling.** Both the browser and the server normalize the
submitted code by stripping whitespace and uppercasing — the alphabet
is uppercase-only so case folding lets the user type either case
without it counting as wrong. The comparison itself is constant-time
(`ct_eq`). The browser input also carries `autocapitalize="characters"`
and `text-transform: uppercase` so what the user sees while typing
matches what the TUI printed.

**Pre-flight check.** The browser pre-validates the code with the
server *before* invoking `navigator.credentials.create()` / `.get()`,
via `POST /auth/<key>/api/check-code` with body `{"setup_code": "..."}`.
This way a wrong code surfaces immediately instead of after the user
has just authenticated against their device. The route never delivers
an outcome — it only succeeds (200) or fails (401 / 403). The
subsequent `POST /api/setup` re-validates the same code (the server
never trusts a "I pre-checked it" claim from the client), and both
routes share the same `check_setup_code` helper and the same strike
counter — so an attacker can't double the budget by alternating
endpoints.

**Lock-out.** Five wrong codes in one ceremony — counted across
**both** `/api/check-code` and `/api/setup` combined — trip a `killed`
flag on the server's `Ctx`. From that moment forward every keyed route
returns 403 with the same "expired or cancelled" message used for the
30-min TTL; the user has to quit wrustic and relaunch to get a fresh
code. This is a kill-switch (so a typo'd code doesn't keep the
ceremony exploitable indefinitely under the 30-min TTL), not
anti-brute-force entropy — the alphabet itself already makes brute
force impractical within the TTL.

**Display.** The code is printed tight (no inter-character padding —
spacing only invites typos) on the Passkey screen when phase is Setup:

```
Setup code (type this in the browser):

    K4M9XR
```

It's suppressed when the screen is in its expired state, since there's
no ceremony left to confirm at that point.

### 30-minute expiry net

`PASSKEY_TTL = 30 minutes`, captured at `start()` as
`deadline: Instant`. After expiry the server **keeps accepting
connections** (so a stale browser tab gets a clear 403 instead of a
confusing "connection refused"), but every keyed route returns:

```
403 Forbidden
Passkey ceremony expired (30 minute cap).
Quit wrustic in the terminal and relaunch to start a new ceremony.
```

The TUI checks the same `deadline` via `PasskeyHandle::is_expired()`
and switches the screen to a red "session expired" message. Quit +
relaunch is the only recovery — no flow logic for in-place renewal.

Ordering inside `handle()`:

1. Auth-key check (404 on miss — unauthenticated scanners learn
   nothing).
2. Expiry check (403 on miss — only legitimate callers ever see this).
3. Route dispatch.

### HTML and JS

The ceremony page is one static `const` string in `src/passkey.rs`. No
build step, no static-file routing — the response body is a string
literal.

The inline `<script>`:
- Derives `API_BASE` from `window.location.pathname` (with a trailing-
  slash strip) so `fetch` targets stay under `/auth/<key>/api/…`
  without needing the key templated into the HTML.
- Calls `navigator.credentials.create()` / `.get()` with
  `userVerification: "required"` and the PRF extension
  (`extensions: { prf: { eval: { first: prfSalt } } }`).
- Imports the PRF output into WebCrypto as a non-extractable HKDF key,
  derives the wrustic config key with `info =
  "wrustic-passkey-config-v1"`, zeroes the temporary PRF bytes best-effort,
  and only exports the derived config key because the Rust process needs it
  to decrypt `config.toml`.
- Wraps every `/api/*` POST body in the transport-encryption envelope
  described below — the derived config key never leaves the browser as
  plaintext on the wire, and the raw PRF output is not sent at all.
- Disables all buttons on success so a second click can't re-prompt
  the authenticator (the server would also reject the second POST with
  409 "already provided this session").

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
the usual JSON string characters so a passkey label such as `</script>`
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
keypair (`ServerTransport::generate` in `src/passkey.rs`). The private
half lives in `Ctx` for the ceremony's lifetime; the public half is
base64'd and inlined into the HTML as the JS const `SERVER_PUB_B64`.
For each request the browser generates its own ephemeral X25519 keypair
(`crypto.subtle.generateKey({ name: "X25519" }, false, …)` — private
imported `extractable: false`), does
`ECDH(server_pub, client_priv)` directly into a non-extractable HKDF
`CryptoKey`, runs it through HKDF-SHA256 with empty salt and
`info = b"wrustic-passkey-transport-v1"` to derive a 32-byte AES-256-GCM
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
transport HKDF key, the transport AES-GCM key, and the imported PRF
master key are all `extractable: false`. An attacker inside the ceremony
page can still invoke WebCrypto while the page is alive, but cannot
`exportKey` those values as raw bytes.

The PRF output itself comes out of WebAuthn as an `ArrayBuffer`, not a
`CryptoKey`, so it cannot be non-extractable at the instant the browser
returns it. wrustic imports it into non-extractable HKDF key material
immediately, zeroes the temporary buffer best-effort, and does not send
the raw PRF output to Rust. The derived config key must be exported so
the Rust process can decrypt `config.toml`; that exported key is placed
inside the X25519/AES-GCM transport envelope before it crosses localhost.

**What this doesn't defend against.**
- An attacker who controls the wrustic process itself (they have the
  server private key and receive the config key by definition).
- An attacker who can serve their own HTML at `/auth/<key>` (they'd
  already need to be the wrustic server — there's no separate user
  agent doing TLS to verify the server identity, only the capability
  URL).
- The browser process being compromised (extensions are mitigated
  somewhat by `extractable: false`, but a sufficiently privileged
  extension can still drive the page).

**Browser support.** WebCrypto `X25519` became broadly available in
2025: Chrome 133+ (Feb 2025), Firefox 130+ (Sept 2024), Safari 18.4+
(March 2025). wrustic's passkey mode is flagged `--experimental-
passkey` and explicitly targets these versions; if `crypto.subtle.
generateKey({ name: "X25519" }, …)` rejects, the page shows the error
unchanged ("This browser does not support X25519").

**Algorithm choice.**
- X25519 over P-256 ECDH: smaller key, single fixed curve, faster, no
  parameter-confusion footguns. The corresponding WebCrypto API is
  the late arrival that finally made it usable in the browser.
- AES-256-GCM over ChaCha20-Poly1305: WebCrypto doesn't expose
  ChaCha20-Poly1305, so AES-GCM is the only AEAD that works on both
  ends without a userland JS implementation. The Rust side pulls
  `aes-gcm = "0.10"` (≈ 30 KB compiled) to match.
- Empty HKDF salt: the ECDH shared secret is already uniformly random
  and unique per request; adding a salt would just be ceremony. A
  versioned `info` string handles algorithm cutover instead.
- The config-key HKDF also uses an empty salt because the WebAuthn PRF
  output is already high-entropy secret material bound to `[passkey].prf_salt`;
  the versioned `info = "wrustic-passkey-config-v1"` domain-separates it
  from any future PRF uses.

**Replay.** Each ceremony has a fresh server keypair (30-min lifespan),
each request a fresh client keypair, so every shared secret is unique
and a captured ciphertext can't be decrypted after the ceremony ends
or replayed against a future one.

**No body-size hiding.** The envelope leaks the inner plaintext length
(≈ ciphertext length minus 16 bytes for the tag). For the routes here
the lengths are essentially fixed and known a priori (a 6-char setup
code, a 32-byte config key, etc.), so padding would add nothing.

### What the server does *not* do

- No webauthn-rs / no attestation verification. The browser is trusted
  to faithfully run the PRF extension and the inline derivation code. On
  Unlock, a wrong key fails on the first AEAD tag check. On first Setup,
  this is trust-on-first-use: the setup-code gate and CSP protect against
  accidental or injected flow confusion, but wrustic does not independently
  verify an attestation statement.
- No persistence of PRF output on disk. Only the credential id and the
  salt are written. The raw PRF output is not sent to Rust; the derived
  32-byte config key lives in the App's memory for the session.
- No CORS / no auth header / no cookies. The capability URL is the
  whole auth surface.

## Share dialog signing key

The share server (`src/share.rs`) signs URLs with HMAC-SHA256 over
`(snap_id, tree_id, name, exp)`. The 32-byte signing key is derived from
the active cipher's material:

| Mode | Derivation |
|---|---|
| age | `derive_signing_key(age.key bytes)` — SHA-256 over the raw key file |
| passkey | `passkey::derive_share_signing_key(config_key)` — SHA-256 over `"wrustic-share-v1\0" \|\| config_key` |

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
  the registered passkey (passkey mode).
- **Cross-config mixing.** Passkey configs cannot be opened in age mode
  and vice versa; URLs minted under one identity cannot be redeemed
  under another (covered by the share signing key and the AEAD's tag).
- **Mid-save corruption.** Atomic rename leaves the previous config
  intact even if the process is killed mid-write.

Not in scope:
- **Hostile local accounts on the same machine.** wrustic doesn't
  defend against this — single-user scope. Whoever runs wrustic also
  has whatever access the OS gives them to `age.key` (or to invoking
  the browser's WebAuthn API). Don't run wrustic on a host where you
  don't trust the local accounts.
- **Root / disk-image access.** Anyone with raw disk access or with the
  key file / authenticator can decrypt the config. Use full-disk
  encryption if that matters.
- **Memory disclosure** (core dumps, ptrace, swap). Cipher key bytes are
  ordinary heap memory — not `mlock`ed, not zeroized on drop.
- **Repo-level secrecy.** This is about `config.toml`, not about the
  restic repository itself. Restic has its own password (which wrustic
  stores encrypted in the per-profile `password` field) and its own
  at-rest encryption — those handle the repository data.
- **Authenticator phishing / WebAuthn RP correctness.** wrustic uses
  the browser's effective RP ID for `localhost`; WebAuthn RP IDs are not
  port-scoped. Another local web server on `localhost` can ask the browser
  for passkeys registered to `localhost` if the user approves the prompt.
  wrustic requires user verification and the setup-code gate for Setup,
  but this remains a local-browser trust assumption and another reason
  for the single-user scope.

For the surrounding system shape (boot flow, module layout, the share
dialog, the runtime loop), see [architecture.md](architecture.md).
