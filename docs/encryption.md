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
| `Cipher::Passkey` | `pkenc:` | ChaCha20-Poly1305 AEAD | WebAuthn PRF output, never on disk | experimental, gated behind `--experimental-passkey` |

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
```

Both fields are **public** WebAuthn identifiers — no key material here.
They live inline in `config.toml` (rather than a separate file) so:

- `config::peek` can read them without decrypting anything, which is what
  lets boot pick Setup vs Unlock before the cipher is even constructed
  (chicken-and-egg: you need the salt to run the ceremony, you need the
  ceremony to derive the cipher).
- Copying `config.toml` between machines that share the same passkey just
  works — the salt rides along.

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

The 32-byte AEAD key comes from the **WebAuthn PRF extension**
(`hmac-secret`) — the browser/authenticator computes a deterministic HMAC
of the credential's secret with a salt we provide:

```
prf_output = HMAC_credentialSecret(prf_salt)   // computed by authenticator
key        = prf_output                        // used directly as ChaCha20-Poly1305 key
```

The salt is generated once at Setup (`random_bytes(16)`) and stored in
`[passkey].prf_salt` so subsequent unlocks regenerate the same key.

The PRF output **never reaches the wire as a key derivative on disk** —
only the salt and the credential id are persisted. The browser sends the
raw 32 bytes back to localhost over the keyed `/auth/<key>/api/...` POST,
and the App keeps them in memory for the session only.

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
- ChaCha20-Poly1305 with the 32-byte PRF-derived key.
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
the URL in the TUI, and waits for the browser to POST the PRF output
back. This section covers the server's shape; the cryptographic
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
| `POST /auth/<key>/api/setup` (Setup phase) | accept `{credential_id, prf}` → deliver outcome |
| `POST /auth/<key>/api/unlock` (Unlock phase) | accept `{prf}` → deliver outcome |

The auth-key check runs **before** the expiry check by design: an
unauthenticated caller never gets to distinguish "running" from
"expired" — both look like 404.

### Two phases: Setup and Unlock

The phase is picked at boot by `config::peek`:

- **No `config.toml` (or no `[passkey]` block)** → `PasskeyPhase::Setup`.
  Server presents two buttons:
  - *Create new passkey* — `navigator.credentials.create()` with the PRF
    extension. Some authenticators don't return PRF during `create()`;
    the page transparently falls back to a follow-up `get()` against
    the just-created credential.
  - *Use existing passkey* — `navigator.credentials.get()` with no
    `allowCredentials`, so the browser presents every passkey valid
    for `localhost`. The user picks one and the page derives the key
    from its PRF using a fresh salt. The HTML carries a disclaimer
    explaining this won't open another machine's existing config (the
    salt would differ).
  - On POST: server delivers
    `PasskeyOutcome { key, new_meta: Some(PasskeyMeta { credential_id,
    prf_salt }) }`. The App splices the meta into `self.config.passkey`
    and immediately calls `config::save` so the `[passkey]` block
    lands on disk — next launch routes into Unlock.

- **`[passkey]` block already present** → `PasskeyPhase::Unlock`. Server
  presents the stored `credential_id` + `prf_salt` to the page, the
  browser does `.get()` against that exact credential, posts the PRF
  back. Server delivers `PasskeyOutcome { key, new_meta: None }`. App
  uses the key to decrypt every `pkenc:` value in the config.

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
- Calls `navigator.credentials.create()` / `.get()` with the PRF
  extension (`extensions: { prf: { eval: { first: prfSalt } } }`).
- POSTs the base64-encoded PRF output back to the API route.
- Disables all buttons on success so a second click can't re-prompt
  the authenticator (the server would also reject the second POST with
  409 "already provided this session").

### What the server does *not* do

- No webauthn-rs / no attestation verification. The browser is trusted
  to faithfully run the PRF extension; if it lied, the AEAD tag would
  fail on the first decrypt and the user would see an error. This is a
  deliberate simplification for an experimental, single-user feature.
- No persistence of PRF output on disk. Only the credential id and the
  salt are written; the 32-byte key itself only lives in the App's
  memory for the session.
- No CORS / no auth header / no cookies. The capability URL is the
  whole auth surface.

## Share dialog signing key

The share server (`src/share.rs`) signs URLs with HMAC-SHA256 over
`(snap_id, tree_id, name, exp)`. The 32-byte signing key is derived from
the active cipher's material:

| Mode | Derivation |
|---|---|
| age | `derive_signing_key(age.key bytes)` — SHA-256 over the raw key file |
| passkey | `passkey::derive_share_signing_key(prf_output)` — SHA-256 over `"wrustic-share-v1\0" \|\| prf_output` |

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
  `rp.name = "wrustic"` without RP id validation since the origin is
  `localhost`. Anything that can serve content on the same origin (i.e.
  anything else the user runs locally) can in principle drive the
  ceremony — another reason for the single-user scope.

For the surrounding system shape (boot flow, module layout, the share
dialog, the runtime loop), see [architecture.md](architecture.md).
