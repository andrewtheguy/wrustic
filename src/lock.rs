//! restic-compatible repository locking.
//!
//! Implements the exact lock protocol restic 0.19 uses (see docs/locking.md
//! for the full design and the source citations): lock files live under
//! `locks/` in the repo, encoded like any unpacked repo file — JSON, zstd
//! (repo v2), then AES-256-CTR + Poly1305-AES with the repo master key —
//! named by the SHA-256 of the ciphertext. Acquisition writes the lock,
//! waits 200 ms, and re-checks for a concurrently created conflicting lock;
//! a background thread refreshes the lock every 5 minutes (each refresh is a
//! new file replacing the old). rustic_core knows nothing about locks (its
//! `FileType` enum can't even address `locks/`), so this module talks to the
//! backends directly via [`LockBackend`].
//!
//! Non-exclusive lock: holder only appends; conflicts with an exclusive
//! lock. Exclusive lock: holder may delete/rewrite; conflicts with any lock.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use aes256ctr_poly1305aes::{
    Aes256CtrPoly1305Aes,
    aead::{Aead, AeadInPlace},
};
use jiff::Timestamp;
use rand::Rng;
use rustic_core::{Open, Repository};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// restic's timing constants (internal/restic/lock.go,
// internal/repository/lock.go in restic 0.19.1). Values must match: other
// restic processes judge our locks by them and vice versa.
const WAIT_BEFORE_LOCK_CHECK: Duration = Duration::from_millis(200);
const REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);
const STALE_TIMEOUT_SECS: i64 = 30 * 60;

type Nonce = aes256ctr_poly1305aes::aead::Nonce<Aes256CtrPoly1305Aes>;
type AeadKey = aes256ctr_poly1305aes::Key;

// ---------------------------------------------------------------------------
// Lock file content — must round-trip with restic's `restic.Lock` JSON.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LockData {
    time: Timestamp,
    exclusive: bool,
    hostname: String,
    username: String,
    pid: i32,
    #[serde(default, skip_serializing_if = "is_zero")]
    uid: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    gid: u32,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde requires &T
fn is_zero(v: &u32) -> bool {
    *v == 0
}

impl LockData {
    fn ours(exclusive: bool) -> Self {
        Self {
            time: Timestamp::now(),
            exclusive,
            hostname: our_hostname(),
            username: std::env::var("USER")
                .or_else(|_| std::env::var("LOGNAME"))
                .unwrap_or_default(),
            pid: std::process::id() as i32,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        }
    }

    // Mirrors restic's Lock.Stale(): older than 30 minutes, or created on
    // this host by a process that no longer exists. restic probes the PID
    // with SIGHUP; we use signal 0 instead — same liveness answer without
    // ever terminating an innocent process.
    fn is_stale(&self) -> bool {
        let age = Timestamp::now().as_second() - self.time.as_second();
        if age > STALE_TIMEOUT_SECS {
            return true;
        }
        self.hostname == our_hostname() && !process_exists(self.pid)
    }

    fn describe(&self, storage_id: &str) -> String {
        let age = Timestamp::now().as_second() - self.time.as_second();
        format!(
            "PID {} on {} by {} (UID {}, GID {}), lock was created at {} ({}m{}s ago), storage ID {}",
            self.pid,
            self.hostname,
            self.username,
            self.uid,
            self.gid,
            self.time.strftime("%Y-%m-%d %H:%M:%S"),
            age / 60,
            age.rem_euclid(60),
            &storage_id[..storage_id.len().min(8)],
        )
    }
}

fn our_hostname() -> String {
    gethostname::gethostname().to_string_lossy().into_owned()
}

fn process_exists(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    // EPERM: the process exists but belongs to someone else.
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

// ---------------------------------------------------------------------------
// Crypto — restic's "unpacked file" envelope.
// ---------------------------------------------------------------------------

/// Encrypts/decrypts unpacked repo files with the master key of an opened
/// repository. Byte-compatible with rustic_core's `DecryptBackend`
/// (`backend/decrypt.rs`): ciphertext is `nonce(16) ‖ AES-256-CTR data ‖
/// Poly1305-AES tag(16)`; the plaintext is raw JSON (repo v1) or
/// `0x02 ‖ zstd(JSON)` (repo v2), distinguished on read by the first byte.
#[derive(Clone)]
pub(crate) struct RepoCrypto {
    key: AeadKey,
    compress: bool,
}

impl RepoCrypto {
    pub(crate) fn from_repo<S: Open>(repo: &Repository<S>) -> Result<Self> {
        let mk = repo.key();
        if mk.encrypt.len() != 32 || mk.mac.k.len() != 16 || mk.mac.r.len() != 16 {
            bail!(
                "unexpected master key layout (encrypt {} bytes, k {} bytes, r {} bytes)",
                mk.encrypt.len(),
                mk.mac.k.len(),
                mk.mac.r.len()
            );
        }
        let mut key = AeadKey::default();
        key[0..32].copy_from_slice(&mk.encrypt);
        key[32..48].copy_from_slice(&mk.mac.k);
        key[48..64].copy_from_slice(&mk.mac.r);
        Ok(Self { key, compress: repo.config().version >= 2 })
    }

    fn seal(&self, plain: &[u8]) -> Result<Vec<u8>> {
        let payload = if self.compress {
            let mut out = vec![2_u8];
            zstd::stream::copy_encode(plain, &mut out, 0).context("zstd-compressing lock file")?;
            out
        } else {
            plain.to_vec()
        };
        let mut nonce = Nonce::default();
        rand::rng().fill_bytes(&mut nonce);
        let mut res = Vec::with_capacity(payload.len() + 32);
        res.extend_from_slice(&nonce);
        res.extend_from_slice(&payload);
        let tag = Aes256CtrPoly1305Aes::new(&self.key)
            .encrypt_in_place_detached(&nonce, &[], &mut res[16..])
            .map_err(|e| anyhow!("encrypting lock file: {e}"))?;
        res.extend_from_slice(&tag);
        Ok(res)
    }

    fn open(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 32 {
            bail!("lock file too short ({} bytes)", data.len());
        }
        let plain = Aes256CtrPoly1305Aes::new(&self.key)
            .decrypt(Nonce::from_slice(&data[0..16]), &data[16..])
            .map_err(|e| anyhow!("decrypting lock file (MAC check failed): {e}"))?;
        match plain.first() {
            Some(b'{' | b'[') => Ok(plain),
            Some(2) => zstd::stream::decode_all(&plain[1..]).context("zstd-decoding lock file"),
            _ => bail!("lock file plaintext is in an unknown format"),
        }
    }
}

// ---------------------------------------------------------------------------
// Backend access to the repo's `locks/` directory.
// ---------------------------------------------------------------------------

/// Raw file operations on `locks/`. Lock names are the hex storage ids.
pub(crate) trait LockBackend: Send + Sync {
    /// All lock files as `(name, size)`. Zero-size entries are interrupted
    /// uploads and get skipped by callers (as restic does).
    fn list(&self) -> Result<Vec<(String, u64)>>;
    /// `None` when the lock vanished between list and read — a lock that is
    /// gone cannot conflict, so callers just skip it.
    fn read(&self, name: &str) -> Result<Option<Vec<u8>>>;
    fn write(&self, name: &str, data: &[u8]) -> Result<()>;
    /// Removing an already-missing lock is not an error.
    fn remove(&self, name: &str) -> Result<()>;
}

pub(crate) struct LocalLockBackend {
    dir: std::path::PathBuf,
}

impl LocalLockBackend {
    pub(crate) fn new(repo_path: &str) -> Self {
        Self { dir: std::path::Path::new(repo_path).join("locks") }
    }
}

impl LockBackend for LocalLockBackend {
    fn list(&self) -> Result<Vec<(String, u64)>> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).context("listing locks/"),
        };
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry.context("reading locks/ entry")?;
            let meta = entry.metadata().context("reading locks/ entry metadata")?;
            if meta.is_file() {
                out.push((entry.file_name().to_string_lossy().into_owned(), meta.len()));
            }
        }
        Ok(out)
    }

    fn read(&self, name: &str) -> Result<Option<Vec<u8>>> {
        match std::fs::read(self.dir.join(name)) {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading lock {name}")),
        }
    }

    fn write(&self, name: &str, data: &[u8]) -> Result<()> {
        std::fs::create_dir_all(&self.dir).context("creating locks/")?;
        // Write-then-rename so other processes never see a partial lock file.
        let tmp = self.dir.join(format!(".tmp-{name}"));
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp).context("creating lock temp file")?;
            f.write_all(data).context("writing lock temp file")?;
            f.sync_all().context("syncing lock temp file")?;
        }
        std::fs::rename(&tmp, self.dir.join(name)).context("renaming lock into place")
    }

    fn remove(&self, name: &str) -> Result<()> {
        match std::fs::remove_file(self.dir.join(name)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("removing lock {name}")),
        }
    }
}

pub(crate) struct RestLockBackend {
    locks_url: url::Url,
    user: String,
    password: String,
    client: reqwest::blocking::Client,
}

impl RestLockBackend {
    pub(crate) fn new(rest_url: &str, user: &str, password: &str) -> Result<Self> {
        let mut base = rest_url.to_string();
        if !base.ends_with('/') {
            base.push('/');
        }
        let locks_url = url::Url::parse(&base)
            .with_context(|| format!("parsing REST URL `{rest_url}`"))?
            .join("locks/")
            .context("building locks/ URL")?;
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("building HTTP client")?;
        Ok(Self {
            locks_url,
            user: user.to_string(),
            password: password.to_string(),
            client,
        })
    }

    fn request(&self, method: reqwest::Method, url: url::Url) -> reqwest::blocking::RequestBuilder {
        let req = self.client.request(method, url);
        if self.user.is_empty() {
            req
        } else {
            req.basic_auth(&self.user, Some(&self.password))
        }
    }

    fn item_url(&self, name: &str) -> Result<url::Url> {
        self.locks_url.join(name).with_context(|| format!("building URL for lock {name}"))
    }
}

impl LockBackend for RestLockBackend {
    fn list(&self) -> Result<Vec<(String, u64)>> {
        // rest-server API v2 lists `[{"name": ..., "size": ...}]`; a v1
        // server replies with a plain array of names (size unknown — report
        // it as nonzero so the entry is still read rather than skipped).
        let resp = self
            .request(reqwest::Method::GET, self.locks_url.clone())
            .header("Accept", "application/vnd.x.restic.rest.v2")
            .send()
            .context("listing locks via REST")?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(Vec::new());
        }
        let resp = resp.error_for_status().context("listing locks via REST")?;
        let value: serde_json::Value = resp.json().context("parsing REST lock list")?;
        let Some(items) = value.as_array() else {
            bail!("REST lock list is not a JSON array: {value}");
        };
        let mut out = Vec::new();
        for item in items {
            match item {
                serde_json::Value::String(name) => out.push((name.clone(), u64::MAX)),
                serde_json::Value::Object(obj) => {
                    let name = obj
                        .get("name")
                        .and_then(|n| n.as_str())
                        .ok_or_else(|| anyhow!("REST lock list entry without name: {item}"))?;
                    let size = obj.get("size").and_then(serde_json::Value::as_u64).unwrap_or(u64::MAX);
                    out.push((name.to_string(), size));
                }
                other => bail!("unexpected REST lock list entry: {other}"),
            }
        }
        Ok(out)
    }

    fn read(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let resp = self
            .request(reqwest::Method::GET, self.item_url(name)?)
            .header("Accept", "application/octet-stream")
            .send()
            .with_context(|| format!("reading lock {name} via REST"))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = resp.error_for_status().with_context(|| format!("reading lock {name}"))?;
        Ok(Some(resp.bytes().context("reading lock body")?.to_vec()))
    }

    fn write(&self, name: &str, data: &[u8]) -> Result<()> {
        self.request(reqwest::Method::POST, self.item_url(name)?)
            .header("Content-Type", "application/octet-stream")
            .body(data.to_vec())
            .send()
            .with_context(|| format!("writing lock {name} via REST"))?
            .error_for_status()
            .with_context(|| format!("writing lock {name}"))?;
        Ok(())
    }

    fn remove(&self, name: &str) -> Result<()> {
        let resp = self
            .request(reqwest::Method::DELETE, self.item_url(name)?)
            .send()
            .with_context(|| format!("removing lock {name} via REST"))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        resp.error_for_status().with_context(|| format!("removing lock {name}"))?;
        Ok(())
    }
}

/// Lock-file access for a profile's repository. Independent of the
/// rustic_core backend an open `Repository` uses — rustic_core's `FileType`
/// enum cannot address `locks/` at all.
pub(crate) fn backend_for_profile(profile: &crate::config::Profile) -> Result<Arc<dyn LockBackend>> {
    use crate::config::Profile;
    Ok(match profile {
        Profile::Local { local_path, .. } => Arc::new(LocalLockBackend::new(local_path)),
        Profile::Rest { rest_url, rest_user, rest_password, .. } => {
            Arc::new(RestLockBackend::new(rest_url, rest_user, rest_password)?)
        }
        Profile::S3 {
            s3_endpoint,
            s3_bucket,
            s3_region,
            s3_root,
            s3_access_key,
            s3_secret_key,
            ..
        } => Arc::new(crate::s3_backend::S3LockBackend::new(
            s3_endpoint,
            s3_bucket,
            s3_region,
            s3_root,
            s3_access_key,
            s3_secret_key,
        )?),
    })
}

// Plants an already-stale (aged well past the 30-minute timeout) lock so
// integration tests can exercise stale-lock removal without killing a live
// restic mid-operation.
#[cfg(test)]
pub(crate) fn write_stale_lock_for_tests(backend: &dyn LockBackend, crypto: &RepoCrypto) {
    let mut data = LockData::ours(false);
    data.time = Timestamp::now() - jiff::SignedDuration::from_secs(STALE_TIMEOUT_SECS + 300);
    write_lock(backend, crypto, &data).expect("writing stale test lock");
}

// ---------------------------------------------------------------------------
// The lock itself.
// ---------------------------------------------------------------------------

struct LockShared {
    current_name: String,
    stop: bool,
}

/// A held repository lock. Refreshes itself every 5 minutes on a background
/// thread and removes its lock file on drop. While any `RepoLock` is alive
/// the process ignores SIGHUP: restic's staleness probe (`restic unlock` on
/// the same host) delivers SIGHUP to the lock-holder PID, which would
/// otherwise kill the TUI.
pub(crate) struct RepoLock {
    backend: Arc<dyn LockBackend>,
    shared: Arc<(Mutex<LockShared>, Condvar)>,
    refresher: Option<JoinHandle<()>>,
}

impl RepoLock {
    pub(crate) fn acquire_exclusive(
        backend: Arc<dyn LockBackend>,
        crypto: RepoCrypto,
    ) -> Result<Self> {
        Self::acquire(backend, crypto, true)
    }

    #[allow(dead_code)] // for append-only operations (native backup, phase 3)
    pub(crate) fn acquire_shared(
        backend: Arc<dyn LockBackend>,
        crypto: RepoCrypto,
    ) -> Result<Self> {
        Self::acquire(backend, crypto, false)
    }

    fn acquire(backend: Arc<dyn LockBackend>, crypto: RepoCrypto, exclusive: bool) -> Result<Self> {
        check_for_other_locks(backend.as_ref(), &crypto, None, exclusive)?;
        sighup_ignore_acquire();
        let name = match Self::write_then_recheck(backend.as_ref(), &crypto, exclusive) {
            Ok(name) => name,
            Err(e) => {
                sighup_ignore_release();
                return Err(e);
            }
        };

        let shared = Arc::new((
            Mutex::new(LockShared { current_name: name, stop: false }),
            Condvar::new(),
        ));
        let refresher = {
            let backend = Arc::clone(&backend);
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || refresh_loop(&backend, &crypto, exclusive, &shared))
        };
        Ok(Self { backend, shared, refresher: Some(refresher) })
    }

    // restic's acquisition protocol: write our lock, wait 200 ms, then check
    // again — if a conflicting lock appeared concurrently, back off by
    // removing our own lock and failing.
    fn write_then_recheck(
        backend: &dyn LockBackend,
        crypto: &RepoCrypto,
        exclusive: bool,
    ) -> Result<String> {
        let name = write_lock(backend, crypto, &LockData::ours(exclusive))?;
        std::thread::sleep(WAIT_BEFORE_LOCK_CHECK);
        if let Err(e) = check_for_other_locks(backend, crypto, Some(&name), exclusive) {
            let _ = backend.remove(&name);
            return Err(e);
        }
        Ok(name)
    }
}

impl Drop for RepoLock {
    fn drop(&mut self) {
        {
            let (state, cv) = &*self.shared;
            state.lock().expect("lock state poisoned").stop = true;
            cv.notify_all();
        }
        if let Some(handle) = self.refresher.take() {
            let _ = handle.join();
        }
        let name = self.shared.0.lock().expect("lock state poisoned").current_name.clone();
        let _ = self.backend.remove(&name);
        sighup_ignore_release();
    }
}

fn refresh_loop(
    backend: &Arc<dyn LockBackend>,
    crypto: &RepoCrypto,
    exclusive: bool,
    shared: &Arc<(Mutex<LockShared>, Condvar)>,
) {
    let (state, cv) = &**shared;
    loop {
        let guard = state.lock().expect("lock state poisoned");
        let (guard, timeout) = cv
            .wait_timeout_while(guard, REFRESH_INTERVAL, |s| !s.stop)
            .expect("lock state poisoned");
        if !timeout.timed_out() {
            return; // stop requested
        }
        let old = guard.current_name.clone();
        drop(guard);
        // Refresh = write a fresh lock file (new timestamp, new storage id),
        // then delete the previous one — same order restic uses, so there is
        // never a moment without a valid lock in the repo.
        if let Ok(new) = write_lock(backend.as_ref(), crypto, &LockData::ours(exclusive)) {
            let _ = backend.remove(&old);
            state.lock().expect("lock state poisoned").current_name = new;
        }
        // On refresh failure just try again next tick; the lock only turns
        // stale for others after 30 minutes without a successful refresh.
        // (An abort-if-unrefreshable signal, restic's 22.5-minute rule, comes
        // with native backup — today's critical sections last seconds.)
    }
}

fn write_lock(backend: &dyn LockBackend, crypto: &RepoCrypto, data: &LockData) -> Result<String> {
    let json = serde_json::to_vec(data).context("serializing lock file")?;
    let sealed = crypto.seal(&json)?;
    let name = hex(&Sha256::digest(&sealed));
    backend.write(&name, &sealed)?;
    Ok(name)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    })
}

// Conflict rules (restic lock.go checkForOtherLocks): a non-exclusive lock
// conflicts only with an existing exclusive lock; an exclusive lock
// conflicts with any existing lock. Unreadable locks abort acquisition —
// restic behaves the same and points users at `unlock --remove-all`.
fn check_for_other_locks(
    backend: &dyn LockBackend,
    crypto: &RepoCrypto,
    own: Option<&str>,
    exclusive: bool,
) -> Result<()> {
    for (name, size) in backend.list()? {
        if Some(name.as_str()) == own || size == 0 {
            continue;
        }
        let Some(raw) = backend.read(&name)? else {
            continue; // vanished since listing — cannot conflict
        };
        if raw.is_empty() {
            continue; // interrupted upload, ignored like restic does
        }
        let other: LockData = parse_lock(crypto, &raw)
            .with_context(|| format!("lock file {name} is unreadable (wrong key or corrupt); `restic unlock --remove-all` can force-remove it"))?;
        if other.exclusive || exclusive {
            bail!(
                "unable to create lock in backend: repository is already locked {}by {}",
                if other.exclusive { "exclusively " } else { "" },
                other.describe(&name),
            );
        }
    }
    Ok(())
}

fn parse_lock(crypto: &RepoCrypto, raw: &[u8]) -> Result<LockData> {
    let json = crypto.open(raw)?;
    serde_json::from_slice(&json).context("parsing lock file JSON")
}

/// Removes stale locks (mirrors `restic unlock`): locks older than 30
/// minutes, locks from this host whose process is gone, and zero-byte
/// leftovers of interrupted uploads. Live locks stay; unreadable locks stay
/// too and are reported as an error, matching restic's split between
/// `unlock` and `unlock --remove-all`.
pub(crate) fn remove_stale_locks(backend: &dyn LockBackend, crypto: &RepoCrypto) -> Result<usize> {
    let mut removed = 0_usize;
    let mut unreadable = 0_usize;
    for (name, size) in backend.list()? {
        if size == 0 {
            backend.remove(&name)?;
            removed += 1;
            continue;
        }
        let Some(raw) = backend.read(&name)? else {
            continue;
        };
        if raw.is_empty() {
            backend.remove(&name)?;
            removed += 1;
            continue;
        }
        match parse_lock(crypto, &raw) {
            Ok(lock) => {
                if lock.is_stale() {
                    backend.remove(&name)?;
                    removed += 1;
                }
            }
            Err(_) => unreadable += 1,
        }
    }
    if unreadable > 0 {
        bail!(
            "removed {removed} stale lock(s), but {unreadable} lock file(s) could not be read \
             (wrong key or corrupt) and were left in place; \
             `restic unlock --remove-all` can force-remove them"
        );
    }
    Ok(removed)
}

/// True when a failure was caused by an existing repository lock — i.e. when
/// offering stale-lock removal is the right next step. Matches both our own
/// conflict message and restic's stderr shape.
pub(crate) fn is_lock_error(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    m.contains("unable to create lock") || m.contains("already locked")
}

// ---------------------------------------------------------------------------
// SIGHUP handling — see the RepoLock doc comment.
// ---------------------------------------------------------------------------

static LOCKS_HELD: AtomicUsize = AtomicUsize::new(0);

fn sighup_ignore_acquire() {
    if LOCKS_HELD.fetch_add(1, Ordering::SeqCst) == 0 {
        unsafe {
            let _ = libc::signal(libc::SIGHUP, libc::SIG_IGN);
        }
    }
}

fn sighup_ignore_release() {
    if LOCKS_HELD.fetch_sub(1, Ordering::SeqCst) == 1 {
        unsafe {
            let _ = libc::signal(libc::SIGHUP, libc::SIG_DFL);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    struct MemLockBackend {
        files: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl MemLockBackend {
        fn new() -> Arc<Self> {
            Arc::new(Self { files: Mutex::new(HashMap::new()) })
        }

        fn count(&self) -> usize {
            self.files.lock().unwrap().len()
        }
    }

    impl LockBackend for MemLockBackend {
        fn list(&self) -> Result<Vec<(String, u64)>> {
            Ok(self
                .files
                .lock()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.len() as u64))
                .collect())
        }

        fn read(&self, name: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.files.lock().unwrap().get(name).cloned())
        }

        fn write(&self, name: &str, data: &[u8]) -> Result<()> {
            let _ = self.files.lock().unwrap().insert(name.to_string(), data.to_vec());
            Ok(())
        }

        fn remove(&self, name: &str) -> Result<()> {
            let _ = self.files.lock().unwrap().remove(name);
            Ok(())
        }
    }

    fn test_crypto(compress: bool) -> RepoCrypto {
        let mut key = AeadKey::default();
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        RepoCrypto { key, compress }
    }

    #[test]
    fn seal_open_round_trip_uncompressed() {
        let crypto = test_crypto(false);
        let json = br#"{"time":"2026-08-04T00:00:00Z","exclusive":true}"#;
        let sealed = crypto.seal(json).unwrap();
        assert_ne!(&sealed, json);
        assert_eq!(crypto.open(&sealed).unwrap(), json);
    }

    #[test]
    fn seal_open_round_trip_compressed() {
        let crypto = test_crypto(true);
        let json = br#"{"time":"2026-08-04T00:00:00Z","exclusive":false}"#;
        let sealed = crypto.seal(json).unwrap();
        // The decrypted payload must carry restic's `2` compression marker.
        let plain = Aes256CtrPoly1305Aes::new(&crypto.key)
            .decrypt(Nonce::from_slice(&sealed[0..16]), &sealed[16..])
            .unwrap();
        assert_eq!(plain[0], 2);
        assert_eq!(crypto.open(&sealed).unwrap(), json);
    }

    #[test]
    fn open_rejects_tampered_data() {
        let crypto = test_crypto(true);
        let mut sealed = crypto.seal(b"{}").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;
        assert!(crypto.open(&sealed).is_err());
    }

    #[test]
    fn lock_json_matches_restic_schema() {
        let lock = LockData {
            time: "2026-08-04T10:00:00Z".parse().unwrap(),
            exclusive: true,
            hostname: "host1".into(),
            username: "andrew".into(),
            pid: 4242,
            uid: 1000,
            gid: 1000,
        };
        let value: serde_json::Value = serde_json::to_value(&lock).unwrap();
        let obj = value.as_object().unwrap();
        for key in ["time", "exclusive", "hostname", "username", "pid", "uid", "gid"] {
            assert!(obj.contains_key(key), "missing key {key}");
        }
        assert_eq!(obj.len(), 7);

        // Field shape restic 0.19 writes (Go time.Time marshals RFC3339Nano).
        let restic_json = r#"{
            "time": "2026-08-04T12:00:31.123456789+02:00",
            "exclusive": false,
            "hostname": "it3s-MBP-4",
            "username": "it3",
            "pid": 7344,
            "uid": 501,
            "gid": 20
        }"#;
        let parsed: LockData = serde_json::from_str(restic_json).unwrap();
        assert!(!parsed.exclusive);
        assert_eq!(parsed.pid, 7344);
        assert_eq!(parsed.uid, 501);
    }

    #[test]
    fn uid_gid_omitted_when_zero_and_optional_on_parse() {
        let lock = LockData {
            time: Timestamp::now(),
            exclusive: false,
            hostname: "h".into(),
            username: "root".into(),
            pid: 1,
            uid: 0,
            gid: 0,
        };
        let value = serde_json::to_value(&lock).unwrap();
        let obj = value.as_object().unwrap();
        assert!(!obj.contains_key("uid"));
        assert!(!obj.contains_key("gid"));

        let minimal = r#"{"time":"2026-08-04T10:00:00Z","exclusive":true,
                          "hostname":"h","username":"u","pid":2}"#;
        let parsed: LockData = serde_json::from_str(minimal).unwrap();
        assert_eq!(parsed.uid, 0);
    }

    #[test]
    fn lock_name_is_sha256_of_ciphertext() {
        let backend = MemLockBackend::new();
        let crypto = test_crypto(true);
        let name = write_lock(backend.as_ref(), &crypto, &LockData::ours(false)).unwrap();
        let stored = backend.read(&name).unwrap().unwrap();
        assert_eq!(name, hex(&Sha256::digest(&stored)));
        assert_eq!(name.len(), 64);
    }

    #[test]
    fn exclusive_conflicts_with_any_lock_shared_only_with_exclusive() {
        let backend = MemLockBackend::new();
        let crypto = test_crypto(true);

        // Existing non-exclusive lock: shared OK, exclusive conflicts.
        let shared_name =
            write_lock(backend.as_ref(), &crypto, &LockData::ours(false)).unwrap();
        assert!(check_for_other_locks(backend.as_ref(), &crypto, None, false).is_ok());
        let err = check_for_other_locks(backend.as_ref(), &crypto, None, true).unwrap_err();
        assert!(is_lock_error(&format!("{err:#}")), "unexpected error: {err:#}");
        backend.remove(&shared_name).unwrap();

        // Existing exclusive lock: everything conflicts.
        let _excl = write_lock(backend.as_ref(), &crypto, &LockData::ours(true)).unwrap();
        assert!(check_for_other_locks(backend.as_ref(), &crypto, None, false).is_err());
        assert!(check_for_other_locks(backend.as_ref(), &crypto, None, true).is_err());
    }

    #[test]
    fn acquire_writes_lock_and_drop_removes_it() {
        let backend = MemLockBackend::new();
        let crypto = test_crypto(true);
        let lock = RepoLock::acquire_exclusive(
            Arc::clone(&backend) as Arc<dyn LockBackend>,
            crypto.clone(),
        )
        .unwrap();
        assert_eq!(backend.count(), 1);
        // A second exclusive acquisition must fail while the first is held.
        let err = RepoLock::acquire_exclusive(
            Arc::clone(&backend) as Arc<dyn LockBackend>,
            crypto,
        )
        .map(|_| ())
        .unwrap_err();
        assert!(is_lock_error(&format!("{err:#}")));
        drop(lock);
        assert_eq!(backend.count(), 0);
    }

    #[test]
    fn corrupt_lock_aborts_acquisition() {
        let backend = MemLockBackend::new();
        let crypto = test_crypto(true);
        backend.write("deadbeef", b"not a lock file").unwrap();
        let err = check_for_other_locks(backend.as_ref(), &crypto, None, false).unwrap_err();
        assert!(format!("{err:#}").contains("unreadable"));
    }

    #[test]
    fn zero_byte_locks_are_ignored_for_conflicts_and_removed_by_unlock() {
        let backend = MemLockBackend::new();
        let crypto = test_crypto(true);
        backend.write("empty", b"").unwrap();
        assert!(check_for_other_locks(backend.as_ref(), &crypto, None, true).is_ok());
        assert_eq!(remove_stale_locks(backend.as_ref(), &crypto).unwrap(), 1);
        assert_eq!(backend.count(), 0);
    }

    #[test]
    fn stale_locks_removed_live_locks_kept() {
        let backend = MemLockBackend::new();
        let crypto = test_crypto(true);

        let mut stale = LockData::ours(false);
        stale.time = Timestamp::now() - jiff::SignedDuration::from_secs(STALE_TIMEOUT_SECS + 60);
        write_lock(backend.as_ref(), &crypto, &stale).unwrap();

        // Dead-process lock on this host: stale even though recent.
        let mut dead = LockData::ours(false);
        dead.pid = i32::MAX - 1; // no live process has this PID
        write_lock(backend.as_ref(), &crypto, &dead).unwrap();

        // Fresh lock owned by this live process: kept.
        let live_name = write_lock(backend.as_ref(), &crypto, &LockData::ours(true)).unwrap();

        assert_eq!(remove_stale_locks(backend.as_ref(), &crypto).unwrap(), 2);
        assert_eq!(backend.count(), 1);
        assert!(backend.read(&live_name).unwrap().is_some());
    }

    #[test]
    fn recent_lock_from_other_host_is_not_stale() {
        // Different hostname → the PID check must not apply (restic assumes
        // remote processes are alive until the 30-minute timeout).
        let lock = LockData {
            time: Timestamp::now(),
            exclusive: false,
            hostname: "some-other-host".into(),
            username: "u".into(),
            pid: i32::MAX - 1,
            uid: 1,
            gid: 1,
        };
        assert!(!lock.is_stale());
    }

    #[test]
    fn detects_lock_errors() {
        // Verbatim shape of what restic 0.18/0.19 writes to stderr.
        let restic = "unable to create lock in backend: repository is already locked by PID \
                      7344 on it3s-MBP-4 by it3 (UID 501, GID 20)";
        assert!(is_lock_error(restic));
        assert!(is_lock_error("Fatal: unable to create lock in backend: circuit breaker open"));
        assert!(!is_lock_error("rustic and restic disagree on snapshot metadata"));
    }
}
