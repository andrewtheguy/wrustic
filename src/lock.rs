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

// restic's refreshability rule (`internal/repository/lock.go`
// refreshabilityTimeout): when a lock has not been successfully refreshed for
// StaleLockTimeout − 1.5 × refreshInterval = 22.5 minutes, the operation must
// abort — other processes are 7.5 minutes away from judging the lock stale
// and removing it via `restic unlock`. Expressed as a multiple of the refresh
// interval (22.5 min / 5 min = 4.5) so tests with a shortened interval get a
// proportionally shortened timeout.
fn refreshability_timeout(refresh_interval: Duration) -> Duration {
    refresh_interval * 9 / 2
}

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
                .or_else(|_| std::env::var("USERNAME")) // Windows
                .unwrap_or_default(),
            pid: std::process::id() as i32,
            uid: our_uid(),
            gid: our_gid(),
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

#[cfg(unix)]
fn our_uid() -> u32 {
    unsafe { libc::getuid() }
}

#[cfg(unix)]
fn our_gid() -> u32 {
    unsafe { libc::getgid() }
}

// Windows has no numeric uid/gid; restic writes 0 for both there
// (`internal/restic/lock_windows.go` uidGidInt), and so do we.
#[cfg(windows)]
fn our_uid() -> u32 {
    0
}

#[cfg(windows)]
fn our_gid() -> u32 {
    0
}

#[cfg(unix)]
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

// Windows probe via OpenProcess (restic uses the same call through
// os.FindProcess, `lock_windows.go`): a PID we can open a handle to is alive.
// ACCESS_DENIED means the process exists but belongs to someone else — the
// exact analog of EPERM in the Unix probe above, and like there it counts as
// alive so a live lock is never judged stale. Any other failure (notably
// ERROR_INVALID_PARAMETER) means the PID doesn't resolve.
#[cfg(windows)]
fn process_exists(pid: i32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED, GetLastError};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    if pid <= 0 {
        return false;
    }
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid as u32) };
    if handle.is_null() {
        return unsafe { GetLastError() } == ERROR_ACCESS_DENIED;
    }
    unsafe { CloseHandle(handle) };
    true
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

/// Raw file operations on one unpacked-file directory of the repo. Built for
/// `locks/` (which rustic_core cannot address at all), but the operations are
/// directory-agnostic, so the same backends also serve `snapshots/` for the
/// native tag edit's lossless raw-JSON rewrite (`repo::edit_snapshot_tags`).
/// File names are the hex storage ids.
pub(crate) trait LockBackend: Send + Sync {
    /// All files as `(name, size)`. Zero-size entries are interrupted
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
    pub(crate) fn new(repo_path: &str, dir: &str) -> Self {
        Self { dir: std::path::Path::new(repo_path).join(dir) }
    }
}

impl LockBackend for LocalLockBackend {
    fn list(&self) -> Result<Vec<(String, u64)>> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("listing {}", self.dir.display())),
        };
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry.context("reading dir entry")?;
            let meta = entry.metadata().context("reading dir entry metadata")?;
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
            Err(e) => Err(e).with_context(|| format!("reading {name}")),
        }
    }

    fn write(&self, name: &str, data: &[u8]) -> Result<()> {
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("creating {}", self.dir.display()))?;
        // Write-then-rename so other processes never see a partial file.
        let tmp = self.dir.join(format!(".tmp-{name}"));
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp).context("creating temp file")?;
            f.write_all(data).context("writing temp file")?;
            f.sync_all().context("syncing temp file")?;
        }
        std::fs::rename(&tmp, self.dir.join(name)).context("renaming into place")
    }

    fn remove(&self, name: &str) -> Result<()> {
        match std::fs::remove_file(self.dir.join(name)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("removing {name}")),
        }
    }
}

pub(crate) struct RestLockBackend {
    dir_url: url::Url,
    user: String,
    password: String,
    client: reqwest::blocking::Client,
}

impl RestLockBackend {
    pub(crate) fn new(rest_url: &str, user: &str, password: &str, dir: &str) -> Result<Self> {
        let mut base = rest_url.to_string();
        if !base.ends_with('/') {
            base.push('/');
        }
        let dir_url = url::Url::parse(&base)
            .with_context(|| format!("parsing REST URL `{rest_url}`"))?
            .join(&format!("{dir}/"))
            .with_context(|| format!("building {dir}/ URL"))?;
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("building HTTP client")?;
        Ok(Self {
            dir_url,
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
        self.dir_url.join(name).with_context(|| format!("building URL for {name}"))
    }
}

impl LockBackend for RestLockBackend {
    fn list(&self) -> Result<Vec<(String, u64)>> {
        // rest-server API v2 lists `[{"name": ..., "size": ...}]`; a v1
        // server replies with a plain array of names (size unknown — report
        // it as nonzero so the entry is still read rather than skipped).
        let resp = self
            .request(reqwest::Method::GET, self.dir_url.clone())
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
    dir_backend_for_profile(profile, "locks")
}

/// Raw access to the repo's `snapshots/` directory, for the native tag
/// edit's lossless rewrite (unlike locks, rustic_core *can* address
/// snapshots — but only through its typed `SnapshotFile`, which drops
/// restic fields it doesn't model, e.g. `excludes`).
pub(crate) fn snapshot_backend_for_profile(
    profile: &crate::config::Profile,
) -> Result<Arc<dyn LockBackend>> {
    dir_backend_for_profile(profile, "snapshots")
}

fn dir_backend_for_profile(
    profile: &crate::config::Profile,
    dir: &str,
) -> Result<Arc<dyn LockBackend>> {
    use crate::config::Profile;
    Ok(match profile {
        Profile::Local { local_path, .. } => Arc::new(LocalLockBackend::new(local_path, dir)),
        Profile::Rest { rest_url, rest_user, rest_password, .. } => {
            Arc::new(RestLockBackend::new(rest_url, rest_user, rest_password, dir)?)
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
            dir,
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
    // When the lock file on the backend last got a fresh timestamp — set at
    // acquisition and after every successful refresh. Feeds `poisoned()`.
    last_refresh: std::time::Instant,
    // Latched by `poisoned()`: once the refreshability timeout was observed
    // exceeded, a later successful refresh must not un-poison the lock — in
    // the meantime another process may have removed it as stale and started
    // an exclusive operation.
    poisoned: bool,
}

/// A held repository lock. Refreshes itself every 5 minutes on a background
/// thread and removes its lock file on drop. While any `RepoLock` is alive
/// the process ignores SIGHUP: restic's staleness probe (`restic unlock` on
/// the same host) delivers SIGHUP to the lock-holder PID, which would
/// otherwise kill the TUI. Long-running holders must watch [`Self::poisoned`]
/// and abort when it turns true.
pub(crate) struct RepoLock {
    backend: Arc<dyn LockBackend>,
    shared: Arc<(Mutex<LockShared>, Condvar)>,
    refresher: Option<JoinHandle<()>>,
    // 22.5 minutes at the protocol's real refresh interval; see
    // `refreshability_timeout`.
    poison_after: Duration,
}

impl RepoLock {
    pub(crate) fn acquire_exclusive(
        backend: Arc<dyn LockBackend>,
        crypto: RepoCrypto,
    ) -> Result<Self> {
        Self::acquire(backend, crypto, true, REFRESH_INTERVAL)
    }

    pub(crate) fn acquire_shared(
        backend: Arc<dyn LockBackend>,
        crypto: RepoCrypto,
    ) -> Result<Self> {
        Self::acquire(backend, crypto, false, REFRESH_INTERVAL)
    }

    // The refresh interval is a protocol constant; overriding it exists only
    // so tests can watch a refresh happen without waiting five minutes.
    #[cfg(test)]
    fn acquire_exclusive_with_refresh_interval(
        backend: Arc<dyn LockBackend>,
        crypto: RepoCrypto,
        refresh_interval: Duration,
    ) -> Result<Self> {
        Self::acquire(backend, crypto, true, refresh_interval)
    }

    fn acquire(
        backend: Arc<dyn LockBackend>,
        crypto: RepoCrypto,
        exclusive: bool,
        refresh_interval: Duration,
    ) -> Result<Self> {
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
            Mutex::new(LockShared {
                current_name: name,
                stop: false,
                last_refresh: std::time::Instant::now(),
                poisoned: false,
            }),
            Condvar::new(),
        ));
        let refresher = {
            let backend = Arc::clone(&backend);
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || {
                refresh_loop(&backend, &crypto, exclusive, refresh_interval, &shared);
            })
        };
        Ok(Self {
            backend,
            shared,
            refresher: Some(refresher),
            poison_after: refreshability_timeout(refresh_interval),
        })
    }

    /// restic's abort-if-unrefreshable rule for long-running operations: true
    /// once the lock went 22.5 minutes without a successful refresh. From that
    /// point other processes are close to (or past) judging the lock stale and
    /// removing it, after which an exclusive operation like prune could run —
    /// so the owning operation must stop. Latched: a refresh that succeeds
    /// after the timeout was observed does not make the lock trustworthy
    /// again.
    pub(crate) fn poisoned(&self) -> bool {
        use std::sync::PoisonError;
        let mut state = self.shared.0.lock().unwrap_or_else(PoisonError::into_inner);
        if !state.poisoned && state.last_refresh.elapsed() > self.poison_after {
            state.poisoned = true;
        }
        state.poisoned
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
        // A panic here during unwinding would abort the process, and a
        // poisoned state must not stop cleanup — the lock file has to go and
        // the SIGHUP disposition has to be restored regardless.
        use std::sync::PoisonError;
        {
            let (state, cv) = &*self.shared;
            state.lock().unwrap_or_else(PoisonError::into_inner).stop = true;
            cv.notify_all();
        }
        if let Some(handle) = self.refresher.take() {
            let _ = handle.join();
        }
        let name = self
            .shared
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .current_name
            .clone();
        let _ = self.backend.remove(&name);
        sighup_ignore_release();
    }
}

fn refresh_loop(
    backend: &Arc<dyn LockBackend>,
    crypto: &RepoCrypto,
    exclusive: bool,
    refresh_interval: Duration,
    shared: &Arc<(Mutex<LockShared>, Condvar)>,
) {
    let (state, cv) = &**shared;
    loop {
        let guard = state.lock().expect("lock state poisoned");
        let (guard, timeout) = cv
            .wait_timeout_while(guard, refresh_interval, |s| !s.stop)
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
            let mut s = state.lock().expect("lock state poisoned");
            s.current_name = new;
            s.last_refresh = std::time::Instant::now();
        }
        // On refresh failure just try again next tick; the lock only turns
        // stale for others after 30 minutes without a successful refresh.
        // Long-running holders (the SMB share) watch `poisoned()` and abort
        // per restic's 22.5-minute refreshability rule.
    }
}

fn write_lock(backend: &dyn LockBackend, crypto: &RepoCrypto, data: &LockData) -> Result<String> {
    let json = serde_json::to_vec(data).context("serializing lock file")?;
    write_unpacked(backend, crypto, &json)
}

/// Seals a payload as an unpacked repo file (the encoding restic uses for
/// locks, snapshots, index, …) and writes it under its content-addressed
/// name — the SHA-256 hex of the ciphertext. Returns the name.
pub(crate) fn write_unpacked(
    backend: &dyn LockBackend,
    crypto: &RepoCrypto,
    plain: &[u8],
) -> Result<String> {
    let sealed = crypto.seal(plain)?;
    let name = hex(&Sha256::digest(&sealed));
    backend.write(&name, &sealed)?;
    Ok(name)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
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

/// restic's acquisition-time conflict check without writing a lock file:
/// would a command that takes a lock of the given kind be blocked right now?
/// Callers use this to know *before spawning restic* that the repo is locked
/// (restic itself never auto-removes stale locks during acquisition, so even
/// a stale lock blocks). The error carries the holder's details and matches
/// [`is_lock_error`]. Test-only, like its only caller — the restic spawn
/// harness (`src/restic.rs`) — since no runtime flow spawns restic anymore.
#[cfg(test)]
pub(crate) fn check_blocking_locks(
    backend: &dyn LockBackend,
    crypto: &RepoCrypto,
    exclusive: bool,
) -> Result<()> {
    check_for_other_locks(backend, crypto, None, exclusive)
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
//
// Unix-only concept: a same-host `restic unlock` probes the holder PID with
// SIGHUP, which would kill us unless ignored. restic on Windows probes with
// OpenProcess instead (`lock_windows.go`), so there is nothing to guard —
// the counter still runs so both platforms share one code path.
// ---------------------------------------------------------------------------

static LOCKS_HELD: AtomicUsize = AtomicUsize::new(0);

fn sighup_ignore_acquire() {
    if LOCKS_HELD.fetch_add(1, Ordering::SeqCst) == 0 {
        #[cfg(unix)]
        unsafe {
            let _ = libc::signal(libc::SIGHUP, libc::SIG_IGN);
        }
    }
}

fn sighup_ignore_release() {
    if LOCKS_HELD.fetch_sub(1, Ordering::SeqCst) == 1 {
        #[cfg(unix)]
        unsafe {
            let _ = libc::signal(libc::SIGHUP, libc::SIG_DFL);
        }
    }
}

// Signal disposition and LOCKS_HELD are process-global, and the test harness
// runs tests on parallel threads — so every test (in any module) that
// acquires a RepoLock must hold this guard, or the SIGHUP assertions would
// race with other acquiring tests.
#[cfg(test)]
pub(crate) fn test_acquire_guard() -> std::sync::MutexGuard<'static, ()> {
    static ACQUIRING: Mutex<()> = Mutex::new(());
    ACQUIRING.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    type WriteHook = Box<dyn FnOnce(&MemLockBackend) + Send>;

    struct MemLockBackend {
        files: Mutex<HashMap<String, Vec<u8>>>,
        // Fired once, right after the next write completes — lets a test
        // inject a competing lock inside acquisition's 200 ms grace window.
        on_write: Mutex<Option<WriteHook>>,
        // Simulates an unreachable backend for the refresh loop: while set,
        // every write fails (reads and removes keep working, like a backend
        // that turned read-only or an object store rejecting PUTs).
        fail_writes: std::sync::atomic::AtomicBool,
    }

    impl MemLockBackend {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                files: Mutex::new(HashMap::new()),
                on_write: Mutex::new(None),
                fail_writes: std::sync::atomic::AtomicBool::new(false),
            })
        }

        fn count(&self) -> usize {
            self.files.lock().unwrap().len()
        }

        fn set_write_hook(&self, hook: WriteHook) {
            *self.on_write.lock().unwrap() = Some(hook);
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
            if self.fail_writes.load(Ordering::SeqCst) {
                bail!("injected write failure");
            }
            let _ = self.files.lock().unwrap().insert(name.to_string(), data.to_vec());
            let hook = self.on_write.lock().unwrap().take();
            if let Some(hook) = hook {
                hook(self);
            }
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

    // The pre-spawn check the restic harness uses (src/restic.rs) — same
    // rules as acquisition, no lock file written, and a stale lock still
    // blocks (restic never auto-removes stale locks during acquisition).
    #[test]
    fn check_blocking_locks_applies_restic_rules_without_writing() {
        let backend = MemLockBackend::new();
        let crypto = test_crypto(true);

        assert!(check_blocking_locks(backend.as_ref(), &crypto, false).is_ok());
        assert!(check_blocking_locks(backend.as_ref(), &crypto, true).is_ok());
        assert_eq!(backend.count(), 0, "the check must not create lock files");

        let mut stale = LockData::ours(false);
        stale.time = Timestamp::now() - jiff::SignedDuration::from_secs(STALE_TIMEOUT_SECS + 300);
        write_lock(backend.as_ref(), &crypto, &stale).unwrap();
        assert!(check_blocking_locks(backend.as_ref(), &crypto, false).is_ok());
        let err = check_blocking_locks(backend.as_ref(), &crypto, true).unwrap_err();
        assert!(is_lock_error(&format!("{err:#}")), "unexpected error: {err:#}");
    }

    #[test]
    fn acquire_writes_lock_and_drop_removes_it() {
        let _guard = test_acquire_guard();
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

    #[test]
    fn refresh_replaces_lock_file_and_never_leaves_zero_locks() {
        let _guard = test_acquire_guard();
        let backend = MemLockBackend::new();
        let crypto = test_crypto(true);
        let lock = RepoLock::acquire_exclusive_with_refresh_interval(
            Arc::clone(&backend) as Arc<dyn LockBackend>,
            crypto.clone(),
            Duration::from_millis(50),
        )
        .unwrap();
        let first = backend.list().unwrap()[0].0.clone();

        // Wait for a refresh: a lock file with a new storage id appears. In
        // restic's refresh order (write new, then remove old) there may
        // transiently be two locks, but never zero.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let refreshed = loop {
            let names: Vec<String> =
                backend.list().unwrap().into_iter().map(|(n, _)| n).collect();
            assert!(!names.is_empty(), "refresh must never leave the repo unlocked");
            assert!(names.len() <= 2, "more than two lock files during refresh: {names:?}");
            if let Some(new) = names.iter().find(|n| **n != first) {
                break new.clone();
            }
            assert!(std::time::Instant::now() < deadline, "lock was never refreshed");
            std::thread::sleep(Duration::from_millis(5));
        };

        // The old file is removed right after the new one is written, and the
        // refreshed lock still parses as our exclusive lock.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while backend.read(&first).unwrap().is_some() {
            assert!(std::time::Instant::now() < deadline, "old lock file was never removed");
            std::thread::sleep(Duration::from_millis(5));
        }
        let raw = backend.read(&refreshed).unwrap().expect("refreshed lock exists");
        let data = parse_lock(&crypto, &raw).unwrap();
        assert!(data.exclusive);
        assert_eq!(data.pid, std::process::id() as i32);

        drop(lock);
        assert_eq!(backend.count(), 0, "drop must remove the *current* (refreshed) lock");
    }

    // restic's refreshability rule scaled down: at a 20 ms refresh interval
    // the poison threshold is 90 ms (4.5×, the same ratio as 22.5 min to
    // 5 min). Once the backend stops accepting writes for that long, the
    // lock reports poisoned — and stays poisoned even after the backend
    // recovers and a refresh succeeds again.
    #[test]
    fn unrefreshable_lock_becomes_poisoned_and_stays_poisoned() {
        let _guard = test_acquire_guard();
        let backend = MemLockBackend::new();
        let crypto = test_crypto(true);
        let lock = RepoLock::acquire_exclusive_with_refresh_interval(
            Arc::clone(&backend) as Arc<dyn LockBackend>,
            crypto,
            Duration::from_millis(20),
        )
        .unwrap();
        assert!(!lock.poisoned(), "a fresh lock is healthy");

        backend.fail_writes.store(true, Ordering::SeqCst);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !lock.poisoned() {
            assert!(std::time::Instant::now() < deadline, "lock never became poisoned");
            std::thread::sleep(Duration::from_millis(5));
        }

        // Backend recovers; wait until a refresh visibly succeeded (the lock
        // file's storage id changes on every refresh).
        let before: Vec<String> =
            backend.list().unwrap().into_iter().map(|(n, _)| n).collect();
        backend.fail_writes.store(false, Ordering::SeqCst);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let now: Vec<String> =
                backend.list().unwrap().into_iter().map(|(n, _)| n).collect();
            if now != before {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "refresh never resumed");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            lock.poisoned(),
            "poisoning must latch: during the outage another process may have \
             removed the lock as stale"
        );

        drop(lock);
        assert_eq!(backend.count(), 0);
    }

    #[test]
    fn competing_lock_in_grace_window_backs_off_and_removes_own_lock() {
        let _guard = test_acquire_guard();
        let backend = MemLockBackend::new();
        let crypto = test_crypto(true);

        // The instant our lock file lands, a competing exclusive lock appears
        // — after the initial conflict check, inside the 200 ms wait. The
        // re-check must spot it, remove our own lock, and fail.
        let planted = crypto.clone();
        backend.set_write_hook(Box::new(move |b| {
            let mut other = LockData::ours(true);
            other.pid = 1; // some other process
            write_lock(b, &planted, &other).unwrap();
        }));

        let err = RepoLock::acquire_exclusive(
            Arc::clone(&backend) as Arc<dyn LockBackend>,
            crypto.clone(),
        )
        .map(|_| ())
        .unwrap_err();
        assert!(is_lock_error(&format!("{err:#}")), "unexpected error: {err:#}");

        // Only the competitor's lock remains — ours was backed off.
        let remaining = backend.list().unwrap();
        assert_eq!(remaining.len(), 1);
        let data =
            parse_lock(&crypto, &backend.read(&remaining[0].0).unwrap().unwrap()).unwrap();
        assert_eq!(data.pid, 1);
    }

    #[test]
    fn simultaneous_exclusive_acquisitions_never_both_succeed() {
        let _guard = test_acquire_guard();
        let backend = MemLockBackend::new();
        let crypto = test_crypto(true);

        // Both threads race the full protocol. Valid outcomes per restic's
        // rules: one winner, or both back off (each saw the other's lock in
        // the re-check). Never two holders, never leftover lock files.
        for round in 0..3 {
            let barrier = std::sync::Barrier::new(2);
            let results: Vec<Result<RepoLock>> = std::thread::scope(|s| {
                let handles: Vec<_> = (0..2)
                    .map(|_| {
                        let b = Arc::clone(&backend) as Arc<dyn LockBackend>;
                        let c = crypto.clone();
                        let barrier = &barrier;
                        s.spawn(move || {
                            barrier.wait();
                            RepoLock::acquire_exclusive(b, c)
                        })
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().unwrap()).collect()
            });

            let winners = results.iter().filter(|r| r.is_ok()).count();
            assert!(winners <= 1, "round {round}: two holders of an exclusive lock");
            for failed in results.iter().filter_map(|r| r.as_ref().err()) {
                assert!(is_lock_error(&format!("{failed:#}")), "round {round}: {failed:#}");
            }
            assert_eq!(
                backend.count(),
                winners,
                "round {round}: losers must remove their own lock files"
            );
            drop(results);
            assert_eq!(backend.count(), 0, "round {round}: lock file left after release");
        }
    }

    // Unix-only: on Windows there is no SIGHUP probe to defend against, and
    // the acquire/release helpers are deliberate no-ops there.
    #[cfg(unix)]
    #[test]
    fn sighup_ignored_while_any_lock_held_and_restored_after() {
        let _guard = test_acquire_guard();

        fn disposition() -> libc::sighandler_t {
            unsafe {
                let mut old: libc::sigaction = std::mem::zeroed();
                assert_eq!(libc::sigaction(libc::SIGHUP, std::ptr::null(), &mut old), 0);
                old.sa_sigaction
            }
        }

        assert_eq!(disposition(), libc::SIG_DFL, "no lock held yet");

        let crypto = test_crypto(true);
        let backend_a = MemLockBackend::new();
        let exclusive = RepoLock::acquire_exclusive(
            Arc::clone(&backend_a) as Arc<dyn LockBackend>,
            crypto.clone(),
        )
        .unwrap();
        assert_eq!(disposition(), libc::SIG_IGN, "SIGHUP must be ignored while holding a lock");

        // restic's same-host staleness probe (`restic unlock`) delivers a real
        // SIGHUP to the holder PID — the process must survive it.
        unsafe {
            assert_eq!(libc::raise(libc::SIGHUP), 0);
        }

        // A second held lock (different repo) keeps SIGHUP ignored until the
        // *last* lock is released.
        let backend_b = MemLockBackend::new();
        let shared =
            RepoLock::acquire_shared(Arc::clone(&backend_b) as Arc<dyn LockBackend>, crypto)
                .unwrap();
        drop(exclusive);
        assert_eq!(disposition(), libc::SIG_IGN, "still holding one lock");
        drop(shared);
        assert_eq!(disposition(), libc::SIG_DFL, "all locks released");
    }

    // -----------------------------------------------------------------------
    // RestLockBackend against a minimal in-process rest-server mock.
    // -----------------------------------------------------------------------

    struct RestMock {
        base_url: String,
        auths: Arc<Mutex<Vec<Option<String>>>>,
        accepts: Arc<Mutex<Vec<Option<String>>>>,
    }

    impl RestMock {
        // `v1_list` makes GET /locks/ answer with the API-v1 plain name array
        // regardless of the Accept header (an old rest-server).
        fn start(v1_list: bool) -> Self {
            use std::io::{BufRead, BufReader, Read, Write};
            use std::net::{TcpListener, TcpStream};

            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let files: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::default();
            let auths: Arc<Mutex<Vec<Option<String>>>> = Arc::default();
            let accepts: Arc<Mutex<Vec<Option<String>>>> = Arc::default();

            fn serve(
                stream: TcpStream,
                files: &Mutex<HashMap<String, Vec<u8>>>,
                auths: &Mutex<Vec<Option<String>>>,
                accepts: &Mutex<Vec<Option<String>>>,
                v1_list: bool,
            ) -> std::io::Result<()> {
                let mut writer = stream.try_clone()?;
                let mut reader = BufReader::new(stream);
                // reqwest keeps connections alive: serve requests until EOF.
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line)? == 0 {
                        return Ok(());
                    }
                    let mut parts = line.split_whitespace();
                    let method = parts.next().unwrap_or("").to_string();
                    let path = parts.next().unwrap_or("").to_string();
                    let (mut len, mut auth, mut accept) = (0_usize, None, None);
                    loop {
                        let mut h = String::new();
                        reader.read_line(&mut h)?;
                        let h = h.trim_end();
                        if h.is_empty() {
                            break;
                        }
                        let Some((k, v)) = h.split_once(':') else { continue };
                        let v = v.trim();
                        match k.to_ascii_lowercase().as_str() {
                            "content-length" => len = v.parse().unwrap_or(0),
                            "authorization" => auth = Some(v.to_string()),
                            "accept" => accept = Some(v.to_string()),
                            _ => {}
                        }
                    }
                    let mut body = vec![0_u8; len];
                    reader.read_exact(&mut body)?;
                    auths.lock().unwrap().push(auth);
                    accepts.lock().unwrap().push(accept.clone());

                    let (status, resp): (u16, Vec<u8>) = if let Some(name) =
                        path.strip_prefix("/repo/locks/")
                    {
                        match (method.as_str(), name) {
                            ("GET", "") => {
                                let files = files.lock().unwrap();
                                let v2 = accept.as_deref()
                                    == Some("application/vnd.x.restic.rest.v2");
                                let json = if v2 && !v1_list {
                                    serde_json::Value::Array(
                                        files
                                            .iter()
                                            .map(|(k, v)| {
                                                serde_json::json!({"name": k, "size": v.len()})
                                            })
                                            .collect(),
                                    )
                                } else {
                                    serde_json::json!(files.keys().collect::<Vec<_>>())
                                };
                                (200, json.to_string().into_bytes())
                            }
                            ("GET", name) => files
                                .lock()
                                .unwrap()
                                .get(name)
                                .map_or((404, Vec::new()), |d| (200, d.clone())),
                            ("POST", name) => {
                                let _ = files.lock().unwrap().insert(name.to_string(), body);
                                (200, Vec::new())
                            }
                            ("DELETE", name) => {
                                if files.lock().unwrap().remove(name).is_some() {
                                    (200, Vec::new())
                                } else {
                                    (404, Vec::new())
                                }
                            }
                            _ => (405, Vec::new()),
                        }
                    } else {
                        (404, Vec::new())
                    };
                    let head = format!(
                        "HTTP/1.1 {status} status\r\nContent-Length: {}\r\n\
                         Content-Type: application/octet-stream\r\n\r\n",
                        resp.len()
                    );
                    writer.write_all(head.as_bytes())?;
                    writer.write_all(&resp)?;
                    writer.flush()?;
                }
            }

            {
                let (files, auths, accepts) =
                    (Arc::clone(&files), Arc::clone(&auths), Arc::clone(&accepts));
                std::thread::spawn(move || {
                    for conn in listener.incoming() {
                        let Ok(stream) = conn else { return };
                        let (files, auths, accepts) =
                            (Arc::clone(&files), Arc::clone(&auths), Arc::clone(&accepts));
                        std::thread::spawn(move || {
                            let _ = serve(stream, &files, &auths, &accepts, v1_list);
                        });
                    }
                });
            }
            Self { base_url: format!("http://127.0.0.1:{port}/repo/"), auths, accepts }
        }
    }

    #[test]
    fn rest_backend_v2_full_cycle_with_basic_auth() {
        let mock = RestMock::start(false);
        let backend = RestLockBackend::new(&mock.base_url, "andrew", "hunter2", "locks").unwrap();

        assert!(backend.list().unwrap().is_empty());
        backend.write("aaaa", b"data-1").unwrap();
        backend.write("bbbb", b"data-two").unwrap();
        let mut listed = backend.list().unwrap();
        listed.sort();
        assert_eq!(
            listed,
            vec![("aaaa".to_string(), 6), ("bbbb".to_string(), 8)],
            "v2 list must carry real sizes"
        );
        assert_eq!(backend.read("aaaa").unwrap(), Some(b"data-1".to_vec()));
        assert_eq!(backend.read("missing").unwrap(), None, "404 read maps to None");
        backend.remove("aaaa").unwrap();
        backend.remove("aaaa").unwrap(); // removing a missing lock is not an error
        assert_eq!(backend.list().unwrap(), vec![("bbbb".to_string(), 8)]);

        // Every request carried basic auth; every list asked for API v2.
        let auths = mock.auths.lock().unwrap();
        assert!(!auths.is_empty());
        assert!(
            auths.iter().all(|a| a.as_deref() == Some("Basic YW5kcmV3Omh1bnRlcjI=")),
            "unexpected auth headers: {auths:?}"
        );
        assert!(
            mock.accepts
                .lock()
                .unwrap()
                .iter()
                .any(|a| a.as_deref() == Some("application/vnd.x.restic.rest.v2"))
        );
    }

    #[test]
    fn rest_backend_v1_list_fallback_and_no_auth_without_user() {
        let mock = RestMock::start(true);
        let backend = RestLockBackend::new(&mock.base_url, "", "", "locks").unwrap();

        backend.write("cccc", b"x").unwrap();
        // v1 answers with names only — size is unknown, reported as u64::MAX
        // so the entry is still read instead of skipped as a 0-byte upload.
        assert_eq!(backend.list().unwrap(), vec![("cccc".to_string(), u64::MAX)]);

        let auths = mock.auths.lock().unwrap();
        assert!(auths.iter().all(Option::is_none), "no user configured, no auth header");
    }

    #[test]
    fn rest_backend_list_404_means_no_locks() {
        // rest-server answers 404 for a repo without a locks/ dir yet; the
        // mock 404s everything outside /repo/.
        let mock = RestMock::start(false);
        let url = mock.base_url.replace("/repo/", "/uninitialized/");
        let backend = RestLockBackend::new(&url, "", "", "locks").unwrap();
        assert!(backend.list().unwrap().is_empty());
        // Writes must NOT swallow errors the same way.
        assert!(backend.write("aaaa", b"x").is_err());
    }

    // Live: full LockBackend + RepoLock protocol cycle against a real Garage
    // S3 server (scripts/garage-test-server.sh). Uses a per-run root so the
    // seeded read-test repository is never touched.
    #[test]
    #[ignore]
    fn live_garage_s3_lock_backend_cycle() {
        let _guard = test_acquire_guard();
        let endpoint = std::env::var("WRUSTIC_GARAGE_ENDPOINT")
            .unwrap_or_else(|_| "http://127.0.0.1:3900".into());
        let backend: Arc<dyn LockBackend> = Arc::new(
            crate::s3_backend::S3LockBackend::new(
                &endpoint,
                "wrustic-it",
                "garage",
                &format!("lock-backend-it-{}", std::process::id()),
                "GK22222222222222222222222222222222",
                "3333333333333333333333333333333333333333333333333333333333333333",
                "locks",
            )
            .unwrap(),
        );
        let crypto = test_crypto(true);

        // Raw file operations on the locks/ prefix.
        assert!(backend.list().unwrap().is_empty());
        backend.write("feedface", b"payload").unwrap();
        assert_eq!(backend.list().unwrap(), vec![("feedface".to_string(), 7)]);
        assert_eq!(backend.read("feedface").unwrap(), Some(b"payload".to_vec()));
        assert_eq!(backend.read("missing").unwrap(), None);
        backend.remove("feedface").unwrap();
        backend.remove("feedface").unwrap(); // idempotent
        assert!(backend.list().unwrap().is_empty());

        // Full protocol over S3: acquire, conflict, release.
        let lock =
            RepoLock::acquire_exclusive(Arc::clone(&backend), crypto.clone()).unwrap();
        let err = RepoLock::acquire_exclusive(Arc::clone(&backend), crypto.clone())
            .map(|_| ())
            .unwrap_err();
        assert!(is_lock_error(&format!("{err:#}")), "unexpected error: {err:#}");
        drop(lock);
        assert!(backend.list().unwrap().is_empty(), "release must remove the S3 lock");

        // Stale-lock removal over S3.
        write_stale_lock_for_tests(backend.as_ref(), &crypto);
        assert_eq!(remove_stale_locks(backend.as_ref(), &crypto).unwrap(), 1);
        assert!(backend.list().unwrap().is_empty());
    }
}
