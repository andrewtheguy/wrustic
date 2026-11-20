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
use rustic_core::{
    BytesList, ErrorKind, FileType, Id, Open, ReadBackend, Repository, RepositoryBackends,
    RusticError, RusticResult, WriteBackend,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// restic's timing constants (internal/restic/lock.go,
// internal/repository/lock.go in restic 0.19.1). Values must match: other
// restic processes judge our locks by them and vice versa.
const WAIT_BEFORE_LOCK_CHECK: Duration = Duration::from_millis(200);
const REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);
const STALE_TIMEOUT_SECS: i64 = 30 * 60;
// Between attempts to store a file that a backend keeps failing to write
// (`RepoLock::write_unpacked_while_held`).
const WRITE_RETRY_PAUSE: Duration =
    if cfg!(test) { Duration::from_millis(2) } else { Duration::from_secs(5) };

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
    /// Whether a `write` that returned an error can still be completed by the
    /// backend afterwards. True wherever a server takes the request: once it
    /// holds the whole body, it stores the file whether or not the client is
    /// still there — rest-server reads the body and goes on to sync and
    /// rename without looking at the connection again — and it answers a
    /// removal sent in between with success, there being nothing to remove
    /// yet. No client-side call cancels such a write or waits for it. So for
    /// these backends a failed write followed by a successful `remove` does
    /// not mean the file will not appear.
    fn failed_write_can_land_later(&self) -> bool {
        true
    }
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

    // The write is this process's own system calls: when it has returned,
    // nothing of it is still under way.
    fn failed_write_can_land_later(&self) -> bool {
        false
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
        Self::with_timeout(rest_url, user, password, dir, Duration::from_secs(30))
    }

    fn with_timeout(
        rest_url: &str,
        user: &str,
        password: &str,
        dir: &str,
        timeout: Duration,
    ) -> Result<Self> {
        let mut base = rest_url.to_string();
        if !base.ends_with('/') {
            base.push('/');
        }
        let dir_url = url::Url::parse(&base)
            .with_context(|| format!("parsing REST URL `{rest_url}`"))?
            .join(&format!("{dir}/"))
            .with_context(|| format!("building {dir}/ URL"))?;
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
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
        let poison_after = refreshability_timeout(refresh_interval);
        let refresher = {
            let backend = Arc::clone(&backend);
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || {
                refresh_loop(&backend, &crypto, exclusive, refresh_interval, poison_after, &shared);
            })
        };
        Ok(Self {
            backend,
            shared,
            refresher: Some(refresher),
            poison_after,
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
        self.health().poisoned()
    }

    /// A handle that answers [`Self::poisoned`] without owning the lock, for a
    /// reader on another thread that has to stop as soon as the lock goes bad.
    pub(crate) fn health(&self) -> LockHealth {
        LockHealth {
            shared: Arc::clone(&self.shared),
            poison_after: self.poison_after,
        }
    }

    /// [`write_unpacked`] for a file that is only sound if this lock held
    /// until it was stored — a snapshot naming blobs nothing else refers to
    /// yet, which a prune deletes once the lock is out of its way.
    ///
    /// Checking [`Self::poisoned`] beforehand is not enough for that, because
    /// no backend bounds the write to the 7.5 minutes a lock stays valid for
    /// others after it turns poisoned: a local write blocks for as long as
    /// the filesystem does, the S3 one has a stall timeout and retries but no
    /// total, and only REST gives up after 30 seconds. None can be cancelled
    /// from another thread either. So the lock is asked again once the write
    /// returned: still healthy means it was refreshed in time all the way
    /// through (poisoning latches), so no prune can have started before the
    /// file existed. Poisoned means that is no longer known, and the file is
    /// removed again rather than reported as written.
    ///
    /// A write that reports an error says nothing about whether the file is
    /// there: a backend can fail a write it has in fact stored (a timeout
    /// after the server committed). So an error is checked against the
    /// repository before it is believed. A file that is there as written,
    /// under a healthy lock, is published, and is reported as that; one that
    /// is not is written again, because a write that then succeeds settles
    /// the matter whatever became of the earlier ones.
    ///
    /// How often depends on what a failure leaves behind. A backend whose
    /// write is over once it returned gets one more attempt, and then the
    /// file is removed and the error passed on. For one whose failed writes
    /// can still land ([`LockBackend::failed_write_can_land_later`]) there is
    /// no giving up while the lock holds: returning drops the lock, a prune
    /// can then delete the blobs the file names, and the write the server
    /// was still holding publishes a file pointing at nothing. Under the
    /// lock a late write is harmless, so the attempts go on, checking the
    /// repository before each, until the file is stored or the lock is
    /// lost — with the repository out of reach that is the 22.5 minutes
    /// the lock takes to turn bad.
    ///
    /// Once the lock is lost the removal proves nothing for such a backend:
    /// it cannot be ordered after a write the server is still holding, and
    /// the error says so instead of claiming the file is gone. The name is
    /// known beforehand — it is the hash of what is written — and is in
    /// every error, so such a file can be found.
    pub(crate) fn write_unpacked_while_held(
        &self,
        backend: &dyn LockBackend,
        crypto: &RepoCrypto,
        plain: &[u8],
    ) -> Result<String> {
        if self.poisoned() {
            bail!("the repository lock could not be refreshed in time; nothing was written");
        }
        let (name, sealed) = seal_named(crypto, plain)?;
        let is_stored = || matches!(backend.read(&name), Ok(Some(found)) if found == sealed);
        let mut written = backend.write(&name, &sealed);
        let mut stored = written.is_ok();
        let a_write_failed = written.is_err();
        let settled_on_return = !backend.failed_write_can_land_later();
        let mut retried = false;
        while !stored && !self.poisoned() {
            stored = is_stored();
            if stored || (settled_on_return && retried) {
                break;
            }
            if retried {
                std::thread::sleep(WRITE_RETRY_PAUSE);
            }
            retried = true;
            written = backend.write(&name, &sealed);
            stored = written.is_ok();
        }
        let lost = self.poisoned();
        if stored && !lost {
            return Ok(name);
        }
        let why = match (&written, lost) {
            (Err(e), false) => format!("writing {name} failed ({e:#})"),
            (Ok(()), _) => format!(
                "the repository lock could not be refreshed while {name} was being written, so \
                 it cannot be trusted"
            ),
            (Err(e), true) => format!(
                "the repository lock could not be refreshed while {name} was being written, so \
                 it cannot be trusted (the write itself reported: {e:#})"
            ),
        };
        // `LockBackend::remove` succeeds for a file that is not there. For a
        // write that returned, that makes a success final; for one that
        // failed it may only mean the file is not there *yet*.
        match backend.remove(&name) {
            Err(e) => bail!(
                "{why}, and removing it failed ({e:#}) — {name} may be in the repository \
                 without being meant to: check the repository and remove it"
            ),
            Ok(()) if !a_write_failed => bail!("{why}; it was removed again"),
            Ok(()) if !backend.failed_write_can_land_later() => bail!(
                "{why}; it is not in the repository (removed again in case it had been stored)"
            ),
            Ok(()) => bail!(
                "{why}; it is not in the repository now (removed again in case it had been \
                 stored), but the server can still complete a write it reported as failed, \
                 and nothing can cancel that — if {name} turns up later it was not meant to \
                 be published: remove it"
            ),
        }
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

/// See [`RepoLock::health`].
#[derive(Clone)]
pub(crate) struct LockHealth {
    shared: Arc<(Mutex<LockShared>, Condvar)>,
    poison_after: Duration,
}

impl LockHealth {
    /// [`RepoLock::poisoned`]. Accurate whenever it is asked, not only when
    /// asked often: the refresher latches a timeout it outlived, too.
    pub(crate) fn poisoned(&self) -> bool {
        use std::sync::PoisonError;
        let mut state = self.shared.0.lock().unwrap_or_else(PoisonError::into_inner);
        if !state.poisoned && state.last_refresh.elapsed() > self.poison_after {
            state.poisoned = true;
        }
        state.poisoned
    }
}

/// Makes everything rustic_core writes through `backends` depend on a lock:
/// the returned backends are what the repository is opened with, and the
/// [`WriteGate`] is armed with the lock once it is held (the lock needs the
/// master key, which only the opened repository has).
///
/// This is restic's cancel-on-lost-lock for an operation that cannot be
/// cancelled. A long rustic_core call — `merge_trees` — writes packs and then
/// the index files that make them count, and returns only when it is done; a
/// check of [`RepoLock::poisoned`] afterwards is too late if the lock was
/// lost in between, because a prune that got in meanwhile deletes packs no
/// index names yet, and the index written after that names deleted packs.
/// Behind the gate, a write is refused once the lock is poisoned, and a file
/// whose write returned after the lock went bad is removed again and reported
/// as failed — so whatever is left was written under a lock that had been
/// healthy all along (poisoning latches), which no prune can have preceded.
///
/// It also ends the writing: rustic_core's packer hands its packs to threads
/// it only waits for when it finishes normally, so after an error return
/// they may still be storing a pack and the index entry for it.
/// [`WriteGate::close`] waits for the writes under way and refuses every
/// later one, and has to be called before the lock is given up.
pub(crate) fn gate_writes(backends: &RepositoryBackends) -> (RepositoryBackends, WriteGate) {
    let gate = WriteGate(Arc::new(GateState {
        health: std::sync::OnceLock::new(),
        closed: std::sync::RwLock::new(false),
        unconfirmed: Mutex::new(Vec::new()),
    }));
    let gated = |inner: Arc<dyn WriteBackend>| -> Arc<dyn WriteBackend> {
        Arc::new(LockGatedBackend { inner, gate: gate.clone() })
    };
    let gated = RepositoryBackends::new(
        gated(backends.repository()),
        backends.repo_hot().map(gated),
    );
    (gated, gate)
}

/// See [`gate_writes`]. Lets everything through until it is armed.
#[derive(Clone)]
pub(crate) struct WriteGate(Arc<GateState>);

struct GateState {
    health: std::sync::OnceLock<LockHealth>,
    // Held shared by every write for as long as it runs, exclusively by
    // `close`, which is how closing waits for the writes under way.
    closed: std::sync::RwLock<bool>,
    // Files written past a lost lock whose removal could not be confirmed.
    unconfirmed: Mutex<Vec<String>>,
}

impl WriteGate {
    pub(crate) fn arm(&self, lock: &RepoLock) {
        let _ = self.0.health.set(lock.health());
    }

    /// Waits for the writes under way and refuses every later one. Idempotent.
    pub(crate) fn close(&self) {
        use std::sync::PoisonError;
        *self.0.closed.write().unwrap_or_else(PoisonError::into_inner) = true;
    }

    /// A guard that closes the gate when dropped. Declared after the lock it
    /// protects, it is dropped before it — on every way out, a panic included.
    pub(crate) fn close_on_drop(&self) -> ClosesGate {
        ClosesGate(self.clone())
    }

    /// The files (`<directory> <id>`) that were written after the lock was
    /// lost and are not known to be gone again: removing them failed, and
    /// they could not be shown to be absent. Anything but a pack is listed —
    /// an index file left behind may name packs a prune has deleted, whereas
    /// a pack nothing names is only waste the next prune collects.
    pub(crate) fn unconfirmed_removals(&self) -> Vec<String> {
        use std::sync::PoisonError;
        self.0.unconfirmed.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    fn lock_lost(&self) -> bool {
        self.0.health.get().is_some_and(LockHealth::poisoned)
    }
}

/// See [`WriteGate::close_on_drop`].
pub(crate) struct ClosesGate(WriteGate);

impl Drop for ClosesGate {
    fn drop(&mut self) {
        self.0.close();
    }
}

struct LockGatedBackend {
    inner: Arc<dyn WriteBackend>,
    gate: WriteGate,
}

impl std::fmt::Debug for LockGatedBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LockGatedBackend({})", self.inner.location())
    }
}

impl ReadBackend for LockGatedBackend {
    fn location(&self) -> String {
        self.inner.location()
    }

    fn list_with_size(&self, tpe: FileType) -> RusticResult<Vec<(Id, u32)>> {
        self.inner.list_with_size(tpe)
    }

    fn list(&self, tpe: FileType) -> RusticResult<Vec<Id>> {
        self.inner.list(tpe)
    }

    fn read_full(&self, tpe: FileType, id: &Id) -> RusticResult<bytes::Bytes> {
        self.inner.read_full(tpe, id)
    }

    fn read_partial(
        &self,
        tpe: FileType,
        id: &Id,
        cacheable: bool,
        offset: u32,
        length: u32,
    ) -> RusticResult<bytes::Bytes> {
        self.inner.read_partial(tpe, id, cacheable, offset, length)
    }

    fn warmup_path(&self, tpe: FileType, id: &Id) -> String {
        self.inner.warmup_path(tpe, id)
    }

    fn needs_warm_up(&self) -> bool {
        self.inner.needs_warm_up()
    }

    fn warm_up(&self, tpe: FileType, id: &Id) -> RusticResult<()> {
        self.inner.warm_up(tpe, id)
    }
}

impl WriteBackend for LockGatedBackend {
    fn create(&self) -> RusticResult<()> {
        self.inner.create()
    }

    fn write_bytes(
        &self,
        tpe: FileType,
        id: &Id,
        cacheable: bool,
        content: BytesList,
    ) -> RusticResult<()> {
        use std::sync::PoisonError;
        // Shared for the whole write, so that `WriteGate::close` returns only
        // when no write is under way.
        let closed = self.gate.0.closed.read().unwrap_or_else(PoisonError::into_inner);
        if *closed {
            return Err(RusticError::new(
                ErrorKind::Backend,
                "the operation this write belongs to is over; nothing more is written",
            ));
        }
        if self.gate.lock_lost() {
            return Err(RusticError::new(
                ErrorKind::Backend,
                "the repository lock could not be refreshed in time; nothing more is written",
            ));
        }
        let written = self.inner.write_bytes(tpe, id, cacheable, content);
        if !self.gate.lock_lost() {
            return written;
        }
        // The lock was lost over this write. The file is taken to be there
        // even if the write reported an error — a backend can fail a write it
        // has stored — and must not stay.
        let what = format!("{} {}", tpe.dirname(), id.to_hex().as_str());
        let write_error = match &written {
            Ok(()) => String::new(),
            Err(e) => format!(" (the write itself reported: {e})"),
        };
        let gone = match self.inner.remove(tpe, id, cacheable) {
            Ok(()) => Ok(()),
            // A failed removal of something that is not there is no failure.
            Err(e) if tpe != FileType::Pack => match self.inner.list(tpe) {
                Ok(present) if !present.contains(id) => Ok(()),
                _ => Err(e),
            },
            Err(e) => Err(e),
        };
        Err(match gone {
            Ok(()) => RusticError::new(
                ErrorKind::Backend,
                format!(
                    "the repository lock could not be refreshed while {what} was being \
                     written, so it cannot be trusted and was removed again{write_error}"
                ),
            ),
            Err(e) => {
                if tpe != FileType::Pack {
                    self.gate
                        .0
                        .unconfirmed
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(what.clone());
                }
                RusticError::new(
                    ErrorKind::Backend,
                    format!(
                        "the repository lock could not be refreshed while {what} was being \
                         written, so it cannot be trusted, and removing it failed \
                         ({e}){write_error}"
                    ),
                )
            }
        })
    }

    fn remove(&self, tpe: FileType, id: &Id, cacheable: bool) -> RusticResult<()> {
        self.inner.remove(tpe, id, cacheable)
    }
}

#[cfg(test)]
impl LockHealth {
    /// Makes the lock count as unrefreshed past the cutoff from here on,
    /// without waiting for it: the moment a test loses the lock is then one
    /// it chooses, not one a slow scheduler can choose for it.
    pub(crate) fn expire_for_tests(&self) {
        self.shared.0.lock().expect("lock state poisoned").poisoned = true;
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
    poison_after: Duration,
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
            // A refresh that lands after the timeout ran out does not make
            // the lock trustworthy again, whether or not anyone asked in
            // between.
            if s.last_refresh.elapsed() > poison_after {
                s.poisoned = true;
            }
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
    let (name, sealed) = seal_named(crypto, plain)?;
    backend.write(&name, &sealed)?;
    Ok(name)
}

/// A payload sealed as an unpacked repo file, and the name it is stored
/// under: known before anything is written.
fn seal_named(crypto: &RepoCrypto, plain: &[u8]) -> Result<(String, Vec<u8>)> {
    let sealed = crypto.seal(plain)?;
    Ok((hex(&Sha256::digest(&sealed)), sealed))
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
/// [`is_lock_error`]. Its caller is the restic spawn harness
/// (`src/restic.rs`), whose unstick pre-check runs it before every spawn.
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
        // A write that is stored and then reported as failed — a timeout
        // after the server committed — and a backend that cannot delete.
        report_write_failure: std::sync::atomic::AtomicBool,
        fail_removes: std::sync::atomic::AtomicBool,
        // A write the server took in full and reports as failed before it
        // has stored anything — a client timeout during the server's sync —
        // which `complete_held_writes` then stores, as the server would.
        hold_writes: std::sync::atomic::AtomicBool,
        held: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl MemLockBackend {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                files: Mutex::new(HashMap::new()),
                on_write: Mutex::new(None),
                fail_writes: std::sync::atomic::AtomicBool::new(false),
                report_write_failure: std::sync::atomic::AtomicBool::new(false),
                fail_removes: std::sync::atomic::AtomicBool::new(false),
                hold_writes: std::sync::atomic::AtomicBool::new(false),
                held: Mutex::new(Vec::new()),
            })
        }

        fn complete_held_writes(&self) {
            let held = std::mem::take(&mut *self.held.lock().unwrap());
            self.files.lock().unwrap().extend(held);
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
            if self.hold_writes.load(Ordering::SeqCst) {
                self.held.lock().unwrap().push((name.to_string(), data.to_vec()));
                bail!("injected timeout of a write the server is still holding");
            }
            let _ = self.files.lock().unwrap().insert(name.to_string(), data.to_vec());
            let hook = self.on_write.lock().unwrap().take();
            if let Some(hook) = hook {
                hook(self);
            }
            if self.report_write_failure.load(Ordering::SeqCst) {
                bail!("injected failure of a write that was stored");
            }
            Ok(())
        }

        fn remove(&self, name: &str) -> Result<()> {
            if self.fail_removes.load(Ordering::SeqCst) {
                bail!("injected remove failure");
            }
            let _ = self.files.lock().unwrap().remove(name);
            Ok(())
        }
    }

    // A backend whose write is over once it has returned, as a local
    // repository's is.
    struct Synchronous(Arc<MemLockBackend>);
    impl LockBackend for Synchronous {
        fn list(&self) -> Result<Vec<(String, u64)>> {
            self.0.list()
        }
        fn read(&self, name: &str) -> Result<Option<Vec<u8>>> {
            self.0.read(name)
        }
        fn write(&self, name: &str, data: &[u8]) -> Result<()> {
            self.0.write(name, data)
        }
        fn remove(&self, name: &str) -> Result<()> {
            self.0.remove(name)
        }
        fn failed_write_can_land_later(&self) -> bool {
            false
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

    // A lock for the lock-loss tests: on restic's real timing, so it cannot
    // go bad by itself however slowly the test is scheduled. A test loses it
    // with `LockHealth::expire_for_tests`, at the moment it chooses.
    fn steady_lock(crypto: &RepoCrypto) -> (Arc<MemLockBackend>, RepoLock) {
        let locks = MemLockBackend::new();
        let lock =
            RepoLock::acquire_exclusive(Arc::clone(&locks) as Arc<dyn LockBackend>, crypto.clone())
                .expect("acquire the lock");
        (locks, lock)
    }

    // A file that depends on the lock, written by a backend that takes longer
    // than the lock lasts: the write itself succeeds, so only asking the lock
    // again afterwards can tell that the file may already point at pruned
    // data. It must come back as an error with the file gone — and a lock
    // that is already bad must not get as far as writing.
    #[test]
    fn a_file_whose_write_outlasted_the_lock_is_taken_back() {
        let _guard = test_acquire_guard();
        let crypto = test_crypto(true);
        let (locks, lock) = steady_lock(&crypto);

        let files = MemLockBackend::new();
        let name = lock
            .write_unpacked_while_held(files.as_ref(), &crypto, b"{\"kept\":true}")
            .expect("a healthy lock publishes");
        assert!(files.read(&name).unwrap().is_some());

        // The lock is lost while the next write is under way: the hook runs
        // inside the backend's write, after the file is stored.
        let health = lock.health();
        files.set_write_hook(Box::new(move |_| health.expire_for_tests()));
        let err = lock
            .write_unpacked_while_held(files.as_ref(), &crypto, b"{\"kept\":false}")
            .expect_err("a write that outlasted the lock must not count as written");
        assert!(format!("{err:#}").contains("removed again"), "{err:#}");
        assert_eq!(files.count(), 1, "only the file written under the healthy lock remains");
        assert!(files.read(&name).unwrap().is_some());

        // From then on a write never reaches the backend.
        let reached = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&reached);
        files.set_write_hook(Box::new(move |_| flag.store(true, Ordering::SeqCst)));
        let err = lock
            .write_unpacked_while_held(files.as_ref(), &crypto, b"{\"late\":true}")
            .expect_err("a poisoned lock must not publish at all");
        assert!(format!("{err:#}").contains("nothing was written"), "{err:#}");
        assert!(!reached.load(Ordering::SeqCst), "the write must not reach the backend");
        assert_eq!(files.count(), 1);

        drop(lock);
        assert_eq!(locks.count(), 0);
    }

    // A backend can report a write as failed that it has stored. With the
    // lock lost over it, that file is as untrustworthy as one whose write
    // succeeded, so it is removed too; and when it cannot be removed, the
    // error has to name it, with what the write and the removal reported.
    #[test]
    fn a_failed_write_past_the_lock_is_reconciled() {
        let _guard = test_acquire_guard();
        let crypto = test_crypto(true);

        // Stored, reported as failed, lock lost: removed.
        let (_locks, lock) = steady_lock(&crypto);
        let files = MemLockBackend::new();
        files.report_write_failure.store(true, Ordering::SeqCst);
        let health = lock.health();
        files.set_write_hook(Box::new(move |_| health.expire_for_tests()));
        let err = lock
            .write_unpacked_while_held(files.as_ref(), &crypto, b"{\"n\":1}")
            .expect_err("the write failed and the lock is lost");
        let message = format!("{err:#}");
        assert!(message.contains("removed again"), "{message}");
        assert!(message.contains("injected failure of a write that was stored"), "{message}");
        assert_eq!(files.count(), 0, "the stored file must not stay");
        drop(lock);

        // Stored, lock lost, and the backend cannot remove it: the error
        // names the file and says so.
        let (_locks, lock) = steady_lock(&crypto);
        let files = MemLockBackend::new();
        files.fail_removes.store(true, Ordering::SeqCst);
        let health = lock.health();
        files.set_write_hook(Box::new(move |_| health.expire_for_tests()));
        let err = lock
            .write_unpacked_while_held(files.as_ref(), &crypto, b"{\"n\":2}")
            .expect_err("the lock is lost");
        let message = format!("{err:#}");
        let left = files.list().unwrap().remove(0).0;
        assert!(message.contains("removing it failed"), "{message}");
        assert!(message.contains("injected remove failure"), "{message}");
        assert!(message.contains(&left), "the file left behind must be named: {message}");
        assert!(!message.contains("removed again"), "{message}");
        drop(lock);

        // Under a healthy lock, on a backend that is done with a write once
        // it returned, a failed write is just that, named.
        let (_locks, lock) = steady_lock(&crypto);
        let files = MemLockBackend::new();
        files.fail_writes.store(true, Ordering::SeqCst);
        let err = lock
            .write_unpacked_while_held(&Synchronous(Arc::clone(&files)), &crypto, b"{\"n\":3}")
            .expect_err("the write failed");
        let message = format!("{err:#}");
        assert!(message.contains("injected write failure"), "{message}");
        assert!(message.starts_with("writing "), "{message}");
        drop(lock);
    }

    // The same ambiguity with the lock in good health: a write reported as
    // failed may have stored the file. What is reported has to be what is in
    // the repository — a snapshot that is there is published, not a failure
    // with a snapshot behind it.
    #[test]
    fn a_write_reported_as_failed_but_stored_counts_as_published() {
        let _guard = test_acquire_guard();
        let crypto = test_crypto(true);
        let (_locks, lock) = steady_lock(&crypto);

        // Stored, reported as failed: found in the repository as written.
        let files = MemLockBackend::new();
        files.report_write_failure.store(true, Ordering::SeqCst);
        let name = lock
            .write_unpacked_while_held(files.as_ref(), &crypto, b"{\"n\":1}")
            .expect("the file is there, whatever the write said");
        assert_eq!(files.count(), 1);
        assert!(files.read(&name).unwrap().is_some());
        assert!(!lock.poisoned(), "the lock was healthy throughout");

        // Not stored the first times: the attempts go on until one settles
        // it, the backend being one whose failed writes can still land.
        let files = MemLockBackend::new();
        files.fail_writes.store(true, Ordering::SeqCst);
        let recovering = Arc::clone(&files);
        // The backend comes back for the fourth attempt.
        let attempts = Arc::new(AtomicUsize::new(0));
        struct Recovers(Arc<MemLockBackend>, Arc<AtomicUsize>);
        impl LockBackend for Recovers {
            fn list(&self) -> Result<Vec<(String, u64)>> {
                self.0.list()
            }
            fn read(&self, name: &str) -> Result<Option<Vec<u8>>> {
                self.0.read(name)
            }
            fn write(&self, name: &str, data: &[u8]) -> Result<()> {
                if self.1.fetch_add(1, Ordering::SeqCst) == 3 {
                    self.0.fail_writes.store(false, Ordering::SeqCst);
                }
                self.0.write(name, data)
            }
            fn remove(&self, name: &str) -> Result<()> {
                self.0.remove(name)
            }
        }
        let name = lock
            .write_unpacked_while_held(&Recovers(recovering, Arc::clone(&attempts)), &crypto, b"{\"n\":2}")
            .expect("the fourth attempt succeeds");
        assert_eq!(attempts.load(Ordering::SeqCst), 4);
        assert!(files.read(&name).unwrap().is_some());

        // A write that succeeds is still just that, in one attempt.
        let files = MemLockBackend::new();
        let name = lock
            .write_unpacked_while_held(files.as_ref(), &crypto, b"{\"n\":3}")
            .expect("a healthy lock publishes");
        assert!(files.read(&name).unwrap().is_some());
        drop(lock);
    }

    // What a removal cannot settle. A server that has taken a write in full
    // stores it whether or not the client is still waiting, and answers a
    // removal sent meanwhile with success: nothing is there yet. Giving up
    // on such a write hands the lock back with the write still to come, so
    // while the lock holds the attempts go on until the file is there; and
    // once it is lost, the error must say the file can still be published
    // rather than that it is gone.
    #[test]
    fn a_failed_write_the_server_still_holds_is_retried_while_the_lock_holds() {
        fn wait_for_attempts(files: &MemLockBackend, attempts: usize) {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while files.held.lock().unwrap().len() < attempts {
                assert!(std::time::Instant::now() < deadline, "the write was not retried");
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        let _guard = test_acquire_guard();
        let crypto = test_crypto(true);

        // Every attempt times out with the server holding it. The lock is
        // healthy, so the publication does not return; when the server gets
        // round to storing the file, it is found and reported as published.
        let (_locks, lock) = steady_lock(&crypto);
        let files = MemLockBackend::new();
        files.hold_writes.store(true, Ordering::SeqCst);
        let name = std::thread::scope(|scope| {
            let publication = scope
                .spawn(|| lock.write_unpacked_while_held(files.as_ref(), &crypto, b"{\"n\":1}"));
            wait_for_attempts(&files, 3);
            assert!(!publication.is_finished(), "no giving up under a healthy lock");
            assert_eq!(files.count(), 0, "nothing is stored yet");
            files.complete_held_writes();
            publication.join().expect("the publication panicked")
        })
        .expect("the file is there, under a lock that held throughout");
        assert!(files.read(&name).unwrap().is_some());
        assert!(!lock.poisoned());
        drop(lock);

        // The same, and the lock is lost before the server stores anything:
        // only now is the ambiguous error due.
        let (_locks, lock) = steady_lock(&crypto);
        let files = MemLockBackend::new();
        files.hold_writes.store(true, Ordering::SeqCst);
        let err = std::thread::scope(|scope| {
            let publication = scope
                .spawn(|| lock.write_unpacked_while_held(files.as_ref(), &crypto, b"{\"n\":1}"));
            wait_for_attempts(&files, 3);
            assert!(!publication.is_finished(), "no giving up under a healthy lock");
            lock.health().expire_for_tests();
            publication.join().expect("the publication panicked")
        })
        .expect_err("the lock was lost with the write unsettled");
        let message = format!("{err:#}");
        assert_eq!(files.count(), 0, "nothing is stored yet, and the removal found nothing");
        assert!(message.contains("could not be refreshed"), "{message}");
        assert!(message.contains("can still complete a write"), "{message}");
        assert!(message.contains("turns up later"), "{message}");
        assert!(!message.contains("it is not in the repository ("), "{message}");

        // The server gets round to it: the file is published after all, under
        // the name the error gave.
        files.complete_held_writes();
        let published = files.list().unwrap().remove(0).0;
        assert!(message.contains(&published), "the error must name the file: {message}");
        drop(lock);

        // A backend whose writes are its own system calls has nothing under
        // way once the write returned: one more attempt, and it may say the
        // file is gone.
        let (_locks, lock) = steady_lock(&crypto);
        let files = MemLockBackend::new();
        files.fail_writes.store(true, Ordering::SeqCst);
        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&attempts);
        struct Counted(Synchronous, Arc<AtomicUsize>);
        impl LockBackend for Counted {
            fn list(&self) -> Result<Vec<(String, u64)>> {
                self.0.list()
            }
            fn read(&self, name: &str) -> Result<Option<Vec<u8>>> {
                self.0.read(name)
            }
            fn write(&self, name: &str, data: &[u8]) -> Result<()> {
                let _ = self.1.fetch_add(1, Ordering::SeqCst);
                self.0.write(name, data)
            }
            fn remove(&self, name: &str) -> Result<()> {
                self.0.remove(name)
            }
            fn failed_write_can_land_later(&self) -> bool {
                self.0.failed_write_can_land_later()
            }
        }
        let err = lock
            .write_unpacked_while_held(
                &Counted(Synchronous(Arc::clone(&files)), counter),
                &crypto,
                b"{\"n\":2}",
            )
            .expect_err("the write failed");
        let message = format!("{err:#}");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert!(message.contains("it is not in the repository ("), "{message}");
        assert!(!message.contains("turns up later"), "{message}");
        assert!(!LocalLockBackend::new("tmp", "snapshots").failed_write_can_land_later());
        drop(lock);
    }

    // A rustic_core data backend that keeps its files in memory. `on_write`
    // fires once, after the next write has stored its file.
    #[derive(Default)]
    struct MemDataBackend {
        files: Mutex<HashMap<(String, Id), Vec<u8>>>,
        on_write: Mutex<Option<Box<dyn FnOnce() + Send>>>,
        // A write that is stored and then reported as failed, one that fails
        // without storing anything, and a backend that cannot delete.
        report_write_failure: std::sync::atomic::AtomicBool,
        drop_writes: std::sync::atomic::AtomicBool,
        fail_removes: std::sync::atomic::AtomicBool,
    }

    // `FileType` does not hash.
    fn file_key(tpe: FileType, id: &Id) -> (String, Id) {
        (format!("{tpe:?}"), *id)
    }

    impl std::fmt::Debug for MemDataBackend {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("MemDataBackend")
        }
    }

    impl ReadBackend for MemDataBackend {
        fn location(&self) -> String {
            "memory".into()
        }

        fn list_with_size(&self, tpe: FileType) -> RusticResult<Vec<(Id, u32)>> {
            let files = self.files.lock().unwrap();
            Ok(files
                .iter()
                .filter(|((t, _), _)| *t == format!("{tpe:?}"))
                .map(|((_, id), data)| (*id, data.len() as u32))
                .collect())
        }

        fn read_full(&self, tpe: FileType, id: &Id) -> RusticResult<bytes::Bytes> {
            self.files
                .lock()
                .unwrap()
                .get(&file_key(tpe, id))
                .map(|data| data.clone().into())
                .ok_or_else(|| RusticError::new(ErrorKind::Backend, "no such file"))
        }

        fn read_partial(
            &self,
            tpe: FileType,
            id: &Id,
            _cacheable: bool,
            offset: u32,
            length: u32,
        ) -> RusticResult<bytes::Bytes> {
            let all = self.read_full(tpe, id)?;
            Ok(all.slice(offset as usize..(offset + length) as usize))
        }

        fn warmup_path(&self, _tpe: FileType, id: &Id) -> String {
            id.to_hex().as_str().to_string()
        }
    }

    impl WriteBackend for MemDataBackend {
        fn write_bytes(
            &self,
            tpe: FileType,
            id: &Id,
            _cacheable: bool,
            content: BytesList,
        ) -> RusticResult<()> {
            let dropped = self.drop_writes.load(Ordering::SeqCst);
            if !dropped {
                let _ = self
                    .files
                    .lock()
                    .unwrap()
                    .insert(file_key(tpe, id), content.into_vec().concat());
            }
            let hook = self.on_write.lock().unwrap().take();
            if let Some(hook) = hook {
                hook();
            }
            if dropped || self.report_write_failure.load(Ordering::SeqCst) {
                return Err(RusticError::new(ErrorKind::Backend, "injected write failure"));
            }
            Ok(())
        }

        fn remove(&self, tpe: FileType, id: &Id, _cacheable: bool) -> RusticResult<()> {
            if self.fail_removes.load(Ordering::SeqCst) {
                return Err(RusticError::new(ErrorKind::Backend, "injected remove failure"));
            }
            let _ = self.files.lock().unwrap().remove(&file_key(tpe, id));
            Ok(())
        }
    }

    struct Gated {
        lock: RepoLock,
        data: Arc<MemDataBackend>,
        gate: WriteGate,
        backend: Arc<dyn WriteBackend>,
    }

    impl Gated {
        // A gate armed with a steady lock, over a memory backend.
        fn new() -> Self {
            let (_locks, lock) = steady_lock(&test_crypto(true));
            let data = Arc::new(MemDataBackend::default());
            let (backends, gate) = gate_writes(&RepositoryBackends::new(
                Arc::clone(&data) as Arc<dyn WriteBackend>,
                None,
            ));
            gate.arm(&lock);
            Self { lock, data, gate, backend: backends.repository() }
        }

        fn id(n: u8) -> Id {
            format!("{n:02x}").repeat(32).parse().expect("id")
        }

        fn write(&self, tpe: FileType, n: u8) -> RusticResult<()> {
            self.backend.write_bytes(tpe, &Self::id(n), false, vec![n].into())
        }

        fn stored(&self, tpe: FileType, n: u8) -> bool {
            self.data.files.lock().unwrap().contains_key(&file_key(tpe, &Self::id(n)))
        }

        // The lock is lost while the next write is under way.
        fn lose_the_lock_during_the_next_write(&self) {
            let health = self.lock.health();
            *self.data.on_write.lock().unwrap() = Some(Box::new(move || health.expire_for_tests()));
        }
    }

    // What `merge_trees` writes goes through the gate: packs first, then the
    // index that names them. Once the lock is lost — which is when a prune may
    // delete packs no index names yet — no index may be written any more, and
    // one whose write was under way when the lock went bad must not stay.
    #[test]
    fn gated_writes_stop_when_the_lock_is_lost() {
        let _guard = test_acquire_guard();

        // Unarmed: writes go through.
        let data = Arc::new(MemDataBackend::default());
        let (backends, _gate) = gate_writes(&RepositoryBackends::new(
            Arc::clone(&data) as Arc<dyn WriteBackend>,
            None,
        ));
        backends
            .repository()
            .write_bytes(FileType::Pack, &Gated::id(9), false, vec![9].into())
            .expect("an unarmed gate lets writes through");
        assert_eq!(data.files.lock().unwrap().len(), 1);

        // Armed with a healthy lock: writes go through, and the rest of the
        // backend is the inner one.
        let gated = Gated::new();
        gated.write(FileType::Pack, 1).expect("a healthy lock lets writes through");
        gated.write(FileType::Index, 2).expect("a healthy lock lets writes through");
        assert!(gated.stored(FileType::Pack, 1) && gated.stored(FileType::Index, 2));
        assert_eq!(
            gated.backend.read_full(FileType::Index, &Gated::id(2)).unwrap().as_ref(),
            [2]
        );
        assert_eq!(gated.backend.list(FileType::Pack).unwrap(), [Gated::id(1)]);

        // The lock is lost while an index write is under way.
        gated.lose_the_lock_during_the_next_write();
        let err = gated.write(FileType::Index, 3).expect_err("the write outlasted the lock");
        assert!(format!("{err}").contains("removed again"), "{err}");
        assert!(format!("{err}").contains(Gated::id(3).to_hex().as_str()), "{err}");
        assert!(!gated.stored(FileType::Index, 3), "an index written past the lock must not stay");
        assert!(gated.gate.unconfirmed_removals().is_empty());

        // And afterwards a write never reaches the backend.
        let reached = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&reached);
        *gated.data.on_write.lock().unwrap() =
            Some(Box::new(move || flag.store(true, Ordering::SeqCst)));
        let err = gated.write(FileType::Index, 4).expect_err("the lock is lost");
        assert!(format!("{err}").contains("nothing more is written"), "{err}");
        assert!(!reached.load(Ordering::SeqCst), "the write must not reach the backend");
        assert!(!gated.stored(FileType::Index, 4));
        assert!(gated.stored(FileType::Pack, 1) && gated.stored(FileType::Index, 2));
    }

    // Taking a file back can itself fail, and a write can report failure for
    // a file it stored. What matters afterwards is whether an index written
    // past the lock is still there: one that is has to be reported by name,
    // because it may name packs a prune deleted; one that is gone, or was
    // never stored, must not be reported at all.
    #[test]
    fn an_index_that_could_not_be_taken_back_is_reported() {
        let _guard = test_acquire_guard();
        let index_3 = format!("index {}", Gated::id(3).to_hex().as_str());

        // Stored, reported as failed: removed like a write that succeeded.
        let gated = Gated::new();
        gated.data.report_write_failure.store(true, Ordering::SeqCst);
        gated.lose_the_lock_during_the_next_write();
        let err = gated.write(FileType::Index, 3).expect_err("failed, and the lock is lost");
        assert!(format!("{err}").contains("removed again"), "{err}");
        assert!(format!("{err}").contains("injected write failure"), "{err}");
        assert!(!gated.stored(FileType::Index, 3));
        assert!(gated.gate.unconfirmed_removals().is_empty());

        // Stored and not removable: reported, by name.
        let gated = Gated::new();
        gated.data.fail_removes.store(true, Ordering::SeqCst);
        gated.lose_the_lock_during_the_next_write();
        let err = gated.write(FileType::Index, 3).expect_err("the lock is lost");
        assert!(format!("{err}").contains("removing it failed"), "{err}");
        assert!(format!("{err}").contains(&index_3), "{err}");
        assert!(gated.stored(FileType::Index, 3));
        assert_eq!(gated.gate.unconfirmed_removals(), std::slice::from_ref(&index_3));

        // Never stored, and the removal fails: nothing is there, so nothing
        // is left behind.
        let gated = Gated::new();
        gated.data.drop_writes.store(true, Ordering::SeqCst);
        gated.data.fail_removes.store(true, Ordering::SeqCst);
        gated.lose_the_lock_during_the_next_write();
        let err = gated.write(FileType::Index, 3).expect_err("failed, and the lock is lost");
        assert!(format!("{err}").contains("removed again"), "{err}");
        assert!(gated.gate.unconfirmed_removals().is_empty());

        // A pack nothing names is waste, not damage: not reported.
        let gated = Gated::new();
        gated.data.fail_removes.store(true, Ordering::SeqCst);
        gated.lose_the_lock_during_the_next_write();
        let _ = gated.write(FileType::Pack, 5).expect_err("the lock is lost");
        assert!(gated.gate.unconfirmed_removals().is_empty());
    }

    // rustic_core's packer threads can still be writing when `merge_trees` has
    // returned an error. Closing the gate is what makes it safe to give up
    // the lock then: it must not return while a write is under way, and no
    // write may start after it.
    #[test]
    fn closing_the_gate_waits_for_writes_and_refuses_later_ones() {
        let _guard = test_acquire_guard();
        let gated = Gated::new();

        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        *gated.data.on_write.lock().unwrap() = Some(Box::new(move || {
            started_tx.send(()).expect("signal the write is under way");
            release_rx.recv().expect("wait to be released");
        }));
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        std::thread::scope(|scope| {
            let writer = scope.spawn(|| gated.write(FileType::Pack, 1));
            started_rx.recv().expect("the write is under way");
            let closer = scope.spawn(|| {
                gated.gate.close();
                closed.store(true, Ordering::SeqCst);
            });
            std::thread::sleep(Duration::from_millis(100));
            assert!(
                !closed.load(Ordering::SeqCst),
                "close returned while a write was still under way"
            );
            release_tx.send(()).expect("release the write");
            writer.join().unwrap().expect("the write under way completes");
            closer.join().unwrap();
        });
        assert!(closed.load(Ordering::SeqCst));
        assert!(gated.stored(FileType::Pack, 1));

        let err = gated.write(FileType::Index, 2).expect_err("the gate is closed");
        assert!(format!("{err}").contains("is over"), "{err}");
        assert!(!gated.stored(FileType::Index, 2));

        // The guard does the same when it goes out of scope.
        let gated = Gated::new();
        drop(gated.gate.close_on_drop());
        assert!(gated.write(FileType::Pack, 1).is_err());
    }

    // The same outage with nobody asking until it is over: a holder busy
    // elsewhere must still learn that the lock went bad, rather than see a
    // healthy lock because the refresh that ended the outage reset the clock.
    #[test]
    fn an_outage_nobody_watched_still_poisons_the_lock() {
        let _guard = test_acquire_guard();
        let backend = MemLockBackend::new();
        let crypto = test_crypto(true);
        let lock = RepoLock::acquire_exclusive_with_refresh_interval(
            Arc::clone(&backend) as Arc<dyn LockBackend>,
            crypto,
            Duration::from_millis(20),
        )
        .unwrap();
        let health = lock.health();

        backend.fail_writes.store(true, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(300));
        let before: Vec<String> =
            backend.list().unwrap().into_iter().map(|(n, _)| n).collect();
        backend.fail_writes.store(false, Ordering::SeqCst);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while backend.list().unwrap().into_iter().map(|(n, _)| n).collect::<Vec<_>>() == before {
            assert!(std::time::Instant::now() < deadline, "refresh never resumed");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(health.poisoned(), "the refresher must latch the outage it outlived");
        assert!(lock.poisoned());

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
        // While true, a POST whose body has arrived waits before it stores
        // the file — a server stuck syncing to a stalled disk. Like
        // rest-server, it then stores the file without looking at whether
        // the client is still there.
        hold_posts: Arc<(Mutex<bool>, Condvar)>,
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
                hold_posts: &(Mutex<bool>, Condvar),
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
                                drop(
                                    hold_posts
                                        .1
                                        .wait_while(hold_posts.0.lock().unwrap(), |held| *held)
                                        .unwrap(),
                                );
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

            let hold_posts: Arc<(Mutex<bool>, Condvar)> = Arc::default();
            {
                let (files, auths, accepts, hold_posts) = (
                    Arc::clone(&files),
                    Arc::clone(&auths),
                    Arc::clone(&accepts),
                    Arc::clone(&hold_posts),
                );
                std::thread::spawn(move || {
                    for conn in listener.incoming() {
                        let Ok(stream) = conn else { return };
                        let (files, auths, accepts, hold_posts) = (
                            Arc::clone(&files),
                            Arc::clone(&auths),
                            Arc::clone(&accepts),
                            Arc::clone(&hold_posts),
                        );
                        std::thread::spawn(move || {
                            let _ = serve(stream, &files, &auths, &accepts, &hold_posts, v1_list);
                        });
                    }
                });
            }
            Self { base_url: format!("http://127.0.0.1:{port}/repo/"), auths, accepts, hold_posts }
        }

        fn hold_posts(&self, held: bool) {
            *self.hold_posts.0.lock().unwrap() = held;
            self.hold_posts.1.notify_all();
        }
    }

    // The contract `LockBackend::failed_write_can_land_later` states, shown
    // with the real REST client against a server that behaves as rest-server
    // does: it has the whole POST, is held up before storing it, and the
    // client gives up. The removal that follows succeeds — there is nothing
    // to remove — and the file is published once the server gets on with it.
    #[test]
    fn rest_write_that_timed_out_is_stored_after_its_removal() {
        let mock = RestMock::start(false);
        let backend = RestLockBackend::with_timeout(
            &mock.base_url,
            "",
            "",
            "locks",
            Duration::from_millis(300),
        )
        .unwrap();
        assert!(backend.failed_write_can_land_later());

        mock.hold_posts(true);
        backend.write("cccc", b"late").expect_err("the client times out waiting for the server");
        backend.remove("cccc").expect("removing what is not there yet succeeds");
        assert_eq!(backend.read("cccc").unwrap(), None, "not published yet");

        mock.hold_posts(false);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while backend.read("cccc").unwrap().is_none() {
            assert!(std::time::Instant::now() < deadline, "the held write never landed");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(backend.read("cccc").unwrap(), Some(b"late".to_vec()));
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

    // Live: full LockBackend + RepoLock protocol cycle against a real Silo
    // S3 server (scripts/silo-test-server.sh). Uses a per-run root so the
    // seeded read-test repository is never touched.
    #[test]
    #[ignore]
    fn live_silo_s3_lock_backend_cycle() {
        let _guard = test_acquire_guard();
        let endpoint = std::env::var("WRUSTIC_SILO_ENDPOINT")
            .unwrap_or_else(|_| "http://127.0.0.1:9000".into());
        let backend: Arc<dyn LockBackend> = Arc::new(
            crate::s3_backend::S3LockBackend::new(
                &endpoint,
                "wrustic-it",
                "us-east-1",
                &format!("lock-backend-it-{}", std::process::id()),
                "wrustic-it",
                "wrustic-it-secret",
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
