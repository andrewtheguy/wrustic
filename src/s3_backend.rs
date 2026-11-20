//! S3 access to the repository — both repository data and `locks/`.
//!
//! [`S3DataBackend`] implements rustic_core's `ReadBackend`/`WriteBackend`
//! over an opendal S3 operator, replacing rustic_backend's generic opendal
//! backend. rustic_backend 0.8.0 still offers no per-service opendal features — its
//! `opendal` feature drags in every service crate (~150 packages) — so
//! wrustic carries this thin wrapper instead and compiles only
//! `opendal-service-s3`.
//!
//! [`S3LockBackend`] serves the lock module: lock files are outside
//! rustic_core's `FileType`-addressed world entirely (its enum has no `Lock`
//! variant), so it reaches the `locks/` prefix directly. The prefix is a
//! constructor parameter, so the same backend also serves `snapshots/` for
//! the native tag edit's raw-JSON rewrite. See docs/locking.md.

use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicUsize, Ordering},
};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use opendal::{
    HttpTransporter, OperationContext,
    blocking::Operator,
    layers::{RetryEvent, RetryInterceptor, RetryLayer},
    options::{ListOptions, ReadOptions},
    services::S3,
};
use opendal_http_transport_reqwest::ReqwestTransport;
use rustic_core::{
    BytesList, ErrorKind, FileType, Id, ReadBackend, RusticError, RusticResult, WriteBackend,
};
use tokio::runtime::Runtime;

use crate::lock::LockBackend;
use crate::repo::{CONNECT_TIMEOUT, RequestPolicy};

/// Counts the retries an operator makes by itself. opendal retries a request
/// that failed without the server's answer and reports only the last
/// attempt's error, so a write can come back as refused while an earlier
/// attempt of it is still on its way to being stored. A write during which
/// the count moved was attempted more than once — or another thread's
/// request was, which errs on the side of saying so.
#[derive(Clone, Debug, Default)]
struct Retries(Arc<AtomicUsize>);

impl Retries {
    fn count(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

impl RetryInterceptor for Retries {
    fn intercept(&self, _event: RetryEvent<'_>) {
        let _ = self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// The context key [`S3DataBackend`] puts on the error of a write that was
/// attempted more than once ([`Retries`]).
pub(crate) const AFTER_EARLIER_ATTEMPTS: &str = "after-earlier-attempts";

/// Blocking S3 operator for a profile's repository root. Shared by the data
/// and lock backends so both speak to the same place the same way: the same
/// connect and stall timeouts as the REST backend, over wrustic's own reqwest
/// client (opendal's default client has neither).
fn build_operator(
    endpoint: &str,
    bucket: &str,
    region: &str,
    root: &str,
    access_key: &str,
    secret_key: &str,
    policy: RequestPolicy,
) -> Result<(Operator, Retries)> {
    let mut builder = S3::default()
        .bucket(bucket)
        .region(region)
        .root(root)
        .access_key_id(access_key)
        .secret_access_key(secret_key);
    if !endpoint.is_empty() {
        builder = builder.endpoint(endpoint);
    }

    let client = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(policy.read_timeout)
        .build()
        .context("building the S3 HTTP client")?;
    let context = OperationContext::new()
        .with_http_transport(HttpTransporter::new(ReqwestTransport::new(client)));

    let retries = Retries::default();
    let operator = opendal::Operator::new(builder)
        .context("creating the S3 backend")?
        .with_context(context)
        .layer(
            RetryLayer::new()
                .with_max_times(policy.retries)
                .with_jitter()
                .with_notify(retries.clone()),
        );

    let _guard = runtime().enter();
    Ok((Operator::new(operator).context("creating the blocking S3 backend")?, retries))
}

pub(crate) struct S3LockBackend {
    operator: Operator,
    retries: Retries,
    dir: String,
}

impl S3LockBackend {
    pub(crate) fn new(
        endpoint: &str,
        bucket: &str,
        region: &str,
        root: &str,
        access_key: &str,
        secret_key: &str,
        dir: &str,
    ) -> Result<Self> {
        let (operator, retries) = build_operator(
            endpoint,
            bucket,
            region,
            root,
            access_key,
            secret_key,
            RequestPolicy::STANDARD,
        )
        .with_context(|| format!("creating the S3 {dir} backend"))?;
        Ok(Self { operator, retries, dir: dir.to_string() })
    }

    fn key(&self, name: &str) -> String {
        format!("{}/{name}", self.dir)
    }
}

impl LockBackend for S3LockBackend {
    fn list(&self) -> Result<Vec<(String, u64)>> {
        let options = ListOptions {
            recursive: true,
            ..Default::default()
        };
        let entries = self
            .operator
            .lister_options(&format!("{}/", self.dir), options)
            .map_err(|err| anyhow!("listing S3 {}: {err}", self.dir))?;
        let mut out = Vec::new();
        for result in entries {
            let entry = result.map_err(|err| anyhow!("reading S3 {} listing: {err}", self.dir))?;
            if entry.metadata().is_file() {
                out.push((entry.name().to_string(), entry.metadata().content_length()));
            }
        }
        Ok(out)
    }

    fn read(&self, name: &str) -> Result<Option<Vec<u8>>> {
        match self.operator.read(&self.key(name)) {
            Ok(buf) => Ok(Some(buf.to_bytes().to_vec())),
            Err(err) if err.kind() == opendal::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(anyhow!("reading S3 {}: {err}", self.key(name))),
        }
    }

    fn write(&self, name: &str, data: &[u8]) -> Result<()> {
        let retries_before = self.retries.count();
        self.operator
            .write(&self.key(name), data.to_vec())
            .map_err(|err| {
                let error =
                    anyhow::Error::new(err).context(format!("writing S3 {}", self.key(name)));
                if self.retries.count() == retries_before {
                    error
                } else {
                    error.context(crate::lock::AfterEarlierAttempts)
                }
            })?;
        Ok(())
    }

    fn remove(&self, name: &str) -> Result<()> {
        match self.operator.delete(&self.key(name)) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == opendal::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(anyhow!("removing S3 {}: {err}", self.key(name))),
        }
    }

    // A refusal is the last attempt's answer; it settles the write only if
    // that attempt was the only one.
    fn failed_write_can_land_later(&self, error: &anyhow::Error) -> bool {
        error.downcast_ref::<crate::lock::AfterEarlierAttempts>().is_some()
            || !crate::lock::server_refused(crate::lock::as_std_error(error))
    }
}

fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("building the S3 runtime")
    })
}

// ---------------------------------------------------------------------------
// Repository data — rustic_core's backend traits over the same operator.
// ---------------------------------------------------------------------------

/// rustic_core backend for repository *data* on S3. A trimmed-down port of
/// rustic_backend 0.8.0's `OpenDALBackend` (same layout rules, same operator
/// calls), S3-only and without the throttle/connection-limit knobs wrustic
/// never exposed. `create()` keeps its default no-op — repository init stays
/// on the restic CLI.
#[derive(Clone, Debug)]
pub(crate) struct S3DataBackend {
    operator: Operator,
    retries: Retries,
}

impl S3DataBackend {
    pub(crate) fn new(
        endpoint: &str,
        bucket: &str,
        region: &str,
        root: &str,
        access_key: &str,
        secret_key: &str,
        policy: RequestPolicy,
    ) -> Result<Self> {
        let (operator, retries) =
            build_operator(endpoint, bucket, region, root, access_key, secret_key, policy)
                .context("creating the S3 data backend")?;
        Ok(Self { operator, retries })
    }

    /// Repo-relative object key for a file — restic's on-disk layout:
    /// `config` at the root, packs sharded as `data/<first two hex>/<id>`,
    /// everything else flat under its type directory.
    fn path(tpe: FileType, id: &Id) -> String {
        let hex_id = id.to_hex();
        match tpe {
            FileType::Config => "config".to_string(),
            FileType::Pack => format!("data/{}/{}", &hex_id[0..2], hex_id.as_str()),
            _ => format!("{}/{}", tpe.dirname(), hex_id.as_str()),
        }
    }
}

fn backend_error(err: opendal::Error, what: &str, path: &str) -> Box<RusticError> {
    RusticError::with_source(ErrorKind::Backend, "S3 backend: {what} failed for `{path}`", err)
        .attach_context("what", what.to_string())
        .attach_context("path", path.to_string())
}

impl ReadBackend for S3DataBackend {
    fn location(&self) -> String {
        let info = self.operator.info();
        format!("opendal:{}:{}", info.scheme(), info.name())
    }

    fn list_with_size(&self, tpe: FileType) -> RusticResult<Vec<(Id, u32)>> {
        // The config file is a singleton addressed by a default id.
        if tpe == FileType::Config {
            return match self.operator.stat("config") {
                Ok(meta) => {
                    let Ok(length) = u32::try_from(meta.content_length()) else {
                        return Err(RusticError::new(
                            ErrorKind::Backend,
                            "S3 backend: file `{path}` is too large for a u32 length",
                        )
                        .attach_context("path", "config".to_string()));
                    };
                    Ok(vec![(Id::default(), length)])
                }
                Err(err) if err.kind() == opendal::ErrorKind::NotFound => Ok(Vec::new()),
                Err(err) => Err(backend_error(err, "stat", "config")),
            };
        }

        let path = tpe.dirname().to_string() + "/";
        let options = ListOptions {
            recursive: true,
            ..Default::default()
        };
        let lister = self
            .operator
            .lister_options(&path, options)
            .map_err(|err| backend_error(err, "list", &path))?;
        let mut entries = Vec::new();
        for result in lister {
            let entry = result.map_err(|err| backend_error(err, "list entry", &path))?;
            let metadata = entry.metadata();
            if !metadata.is_file() {
                continue;
            }
            let Some(id) = Id::parse_some(entry.name(), tpe) else {
                continue;
            };
            let Ok(length) = u32::try_from(metadata.content_length()) else {
                return Err(RusticError::new(
                    ErrorKind::Backend,
                    "S3 backend: file `{path}` is too large for a u32 length",
                )
                .attach_context("path", entry.path().to_string()));
            };
            entries.push((id, length));
        }
        Ok(entries)
    }

    fn read_full(&self, tpe: FileType, id: &Id) -> RusticResult<Bytes> {
        let path = Self::path(tpe, id);
        Ok(self
            .operator
            .read(&path)
            .map_err(|err| backend_error(err, "read", &path))?
            .to_bytes())
    }

    fn read_partial(
        &self,
        tpe: FileType,
        id: &Id,
        _cacheable: bool,
        offset: u32,
        length: u32,
    ) -> RusticResult<Bytes> {
        let path = Self::path(tpe, id);
        let options = ReadOptions {
            range: (u64::from(offset)..u64::from(offset) + u64::from(length)).into(),
            ..Default::default()
        };
        Ok(self
            .operator
            .read_options(&path, options)
            .map_err(|err| backend_error(err, "partial read", &path))?
            .to_bytes())
    }

    fn warmup_path(&self, tpe: FileType, id: &Id) -> String {
        // Full object key including the configured root, mirroring
        // rustic_backend — warm-up commands want the real S3 key.
        let root = self.operator.info().root();
        let root = root.trim_matches('/');
        let relative = Self::path(tpe, id);
        if root.is_empty() {
            relative
        } else {
            format!("{root}/{relative}")
        }
    }
}

impl WriteBackend for S3DataBackend {
    fn write_bytes(
        &self,
        tpe: FileType,
        id: &Id,
        _cacheable: bool,
        content: BytesList,
    ) -> RusticResult<()> {
        let path = Self::path(tpe, id);
        let retries_before = self.retries.count();
        self.operator.write(&path, content.into_vec()).map(|_| ()).map_err(|err| {
            let error = backend_error(err, "write", &path);
            if self.retries.count() == retries_before {
                error
            } else {
                error.attach_context(AFTER_EARLIER_ATTEMPTS, "yes")
            }
        })
    }

    fn remove(&self, tpe: FileType, id: &Id, _cacheable: bool) -> RusticResult<()> {
        let path = Self::path(tpe, id);
        self.operator
            .delete(&path)
            .map_err(|err| backend_error(err, "remove", &path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_matches_restics_repository_layout() {
        let id: Id = "03dc1178e4e54f69beaf35dd9d4256a5a600e9fa3452b9db80bd649938923e67"
            .parse()
            .unwrap();
        assert_eq!(S3DataBackend::path(FileType::Config, &id), "config");
        assert_eq!(
            S3DataBackend::path(FileType::Pack, &id),
            "data/03/03dc1178e4e54f69beaf35dd9d4256a5a600e9fa3452b9db80bd649938923e67"
        );
        assert_eq!(
            S3DataBackend::path(FileType::Snapshot, &id),
            "snapshots/03dc1178e4e54f69beaf35dd9d4256a5a600e9fa3452b9db80bd649938923e67"
        );
    }

    // A stand-in for S3 that takes PUTs: with `hold_first` it has the first
    // one in full and sits on it until released — a server stuck storing —
    // and answers every other one with AccessDenied; without, it refuses
    // them all.
    struct PutMock {
        endpoint: String,
        state: Arc<(std::sync::Mutex<PutState>, std::sync::Condvar)>,
    }

    #[derive(Default)]
    struct PutState {
        puts: usize,
        held: bool,
        released: bool,
        stored: bool,
    }

    impl PutMock {
        fn start(hold_first: bool) -> Self {
            use std::io::{BufRead, BufReader, Read, Write};

            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let state: Arc<(std::sync::Mutex<PutState>, std::sync::Condvar)> = Arc::default();
            let shared = Arc::clone(&state);
            std::thread::spawn(move || {
                for conn in listener.incoming() {
                    let Ok(stream) = conn else { return };
                    let state = Arc::clone(&shared);
                    std::thread::spawn(move || -> std::io::Result<()> {
                        let mut writer = stream.try_clone()?;
                        let mut reader = BufReader::new(stream);
                        loop {
                            let mut line = String::new();
                            if reader.read_line(&mut line)? == 0 {
                                return Ok(());
                            }
                            let is_put = line.starts_with("PUT ");
                            let mut len = 0_usize;
                            loop {
                                let mut header = String::new();
                                let _ = reader.read_line(&mut header)?;
                                let header = header.trim_end().to_ascii_lowercase();
                                if header.is_empty() {
                                    break;
                                }
                                if let Some(value) = header.strip_prefix("content-length:") {
                                    len = value.trim().parse().unwrap_or(0);
                                }
                            }
                            let mut body = vec![0_u8; len];
                            reader.read_exact(&mut body)?;

                            let first = {
                                let mut put = state.0.lock().unwrap();
                                if is_put {
                                    put.puts += 1;
                                }
                                is_put && hold_first && put.puts == 1
                            };
                            let response = if first {
                                let mut put = state.0.lock().unwrap();
                                put.held = true;
                                state.1.notify_all();
                                let mut put = state.1.wait_while(put, |put| !put.released).unwrap();
                                put.stored = true;
                                state.1.notify_all();
                                "HTTP/1.1 200 OK\r\nETag: \"etag\"\r\nContent-Length: 0\r\n\r\n"
                                    .to_string()
                            } else {
                                let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error>\
                                           <Code>AccessDenied</Code><Message>Access Denied\
                                           </Message></Error>";
                                format!(
                                    "HTTP/1.1 403 Forbidden\r\nContent-Type: application/xml\r\n\
                                     Content-Length: {}\r\n\r\n{xml}",
                                    xml.len()
                                )
                            };
                            writer.write_all(response.as_bytes())?;
                            writer.flush()?;
                        }
                    });
                }
            });
            Self { endpoint, state }
        }

        fn backend(&self) -> S3LockBackend {
            let (operator, retries) = build_operator(
                &self.endpoint,
                "bucket",
                "us-east-1",
                "",
                "key",
                "secret",
                RequestPolicy { retries: 2, read_timeout: std::time::Duration::from_millis(500) },
            )
            .expect("an operator for the mock");
            S3LockBackend { operator, retries, dir: "snapshots".into() }
        }

        fn wait_for(&self, what: impl Fn(&PutState) -> bool) {
            let (state, timed_out) = self
                .state
                .1
                .wait_timeout_while(
                    self.state.0.lock().unwrap(),
                    std::time::Duration::from_secs(20),
                    |put| !what(put),
                )
                .unwrap();
            assert!(!timed_out.timed_out(), "the mock did not get there");
            drop(state);
        }
    }

    // opendal retries a PUT that got no answer and reports the last
    // attempt's error. So a write can come back as AccessDenied while its
    // first PUT is still with the server, which goes on to store it: such a
    // refusal must not count as settling the write. A refusal of the only
    // attempt does.
    #[test]
    fn a_refusal_after_a_put_that_got_no_answer_is_not_final() {
        let refused = |error: &anyhow::Error| {
            crate::lock::server_refused(crate::lock::as_std_error(error))
        };

        let mock = PutMock::start(true);
        let backend = mock.backend();
        let err = backend.write("aaaa", b"late").expect_err("the retry is refused");
        assert!(refused(&err), "the error is the refusal of a later attempt: {err:#}");
        assert!(
            backend.failed_write_can_land_later(&err),
            "and must not be taken for the whole write's: {err:#}"
        );
        // The first PUT had arrived in full, and is stored once the server
        // gets on with it.
        mock.wait_for(|put| put.held);
        mock.state.0.lock().unwrap().released = true;
        mock.state.1.notify_all();
        mock.wait_for(|put| put.stored);

        // The same through rustic_core's backend, which the index goes by.
        let mock = PutMock::start(true);
        let lock_backend = mock.backend();
        let data = S3DataBackend {
            operator: lock_backend.operator.clone(),
            retries: lock_backend.retries.clone(),
        };
        let id: Id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .unwrap();
        let err = data
            .write_bytes(FileType::Index, &id, false, Bytes::from_static(b"late").into())
            .expect_err("the retry is refused");
        assert!(crate::lock::server_refused(&*err), "{err}");
        assert!(err.context_value(AFTER_EARLIER_ATTEMPTS).is_some(), "{err}");
        mock.state.0.lock().unwrap().released = true;
        mock.state.1.notify_all();

        // Refused at once: the one attempt is all there was.
        let mock = PutMock::start(false);
        let backend = mock.backend();
        let err = backend.write("aaaa", b"never").expect_err("refused");
        assert!(refused(&err), "{err:#}");
        assert!(!backend.failed_write_can_land_later(&err), "{err:#}");
        assert_eq!(mock.state.0.lock().unwrap().puts, 1, "a refusal is not retried");
    }

    // Live: the full ReadBackend + WriteBackend surface against a real Silo
    // S3 server (scripts/silo-test-server.sh). Uses a per-run root so the
    // seeded read-test repository is never touched, and removes everything it
    // writes.
    #[test]
    #[ignore]
    fn live_silo_s3_data_backend_read_write_cycle() {
        let endpoint = std::env::var("WRUSTIC_SILO_ENDPOINT")
            .unwrap_or_else(|_| "http://127.0.0.1:9000".into());
        let backend = S3DataBackend::new(
            &endpoint,
            "wrustic-it",
            "us-east-1",
            &format!("data-backend-it-{}", std::process::id()),
            "wrustic-it",
            "wrustic-it-secret",
            RequestPolicy::STANDARD,
        )
        .unwrap();

        assert!(backend.location().starts_with("opendal:s3:"));
        assert!(backend.list_with_size(FileType::Config).unwrap().is_empty());
        assert!(backend.list_with_size(FileType::Snapshot).unwrap().is_empty());

        let id: Id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .unwrap();
        let payload = Bytes::from_static(b"snapshot payload for the data backend");
        backend
            .write_bytes(FileType::Snapshot, &id, false, payload.clone().into())
            .unwrap();
        assert_eq!(
            backend.list_with_size(FileType::Snapshot).unwrap(),
            vec![(id, u32::try_from(payload.len()).unwrap())]
        );
        assert_eq!(backend.read_full(FileType::Snapshot, &id).unwrap(), payload);
        assert_eq!(
            backend.read_partial(FileType::Snapshot, &id, false, 9, 7).unwrap(),
            Bytes::from_static(b"payload")
        );

        // The config singleton is addressed by the default id.
        backend
            .write_bytes(
                FileType::Config,
                &Id::default(),
                false,
                Bytes::from_static(b"cfg").into(),
            )
            .unwrap();
        assert_eq!(
            backend.list_with_size(FileType::Config).unwrap(),
            vec![(Id::default(), 3)]
        );

        backend.remove(FileType::Snapshot, &id, false).unwrap();
        backend.remove(FileType::Config, &Id::default(), false).unwrap();
        assert!(backend.list_with_size(FileType::Snapshot).unwrap().is_empty());
        assert!(backend.list_with_size(FileType::Config).unwrap().is_empty());
    }
}
