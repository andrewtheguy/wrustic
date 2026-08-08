//! S3 access to the repository — both repository data and `locks/`.
//!
//! [`S3DataBackend`] implements rustic_core's `ReadBackend`/`WriteBackend`
//! over an opendal S3 operator, replacing rustic_backend's generic opendal
//! backend. rustic_backend 0.6.2 offers no per-service opendal features — its
//! `opendal` feature drags in every service crate (~150 packages) — so
//! wrustic carries this thin wrapper instead and compiles only
//! `opendal-service-s3`.
//!
//! [`S3LockBackend`] serves the lock module: lock files are outside
//! rustic_core's `FileType`-addressed world entirely (its enum has no `Lock`
//! variant), so it reaches the `locks/` prefix directly. The prefix is a
//! constructor parameter, so the same backend also serves `snapshots/` for
//! the native tag edit's raw-JSON rewrite. See docs/locking.md.

use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use opendal::{
    blocking::Operator,
    layers::RetryLayer,
    options::{ListOptions, ReadOptions},
    services::S3,
};
use rustic_core::{ErrorKind, FileType, Id, ReadBackend, RusticError, RusticResult, WriteBackend};
use tokio::runtime::Runtime;

use crate::lock::LockBackend;

const DEFAULT_RETRIES: usize = 5;

/// Blocking S3 operator for a profile's repository root. Shared by the data
/// and lock backends so both speak to the same place the same way.
fn build_operator(
    endpoint: &str,
    bucket: &str,
    region: &str,
    root: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<Operator> {
    let mut builder = S3::default()
        .bucket(bucket)
        .region(region)
        .root(root)
        .access_key_id(access_key)
        .secret_access_key(secret_key);
    if !endpoint.is_empty() {
        builder = builder.endpoint(endpoint);
    }

    let operator = opendal::Operator::new(builder)
        .context("creating the S3 backend")?
        .layer(
            RetryLayer::new()
                .with_max_times(DEFAULT_RETRIES)
                .with_jitter(),
        )
        .finish();

    let _guard = runtime().enter();
    Operator::new(operator).context("creating the blocking S3 backend")
}

pub(crate) struct S3LockBackend {
    operator: Operator,
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
        Ok(Self {
            operator: build_operator(endpoint, bucket, region, root, access_key, secret_key)
                .with_context(|| format!("creating the S3 {dir} backend"))?,
            dir: dir.to_string(),
        })
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
        self.operator
            .write(&self.key(name), data.to_vec())
            .map_err(|err| anyhow!("writing S3 {}: {err}", self.key(name)))?;
        Ok(())
    }

    fn remove(&self, name: &str) -> Result<()> {
        match self.operator.delete(&self.key(name)) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == opendal::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(anyhow!("removing S3 {}: {err}", self.key(name))),
        }
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
/// rustic_backend 0.6.2's `OpenDALBackend` (same layout rules, same operator
/// calls), S3-only and without the throttle/connection-limit knobs wrustic
/// never exposed. `create()` keeps its default no-op — repository init stays
/// on the restic CLI.
#[derive(Clone, Debug)]
pub(crate) struct S3DataBackend {
    operator: Operator,
}

impl S3DataBackend {
    pub(crate) fn new(
        endpoint: &str,
        bucket: &str,
        region: &str,
        root: &str,
        access_key: &str,
        secret_key: &str,
    ) -> Result<Self> {
        Ok(Self {
            operator: build_operator(endpoint, bucket, region, root, access_key, secret_key)
                .context("creating the S3 data backend")?,
        })
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
    fn write_bytes(&self, tpe: FileType, id: &Id, _cacheable: bool, buf: Bytes) -> RusticResult<()> {
        let path = Self::path(tpe, id);
        self.operator
            .write(&path, buf)
            .map(|_| ())
            .map_err(|err| backend_error(err, "write", &path))
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

    // Live: the full ReadBackend + WriteBackend surface against a real Garage
    // S3 server (scripts/garage-test-server.sh). Uses a per-run root so the
    // seeded read-test repository is never touched, and removes everything it
    // writes.
    #[test]
    #[ignore]
    fn live_garage_s3_data_backend_read_write_cycle() {
        let endpoint = std::env::var("WRUSTIC_GARAGE_ENDPOINT")
            .unwrap_or_else(|_| "http://127.0.0.1:3900".into());
        let backend = S3DataBackend::new(
            &endpoint,
            "wrustic-it",
            "garage",
            &format!("data-backend-it-{}", std::process::id()),
            "GK22222222222222222222222222222222",
            "3333333333333333333333333333333333333333333333333333333333333333",
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
            .write_bytes(FileType::Snapshot, &id, false, payload.clone())
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
            .write_bytes(FileType::Config, &Id::default(), false, Bytes::from_static(b"cfg"))
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
