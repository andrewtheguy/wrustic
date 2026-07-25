use std::sync::{Arc, OnceLock};

use bytes::Bytes;
use opendal::{
    Metadata,
    blocking::Operator,
    layers::RetryLayer,
    options::{ListOptions, ReadOptions},
    services::S3,
};
use rustic_core::{
    ErrorKind, FileType, Id, ReadBackend, RepositoryBackends, RusticError, RusticResult,
    WriteBackend,
};
use tokio::runtime::Runtime;

const DEFAULT_RETRIES: usize = 5;

/// Native, read-only S3 repository backend.
///
/// `rustic_core` currently models repository backends through `WriteBackend`,
/// even when callers only open and read a repository. The mutation methods
/// below therefore reject every operation; wrustic uses restic CLI for writes.
#[derive(Clone, Debug)]
pub(crate) struct S3ReadOnlyBackend {
    operator: Operator,
}

impl S3ReadOnlyBackend {
    pub(crate) fn new(
        endpoint: &str,
        bucket: &str,
        region: &str,
        root: &str,
        access_key: &str,
        secret_key: &str,
    ) -> RusticResult<Self> {
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
            .map_err(|err| backend_error("Creating the S3 backend failed.", err))?
            .layer(
                RetryLayer::new()
                    .with_max_times(DEFAULT_RETRIES)
                    .with_jitter(),
            )
            .finish();

        let _guard = runtime().enter();
        let operator = Operator::new(operator)
            .map_err(|err| backend_error("Creating the blocking S3 backend failed.", err))?;
        Ok(Self { operator })
    }

    fn path(&self, tpe: FileType, id: &Id) -> String {
        let hex_id = id.to_hex();
        match tpe {
            FileType::Config => "config".to_string(),
            FileType::Pack => format!("{}/{}/{}", tpe.dirname(), &hex_id[..2], &hex_id[..]),
            _ => format!("{}/{}", tpe.dirname(), &hex_id[..]),
        }
    }

    fn write_rejected() -> Box<RusticError> {
        RusticError::new(
            ErrorKind::Unsupported,
            "wrustic's native S3 backend is read-only; repository writes must use restic CLI.",
        )
    }
}

impl From<S3ReadOnlyBackend> for RepositoryBackends {
    fn from(backend: S3ReadOnlyBackend) -> Self {
        Self::new(Arc::new(backend), None)
    }
}

impl ReadBackend for S3ReadOnlyBackend {
    fn location(&self) -> String {
        let info = self.operator.info();
        format!("opendal:{}:{}", info.scheme(), info.name())
    }

    fn list_with_size(&self, tpe: FileType) -> RusticResult<Vec<(Id, u32)>> {
        if tpe == FileType::Config {
            return match self.operator.stat("config") {
                Ok(metadata) => Ok(vec![(Id::default(), object_size(&metadata, "config")?)]),
                Err(err) if err.kind() == opendal::ErrorKind::NotFound => Ok(Vec::new()),
                Err(err) => Err(backend_error("Reading S3 config metadata failed.", err)),
            };
        }

        let prefix = format!("{}/", tpe.dirname());
        let options = ListOptions {
            recursive: true,
            ..Default::default()
        };
        let entries = self
            .operator
            .lister_options(&prefix, options)
            .map_err(|err| backend_error("Listing S3 repository objects failed.", err))?;

        let mut files = Vec::new();
        for result in entries {
            let entry = result.map_err(|err| {
                backend_error("Reading an S3 repository listing entry failed.", err)
            })?;
            if !entry.metadata().is_file() {
                continue;
            }
            let Some(id) = Id::parse_some(entry.name(), tpe) else {
                continue;
            };
            files.push((id, object_size(entry.metadata(), entry.path())?));
        }
        Ok(files)
    }

    fn read_full(&self, tpe: FileType, id: &Id) -> RusticResult<Bytes> {
        let path = self.path(tpe, id);
        Ok(self
            .operator
            .read(&path)
            .map_err(|err| backend_error("Reading an S3 repository object failed.", err))?
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
        let path = self.path(tpe, id);
        let start = u64::from(offset);
        let options = ReadOptions {
            range: (start..start + u64::from(length)).into(),
            ..Default::default()
        };
        Ok(self
            .operator
            .read_options(&path, options)
            .map_err(|err| backend_error("Reading part of an S3 repository object failed.", err))?
            .to_bytes())
    }

    fn warmup_path(&self, tpe: FileType, id: &Id) -> String {
        let root = self.operator.info().root().trim_matches('/').to_string();
        let relative = self.path(tpe, id);
        if root.is_empty() {
            relative
        } else {
            format!("{root}/{relative}")
        }
    }
}

impl WriteBackend for S3ReadOnlyBackend {
    fn create(&self) -> RusticResult<()> {
        Err(Self::write_rejected())
    }

    fn write_bytes(
        &self,
        _tpe: FileType,
        _id: &Id,
        _cacheable: bool,
        _buf: Bytes,
    ) -> RusticResult<()> {
        Err(Self::write_rejected())
    }

    fn remove(&self, _tpe: FileType, _id: &Id, _cacheable: bool) -> RusticResult<()> {
        Err(Self::write_rejected())
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

fn object_size(metadata: &Metadata, path: &str) -> RusticResult<u32> {
    metadata.content_length().try_into().map_err(|err| {
        RusticError::with_source(
            ErrorKind::Backend,
            format!("S3 repository object `{path}` is too large to list."),
            err,
        )
    })
}

fn backend_error(message: &'static str, source: opendal::Error) -> Box<RusticError> {
    RusticError::with_source(ErrorKind::Backend, message, source)
}
