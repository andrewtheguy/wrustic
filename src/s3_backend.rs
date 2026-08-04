//! S3 access to the repository's `locks/` directory.
//!
//! Repository data on S3 goes through rustic_backend's opendal backend
//! (`opendal:s3:` in `repo::build_backends`), which is fully read/write.
//! Lock files are outside rustic_core's `FileType`-addressed world entirely
//! (its enum has no `Lock` variant), so this small client reaches the
//! `locks/` prefix directly. See docs/locking.md.

use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow};
use opendal::{
    blocking::Operator,
    layers::RetryLayer,
    options::ListOptions,
    services::S3,
};
use tokio::runtime::Runtime;

use crate::lock::LockBackend;

const DEFAULT_RETRIES: usize = 5;

pub(crate) struct S3LockBackend {
    operator: Operator,
}

impl S3LockBackend {
    pub(crate) fn new(
        endpoint: &str,
        bucket: &str,
        region: &str,
        root: &str,
        access_key: &str,
        secret_key: &str,
    ) -> Result<Self> {
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
            .context("creating the S3 lock backend")?
            .layer(
                RetryLayer::new()
                    .with_max_times(DEFAULT_RETRIES)
                    .with_jitter(),
            )
            .finish();

        let _guard = runtime().enter();
        let operator =
            Operator::new(operator).context("creating the blocking S3 lock backend")?;
        Ok(Self { operator })
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
            .lister_options("locks/", options)
            .map_err(|err| anyhow!("listing S3 locks: {err}"))?;
        let mut out = Vec::new();
        for result in entries {
            let entry = result.map_err(|err| anyhow!("reading S3 lock listing: {err}"))?;
            if entry.metadata().is_file() {
                out.push((entry.name().to_string(), entry.metadata().content_length()));
            }
        }
        Ok(out)
    }

    fn read(&self, name: &str) -> Result<Option<Vec<u8>>> {
        match self.operator.read(&format!("locks/{name}")) {
            Ok(buf) => Ok(Some(buf.to_bytes().to_vec())),
            Err(err) if err.kind() == opendal::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(anyhow!("reading S3 lock {name}: {err}")),
        }
    }

    fn write(&self, name: &str, data: &[u8]) -> Result<()> {
        self.operator
            .write(&format!("locks/{name}"), data.to_vec())
            .map_err(|err| anyhow!("writing S3 lock {name}: {err}"))?;
        Ok(())
    }

    fn remove(&self, name: &str) -> Result<()> {
        match self.operator.delete(&format!("locks/{name}")) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == opendal::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(anyhow!("removing S3 lock {name}: {err}")),
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
