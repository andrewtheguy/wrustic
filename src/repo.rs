use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow, bail};
use rustic_backend::BackendOptions;
use rustic_core::{Credentials, Repository, RepositoryOptions};

use crate::config::Profile;

pub(crate) struct SnapshotRow {
    pub(crate) short_id: String,
    pub(crate) time: String,
    pub(crate) host: String,
    pub(crate) tags: String,
    pub(crate) paths: String,
}

fn build_backend_opts(profile: &Profile) -> Result<BackendOptions> {
    let mut opts = BackendOptions::default();
    match profile {
        Profile::Local { local_path, .. } => {
            opts = opts.repository(local_path.clone());
        }
        Profile::Rest {
            rest_url,
            rest_user,
            rest_password,
            ..
        } => {
            let mut url = url::Url::parse(rest_url)
                .with_context(|| format!("parsing REST URL `{rest_url}`"))?;
            if rest_user.is_empty() && !rest_password.is_empty() {
                bail!("REST profile has a password but no username");
            }
            if !rest_user.is_empty() {
                url.set_username(rest_user)
                    .map_err(|_| anyhow!("REST URL `{rest_url}` cannot carry a username"))?;
            }
            if !rest_password.is_empty() {
                url.set_password(Some(rest_password))
                    .map_err(|_| anyhow!("REST URL `{rest_url}` cannot carry a password"))?;
            }
            opts = opts.repository(format!("rest:{url}"));
        }
        Profile::S3 {
            s3_endpoint,
            s3_bucket,
            s3_region,
            s3_root,
            s3_access_key,
            s3_secret_key,
            ..
        } => {
            opts = opts.repository("opendal:s3:");
            let mut s3_opts = BTreeMap::new();
            s3_opts.insert("bucket".to_string(), s3_bucket.clone());
            s3_opts.insert("region".to_string(), s3_region.clone());
            s3_opts.insert("access_key_id".to_string(), s3_access_key.clone());
            s3_opts.insert("secret_access_key".to_string(), s3_secret_key.clone());
            if !s3_endpoint.is_empty() {
                s3_opts.insert("endpoint".to_string(), s3_endpoint.clone());
            }
            if !s3_root.is_empty() {
                s3_opts.insert("root".to_string(), s3_root.clone());
            }
            opts = opts.options(s3_opts);
        }
    }
    Ok(opts)
}

pub(crate) fn verify_profile(profile: &Profile) -> Result<()> {
    let backends = build_backend_opts(profile)?.to_backends()?;
    Repository::new(&RepositoryOptions::default(), &backends)?
        .open(&Credentials::password(profile.password()))?;
    Ok(())
}

pub(crate) fn load_snapshots(profile: &Profile) -> Result<Vec<SnapshotRow>> {
    let backends = build_backend_opts(profile)?.to_backends()?;
    let repo = Repository::new(&RepositoryOptions::default(), &backends)?
        .open(&Credentials::password(profile.password()))?;

    let mut snaps = repo.get_all_snapshots()?;
    snaps.sort_by(|a, b| b.time.cmp(&a.time));

    Ok(snaps
        .into_iter()
        .map(|s| SnapshotRow {
            short_id: s.id.to_string(),
            time: s.time.strftime("%Y-%m-%d %H:%M:%S").to_string(),
            host: s.hostname.clone(),
            tags: s.tags.to_string(),
            paths: s.paths.to_string(),
        })
        .collect())
}
