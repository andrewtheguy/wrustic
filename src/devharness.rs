//! Developer harnesses: the tools that need wrustic's internals but are not
//! tests. They sit behind the `dev-harness` feature and are reached as
//! `wrustic dev <name>`, so no shipped binary carries them.
//!
//! What they have in common is that a human runs them and judges the result by
//! eye — a config fixture to point the documented passphrase sources at, and
//! SMB servers that stay up long enough to walk to another machine and mount
//! them. None of them asserts anything, which is why none of them is a test.

use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

use crate::automation::{PASSPHRASE_ENV, PASSPHRASE_FILE_ENV};
use crate::cli::DevCommand;
use crate::config::{self, Config, PassphraseMeta, Profile};
use crate::crypto::Cipher;
use crate::passphrase;
use crate::smb::{Bind, Credentials, DEFAULT_SHARE_NAME, DEFAULT_SHARE_USER};

/// Fallback share password. A harness share is loopback-only by default and
/// lives for minutes, so a fixed default is a convenience, not a secret;
/// `WRUSTIC_SMB_SHARE_PASSWORD` overrides it.
const DEFAULT_HARNESS_PASSWORD: &str = "hunter2";

pub(crate) fn run(command: DevCommand) -> Result<()> {
    match command {
        DevCommand::SandboxConfig => sandbox_config(),
        DevCommand::SmbServe => smb_serve(),
        #[cfg(all(windows, feature = "smb-tun"))]
        DevCommand::SmbTun => smb_tun(),
    }
}

/// Writes `tmp/wrustic-sandbox/` — one local profile behind a known
/// passphrase, plus that passphrase in a file — so the passphrase sources the
/// CLI documents can be checked by hand against something real. It is the only
/// way to get a config without the TUI.
///
/// It goes through wrustic's own [`Cipher`] rather than restating the scrypt
/// and AES-256-GCM details, so there is no second implementation of the config
/// format here to drift out of step with the real one.
fn sandbox_config() -> Result<()> {
    const PASSPHRASE: &str = "Sandbox Pass 1!";
    const INSTANCE: &str = "sandbox";

    let dir = std::path::PathBuf::from("tmp/wrustic-sandbox");
    let paths = config::paths(Some(dir.clone())).context("sandbox paths")?;
    std::fs::create_dir_all(&paths.dir).context("create the sandbox directory")?;

    let salt: [u8; 32] = rand::random();
    // `derive_config_key` reports a plain String, not an error type anyhow can
    // chain onto.
    let key = passphrase::derive_config_key(PASSPHRASE, &salt)
        .map_err(|e| anyhow!("derive the config key: {e}"))?;
    let instance_sig = passphrase::compute_instance_sig(INSTANCE, &key);
    let mut config = Config {
        passphrase: Some(PassphraseMeta {
            instance: INSTANCE.to_string(),
            instance_sig: instance_sig.clone(),
            salt: BASE64.encode(salt),
        }),
        ..Config::default()
    };
    config.profiles.insert(
        "sample".to_string(),
        Profile::Local {
            password: "sample-repo-password".to_string(),
            local_path: dir.join("repo").to_string_lossy().into_owned(),
        },
    );
    let cipher = Cipher::new(key, INSTANCE.to_string(), &instance_sig);
    config::save(&config, &paths, &cipher).context("write the sandbox config")?;

    let pass_file = paths.dir.join("passphrase");
    std::fs::write(&pass_file, PASSPHRASE).context("write the passphrase file")?;

    println!(
        "\nwrote {} (instance `{INSTANCE}`, profile `sample`, passphrase `{PASSPHRASE}`)\n\n\
         Neither of these should ask for anything:\n\
         \n  {PASSPHRASE_ENV}='{PASSPHRASE}' \\\n    \
             cargo run --all-features -- --config-dir ./{} env sample\n\
         \n  {PASSPHRASE_FILE_ENV}={} \\\n    \
             cargo run --all-features -- --config-dir ./{} env sample\n\
         \nDrop `env sample` from either line to check the TUI: it should open on the\n\
         profile list, not on the unlock screen. Delete {} when done.\n",
        paths.config.display(),
        dir.display(),
        pass_file.display(),
        dir.display(),
        dir.display(),
    );
    Ok(())
}

/// How long a harness share stays up when `WRUSTIC_SMB_SECONDS` says nothing.
/// Bounded rather than endless so a forgotten server cannot hold the port for
/// the rest of the session.
fn harness_seconds(default: u64) -> u64 {
    std::env::var("WRUSTIC_SMB_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Serve a real restic snapshot, for validating the `SnapshotBacking` path
/// against a live client. This is the cross-platform harness: the TUI's share
/// dies when you leave the screen, and mounting from macOS or Windows needs a
/// server that stays up while you walk over to another machine.
///
/// Driven by environment variables so it needs no wrustic config, and so no
/// password ever reaches argv:
///
///   WRUSTIC_SMB_REPO=<path>       repository to open          (required)
///   WRUSTIC_SMB_PASSWORD=<pw>     its password                (required)
///   WRUSTIC_SMB_SNAPSHOT=<id>     snapshot, or 'latest'       (required)
///   WRUSTIC_SMB_PORT=<n>          listen port                 (default 4456)
///   WRUSTIC_SMB_SHARE_PASSWORD    share password              (default hunter2)
///   WRUSTIC_SMB_SECONDS=<n>       how long to stay up         (default 1200)
///   WRUSTIC_SMB_BIND_ALL=1        every interface, not just loopback
///   WRUSTIC_SMB_LOG=1             trace every command to stderr
fn smb_serve() -> Result<()> {
    let repo = required_env("WRUSTIC_SMB_REPO")?;
    let repo_password = required_env("WRUSTIC_SMB_PASSWORD")?;
    let snapshot = required_env("WRUSTIC_SMB_SNAPSHOT")?;
    let port: u16 = std::env::var("WRUSTIC_SMB_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(crate::cli::DEFAULT_SMB_PORT);

    let profile = Profile::Local {
        password: repo_password,
        local_path: repo,
    };
    let secs = harness_seconds(1200);

    let bind = if std::env::var_os("WRUSTIC_SMB_BIND_ALL").is_some() {
        Bind::AllInterfaces
    } else {
        Bind::Loopback
    };
    let bind_all = matches!(bind, Bind::AllInterfaces);
    let password = std::env::var("WRUSTIC_SMB_SHARE_PASSWORD")
        .unwrap_or_else(|_| DEFAULT_HARNESS_PASSWORD.to_string());
    let handle = crate::smb::start_snapshot_share(
        port,
        &profile,
        &snapshot,
        bind,
        Credentials {
            user: DEFAULT_SHARE_USER.to_string(),
            password: password.clone(),
        },
    )
    .context("snapshot share starts")?;
    let host = if bind_all { "<this-host>" } else { "127.0.0.1" };
    let port = handle.port();
    eprintln!("serving snapshot {snapshot} on {host}:{port} for {secs}s");
    eprintln!();
    eprintln!("  username  {DEFAULT_SHARE_USER}");
    eprintln!("  password  {password}");
    if bind_all {
        eprintln!();
        eprintln!(
            "NOTE: listening on every interface. Traffic is signed but not encrypted, \
             so anyone on the network can read file contents in transit."
        );
    }
    eprintln!();
    eprintln!("Mount it with:");
    eprintln!(
        "  Linux    sudo mount -t cifs -o port={port},vers=2.1,username={DEFAULT_SHARE_USER},ro,uid=$(id -u),gid=$(id -g),file_mode=0444,dir_mode=0555 //{host}/{DEFAULT_SHARE_NAME} /mnt/snap"
    );
    eprintln!(
        "  macOS    Finder → Go → Connect to Server (Cmd+K): smb://{DEFAULT_SHARE_USER}@{host}:{port}/{DEFAULT_SHARE_NAME}"
    );
    eprintln!(
        "  Windows  net use Z: \\\\{host}\\{DEFAULT_SHARE_NAME} * /user:{DEFAULT_SHARE_USER} /TCPPORT:{port}"
    );
    std::thread::sleep(std::time::Duration::from_secs(secs));
    handle.stop();
    Ok(())
}

/// Hold a tun share open on the standard SMB port so an external client can be
/// timed against it. Serves the in-memory tree, so no repository is needed.
/// Needs administrator rights: creating a network adapter always does.
#[cfg(all(windows, feature = "smb-tun"))]
fn smb_tun() -> Result<()> {
    use std::sync::Arc;

    use smbanything_core::smb::{self, Backing, start};

    use crate::smb::{MemBacking, STANDARD_SMB_PORT, TunConfig};

    let secs = harness_seconds(180);
    let handle = start(
        0,
        DEFAULT_SHARE_NAME,
        Bind::Tun(TunConfig {
            port: STANDARD_SMB_PORT,
            addrs: smb::DEFAULT_TUN_ADDRS,
        }),
        Credentials {
            user: DEFAULT_SHARE_USER.to_string(),
            password: DEFAULT_HARNESS_PASSWORD.to_string(),
        },
    )
    .context("tun share starts (are you elevated?)")?;
    let backing: Arc<dyn Backing> = Arc::new(
        MemBacking::new()
            .with_dir("docs")
            .with_file("docs\\readme.txt", b"hello from a snapshot\n")
            .with_file("docs\\notes.md", b"# notes\n")
            .with_file("data.bin", &[0xAB; 9000]),
    );
    handle.load(backing);
    eprintln!(
        "READY {} user={DEFAULT_SHARE_USER} pass={DEFAULT_HARNESS_PASSWORD}",
        handle.unc()
    );
    std::thread::sleep(std::time::Duration::from_secs(secs));
    handle.stop();
    Ok(())
}

/// A harness input with no sensible default: say which one is missing rather
/// than failing later with an unrelated error.
fn required_env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} must be set"))
}
