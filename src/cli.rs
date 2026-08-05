use std::path::PathBuf;

use anyhow::{Result, bail};

pub(crate) const DEFAULT_SERVER_PORT: u16 = 7834;

/// Localhost port for the snapshot SMB share. Fixed rather than ephemeral so a
/// mount command, an `/etc/fstab` line or a saved Windows drive mapping keeps
/// working across restarts of wrustic.
pub(crate) const DEFAULT_SMB_PORT: u16 = 4456;

pub(crate) const USAGE: &str = "\
Usage: wrustic [OPTIONS]

Options:
  -c, --config-dir <PATH>     Use <PATH> as the wrustic config directory instead
                              of the platform default (~/.config/wrustic on Linux).
                              The directory will be created on first run.
  -p, --port <N>              Localhost port for the file-share dialog.
                              Default: 7834.
      --smb-port <N>          Localhost port for the snapshot SMB share ('s' on
                              the snapshot list). Default: 4456. Mounting needs
                              a client that can be pointed at a non-standard
                              port: Linux (-o port=), macOS, and Windows 11 24H2
                              or newer (/TCPPORT:). Earlier Windows builds only
                              speak to port 445 and cannot use this share.
      --no-restic-cache       Turn off restic's on-disk cache: every restic call
                              runs --no-cache. On by default, restic keeps its
                              cache in a 'wrustic' directory under your
                              platform's per-user cache root, private to your
                              account: $XDG_CACHE_HOME or ~/.cache on Linux,
                              ~/Library/Caches on macOS, %LOCALAPPDATA% on
                              Windows. On a machine where no such root can be
                              determined, --no-cache is passed anyway rather
                              than falling back to restic's shared default
                              cache. Only affects the restic CLI commands
                              wrustic can shell out for (maintenance-class);
                              native reads/writes never use a restic cache.
                              The cache
                              speeds up repeated restic work against a remote
                              repository at the cost of disk space — it can
                              reach hundreds of megabytes for a large
                              repository. Cached calls also pass
                              --cleanup-cache, so restic itself drops the
                              per-repository subdirectories there that go 30
                              days unused. To clean it out by hand, point restic
                              at the same directory:
                              'restic --cache-dir <that path> cache --cleanup'.
      --no-mouse              Disable mouse reporting (useful for QA / copy-paste).
      --no-keychain           Disable keychain integration even when the binary
                              was built with the 'keychain' feature.
  -V, --version               Print version and exit.
  -h, --help                  Print this help text.
";

pub(crate) struct Cli {
    pub(crate) config_dir: Option<PathBuf>,
    pub(crate) port: u16,
    pub(crate) smb_port: u16,
    pub(crate) restic_cache: bool,
    pub(crate) no_mouse: bool,
    pub(crate) no_keychain: bool,
    pub(crate) show_version: bool,
    pub(crate) show_help: bool,
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            config_dir: None,
            port: DEFAULT_SERVER_PORT,
            smb_port: DEFAULT_SMB_PORT,
            restic_cache: true,
            no_mouse: false,
            no_keychain: false,
            show_version: false,
            show_help: false,
        }
    }
}

pub(crate) fn parse_cli() -> Result<Cli> {
    let mut cli = Cli::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => cli.show_help = true,
            "-V" | "--version" | "version" => cli.show_version = true,
            "--no-restic-cache" => cli.restic_cache = false,
            "--no-mouse" => cli.no_mouse = true,
            "--no-keychain" => cli.no_keychain = true,
            "-c" | "--config-dir" => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("{arg} requires a path argument"))?;
                if value.is_empty() {
                    bail!("{arg} requires a non-empty path");
                }
                cli.config_dir = Some(PathBuf::from(value));
            }
            other if other.starts_with("--config-dir=") => {
                let value = &other["--config-dir=".len()..];
                if value.is_empty() {
                    bail!("--config-dir= requires a non-empty path");
                }
                cli.config_dir = Some(PathBuf::from(value));
            }
            "-p" | "--port" => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("{arg} requires a port number"))?;
                cli.port = parse_port(&value, arg.as_str())?;
            }
            other if other.starts_with("--port=") => {
                let value = &other["--port=".len()..];
                cli.port = parse_port(value, "--port=")?;
            }
            "--smb-port" => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("{arg} requires a port number"))?;
                cli.smb_port = parse_port(&value, arg.as_str())?;
            }
            other if other.starts_with("--smb-port=") => {
                let value = &other["--smb-port=".len()..];
                cli.smb_port = parse_port(value, "--smb-port=")?;
            }
            other => bail!("unknown argument: {other}"),
        }
    }
    Ok(cli)
}

fn parse_port(value: &str, flag: &str) -> Result<u16> {
    let n: u16 = value
        .parse()
        .map_err(|_| anyhow::anyhow!("{flag} expects a port number 1-65535, got `{value}`"))?;
    if n == 0 {
        bail!("{flag} cannot be 0");
    }
    Ok(n)
}
