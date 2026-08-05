use std::path::PathBuf;

use anyhow::{Result, bail};

pub(crate) const DEFAULT_SERVER_PORT: u16 = 7834;

pub(crate) const USAGE: &str = "\
Usage: wrustic [OPTIONS]

Options:
  -c, --config-dir <PATH>     Use <PATH> as the wrustic config directory instead
                              of the platform default (~/.config/wrustic on Linux).
                              The directory will be created on first run.
  -p, --port <N>              Localhost port for the file-share dialog.
                              Default: 7834.
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
                              wrustic shells out for (prune-class); native
                              reads/writes never use a restic cache. The cache
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

/// `wrustic smb-serve` — export one snapshot over SMB and block until Ctrl-C.
///
/// A separate entry point rather than a TUI action because it is a foreground
/// server: the useful thing to do with it is leave it running in one terminal
/// and mount from another.
pub(crate) struct SmbServe {
    pub(crate) repo: String,
    pub(crate) snapshot: String,
    pub(crate) port: u16,
    pub(crate) bind_all: bool,
    pub(crate) user: String,
}

pub(crate) const SMB_SERVE_USAGE: &str = "\
Usage: wrustic smb-serve --repo <PATH> --snapshot <ID> [OPTIONS]

Serve one snapshot as a read-only SMB 2.1 share and block until Ctrl-C.

Every client must authenticate with NTLMv2, and every message is signed.
The share password comes from WRUSTIC_SMB_SHARE_PASSWORD, or is generated
and printed on startup if that is unset. The *repository* password comes
from WRUSTIC_SMB_PASSWORD (or RESTIC_PASSWORD). Neither is ever taken from
the command line, where it would be visible to every process on the
machine.

Options:
      --repo <PATH>       Local restic repository to open.
      --snapshot <ID>     Snapshot to serve. 'latest' picks the newest.
      --port <N>          Port to listen on. Default: 4456.
      --bind-all          Listen on every interface instead of loopback only.
      --user <NAME>       Account name clients log in with. Default: wrustic.
  -h, --help              Print this help text.

Mount it with:
  Linux    sudo mount -t cifs -o port=<N>,vers=2.1,username=wrustic,password=<pw>,ro \\
               //<host>/snap /mnt
  macOS    mount_smbfs //wrustic@<host>:<N>/snap /Volumes/snap
  Windows  net use Z: \\\\<host>\\snap /user:wrustic <password>

Set WRUSTIC_SMB_LOG=1 to trace every SMB command and its status to stderr.
";

pub(crate) fn parse_smb_serve(args: &[String]) -> Result<SmbServe> {
    let mut repo = None;
    let mut snapshot = None;
    let mut port = 4456u16;
    let mut bind_all = false;
    let mut user = "wrustic".to_string();

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--repo" => repo = Some(it.next().ok_or_else(|| anyhow::anyhow!("--repo requires a path"))?.clone()),
            "--snapshot" => {
                snapshot = Some(it.next().ok_or_else(|| anyhow::anyhow!("--snapshot requires an id"))?.clone())
            }
            "--port" => {
                let v = it.next().ok_or_else(|| anyhow::anyhow!("--port requires a number"))?;
                port = parse_port(v, "--port")?;
            }
            "--bind-all" => bind_all = true,
            "--user" => {
                user = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--user requires a name"))?
                    .clone();
                if user.is_empty() {
                    bail!("--user requires a non-empty name");
                }
            }
            "-h" | "--help" => {
                println!("{SMB_SERVE_USAGE}");
                std::process::exit(0);
            }
            other => bail!("unknown argument: {other}"),
        }
    }

    Ok(SmbServe {
        repo: repo.ok_or_else(|| anyhow::anyhow!("--repo is required"))?,
        snapshot: snapshot.ok_or_else(|| anyhow::anyhow!("--snapshot is required"))?,
        port,
        bind_all,
        user,
    })
}

pub(crate) struct Cli {
    pub(crate) config_dir: Option<PathBuf>,
    pub(crate) port: u16,
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
