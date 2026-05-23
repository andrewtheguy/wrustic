use std::path::PathBuf;

use anyhow::{Result, bail};

pub(crate) const DEFAULT_SERVER_PORT: u16 = 7834;

pub(crate) const USAGE: &str = "\
Usage: wrustic [OPTIONS]

Options:
  -c, --config-dir <PATH>     Use <PATH> as the wrustic config directory instead
                              of the platform default (~/.config/wrustic on Linux).
                              The directory will be created on first run.
  -p, --port <N>              Localhost port for both the file-share dialog and
                              the experimental passphrase ceremony. Default: 7834.
                              They never run concurrently, so they share a port.
      --experimental-passphrase
                              EXPERIMENTAL — encrypt config values with a
                              passphrase instead of age. Requires an explicit
                              --config-dir. Passphrase configs are NOT
                              interoperable with age configs.
  -h, --help                  Print this help text.
";

pub(crate) struct Cli {
    pub(crate) config_dir: Option<PathBuf>,
    pub(crate) port: u16,
    pub(crate) experimental_passphrase: bool,
    pub(crate) show_help: bool,
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            config_dir: None,
            port: DEFAULT_SERVER_PORT,
            experimental_passphrase: false,
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
            "--experimental-passphrase" => cli.experimental_passphrase = true,
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
    if cli.experimental_passphrase && cli.config_dir.is_none() {
        bail!(
            "--experimental-passphrase requires an explicit --config-dir while the feature is experimental"
        );
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
