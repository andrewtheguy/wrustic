use std::path::PathBuf;

use anyhow::{Result, bail};

pub(crate) const USAGE: &str = "\
Usage: wrustic [OPTIONS]

Options:
  -c, --config-dir <PATH>  Use <PATH> as the wrustic config directory instead
                           of the platform default (~/.config/wrustic on Linux).
                           The directory will be created on first run.
  -h, --help               Print this help text.
";

#[derive(Default)]
pub(crate) struct Cli {
    pub(crate) config_dir: Option<PathBuf>,
    pub(crate) show_help: bool,
}

pub(crate) fn parse_cli() -> Result<Cli> {
    let mut cli = Cli::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => cli.show_help = true,
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
            other => bail!("unknown argument: {other}"),
        }
    }
    Ok(cli)
}
