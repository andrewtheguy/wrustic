use std::path::PathBuf;

use anyhow::{Result, bail};

pub(crate) const DEFAULT_SERVER_PORT: u16 = 7834;

/// Localhost port for the snapshot SMB share. Fixed rather than ephemeral so a
/// mount command, an `/etc/fstab` line or a saved Windows drive mapping keeps
/// working across restarts of wrustic.
pub(crate) const DEFAULT_SMB_PORT: u16 = 4456;

/// Whether this build can serve the share on port 445 over a tun adapter.
/// Windows-only, and only when compiled with the `smb-tun` feature.
pub(crate) const SMB_TUN_SUPPORTED: bool = cfg!(all(windows, feature = "smb-tun"));

/// The address pair the tun transport uses when `--smb-tun-ip` is not given.
///
/// 169.254.255.x is link-local, and inside the block RFC 3927 *reserves*:
/// APIPA only ever self-assigns from 169.254.1.0–169.254.254.255, so these two
/// can never collide with an auto-configured address, and link-local traffic
/// is never routed off the machine at all — unlike a private subnet, there is
/// no corporate VPN or LAN range this default can shadow.
pub(crate) const DEFAULT_SMB_TUN_ADDRS: TunAddrs = TunAddrs {
    virtual_ip: std::net::Ipv4Addr::new(169, 254, 255, 1),
};

/// The two host addresses the tun transport claims while a share is open.
///
/// There is no subnet: each address is a /32, and the transport's entire
/// routing footprint is two host routes. The split matters: the adapter gets
/// the *second* address, and the *first* is assigned to nothing — wrustic's
/// own TCP stack answers for it, reached through an explicit on-link /32
/// route. An address Windows holds itself would be looped back internally and
/// hit srvnet.sys's port 445 reservation, which is the whole thing the tun
/// exists to avoid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TunAddrs {
    virtual_ip: std::net::Ipv4Addr,
}

// The flag parses and validates on every platform, so a Linux user gets a real
// error rather than "unknown argument", but only the Windows tun build has
// anything that consumes the derived addresses.
#[cfg_attr(not(all(windows, feature = "smb-tun")), allow(dead_code))]
impl TunAddrs {
    /// The address the share answers on, and the one that goes in the UNC path.
    pub(crate) fn virtual_ip(&self) -> std::net::Ipv4Addr {
        self.virtual_ip
    }

    /// The address assigned to the tun adapter — the next one up, which is
    /// what gives Windows a source address and an interface to route through.
    pub(crate) fn adapter_ip(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(u32::from(self.virtual_ip) + 1)
    }
}

impl std::fmt::Display for TunAddrs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/32 and {}/32", self.virtual_ip(), self.adapter_ip())
    }
}

/// Parse the `--smb-tun-ip` override: the address clients mount, with the next
/// address up going on the adapter.
///
/// Rejects addresses that cannot work rather than failing later at adapter
/// creation — anything the local stack treats specially, for either of the
/// two derived addresses.
fn parse_tun_ip(value: &str, flag: &str) -> Result<TunAddrs> {
    let virtual_ip: std::net::Ipv4Addr = value
        .parse()
        .map_err(|_| anyhow::anyhow!("{flag} expects an IPv4 address like 169.254.255.1, got `{value}`"))?;
    let adapter_ip = u32::from(virtual_ip)
        .checked_add(1)
        .map(std::net::Ipv4Addr::from)
        .ok_or_else(|| {
            anyhow::anyhow!("{flag}: the adapter takes the next address after {virtual_ip}, and there is none")
        })?;
    // Both derived addresses have to be usable, so a mount address that is fine
    // on its own but borders a reserved range is refused too.
    for addr in [virtual_ip, adapter_ip] {
        if addr.is_loopback() || addr.is_multicast() || addr.is_broadcast() || addr.is_unspecified()
        {
            bail!(
                "{flag}: the transport needs {virtual_ip} and the next address up, \
and {addr} is in a range the local stack reserves"
            );
        }
    }
    Ok(TunAddrs { virtual_ip })
}

/// Everything that decides how the snapshot SMB share is exposed.
///
/// Grouped rather than threaded separately: these always travel together, and
/// passing them one by one pushed `run` and `App::boot` past a readable
/// argument count.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SmbOptions {
    /// Loopback port the share listens on. With `tun` set this becomes the
    /// private port behind the proxy and nothing external ever names it.
    pub(crate) port: u16,
    /// Serve on port 445 through the tun transport instead of a plain socket.
    pub(crate) tun: bool,
    /// Address pair the tun transport claims. Only meaningful with `tun`.
    pub(crate) tun_addrs: TunAddrs,
}

impl Default for SmbOptions {
    fn default() -> Self {
        Self {
            port: DEFAULT_SMB_PORT,
            tun: false,
            tun_addrs: DEFAULT_SMB_TUN_ADDRS,
        }
    }
}

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
      --smb-tun               Serve the snapshot share on the standard SMB port
                              (445) over a private tun adapter, so it mounts as
                              a plain UNC path (\\\\169.254.255.1\\snap) and works
                              in Explorer, not only as a mapped drive. Needs
                              administrator rights to create the adapter; the
                              host's own file sharing is left untouched. While a
                              share is open, two /32 host routes point at the
                              tun — no subnet is claimed. Windows only, and only
                              in builds compiled with --features smb-tun.
      --smb-tun-ip <IPv4>     Mount address for --smb-tun. Default 169.254.255.1
                              — link-local, in the block RFC 3927 keeps clear of
                              APIPA autoconfiguration, so it collides with
                              nothing. The address is deliberately assigned to
                              nothing; the next one up (.2) goes on the adapter,
                              and only those two /32s are claimed.
      --no-mouse              Disable mouse reporting (useful for QA / copy-paste).
      --no-keychain           Disable keychain integration even when the binary
                              was built with the 'keychain' feature.
  -V, --version               Print version and exit.
  -h, --help                  Print this help text.
";

pub(crate) struct Cli {
    pub(crate) config_dir: Option<PathBuf>,
    pub(crate) port: u16,
    pub(crate) smb: SmbOptions,
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
            smb: SmbOptions::default(),
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
            // Rejected at parse time rather than ignored: silently falling back
            // to the loopback port would look like the tun came up and the
            // mount was at fault.
            "--smb-tun" => {
                if !SMB_TUN_SUPPORTED {
                    bail!(
                        "--smb-tun is unavailable in this build: it is Windows-only and \
requires compiling with `--features smb-tun`"
                    );
                }
                cli.smb.tun = true;
            }
            "--smb-tun-ip" => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("{arg} requires an IPv4 address"))?;
                cli.smb.tun_addrs = parse_tun_ip(&value, arg.as_str())?;
            }
            other if other.starts_with("--smb-tun-ip=") => {
                let value = &other["--smb-tun-ip=".len()..];
                cli.smb.tun_addrs = parse_tun_ip(value, "--smb-tun-ip=")?;
            }
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
                cli.smb.port = parse_port(&value, arg.as_str())?;
            }
            other if other.starts_with("--smb-port=") => {
                let value = &other["--smb-port=".len()..];
                cli.smb.port = parse_port(value, "--smb-port=")?;
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

/// Constructors the rest of the crate's tests need, without exposing a way to
/// build an unvalidated address pair in normal code.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::TunAddrs;

    /// Parse an address the caller knows is valid. Only the tun tests need it.
    #[cfg_attr(not(all(windows, feature = "smb-tun")), allow(dead_code))]
    pub(crate) fn addrs(ip: &str) -> TunAddrs {
        super::parse_tun_ip(ip, "--smb-tun-ip").expect("valid test address")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The derivation is the contract the tun transport depends on: the given
    /// address is answered for by wrustic's own stack and must stay unassigned,
    /// the next one up goes on the adapter. Getting these the wrong way round
    /// silently reintroduces the srvnet port conflict the whole design exists
    /// to avoid.
    #[test]
    fn tun_ip_derives_the_adapter_address() {
        let a = parse_tun_ip("10.99.0.1", "--smb-tun-ip").expect("parses");
        assert_eq!(a.virtual_ip(), std::net::Ipv4Addr::new(10, 99, 0, 1));
        assert_eq!(a.adapter_ip(), std::net::Ipv4Addr::new(10, 99, 0, 2));
    }

    /// The default has to sit in 169.254.255.x: link-local, so it is never
    /// routed off the machine, and inside the block RFC 3927 reserves — APIPA
    /// self-assigns only from 169.254.1.0–169.254.254.255, so no interface
    /// waiting on DHCP can ever autoconfigure either of these addresses.
    #[test]
    fn default_addresses_sit_in_the_reserved_link_local_block() {
        let d = DEFAULT_SMB_TUN_ADDRS;
        for addr in [d.virtual_ip(), d.adapter_ip()] {
            assert!(addr.is_link_local(), "{addr}");
            assert_eq!(addr.octets()[2], 255, "{addr} is in APIPA's pick range");
        }
        assert_eq!(d.virtual_ip(), std::net::Ipv4Addr::new(169, 254, 255, 1));
        assert_eq!(d.adapter_ip(), std::net::Ipv4Addr::new(169, 254, 255, 2));
    }

    /// Both derived addresses have to be usable, including the adapter's — a
    /// mount address that borders a reserved range fails the pair.
    #[test]
    fn tun_ip_rejects_addresses_the_local_stack_reserves() {
        for bad in [
            "127.0.0.1",         // loopback
            "224.0.0.1",         // multicast
            "0.0.0.0",           // unspecified
            "255.255.255.255",   // broadcast, and +1 overflows too
            "255.255.255.254",   // adapter address would be the broadcast
            "223.255.255.255",   // adapter address would be multicast
        ] {
            assert!(
                parse_tun_ip(bad, "--smb-tun-ip").is_err(),
                "{bad} should be refused"
            );
        }
    }

    #[test]
    fn tun_ip_rejects_malformed_input() {
        // A CIDR is malformed here on purpose: the transport claims two /32s
        // and there is no subnet size to configure.
        for bad in ["10.99.0.0/24", "169.254.255.1/32", "nonsense", ""] {
            assert!(
                parse_tun_ip(bad, "--smb-tun-ip").is_err(),
                "{bad} should be refused"
            );
        }
    }

    /// The flag has to be refused outright where it cannot work, rather than
    /// accepted and quietly ignored — a silent fallback to the loopback port
    /// looks like the tun came up and the mount was at fault.
    #[test]
    fn smb_tun_flag_matches_build_support() {
        assert_eq!(
            SMB_TUN_SUPPORTED,
            cfg!(all(windows, feature = "smb-tun")),
            "the advertised capability must track the actual build"
        );
    }
}
