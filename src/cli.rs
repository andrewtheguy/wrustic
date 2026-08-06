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

/// The private subnet the tun transport uses when `--smb-tun-subnet` is not
/// given. Nothing about 10.99.0.0/24 is special beyond being unlikely to
/// collide with a network the machine already routes.
pub(crate) const DEFAULT_SMB_TUN_SUBNET: TunSubnet = TunSubnet {
    network: std::net::Ipv4Addr::new(10, 99, 0, 0),
    prefix_len: 24,
};

/// The IPv4 subnet the tun transport claims while a share is open.
///
/// Two addresses are derived from it, and the split matters: the *second*
/// address is assigned to the adapter, and the *first* is assigned to nothing
/// and answered for by wrustic's own TCP stack. An address Windows holds
/// itself would be looped back internally and hit srvnet.sys's port 445
/// reservation, which is the whole thing the tun exists to avoid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TunSubnet {
    network: std::net::Ipv4Addr,
    prefix_len: u8,
}

// The flag parses and validates on every platform, so a Linux user gets a real
// error rather than "unknown argument", but only the Windows tun build has
// anything that consumes the derived addresses.
#[cfg_attr(not(all(windows, feature = "smb-tun")), allow(dead_code))]
impl TunSubnet {
    /// The address the share answers on, and the one that goes in the UNC path.
    pub(crate) fn virtual_ip(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(u32::from(self.network) + 1)
    }

    /// The address assigned to the tun adapter, which is what gives Windows a
    /// source address and an on-link route for the subnet.
    pub(crate) fn adapter_ip(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(u32::from(self.network) + 2)
    }

    pub(crate) fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// For messages that have to name the route being added.
    pub(crate) fn cidr(&self) -> String {
        format!("{}/{}", self.network, self.prefix_len)
    }
}

impl std::fmt::Display for TunSubnet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.cidr())
    }
}

/// Parse `a.b.c.d/len`, rounding down to the network address.
///
/// Rejects ranges that cannot work rather than failing later at adapter
/// creation: anything the local stack treats specially, and prefixes too short
/// to be plausible or too long to hold the two addresses the design needs.
fn parse_tun_subnet(value: &str, flag: &str) -> Result<TunSubnet> {
    let (addr, len) = value
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("{flag} expects a subnet like 10.99.0.0/24, got `{value}`"))?;
    let addr: std::net::Ipv4Addr = addr
        .parse()
        .map_err(|_| anyhow::anyhow!("{flag}: `{addr}` is not an IPv4 address"))?;
    let prefix_len: u8 = len
        .parse()
        .map_err(|_| anyhow::anyhow!("{flag}: `{len}` is not a prefix length"))?;

    // /30 is the floor, and not an arbitrary one. The transport needs two
    // addresses in one subnet: the adapter takes the second, and Windows
    // installs an on-link route for the whole subnet, which is what carries
    // traffic for the first — the unassigned one wrustic answers for. A /31 has
    // no room for both, and a /32 assigns a single address and creates no
    // subnet route at all, so nothing would ever reach the stack.
    // Below /8 the range is far too large to be anyone's spare segment.
    if !(8..=30).contains(&prefix_len) {
        bail!(
            "{flag}: prefix length must be between 8 and 30, got /{prefix_len}. \
The transport needs two addresses in one subnet — one for the adapter and one, \
deliberately unassigned, for the share — so /30 is the smallest that works."
        );
    }
    if addr.is_loopback() || addr.is_multicast() || addr.is_link_local() || addr.is_unspecified() {
        bail!("{flag}: {addr} is in a range the local stack reserves; pick a private subnet");
    }

    let mask = u32::MAX << (32 - prefix_len);
    let network = std::net::Ipv4Addr::from(u32::from(addr) & mask);
    Ok(TunSubnet {
        network,
        prefix_len,
    })
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
    /// Subnet the tun transport claims. Only meaningful with `tun`.
    pub(crate) tun_subnet: TunSubnet,
}

impl Default for SmbOptions {
    fn default() -> Self {
        Self {
            port: DEFAULT_SMB_PORT,
            tun: false,
            tun_subnet: DEFAULT_SMB_TUN_SUBNET,
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
                              a plain UNC path (\\\\10.99.0.1\\snap) and works in
                              Explorer, not only as a mapped drive. Needs
                              administrator rights to create the adapter; the
                              host's own file sharing is left untouched. While
                              a share is open, 10.99.0.0/24 routes to the tun.
                              Windows only, and only in builds compiled with
                              --features smb-tun.
      --smb-tun-subnet <CIDR> Private subnet for --smb-tun. Default 10.99.0.0/24.
                              The first address (.1) is what clients mount and
                              is deliberately assigned to nothing; the second
                              (.2) goes on the adapter. Change it if the default
                              collides with a network this machine routes.
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
            "--smb-tun-subnet" => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("{arg} requires a subnet in CIDR form"))?;
                cli.smb.tun_subnet = parse_tun_subnet(&value, arg.as_str())?;
            }
            other if other.starts_with("--smb-tun-subnet=") => {
                let value = &other["--smb-tun-subnet=".len()..];
                cli.smb.tun_subnet = parse_tun_subnet(value, "--smb-tun-subnet=")?;
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
/// build an unvalidated subnet in normal code.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::TunSubnet;

    /// Parse a CIDR that the caller knows is valid. Only the tun tests need it.
    #[cfg_attr(not(all(windows, feature = "smb-tun")), allow(dead_code))]
    pub(crate) fn subnet(cidr: &str) -> TunSubnet {
        super::parse_tun_subnet(cidr, "--smb-tun-subnet").expect("valid test subnet")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The derivation is the contract the tun transport depends on: `.1` is
    /// answered for by wrustic's own stack and must stay unassigned, `.2` goes
    /// on the adapter. Getting these the wrong way round silently reintroduces
    /// the srvnet port conflict the whole design exists to avoid.
    #[test]
    fn subnet_derives_the_virtual_and_adapter_addresses() {
        let s = parse_tun_subnet("10.99.0.0/24", "--smb-tun-subnet").expect("parses");
        assert_eq!(s.virtual_ip(), std::net::Ipv4Addr::new(10, 99, 0, 1));
        assert_eq!(s.adapter_ip(), std::net::Ipv4Addr::new(10, 99, 0, 2));
        assert_eq!(s.cidr(), "10.99.0.0/24");
    }

    /// A host address is rounded down rather than rejected, so `10.99.0.1/24`
    /// means what someone writing it plainly intends.
    #[test]
    fn subnet_rounds_down_to_the_network_address() {
        let s = parse_tun_subnet("192.168.44.37/24", "--smb-tun-subnet").expect("parses");
        assert_eq!(s.cidr(), "192.168.44.0/24");
        assert_eq!(s.virtual_ip(), std::net::Ipv4Addr::new(192, 168, 44, 1));
    }

    /// /30 is the smallest usable subnet, and both derived addresses have to
    /// land inside it.
    #[test]
    fn thirty_is_the_smallest_subnet_that_works() {
        let s = parse_tun_subnet("192.168.77.0/30", "--smb-tun-subnet").expect("/30 parses");
        assert_eq!(s.virtual_ip(), std::net::Ipv4Addr::new(192, 168, 77, 1));
        assert_eq!(s.adapter_ip(), std::net::Ipv4Addr::new(192, 168, 77, 2));

        // A /31 has room for one address and a /32 creates no subnet route at
        // all, so neither can carry this design.
        for too_small in ["192.168.77.0/31", "192.168.77.1/32"] {
            let err = parse_tun_subnet(too_small, "--smb-tun-subnet")
                .expect_err("must be refused")
                .to_string();
            assert!(err.contains("between 8 and 30"), "{too_small}: {err}");
        }
    }

    #[test]
    fn subnet_rejects_ranges_the_local_stack_reserves() {
        for bad in ["127.0.0.0/8", "224.0.0.0/24", "169.254.0.0/16", "0.0.0.0/8"] {
            assert!(
                parse_tun_subnet(bad, "--smb-tun-subnet").is_err(),
                "{bad} should be refused"
            );
        }
    }

    #[test]
    fn subnet_rejects_malformed_input() {
        for bad in ["10.99.0.0", "10.99.0.0/", "nonsense/24", "10.99.0.0/abc"] {
            assert!(
                parse_tun_subnet(bad, "--smb-tun-subnet").is_err(),
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
