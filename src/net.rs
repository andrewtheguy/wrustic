use anyhow::{Result, anyhow};

/// Bind TCP listeners to the loopback address on `port`.
/// Returns an IPv4 listener (must succeed) and an optional IPv6
/// listener for macOS where `*.localhost` resolves to `::1`.
pub(crate) fn bind_loopback(port: u16) -> Result<(std::net::TcpListener, Option<std::net::TcpListener>)> {
    let v4 = std::net::TcpListener::bind(("127.0.0.1", port))
        .map_err(|e| anyhow!("bind 127.0.0.1:{port}: {e}"))?;

    let v6 = {
        use std::net::{Ipv6Addr, SocketAddrV6};
        let addr = SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0);
        std::net::TcpListener::bind(addr).ok()
    };
    if let Some(ref l) = v6 {
        let _ = l.set_nonblocking(true);
    }

    Ok((v4, v6))
}
