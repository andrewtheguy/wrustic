// Serving the SMB share on port 445, the only port Windows Explorer will use
// for a UNC path.
//
// Why this exists: port 445 cannot be bound through the Windows socket layer at
// all. `srvnet.sys` holds it as an exclusive, system-wide reservation, so every
// bind fails with WSAEACCES rather than the WSAEADDRINUSE you would expect —
// on 127.0.0.1 and on every other local address alike. Measured on this
// machine, none of the usual levers change that:
//
//   - adding an interface:             no effect, the reservation is not per-interface
//   - unbinding "File and Printer Sharing" (ms_server) from an adapter: no effect
//   - stopping the LanmanServer service: no effect, srvnet.sys stays loaded
//   - stopping srvnet.sys itself:       frees 445, and takes ALL host file
//                                       sharing down with it
//
// Only the last one works, and paying for a snapshot browser by disabling the
// machine's file sharing is a bad trade.
//
// So wrustic does what a VM guest or a WireGuard peer does: it terminates the
// connection in a TCP/IP stack that is not Windows'. A Wintun adapter gives us
// an L3 device; smoltcp gives us the stack. Windows never sees a socket bound
// to 445, so there is nothing for srvnet to arbitrate, and host file sharing is
// untouched for the whole lifetime of the share.
//
// The routing trick that makes it work: the adapter itself is given
// `ADAPTER_IP`, and we answer for `VIRTUAL_IP` — a second address in the same
// /24 that is assigned to *nothing*. Windows sees an on-link route for the
// subnet and pushes packets for VIRTUAL_IP out through the tun ring. Assign
// VIRTUAL_IP to the adapter instead and Windows treats it as a local address,
// loops the traffic back internally, and the port reservation applies again —
// which is the whole failure mode this module exists to avoid.
//
// The SMB protocol code is deliberately untouched by any of this. smoltcp
// terminates the connection and proxies it to the ordinary loopback listener
// `smb::start` already creates, so the async server, its tests and its wire
// handling never learn that a tun exists. The extra loopback hop costs a memcpy
// per buffer, which is nothing next to a repository read.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant as StdInstant};

use anyhow::{Result, anyhow};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

use crate::cli::TunSubnet;

const ADAPTER_NAME: &str = "wrustic";
const TUNNEL_TYPE: &str = "wrustic snapshot share";

/// Fixed, so repeated shares reuse one interface profile instead of leaving
/// Windows a new one to remember after every run.
const ADAPTER_GUID: u128 = 0x77b3_1c0a_5e42_4d19_8f6b_2a91_c4d7_3e08;

/// Wintun's default. Larger would cut per-packet overhead noticeably on bulk
/// reads, but raising it means changing the adapter MTU on the Windows side,
/// which the wintun crate only does by shelling out to `netsh`. Left at the
/// default until it measures as a bottleneck.
const MTU: usize = 1500;

/// Concurrent connections the share accepts. Clients open a handful — Windows
/// typically two or three per mount — and each costs its socket buffers below.
const MAX_CONNS: usize = 8;

/// Per-direction smoltcp socket buffer. SMB2 reads come in ~1 MiB bursts, and a
/// small window here throttles them to one round trip per segment.
const SOCKET_BUF: usize = 256 * 1024;

/// Cap on bytes buffered from the loopback server before we stop reading it.
/// Without it a client that stops reading would let the proxy buffer grow
/// without bound.
const PROXY_HIGH_WATER: usize = 512 * 1024;

/// The wintun DLL, embedded so wrustic stays a single binary.
///
/// Redistributing it this way is what the Wintun "Prebuilt Binaries License"
/// §3(d) permits: alongside other software that uses it only through the
/// documented API, which is all this module does.
const WINTUN_DLL: &[u8] = include_bytes!("../../vendor/wintun/wintun-amd64.dll");

/// SHA-256 of the embedded driver, pinned so it cannot be swapped unnoticed.
///
/// Provenance: `wintun-0.14.1.zip` from <https://www.wintun.net/builds/>, whose
/// archive hash matched the SHA2-256 published on wintun.net
/// (`07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`), and
/// whose `bin/amd64/wintun.dll` is Authenticode-signed by "WireGuard LLC"
/// (thumbprint DF98E075A012ED8C86FBCF14854B8F9555CB3D45).
///
/// Checked in two places, because a hash that is only verified at download time
/// protects nothing later: a test asserts the vendored bytes still hash to this,
/// and `materialise_dll` re-checks the file on disk before it is ever loaded.
const WINTUN_DLL_SHA256: [u8; 32] = [
    0xe5, 0xda, 0x84, 0x47, 0xdc, 0x2c, 0x32, 0x0e, 0xdc, 0x0f, 0xc5, 0x2f, 0xa0, 0x18, 0x85, 0xc1,
    0x03, 0xde, 0x8c, 0x11, 0x84, 0x81, 0xf6, 0x83, 0x64, 0x3c, 0xac, 0xc3, 0x22, 0x0d, 0xaf, 0xce,
];

/// A running tun-backed front end for a loopback SMB listener.
///
/// Dropping it stops the poll thread and removes the adapter, which takes the
/// address and the on-link route with it — nothing persists across a run.
pub(crate) struct TunShare {
    virtual_ip: Ipv4Addr,
    shutdown: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
    /// Held so the interface outlives the poll thread that reads from it. The
    /// thread owns the session; this is the adapter the session belongs to.
    adapter: Option<Arc<wintun::Adapter>>,
}

impl TunShare {
    /// Bring up the adapter and start proxying `VIRTUAL_IP:port` to
    /// `forward_to`.
    ///
    /// `dll_dir` is where the embedded wintun DLL is materialised; it should be
    /// a directory only this user can write, since it is then loaded as code.
    ///
    /// Requires administrator rights: creating a network adapter always does.
    /// Nothing else about this needs elevation, and no existing service,
    /// binding or adapter is modified.
    pub(crate) fn start(
        dll_dir: &Path,
        port: u16,
        forward_to: SocketAddr,
        subnet: TunSubnet,
    ) -> Result<Self> {
        let virtual_ip = subnet.virtual_ip();
        let adapter_ip = subnet.adapter_ip();
        let prefix_len = subnet.prefix_len();

        // Refused before anything is created: claiming a subnet the machine
        // already routes would black-hole real traffic for as long as the share
        // is open, and the symptom (some unrelated host stops responding) would
        // be almost impossible to connect back to a snapshot browser.
        reject_subnet_in_use(&subnet)?;

        let dll = materialise_dll(dll_dir)?;
        // SAFETY: loading a known-good signed DLL from a path we just wrote
        // ourselves inside the user's own config directory.
        let wintun = unsafe { wintun::load_from_path(&dll) }
            .map_err(|e| adapter_hint(anyhow!("loading {}: {e}", dll.display()), &subnet))?;

        let adapter = wintun::Adapter::create(&wintun, ADAPTER_NAME, TUNNEL_TYPE, Some(ADAPTER_GUID))
            .map_err(|e| {
                adapter_hint(
                    anyhow!("creating the `{ADAPTER_NAME}` tun adapter: {e}"),
                    &subnet,
                )
            })?;

        // windows-sys here vs the wintun crate's older one: structurally the
        // same LUID union, different nominal type, so go through the u64.
        let luid: u64 = unsafe { adapter.get_luid().Value };
        assign_address(luid, adapter_ip, prefix_len, &subnet)?;
        smb_log!("tun: adapter up, {adapter_ip}/{prefix_len}, serving {virtual_ip}:{port}");

        let session = adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|e| anyhow!("starting the tun session: {e}"))?;
        let session = Arc::new(session);

        let shutdown = Arc::new(AtomicBool::new(false));
        let join = {
            let shutdown = shutdown.clone();
            std::thread::Builder::new()
                .name(format!("wrustic-tun-{port}"))
                .spawn(move || {
                    poll_loop(session, virtual_ip, prefix_len, port, forward_to, shutdown)
                })
                .map_err(|e| anyhow!("spawning the tun thread: {e}"))?
        };

        Ok(Self {
            virtual_ip,
            shutdown,
            join: Some(join),
            adapter: Some(adapter),
        })
    }

    /// The UNC host clients should mount, e.g. `10.99.0.1`.
    pub(crate) fn virtual_ip(&self) -> Ipv4Addr {
        self.virtual_ip
    }

}

impl Drop for TunShare {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            // The loop checks the flag at least every idle tick, so this is a
            // bounded wait rather than a hope.
            let _ = join.join();
        }
        // Dropping the last reference removes the interface, and with it the
        // address and the on-link route.
        self.adapter = None;
        smb_log!("tun: adapter removed");
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn file_sha256(path: &Path) -> Option<[u8; 32]> {
    std::fs::read(path).ok().map(|bytes| sha256(&bytes))
}

/// Write the embedded DLL out if what is on disk is not byte-for-byte the
/// driver we shipped, and return its path.
///
/// The file is about to be handed to `LoadLibrary`, so "close enough" is not
/// good enough: a stale or tampered DLL of the same length would previously
/// have been loaded as code. Nothing is loaded unless its SHA-256 matches
/// [`WINTUN_DLL_SHA256`].
///
/// This narrows the window rather than closing it — between the hash check and
/// the load, a writer could still swap the file. `dir` is the user's own config
/// directory, so anything able to win that race can already replace the wrustic
/// binary itself; this defends against a stale or corrupted copy, not against
/// an attacker who already has that much.
fn materialise_dll(dir: &Path) -> Result<PathBuf> {
    let path = dir.join("wintun.dll");
    // Already exactly right: leave it alone. This is also what makes a second
    // share in the same process work, since Windows will not let us overwrite a
    // DLL this process already has loaded.
    if file_sha256(&path).is_some_and(|found| found == WINTUN_DLL_SHA256) {
        return Ok(path);
    }
    std::fs::create_dir_all(dir)
        .map_err(|e| anyhow!("creating {} for the tun driver: {e}", dir.display()))?;
    std::fs::write(&path, WINTUN_DLL)
        .map_err(|e| anyhow!("writing {}: {e}", path.display()))?;

    // Verify what actually landed on disk, not what we meant to put there.
    match file_sha256(&path) {
        Some(found) if found == WINTUN_DLL_SHA256 => Ok(path),
        Some(found) => Err(anyhow!(
            "{} does not match the driver wrustic shipped (found sha256 {}, expected {}); \
refusing to load it",
            path.display(),
            hex(&found),
            hex(&WINTUN_DLL_SHA256),
        )),
        None => Err(anyhow!(
            "{} could not be read back after writing it",
            path.display()
        )),
    }
}

/// Adapter creation fails with a bare Win32 code when not elevated, which says
/// nothing about the cause.
fn adapter_hint(e: anyhow::Error, subnet: &TunSubnet) -> anyhow::Error {
    anyhow!(
        "{e}\n\nCreating a network adapter requires administrator rights. Run \
wrustic elevated to serve on port 445, or drop --smb-tun and mount the ordinary \
loopback share instead.\n\
While the share is up, {} is routed to the tun adapter (change it with \
--smb-tun-subnet).",
        subnet.cidr()
    )
}

/// Refuse a subnet the machine already has a specific route for.
///
/// Every address is "routable" on a machine with a default gateway, so the
/// question is not whether a route exists but whether a *more specific* one
/// does: `GetBestRoute2` returning a prefix length of 0 means the default route
/// matched and the range is free, while anything longer means some real
/// interface already owns it and adding ours would hijack that traffic.
fn reject_subnet_in_use(subnet: &TunSubnet) -> Result<()> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetBestRoute2, MIB_IPFORWARD_ROW2};
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_INET};

    let virtual_ip = subnet.virtual_ip();
    // SAFETY: both structures are zeroed, and only the destination address is
    // read by the call; the outputs are written entirely by the API.
    let (rc, prefix_len) = unsafe {
        let mut dest: SOCKADDR_INET = std::mem::zeroed();
        dest.si_family = AF_INET;
        dest.Ipv4.sin_family = AF_INET;
        dest.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(virtual_ip.octets());

        let mut row: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
        let mut best_source: SOCKADDR_INET = std::mem::zeroed();
        let rc = GetBestRoute2(
            std::ptr::null(),
            0,
            std::ptr::null(),
            &dest,
            0,
            &mut row,
            &mut best_source,
        );
        (rc, row.DestinationPrefix.PrefixLength)
    };

    // A failure here means Windows has no route at all, which is exactly the
    // free case; only a successful lookup can tell us the range is taken.
    if rc == 0 && prefix_len > 0 {
        return Err(anyhow!(
            "{} is already routed by this machine (a /{prefix_len} route matches {virtual_ip}). \
Serving the share there would divert that traffic for as long as it is open. \
Pick a free range with --smb-tun-subnet.",
            subnet.cidr()
        ));
    }
    Ok(())
}

/// Add a unicast address to the interface through iphlpapi.
///
/// Not `netsh`: the wintun crate's own address setters shell out to it, which
/// means parsing localised output to tell success from failure.
fn assign_address(
    luid_value: u64,
    addr: Ipv4Addr,
    prefix_len: u8,
    subnet: &TunSubnet,
) -> Result<()> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        CreateUnicastIpAddressEntry, InitializeUnicastIpAddressEntry, MIB_UNICASTIPADDRESS_ROW,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, IpDadStatePreferred};

    /// ERROR_OBJECT_ALREADY_EXISTS — a previous adapter with this GUID left the
    /// address behind, which is exactly the state we want anyway.
    const ALREADY_EXISTS: u32 = 5010;

    // SAFETY: `row` is zeroed and then initialised by the API itself before we
    // fill in the fields it documents as caller-supplied.
    let rc = unsafe {
        let mut row: MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
        InitializeUnicastIpAddressEntry(&mut row);
        row.InterfaceLuid.Value = luid_value;
        row.Address.si_family = AF_INET;
        row.Address.Ipv4.sin_family = AF_INET;
        row.Address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(addr.octets());
        row.OnLinkPrefixLength = prefix_len;
        // Otherwise the address stays tentative pending duplicate-address
        // detection, which on a tun with no peer never completes.
        row.DadState = IpDadStatePreferred;
        CreateUnicastIpAddressEntry(&row)
    };
    if rc != 0 && rc != ALREADY_EXISTS {
        return Err(adapter_hint(
            anyhow!("assigning {addr}/{prefix_len} to the tun adapter failed with Win32 error {rc}"),
            subnet,
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// smoltcp device over the wintun ring
// ---------------------------------------------------------------------------

struct WintunDevice {
    session: Arc<wintun::Session>,
}

struct WintunRx {
    packet: wintun::Packet,
}

struct WintunTx {
    session: Arc<wintun::Session>,
}

impl RxToken for WintunRx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.packet.bytes())
    }
}

impl TxToken for WintunTx {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        match self.session.allocate_send_packet(len as u16) {
            Ok(mut packet) => {
                let r = f(packet.bytes_mut());
                self.session.send_packet(packet);
                r
            }
            // smoltcp's transmit path cannot fail, so a full ring means the
            // packet is dropped — which is what a congested link does anyway,
            // and TCP retransmits it.
            Err(_) => {
                let mut scratch = vec![0u8; len];
                f(&mut scratch)
            }
        }
    }
}

impl Device for WintunDevice {
    type RxToken<'a>
        = WintunRx
    where
        Self: 'a;
    type TxToken<'a>
        = WintunTx
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        match self.session.try_receive() {
            Ok(Some(packet)) => Some((
                WintunRx { packet },
                WintunTx {
                    session: self.session.clone(),
                },
            )),
            _ => None,
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(WintunTx {
            session: self.session.clone(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        // No Ethernet header: wintun hands over bare IP packets, so there is no
        // ARP or neighbour discovery to answer either.
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        caps
    }
}

// ---------------------------------------------------------------------------
// the proxy
// ---------------------------------------------------------------------------

/// One client connection: a smoltcp socket paired with the loopback connection
/// that carries it to the real SMB server.
struct Bridge {
    handle: SocketHandle,
    upstream: Option<TcpStream>,
    /// Client bytes waiting to be written to the loopback server.
    to_upstream: VecDeque<u8>,
    /// Server bytes waiting to be written back to the client.
    to_client: VecDeque<u8>,
    upstream_eof: bool,
}

impl Bridge {
    fn reset(&mut self) {
        self.upstream = None;
        self.to_upstream.clear();
        self.to_client.clear();
        self.upstream_eof = false;
    }
}

fn poll_loop(
    session: Arc<wintun::Session>,
    virtual_ip: Ipv4Addr,
    prefix_len: u8,
    port: u16,
    forward_to: SocketAddr,
    shutdown: Arc<AtomicBool>,
) {
    let mut device = WintunDevice { session };
    let started = StdInstant::now();
    let now = || Instant::from_micros(started.elapsed().as_micros() as i64);

    let config = Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, &mut device, now());
    iface.update_ip_addrs(|addrs| {
        // `unwrap` on a single push into an empty, statically sized list.
        addrs
            .push(IpCidr::new(IpAddress::Ipv4(virtual_ip), prefix_len))
            .expect("one address fits");
    });

    let mut sockets = SocketSet::new(Vec::new());
    let mut bridges: Vec<Bridge> = (0..MAX_CONNS)
        .map(|_| {
            let rx = tcp::SocketBuffer::new(vec![0u8; SOCKET_BUF]);
            let tx = tcp::SocketBuffer::new(vec![0u8; SOCKET_BUF]);
            let mut sock = tcp::Socket::new(rx, tx);
            // SMB2 is request/response with small headers; Nagle would sit on
            // replies waiting for data that only arrives after the next request.
            sock.set_nagle_enabled(false);
            if let Err(e) = sock.listen(port) {
                smb_log!("tun: listen on {port} failed: {e:?}");
            }
            Bridge {
                handle: sockets.add(sock),
                upstream: None,
                to_upstream: VecDeque::new(),
                to_client: VecDeque::new(),
                upstream_eof: false,
            }
        })
        .collect();

    while !shutdown.load(Ordering::Relaxed) {
        iface.poll(now(), &mut device, &mut sockets);

        let mut did_work = false;
        let mut any_active = false;
        for bridge in &mut bridges {
            did_work |= pump(bridge, &mut sockets, forward_to, port);
            any_active |= bridge.upstream.is_some();
        }

        if did_work {
            // Data moved, so smoltcp has something to send and possibly more to
            // receive; go straight round again rather than sleeping on it.
            continue;
        }
        // No event source spans both the tun ring and the loopback sockets
        // without WSAEventSelect plumbing, so this polls. The rate is the
        // trade: 1 ms while a mount is live keeps round-trip latency off the
        // critical path, and 20 ms when idle keeps a dormant share cheap.
        let idle = if any_active { 1 } else { 20 };
        std::thread::sleep(Duration::from_millis(idle));
    }

    for bridge in &mut bridges {
        sockets.get_mut::<tcp::Socket>(bridge.handle).abort();
    }
    // One last poll so the RSTs actually reach the client instead of being
    // dropped with the adapter.
    iface.poll(now(), &mut device, &mut sockets);
}

/// Move whatever is movable in both directions for one connection.
///
/// Returns whether anything actually moved, which is what decides between
/// looping again immediately and sleeping.
fn pump(
    bridge: &mut Bridge,
    sockets: &mut SocketSet<'_>,
    forward_to: SocketAddr,
    port: u16,
) -> bool {
    let mut did_work = false;
    let sock = sockets.get_mut::<tcp::Socket>(bridge.handle);

    // A client finished the handshake: open the loopback connection that backs
    // it. Blocking connect is fine — the destination is our own listener.
    if bridge.upstream.is_none() && sock.state() == tcp::State::Established {
        match TcpStream::connect(forward_to) {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                if let Err(e) = stream.set_nonblocking(true) {
                    smb_log!("tun: set_nonblocking failed: {e}; dropping connection");
                    sock.abort();
                    return true;
                }
                smb_log!("tun: connection from {:?} bridged", sock.remote_endpoint());
                bridge.upstream = Some(stream);
                did_work = true;
            }
            Err(e) => {
                smb_log!("tun: cannot reach the loopback server at {forward_to}: {e}");
                sock.abort();
                return true;
            }
        }
    }

    let Some(upstream) = bridge.upstream.as_mut() else {
        // Still listening, or already torn down: recycle a socket that has
        // finished closing so the pool keeps accepting.
        if !sock.is_open() {
            bridge.reset();
            if let Err(e) = sock.listen(port) {
                smb_log!("tun: re-listen failed: {e:?}");
            }
            return true;
        }
        return did_work;
    };

    // client -> server
    while sock.can_recv() && bridge.to_upstream.len() < PROXY_HIGH_WATER {
        let mut buf = [0u8; 16 * 1024];
        match sock.recv_slice(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                bridge.to_upstream.extend(&buf[..n]);
                did_work = true;
            }
            Err(_) => break,
        }
    }
    while !bridge.to_upstream.is_empty() {
        let (head, _) = bridge.to_upstream.as_slices();
        match upstream.write(head) {
            Ok(0) => break,
            Ok(n) => {
                bridge.to_upstream.drain(..n);
                did_work = true;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => {
                bridge.upstream_eof = true;
                break;
            }
        }
    }

    // server -> client
    while !bridge.upstream_eof && bridge.to_client.len() < PROXY_HIGH_WATER {
        let mut buf = [0u8; 16 * 1024];
        match upstream.read(&mut buf) {
            Ok(0) => {
                bridge.upstream_eof = true;
                did_work = true;
                break;
            }
            Ok(n) => {
                bridge.to_client.extend(&buf[..n]);
                did_work = true;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => {
                bridge.upstream_eof = true;
                did_work = true;
                break;
            }
        }
    }
    while sock.can_send() && !bridge.to_client.is_empty() {
        let (head, _) = bridge.to_client.as_slices();
        match sock.send_slice(head) {
            Ok(0) => break,
            Ok(n) => {
                bridge.to_client.drain(..n);
                did_work = true;
            }
            Err(_) => break,
        }
    }

    // Teardown, in both directions.
    if bridge.upstream_eof && bridge.to_client.is_empty() && sock.may_send() {
        // Everything the server said has been handed over; let the client see
        // the close rather than a reset.
        sock.close();
        did_work = true;
    }
    if !sock.may_recv() && bridge.to_upstream.is_empty() && !bridge.upstream_eof {
        // The client is done sending: half-close upstream so the SMB server's
        // read loop sees EOF and drops its own state.
        let _ = upstream.shutdown(std::net::Shutdown::Write);
        bridge.upstream_eof = true;
        did_work = true;
    }
    if !sock.is_open() {
        bridge.reset();
        if let Err(e) = sock.listen(port) {
            smb_log!("tun: re-listen failed: {e:?}");
        }
        did_work = true;
    }

    did_work
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two addresses must differ: handing the virtual address to the
    /// adapter makes Windows treat it as local, loop the traffic back
    /// internally, and apply the srvnet port reservation again — the exact
    /// failure this design exists to avoid.
    #[test]
    fn virtual_address_is_not_the_adapter_address() {
        for cidr in ["10.99.0.0/24", "192.168.77.0/30", "172.20.0.0/16"] {
            let subnet = crate::cli::tests_support::subnet(cidr);
            assert_ne!(subnet.adapter_ip(), subnet.virtual_ip(), "{cidr}");
        }
    }

    /// Both have to sit inside the subnet whose on-link route carries them, or
    /// Windows has no route to the virtual address at all. A /30 is the tight
    /// case: exactly two usable addresses, and these must be them.
    #[test]
    fn both_addresses_share_the_subnet_that_routes_them() {
        for cidr in ["10.99.0.0/24", "192.168.77.0/30", "172.20.0.0/16"] {
            let subnet = crate::cli::tests_support::subnet(cidr);
            let mask = u32::MAX << (32 - subnet.prefix_len());
            let net = |ip: Ipv4Addr| u32::from(ip) & mask;
            assert_eq!(
                net(subnet.adapter_ip()),
                net(subnet.virtual_ip()),
                "{cidr}: addresses fell outside one subnet"
            );
        }
    }

    /// The embedded driver has to actually be embedded; an empty or truncated
    /// include would only surface as a load failure at share time.
    #[test]
    fn wintun_dll_is_embedded() {
        assert!(WINTUN_DLL.len() > 100_000, "len {}", WINTUN_DLL.len());
        assert_eq!(&WINTUN_DLL[..2], b"MZ");
    }

    /// The vendored driver is a committed binary that nothing else in the build
    /// would notice changing, and it is loaded as code. Pinning its hash means
    /// replacing it — by accident, by a bad merge, or otherwise — fails the
    /// build instead of silently shipping a different driver.
    #[test]
    fn embedded_driver_matches_its_pinned_hash() {
        let found = sha256(WINTUN_DLL);
        assert_eq!(
            found,
            WINTUN_DLL_SHA256,
            "vendored wintun.dll hashes to {}, expected {}. If this was a \
deliberate driver update, verify the new archive against the SHA2-256 published \
on wintun.net and its Authenticode signature before changing the constant.",
            hex(&found),
            hex(&WINTUN_DLL_SHA256),
        );
    }

    /// A file on disk that is not the driver we shipped must never be loaded,
    /// and must be replaced rather than trusted — the case the old
    /// length-only check got wrong.
    #[test]
    fn materialise_replaces_a_file_that_does_not_match() {
        let dir = std::env::temp_dir().join(format!(
            "wrustic-tun-dll-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("wintun.dll");

        // Same length as the real driver, entirely different bytes: exactly
        // what a length comparison would have accepted.
        std::fs::write(&path, vec![0x41u8; WINTUN_DLL.len()]).expect("write impostor");
        let got = materialise_dll(&dir).expect("impostor is replaced, not trusted");
        assert_eq!(got, path);
        assert_eq!(file_sha256(&path), Some(WINTUN_DLL_SHA256));

        // A second call is a no-op that still returns the verified path.
        assert_eq!(materialise_dll(&dir).expect("idempotent"), path);
        assert_eq!(file_sha256(&path), Some(WINTUN_DLL_SHA256));

        std::fs::remove_dir_all(&dir).ok();
    }
}
