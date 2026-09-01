// The restic-facing side of the snapshot share.
//
// The SMB 2.1 server itself — protocol, NTLMv2, signing, the tun transport —
// lives in the `smbanything_core` crate and is shared with other projects.
// What stays here is everything that knows about restic: `SnapshotBacking`
// walks repository trees and decodes restic's quoted filenames (`name`), and
// `start_snapshot_share` opens the repository under restic's non-exclusive
// lock and keeps that lock alive for exactly as long as the server runs.

mod backing;
mod name;

use std::sync::Arc;

use anyhow::{Result, anyhow};

use crate::config::Profile;
use backing::SnapshotBacking;
use smbanything_core::smb;
pub(crate) use smbanything_core::smb::{Bind, Credentials, random_password};
#[cfg(all(windows, feature = "smb-tun"))]
pub(crate) use smbanything_core::smb::{STANDARD_SMB_PORT, TunConfig};

/// The share name clients connect to: `\\127.0.0.1\snap`.
pub(crate) const DEFAULT_SHARE_NAME: &str = "snap";

/// The account clients authenticate as. Fixed rather than configurable in the
/// TUI: the password is what protects the share, and a second thing to type
/// wrong buys nothing.
pub(crate) const DEFAULT_SHARE_USER: &str = "wrustic";

/// A running snapshot share: the SMB server plus the repository lock it holds.
///
/// Field order is drop order, and it is load-bearing: the server (whose own
/// drop tears the client-facing transport down and signals shutdown) goes
/// before the lock, so the repository is never served unlocked.
pub(crate) struct SmbHandle {
    server: smb::SmbHandle,
    /// restic's non-exclusive repository lock (what `restic mount` takes),
    /// held for the share's lifetime.
    lock: crate::lock::RepoLock,
}

impl SmbHandle {
    /// UNC path for a Linux `mount -t cifs`.
    pub(crate) fn unc(&self) -> String {
        self.server.unc()
    }

    pub(crate) fn share_name(&self) -> &str {
        self.server.share_name()
    }

    /// Host and port a client mounts, as opposed to the bound listener.
    pub(crate) fn mount(&self) -> &smb::MountPoint {
        self.server.mount()
    }

    /// The port the SMB listener actually bound. Equal to the mount port for
    /// every transport except the tun, where it is the private loopback socket
    /// the proxy talks to — which is why nothing user-facing reads it, and only
    /// the manual harness does.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn port(&self) -> u16 {
        self.server.port()
    }

    /// Whether the share is reachable on SMB's standard port, and so mountable
    /// as a plain UNC path with no port option anywhere in the command.
    pub(crate) fn on_standard_port(&self) -> bool {
        self.server.on_standard_port()
    }

    /// restic's abort-if-unrefreshable rule: true once the held lock went
    /// 22.5 minutes without a successful refresh, meaning other processes may
    /// already treat it as stale and remove it — at which point a concurrent
    /// prune could delete data mid-read. The owner must stop the share.
    pub(crate) fn lock_poisoned(&self) -> bool {
        self.lock.poisoned()
    }

    /// True once refused logons since the last successful one have reached the
    /// server's limit. The server has already stopped accepting logons at this
    /// point; the owner is expected to stop it outright.
    pub(crate) fn logon_limit_reached(&self) -> bool {
        self.server.logon_limit_reached()
    }

    /// Refused logons since the last successful one, for the message the owner
    /// shows when it stops.
    pub(crate) fn failed_logons(&self) -> u32 {
        self.server.failed_logons()
    }

    pub(crate) fn stop(self) {
        self.server.stop();
        // `self.lock` drops here, releasing the repo lock after the server has
        // fully stopped.
    }
}

/// Serve one snapshot from `profile`'s repository.
///
/// The repository is opened synchronously, before the listener thread starts,
/// so a bad passphrase or an unreachable backend is reported to the caller
/// rather than surfacing later as a mount that connects and then fails.
///
/// Holds restic's non-exclusive repository lock (what `restic mount` takes)
/// for the share's lifetime, acquired before the index loads and before the
/// snapshot is resolved. A repo locked exclusively (a running prune/forget)
/// makes this fail with restic's "repository is already locked" error rather
/// than serve data that operation may delete.
pub(crate) fn start_snapshot_share(
    port: u16,
    profile: &Profile,
    snapshot_id: &str,
    bind: Bind,
    credentials: Credentials,
) -> Result<SmbHandle> {
    // The library's own switch is `SMBANYTHING_LOG`; wrustic keeps the
    // environment variable its docs and harnesses have always used.
    if std::env::var_os("WRUSTIC_SMB_LOG").is_some() {
        smb::enable_log();
    }

    let (repo, repo_lock) = crate::repo::open_indexed_full_shared_lock(profile)?;
    let repo = Arc::new(repo);
    let snap = repo
        .get_snapshot_from_str(snapshot_id, |_| true)
        .map_err(|e| anyhow!("looking up snapshot `{snapshot_id}`: {e}"))?;

    // restic's standard short id (8 hex chars, `internal/restic/id.go`
    // shortStr) — the same form `restic snapshots` prints, so the name pastes
    // straight into other restic commands.
    let hex = snap.id.to_hex();
    let short_id = &hex.as_str()[..8.min(hex.as_str().len())];
    // Label the volume with it too, so a client that has several of these
    // mounted can tell them apart.
    let label = format!("snap-{short_id}");
    // restic records the snapshot's byte count at backup time; using it avoids
    // a recursive walk and is exact.
    let total_size = snap.summary.as_ref().map(|s| s.total_bytes_processed);
    let backing = SnapshotBacking::new(repo, snap.tree, label, total_size)?;
    // The share root shows a single directory named by the short id: the share
    // name and mount commands stay fixed, while the mount's contents say which
    // snapshot they came from.
    let backing = backing::NestedBacking::new(backing, short_id);

    let server = smb::start(port, DEFAULT_SHARE_NAME, bind, credentials)?;
    server.load(Arc::new(backing));
    Ok(SmbHandle {
        server,
        lock: repo_lock,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use backing::test_support::MemBacking;
    #[cfg(all(windows, feature = "smb-tun"))]
    use smbanything_core::smb::Backing;
    use smbanything_core::smb::start;

    /// A small tree the end-to-end tests can list and read.
    #[cfg(all(windows, feature = "smb-tun"))]
    fn test_backing() -> Arc<dyn Backing> {
        Arc::new(
            MemBacking::new()
                .with_dir("docs")
                .with_file("docs\\readme.txt", b"hello from a snapshot\n")
                .with_file("docs\\notes.md", b"# notes\n")
                .with_file("data.bin", &[0xAB; 9000]),
        )
    }

    const TEST_USER: &str = "wrustic";
    const TEST_PASSWORD: &str = "hunter2";

    fn test_credentials() -> Credentials {
        Credentials {
            user: TEST_USER.to_string(),
            password: TEST_PASSWORD.to_string(),
        }
    }

    /// The Windows installer stages `vendor/wintun/wintun-amd64.dll` next to
    /// wrustic.exe, and smbanything_core refuses to load any driver that is
    /// not byte-for-byte the one it pins. Checking the vendored copy here
    /// turns a driver update that forgets one side into a build failure
    /// instead of a broken `--smb-tun` in the field.
    #[test]
    #[cfg(all(windows, feature = "smb-tun"))]
    fn vendored_driver_matches_the_digest_core_will_load() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("vendor")
            .join("wintun")
            .join("wintun-amd64.dll");
        smb::verify_driver(&path)
            .expect("the vendored Wintun DLL must match smbanything_core's pinned digest");
    }

    /// End-to-end over the tun transport: a real Windows mount of
    /// `\\169.254.255.1\snap` on the standard SMB port, with the host's own
    /// srvnet.sys still holding 445 throughout.
    ///
    /// Ignored by default because it needs administrator rights (creating a
    /// network adapter always does) and briefly adds two /32 host routes.
    /// Run it with:
    ///   cargo test --features smb-tun tun_mount_on_the_standard_port -- --ignored --nocapture
    #[test]
    #[ignore = "needs administrator rights and creates a network adapter"]
    #[cfg(all(windows, feature = "smb-tun"))]
    fn tun_mount_on_the_standard_port() {
        use std::process::Command;

        let addrs = smb::DEFAULT_TUN_ADDRS;
        let unc = format!(r"\\{}\{}", addrs.virtual_ip(), DEFAULT_SHARE_NAME);
        let net_use = |args: &[&str]| {
            Command::new("net")
                .arg("use")
                .args(args)
                .output()
                .expect("net.exe runs")
        };
        // Deleting a mapping that is not there costs 272 seconds: `net use
        // /delete` tries to reach the server first, and an address with no
        // route makes that a full TCP timeout. Listing is instant, so only
        // delete when there is something to delete.
        let drop_stale_mapping = || {
            let listed = net_use(&[]);
            if String::from_utf8_lossy(&listed.stdout).contains(&unc) {
                let _ = net_use(&[&unc, "/delete", "/y"]);
            }
        };

        let handle = start(
            0,
            DEFAULT_SHARE_NAME,
            Bind::Tun(TunConfig {
                port: STANDARD_SMB_PORT,
                addrs,
            }),
            test_credentials(),
        )
        .expect("tun share starts (are you elevated?)");
        handle.load(test_backing());

        // Only now, with the adapter up and the route in place, is talking to
        // the address cheap.
        drop_stale_mapping();

        assert!(handle.on_standard_port());
        assert_eq!(handle.unc(), unc);

        // Everything fallible is captured rather than asserted, so the mapping
        // is always torn down before the test can fail out.
        let connect = net_use(&[&unc, TEST_PASSWORD, &format!("/user:{TEST_USER}")]);
        let read = std::fs::read_to_string(format!(r"{unc}\docs\readme.txt"));
        let listing = std::fs::read_dir(format!(r"{unc}\docs")).map(|d| {
            let mut names: Vec<String> = d
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect();
            names.sort();
            names
        });
        // The whole point of the design: the host's SMB server is untouched.
        let host_445 = Command::new("netstat")
            .args(["-ano", "-p", "TCP"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("0.0.0.0:445"))
            .unwrap_or(false);

        drop_stale_mapping();
        handle.stop();

        assert!(
            connect.status.success(),
            "net use failed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&connect.stdout),
            String::from_utf8_lossy(&connect.stderr),
        );
        assert_eq!(read.expect("readme is readable"), "hello from a snapshot\n");
        assert_eq!(listing.expect("docs lists"), ["notes.md", "readme.txt"]);
        assert!(
            host_445,
            "the host's own srvnet listener on 445 disappeared; the tun transport \
             must never disturb it"
        );
    }

    /// Hold a tun share open so an external client can be timed against it.
    /// Serves the in-memory test tree; no repository needed.
    ///   cargo test --features smb-tun smb_manual_tun -- --ignored --nocapture
    #[test]
    #[ignore = "manual harness: needs administrator rights"]
    #[cfg(all(windows, feature = "smb-tun"))]
    fn smb_manual_tun() {
        let secs: u64 = std::env::var("WRUSTIC_SMB_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(180);
        let handle = start(
            0,
            DEFAULT_SHARE_NAME,
            Bind::Tun(TunConfig {
                port: STANDARD_SMB_PORT,
                addrs: smb::DEFAULT_TUN_ADDRS,
            }),
            test_credentials(),
        )
        .expect("tun share starts (are you elevated?)");
        handle.load(test_backing());
        eprintln!("READY {} user={TEST_USER} pass={TEST_PASSWORD}", handle.unc());
        std::thread::sleep(std::time::Duration::from_secs(secs));
        handle.stop();
    }

    /// Serve a real restic snapshot, for validating the `SnapshotBacking` path
    /// against a live client. This is the cross-platform test harness: the TUI
    /// share dies when you leave the screen, and mounting from macOS or Windows
    /// needs a server that stays up while you walk over to another machine.
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
    ///
    ///   WRUSTIC_SMB_REPO=<path> WRUSTIC_SMB_PASSWORD=<pw> WRUSTIC_SMB_SNAPSHOT=latest \
    ///     cargo test --all-features smb_manual_snapshot -- --ignored --nocapture
    #[test]
    #[ignore]
    fn smb_manual_snapshot() {
        let repo = std::env::var("WRUSTIC_SMB_REPO").expect("WRUSTIC_SMB_REPO");
        let password = std::env::var("WRUSTIC_SMB_PASSWORD").expect("WRUSTIC_SMB_PASSWORD");
        let snapshot = std::env::var("WRUSTIC_SMB_SNAPSHOT").expect("WRUSTIC_SMB_SNAPSHOT");
        let port: u16 = std::env::var("WRUSTIC_SMB_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4456);

        let profile = Profile::Local {
            password,
            local_path: repo,
        };
        // Long enough to mount, poke around and unmount by hand. Bounded rather
        // than infinite so a forgotten server does not hold the port for ever.
        let secs: u64 = std::env::var("WRUSTIC_SMB_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1200);

        let bind = if std::env::var_os("WRUSTIC_SMB_BIND_ALL").is_some() {
            Bind::AllInterfaces
        } else {
            Bind::Loopback
        };
        let bind_all = matches!(bind, Bind::AllInterfaces);
        let password = std::env::var("WRUSTIC_SMB_SHARE_PASSWORD")
            .unwrap_or_else(|_| TEST_PASSWORD.to_string());
        let handle = start_snapshot_share(
            port,
            &profile,
            &snapshot,
            bind,
            Credentials {
                user: TEST_USER.to_string(),
                password: password.clone(),
            },
        )
        .expect("snapshot share starts");
        let host = if bind_all { "<this-host>" } else { "127.0.0.1" };
        let port = handle.port();
        eprintln!("serving snapshot {snapshot} on {host}:{port} for {secs}s");
        eprintln!();
        eprintln!("  username  {TEST_USER}");
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
            "  Linux    sudo mount -t cifs -o port={port},vers=2.1,username={TEST_USER},ro,uid=$(id -u),gid=$(id -g),file_mode=0444,dir_mode=0555 //{host}/{DEFAULT_SHARE_NAME} /mnt/snap"
        );
        eprintln!(
            "  macOS    Finder → Go → Connect to Server (Cmd+K): smb://{TEST_USER}@{host}:{port}/{DEFAULT_SHARE_NAME}"
        );
        eprintln!(
            "  Windows  net use Z: \\\\{host}\\{DEFAULT_SHARE_NAME} * /user:{TEST_USER} /TCPPORT:{port}"
        );
        std::thread::sleep(std::time::Duration::from_secs(secs));
        handle.stop();
    }

    /// A snapshot share's layout as a real client sees it: the share root
    /// lists exactly one directory named by the snapshot's 8-char short id,
    /// and the tree lives inside it.
    #[test]
    fn smbclient_walks_the_nested_snapshot_directory() {
        use std::process::Command;

        if Command::new("smbclient").arg("--version").output().is_err() {
            eprintln!("skipping: smbclient is not installed");
            return;
        }

        let backing = Arc::new(backing::NestedBacking::new(
            MemBacking::new()
                .with_dir("docs")
                .with_file("docs\\readme.txt", b"nested hello\n"),
            "1a2b3c4d",
        ));
        let handle = start(0, DEFAULT_SHARE_NAME, Bind::Loopback, test_credentials())
            .expect("server starts");
        handle.load(backing);
        let target = format!("//127.0.0.1/{}", handle.share_name());

        let out = Command::new("smbclient")
            .arg(&target)
            .args(["-p", &handle.port().to_string()])
            .args(["-U", &format!("{TEST_USER}%{TEST_PASSWORD}")])
            .arg("--option=client min protocol=SMB2_10")
            .arg("--option=client max protocol=SMB2_10")
            .args(["-c", "ls; cd 1a2b3c4d; ls; cd docs; ls"])
            .output()
            .expect("smbclient runs");
        handle.stop();

        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(
            out.status.success(),
            "smbclient failed\nstdout: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&out.stderr),
        );
        assert!(stdout.contains("1a2b3c4d"), "root must list the snapshot dir:\n{stdout}");
        assert!(stdout.contains("docs"), "snapshot dir must list the tree:\n{stdout}");
        assert!(stdout.contains("readme.txt"), "tree must be walkable:\n{stdout}");
    }

    /// The snapshot share holds restic's non-exclusive lock for its lifetime:
    /// while it runs, an exclusive acquisition is blocked but a concurrent
    /// append lock (a backup) is not; stopping releases the lock; and an
    /// existing exclusive lock stops the share from starting at all. The
    /// repository is built in-process (src/testrepo.rs), so this needs no
    /// restic binary and no hand-seeded fixture directory.
    #[test]
    fn snapshot_share_holds_restics_append_lock() {
        let _guard = crate::lock::test_acquire_guard();
        let fixture = crate::testrepo::TestRepo::init("share-lock");
        let snap_id = fixture.backup(&[("readme.txt", b"shared\n")], &[]);
        let profile = fixture.profile().clone();
        let (lock_backend, crypto) =
            crate::repo::lock_context(&profile).expect("lock context");
        assert!(
            lock_backend.list().expect("list locks").is_empty(),
            "fixture repo must start unlocked"
        );

        let handle = start_snapshot_share(
            0,
            &profile,
            &snap_id,
            Bind::Loopback,
            test_credentials(),
        )
        .expect("share starts");
        let err = crate::lock::check_blocking_locks(lock_backend.as_ref(), &crypto, true)
            .unwrap_err();
        assert!(
            crate::lock::is_lock_error(&format!("{err:#}")),
            "a running share must block exclusive operations: {err:#}"
        );
        assert!(
            crate::lock::check_blocking_locks(lock_backend.as_ref(), &crypto, false).is_ok(),
            "a concurrent backup's append lock must not be blocked"
        );
        handle.stop();
        assert!(
            lock_backend.list().expect("list locks").is_empty(),
            "stopping the share must release its lock"
        );

        // An exclusive holder (a prune in flight) refuses the share.
        let held = crate::lock::RepoLock::acquire_exclusive(
            std::sync::Arc::clone(&lock_backend),
            crypto,
        )
        .expect("exclusive lock");
        let err = start_snapshot_share(
            0,
            &profile,
            &snap_id,
            Bind::Loopback,
            test_credentials(),
        )
        .map(|_| ())
        .unwrap_err();
        assert!(
            crate::lock::is_lock_error(&format!("{err:#}")),
            "unexpected error: {err:#}"
        );
        drop(held);
    }
}
