// The restic-facing side of the snapshot share.
//
// The SMB 2.1 server itself — protocol, NTLMv2, signing, the tun transport —
// lives in the `smbanything_core` crate and is shared with other projects.
// What stays here is everything that knows about restic: `SnapshotBacking`
// walks repository trees and decodes restic's quoted filenames (`name`),
// `RootBacking` puts a README beside the shared snapshot's folder (`root`),
// and `ShareServer` ties a shared snapshot to restic's non-exclusive lock on
// its repository for exactly as long as the snapshot is in the share.

mod backing;
mod name;
mod root;

use std::sync::Arc;

use anyhow::{Result, anyhow};

use crate::config::Profile;
use backing::SnapshotBacking;
use root::RootBacking;
pub(crate) use root::SnapshotSummary;
use smbanything_core::smb;
pub(crate) use smbanything_core::smb::{Bind, Credentials, random_password};
#[cfg(all(windows, feature = "smb-tun"))]
pub(crate) use smbanything_core::smb::{STANDARD_SMB_PORT, TunConfig};
/// For the `dev smb-tun` harness, the only user outside this module's tests.
#[cfg(all(windows, feature = "dev-harness", feature = "smb-tun"))]
pub(crate) use backing::test_support::MemBacking;

/// The share name clients connect to: `\\127.0.0.1\snap`.
pub(crate) const DEFAULT_SHARE_NAME: &str = "snap";

/// The account clients authenticate as. Fixed rather than configurable in the
/// TUI: the password is what protects the share, and a second thing to type
/// wrong buys nothing.
pub(crate) const DEFAULT_SHARE_USER: &str = "wrustic";

/// See [`ShareServer::mount_commands`].
pub(crate) struct MountCommands {
    pub(crate) linux: String,
    /// The address for Finder's Connect to Server.
    pub(crate) macos: String,
    pub(crate) windows: String,
    pub(crate) unc: String,
    standard_port: bool,
}

impl MountCommands {
    /// What the copy key puts on the clipboard: the entry for the OS wrustic
    /// runs on, since that is where the share is reachable (it binds this
    /// machine only). On Windows the UNC path when it works on its own — it
    /// pastes straight into Explorer — and the mapped-drive command otherwise.
    pub(crate) fn for_this_os(&self) -> &str {
        if cfg!(target_os = "macos") {
            &self.macos
        } else if cfg!(windows) {
            if self.standard_port { &self.unc } else { &self.windows }
        } else {
            &self.linux
        }
    }
}

/// The snapshot currently in the share, and the lock that makes serving it
/// safe.
struct Shared {
    summary: SnapshotSummary,
    /// restic's non-exclusive repository lock (what `restic mount` takes),
    /// held for as long as the snapshot is in the share.
    lock: crate::lock::RepoLock,
}

/// A running SMB server whose root holds a README and, at most, one shared
/// snapshot's folder.
///
/// The server and the shared snapshot have separate lifetimes. The server is
/// turned on once and keeps its share name, port and password, so a client
/// mounts it once; snapshots are swapped in and out underneath without a
/// remount. The repository lock belongs to the shared snapshot, not the server:
/// a server holding only its README locks nothing.
///
/// Field order is drop order: the server goes before the shared snapshot's
/// lock, so the repository is never served unlocked. `Drop` also joins the
/// server thread, so a share dropped without `stop` (an early return, a panic
/// unwind) releases the lock only once nothing can read through it.
pub(crate) struct ShareServer {
    server: Option<smb::SmbHandle>,
    shared: Option<Shared>,
}

impl Drop for ShareServer {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.stop();
        }
        // `self.shared` drops after this, releasing its lock.
    }
}

impl ShareServer {
    /// Bind and start the server with nothing shared: its root holds only the
    /// README.
    pub(crate) fn start(port: u16, bind: Bind, credentials: Credentials) -> Result<Self> {
        // The library's own switch is `SMBANYTHING_LOG`; wrustic keeps the
        // environment variable its docs and harnesses have always used.
        if std::env::var_os("WRUSTIC_SMB_LOG").is_some() {
            smb::enable_log();
        }
        let server = smb::bind(port, DEFAULT_SHARE_NAME, bind, credentials)?.start()?;
        server.load(Arc::new(RootBacking::empty()));
        Ok(Self {
            server: Some(server),
            shared: None,
        })
    }

    fn server(&self) -> &smb::SmbHandle {
        self.server
            .as_ref()
            .expect("the server is only taken by Drop")
    }

    /// Put one snapshot from `profile`'s repository into the share, in place of
    /// whatever was shared before.
    ///
    /// The repository is opened synchronously, so a bad passphrase or an
    /// unreachable backend is reported to the caller rather than surfacing
    /// later as a folder that lists and then fails. It is opened afresh every
    /// time, never reused from an earlier share: the index in memory is a
    /// snapshot of the repository at open time, and a snapshot backed up since
    /// would reference packs it does not know.
    ///
    /// restic's non-exclusive lock is acquired before the index loads and
    /// before the snapshot is resolved. A repository locked exclusively (a
    /// running prune/forget) fails this with restic's "repository is already
    /// locked" error, and the share keeps what it had.
    ///
    /// The previous snapshot's lock is released only after the new contents
    /// are published, by which time the server guarantees no handle still
    /// reads the old ones.
    pub(crate) fn share_snapshot(
        &mut self,
        profile_name: &str,
        profile: &Profile,
        snapshot_id: &str,
    ) -> Result<()> {
        let (repo, lock) = crate::repo::open_indexed_full_shared_lock(profile)?;
        let repo = Arc::new(repo);
        let snap = repo
            .get_snapshot_from_str(snapshot_id, |_| true)
            .map_err(|e| anyhow!("looking up snapshot `{snapshot_id}`: {e}"))?;

        let id = snap.id.to_hex().as_str().to_string();
        // restic's standard short id (8 hex chars, `internal/restic/id.go`
        // shortStr) — the same form `restic snapshots` prints, so the folder
        // name pastes straight into other restic commands.
        let short_id = id.chars().take(8).collect::<String>();
        let summary = SnapshotSummary {
            short_id: short_id.clone(),
            id,
            repository_id: crate::repo::repository_id(repo.as_ref()),
            profile: profile_name.to_string(),
            time: snap.time.strftime("%Y-%m-%d %H:%M:%S").to_string(),
            host: snap.hostname.clone(),
            paths: snap.paths.iter().cloned().collect(),
            tags: snap.tags.iter().cloned().collect(),
        };
        // Label the volume with the short id too, so a client that has several
        // of these mounted can tell them apart.
        let label = format!("snap-{short_id}");
        // restic records the snapshot's byte count at backup time; using it
        // avoids a recursive walk and is exact.
        let total_size = snap.summary.as_ref().map(|s| s.total_bytes_processed);
        let backing = SnapshotBacking::new(repo, snap.tree, label, total_size)?;

        // Checked by the share itself on every request, so a lock that goes
        // bad takes the snapshot out at once even while the TUI is busy;
        // `lock_poisoned` lets the owner catch up and say so.
        let health = lock.health();
        self.server().load(Arc::new(RootBacking::with_snapshot(
            &summary,
            Arc::new(backing),
            Arc::new(move || health.poisoned()),
        )));
        // The old lock, if any, drops here — after `load` returned.
        self.shared = Some(Shared { summary, lock });
        Ok(())
    }

    /// Take the shared snapshot out, leaving the README, and release its
    /// repository lock. The server keeps running.
    pub(crate) fn unshare(&mut self) {
        self.server().load(Arc::new(RootBacking::empty()));
        self.shared = None;
    }

    /// What is shared right now, if anything.
    pub(crate) fn shared(&self) -> Option<&SnapshotSummary> {
        self.shared.as_ref().map(|s| &s.summary)
    }

    /// Windows UNC path, `\\host\share`.
    pub(crate) fn unc(&self) -> String {
        self.server().unc()
    }

    pub(crate) fn share_name(&self) -> &str {
        self.server().share_name()
    }

    /// Host and port a client mounts, as opposed to the bound listener.
    pub(crate) fn mount(&self) -> &smb::MountPoint {
        self.server().mount()
    }

    /// The port the SMB listener actually bound. Equal to the mount port for
    /// every transport except the tun, where it is the private loopback socket
    /// the proxy talks to — which is why nothing user-facing reads it, and only
    /// the `dev smb-serve` harness and the tests do.
    #[cfg_attr(not(any(test, feature = "dev-harness")), allow(dead_code))]
    pub(crate) fn port(&self) -> u16 {
        self.server().port()
    }

    /// Whether the share is reachable on SMB's standard port, and so mountable
    /// as a plain UNC path with no port option anywhere in the command.
    pub(crate) fn on_standard_port(&self) -> bool {
        self.server().on_standard_port()
    }

    /// How each client OS mounts this share, as shown on the share screen.
    /// Always the share itself, never a snapshot's folder inside it: the mount
    /// outlives any one snapshot. None carries the password: a password on a
    /// command line is readable by every process on the machine while the
    /// command runs, and stays in shell history after, so each one prompts for
    /// it instead.
    pub(crate) fn mount_commands(&self) -> MountCommands {
        let user = DEFAULT_SHARE_USER;
        let share = self.share_name();
        let host = self.mount().host();
        let port = self.mount().port();
        let unc = self.unc();
        // On the standard port there is no port option to carry, which is the
        // entire reason the tun exists.
        let (cifs_port, url_port, tcpport) = if self.on_standard_port() {
            (String::new(), String::new(), String::new())
        } else {
            (format!("port={port},"), format!(":{port}"), format!(" /TCPPORT:{port}"))
        };
        MountCommands {
            linux: format!(
                "sudo mount -t cifs -o {cifs_port}vers=2.1,username={user},ro,uid=$(id -u),gid=$(id -g),file_mode=0444,dir_mode=0555 //{host}/{share} /mnt/snap"
            ),
            macos: format!("smb://{user}@{host}{url_port}/{share}"),
            windows: format!("net use Z: {unc} * /user:{user}{tcpport}"),
            unc,
            standard_port: self.on_standard_port(),
        }
    }

    /// restic's abort-if-unrefreshable rule: true once the shared snapshot's
    /// lock went 22.5 minutes without a successful refresh, meaning other
    /// processes may already treat it as stale and remove it — at which point a
    /// concurrent prune could delete data mid-read. The owner must take the
    /// snapshot out of the share.
    pub(crate) fn lock_poisoned(&self) -> bool {
        self.shared.as_ref().is_some_and(|s| s.lock.poisoned())
    }

    /// True once refused logons since the last successful one have reached the
    /// server's limit. The server has already stopped accepting logons at this
    /// point; the owner is expected to stop it outright.
    pub(crate) fn logon_limit_reached(&self) -> bool {
        self.server().logon_limit_reached()
    }

    /// Refused logons since the last successful one, for the message the owner
    /// shows when it stops.
    pub(crate) fn failed_logons(&self) -> u32 {
        self.server().failed_logons()
    }

    /// Why the packet tunnel fronting this server stopped, once it has: the
    /// adapter was deleted or torn down under it, so nothing reaches the server
    /// any more and the owner is expected to stop it. Always `None` without a
    /// tunnel.
    pub(crate) fn tun_stopped(&self) -> Option<String> {
        self.server().tun_report().stopped
    }

    /// Stop the server, then release the shared snapshot's lock.
    pub(crate) fn stop(self) {
        // `Drop` does both, in that order.
        drop(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use backing::test_support::MemBacking;
    #[cfg(all(windows, feature = "smb-tun"))]
    use smbanything_core::smb::Backing;

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

        let handle = smb::bind(
            0,
            DEFAULT_SHARE_NAME,
            Bind::Tun(TunConfig {
                port: STANDARD_SMB_PORT,
                addrs,
            }),
            test_credentials(),
        )
        .and_then(smb::Bound::start)
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


    /// The share as one real client sees it, mounted once: the root lists the
    /// README beside the shared snapshot's short-id folder, the tree lives
    /// inside that folder, and on the same session — no reconnect — a replaced
    /// snapshot's folder gives way to the new one, and taking the snapshot out
    /// leaves the README alone.
    #[test]
    fn smbclient_sees_the_readme_and_the_shared_snapshot_folder() {
        use std::io::{Read, Write};
        use std::process::{Command, Stdio};
        use std::sync::Mutex;

        if ["smbclient", "stdbuf"]
            .iter()
            .any(|tool| Command::new(tool).arg("--version").output().is_err())
        {
            eprintln!("skipping: smbclient or stdbuf is not installed");
            return;
        }

        let summary = |short_id: &str| SnapshotSummary {
            id: format!("{short_id}5e6f"),
            short_id: short_id.into(),
            repository_id: "feedface".into(),
            profile: "laptop".into(),
            time: "2026-11-18 09:30:00".into(),
            host: "box".into(),
            paths: vec!["/docs".into()],
            tags: Vec::new(),
        };
        let snapshot = |short_id: &str, content: &[u8]| {
            RootBacking::with_snapshot(
                &summary(short_id),
                Arc::new(
                    MemBacking::new()
                        .with_dir("docs")
                        .with_file("docs\\readme.txt", content),
                ),
                Arc::new(|| false),
            )
        };
        let handle = smb::bind(0, DEFAULT_SHARE_NAME, Bind::Loopback, test_credentials())
            .and_then(smb::Bound::start)
            .expect("server starts");
        handle.load(Arc::new(snapshot("1a2b3c4d", b"first hello\n")));

        // Unbuffered both ways. Piped, smbclient would hold its answers back
        // until exit, and a buffered read would swallow the lines after the
        // first into a buffer its wait for more input never looks at.
        let mut client = Command::new("stdbuf")
            .args(["-i0", "-o0", "-e0", "smbclient"])
            .arg(format!("//127.0.0.1/{}", handle.share_name()))
            .args(["-p", &handle.port().to_string()])
            .args(["-U", &format!("{TEST_USER}%{TEST_PASSWORD}")])
            .arg("--option=client min protocol=SMB2_10")
            .arg("--option=client max protocol=SMB2_10")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("smbclient runs");
        let mut stdin = client.stdin.take().expect("stdin");
        let output = Arc::new(Mutex::new(String::new()));
        let reader = |mut pipe: Box<dyn Read + Send>| {
            let output = Arc::clone(&output);
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n @ 1..) = pipe.read(&mut buf) {
                    output.lock().unwrap().push_str(&String::from_utf8_lossy(&buf[..n]));
                }
            })
        };
        let readers = [
            reader(Box::new(client.stdout.take().expect("stdout"))),
            reader(Box::new(client.stderr.take().expect("stderr"))),
        ];
        // Runs `commands` in the open session and returns what they printed.
        // Each batch ends with `pwd`, which always answers, so its line marks
        // the batch done.
        const DONE: &str = "Current directory is";
        let mut batches = 0;
        let mut run = |commands: &str| {
            let start = output.lock().unwrap().len();
            batches += 1;
            writeln!(stdin, "{commands}\npwd").expect("smbclient takes commands");
            stdin.flush().expect("flush");
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            loop {
                let out = output.lock().unwrap();
                if out.matches(DONE).count() >= batches {
                    return out[start..].to_string();
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "smbclient never finished {commands:?}:\n{out}"
                );
                drop(out);
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        };

        let first = run("ls\ncd 1a2b3c4d\\docs\nls\ncd \\\nget 1a2b3c4d\\docs\\readme.txt /dev/stdout");
        handle.load(Arc::new(snapshot("9f8e7d6c", b"second hello\n")));
        let replaced = run("ls\nls 1a2b3c4d\\*\nget 9f8e7d6c\\docs\\readme.txt /dev/stdout");
        handle.load(Arc::new(RootBacking::empty()));
        let empty = run("ls\nget README.txt /dev/stdout");
        writeln!(stdin, "exit").expect("exit");
        drop(stdin);
        let status = client.wait().expect("smbclient exits");
        readers.into_iter().for_each(|r| r.join().expect("reader"));
        handle.stop();

        assert!(status.success(), "smbclient failed:\n{}", output.lock().unwrap());
        assert!(first.contains("README.txt"), "root must list the README:\n{first}");
        assert!(first.contains("1a2b3c4d"), "root must list the snapshot dir:\n{first}");
        assert!(first.contains("first hello"), "tree must be readable:\n{first}");
        assert!(replaced.contains("9f8e7d6c"), "the new snapshot dir must appear:\n{replaced}");
        assert!(replaced.contains("NT_STATUS_OBJECT"), "the old dir must be gone:\n{replaced}");
        assert!(replaced.contains("second hello"), "the new tree must be readable:\n{replaced}");
        assert!(empty.contains("No snapshot is shared"), "the README says so:\n{empty}");
        assert!(!empty.contains("9f8e7d6c"), "the snapshot dir must go:\n{empty}");
    }

    /// A shared snapshot holds restic's non-exclusive lock on its repository,
    /// and only while it is shared: an exclusive acquisition is blocked but a
    /// concurrent append lock (a backup) is not; taking the snapshot out, or
    /// stopping the server, releases the lock; a server sharing nothing locks
    /// nothing; and an existing exclusive lock refuses the share while leaving
    /// the server running. The repository is built in-process
    /// (src/testrepo.rs), so this needs no restic binary and no hand-seeded
    /// fixture directory.
    #[test]
    fn a_shared_snapshot_holds_restics_append_lock() {
        let _guard = crate::lock::test_acquire_guard();
        let fixture = crate::testrepo::TestRepo::init("share-lock");
        let snap_id = fixture.backup(&[("readme.txt", b"shared\n")], &[]);
        let profile = fixture.profile().clone();
        let (lock_backend, crypto) =
            crate::repo::lock_context(&profile).expect("lock context");
        let locks = || lock_backend.list().expect("list locks").len();
        assert_eq!(locks(), 0, "fixture repo must start unlocked");

        let mut server =
            ShareServer::start(0, Bind::Loopback, test_credentials()).expect("server starts");
        assert_eq!(locks(), 0, "a server sharing nothing must lock nothing");
        assert!(server.shared().is_none());

        server
            .share_snapshot("fixture", &profile, &snap_id)
            .expect("snapshot is shared");
        let shared = server.shared().expect("shared").clone();
        assert_eq!(shared.id, snap_id);
        assert_eq!(shared.short_id, &snap_id[..8]);
        assert_eq!(shared.profile, "fixture");
        let err = crate::lock::check_blocking_locks(lock_backend.as_ref(), &crypto, true)
            .unwrap_err();
        assert!(
            crate::lock::is_lock_error(&format!("{err:#}")),
            "a shared snapshot must block exclusive operations: {err:#}"
        );
        assert!(
            crate::lock::check_blocking_locks(lock_backend.as_ref(), &crypto, false).is_ok(),
            "a concurrent backup's append lock must not be blocked"
        );

        // Sharing it again swaps one lock for another; it never stacks.
        server
            .share_snapshot("fixture", &profile, &snap_id)
            .expect("snapshot is shared again");
        assert_eq!(locks(), 1, "the previous snapshot's lock must be released");

        server.unshare();
        assert_eq!(locks(), 0, "taking the snapshot out must release its lock");
        assert!(server.shared().is_none());

        server
            .share_snapshot("fixture", &profile, &snap_id)
            .expect("snapshot is shared");
        server.stop();
        assert_eq!(locks(), 0, "stopping the server must release the lock");

        // An exclusive holder (a prune in flight) refuses the snapshot, and the
        // server goes on serving its README.
        let mut server =
            ShareServer::start(0, Bind::Loopback, test_credentials()).expect("server starts");
        let held = crate::lock::RepoLock::acquire_exclusive(
            std::sync::Arc::clone(&lock_backend),
            crypto,
        )
        .expect("exclusive lock");
        let err = server
            .share_snapshot("fixture", &profile, &snap_id)
            .unwrap_err();
        assert!(
            crate::lock::is_lock_error(&format!("{err:#}")),
            "unexpected error: {err:#}"
        );
        assert!(server.shared().is_none());
        drop(held);
        server.stop();
    }
}
