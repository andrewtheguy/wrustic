mod app;
mod automation;
mod cli;
mod config;
mod crypto;
#[cfg(feature = "dev-harness")]
mod devharness;
#[cfg(feature = "keychain")]
mod keychain;
mod lock;
mod passphrase;
mod repo;
mod restic;
mod s3_backend;
mod share;
mod smb;
// In-process repository fixtures for the tests that must not depend on a
// restic binary being installed.
#[cfg(test)]
mod testrepo;
mod ui;

use anyhow::Result;
use ratatui::{
    DefaultTerminal,
    crossterm::{
        self,
        event::{
            self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind,
            KeyModifiers,
        },
    },
};

use ratatui::widgets::TableState;

use crate::app::{App, BrowseFrame, Screen, UnlockReturn};
use crate::cli::{parse_cli, usage};
use crate::config::{ConfigLock, Paths};
use crate::repo::{
    ContentRow, delete_snapshot, diff_snapshots, edit_snapshot_tags, get_file_details, list_tree,
    load_snapshots,
    open_indexed, preview_snapshot_contents, snapshot_delete_info, snapshot_root_tree,
    unlock, verify_profile,
};
use crate::ui::render;

fn main() -> Result<()> {
    let cli = match parse_cli() {
        Ok(cli) => cli,
        Err(e) => {
            eprintln!("{e:#}");
            eprintln!("\n{}", usage());
            std::process::exit(2);
        }
    };
    if cli.show_version {
        println!("wrustic {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if cli.show_help {
        println!("{}", usage());
        return Ok(());
    }

    restic::set_cache_enabled(cli.restic_cache);

    // Dispatched before a config directory is resolved: a harness either writes
    // its own config or needs none at all.
    #[cfg(feature = "dev-harness")]
    if let Some(dev) = cli.dev {
        return devharness::run(dev);
    }

    // Headless subcommands never touch the terminal, and they read the config
    // without the exclusive directory lock — the TUI's atomic rename-on-save
    // means a concurrent reader only ever sees a complete config, so `env` in
    // a scheduled task keeps working while a TUI session is open.
    if let Some(command) = cli.command {
        let paths = config::paths(cli.config_dir)?;
        return automation::run(command, paths, cli.no_keychain);
    }

    #[cfg(feature = "keychain")]
    let no_keychain = cli.no_keychain || !keychain::init_store();
    #[cfg(not(feature = "keychain"))]
    let no_keychain = cli.no_keychain;

    // Take the config-directory lock before entering the alternate screen, so a
    // "second instance" refusal prints as plain text instead of flashing an
    // empty TUI first.
    let paths = config::paths(cli.config_dir)?;
    let config_lock = match config::acquire_lock(&paths) {
        Ok(lock) => lock,
        Err(e) => {
            eprintln!("{e:#}");
            std::process::exit(1);
        }
    };

    let mut terminal = ratatui::init();
    // `ratatui::init` installed its own panic hook just now — one that calls
    // `ratatui::restore()` unconditionally, any panic, any thread, before
    // chaining to whatever hook it found. Ours must go on *after* it, so ours
    // runs first and that restore happens only when we chain to it. Installed
    // the other way round, any background thread's panic would switch the
    // shell back to its own screen underneath the live TUI.
    install_panic_hook();
    // Enable mouse reporting after entering raw mode. With capture on,
    // terminals route clicks/scroll to us instead of doing native text
    // selection; users can hold Shift to bypass and select text.
    let mouse_enabled = !cli.no_mouse
        && crossterm::execute!(std::io::stdout(), EnableMouseCapture).is_ok();
    let result = run(
        &mut terminal,
        paths,
        config_lock,
        cli.port,
        cli.smb,
        no_keychain,
    );
    if mouse_enabled {
        let _ = crossterm::execute!(std::io::stdout(), DisableMouseCapture);
    }
    ratatui::restore();
    report_withheld_panics();
    result
}

/// Panic reports withheld from a live TUI, printed once the terminal is the
/// shell's again. Bounded because a pool that dies thread by thread produces
/// one apiece and they all say the same thing.
static WITHHELD_PANICS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
const MAX_WITHHELD_PANICS: usize = 4;

/// Keeps panics from writing over the alternate screen.
///
/// Nothing may be printed while the TUI owns the terminal: stderr goes to the
/// alternate screen in raw mode, where `\n` moves down a line without
/// returning to column 0, and the diff-based renderer only repaints cells
/// that changed — so a panic report staircases across the frame and stays
/// there. Whether the report is *wanted* is a separate question from whether
/// it can be shown, and the split is by thread:
///
/// * **The main thread.** The panic unwinds out of `main`, past the
///   `ratatui::restore()` at the end of it, so the terminal has to be handed
///   back here or the shell is left raw and on the alternate screen. The
///   process is going down; restore, then report as usual.
/// * **Any other thread.** The app survives, so the terminal must not be
///   touched — restoring it out from under a running TUI is precisely the
///   corruption this exists to prevent. Withhold the report until exit.
///
/// Must be installed after `ratatui::init()`: the hook taken here is then
/// ratatui's own — restore-then-report — and reaching it becomes this hook's
/// decision instead of the first thing that happens on every panic. The
/// explicit `restore()` before chaining is kept anyway, so handing the
/// terminal back does not silently hinge on what ratatui's hook happens to do.
fn install_panic_hook() {
    // Installed from `main`, so this is the main thread's id — unlike the
    // thread *name*, which any `thread::Builder` in any dependency can also
    // claim, an id compares equal only to the thread itself.
    let main_thread = std::thread::current().id();
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if std::thread::current().id() == main_thread {
            let _ = crossterm::execute!(std::io::stdout(), DisableMouseCapture);
            ratatui::restore();
            default_hook(info);
        } else {
            withhold_panic(info.to_string());
        }
    }));
}

fn withhold_panic(report: String) {
    let mut withheld = WITHHELD_PANICS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if withheld.len() < MAX_WITHHELD_PANICS {
        withheld.push(report);
    }
}

/// Reports what the hook could not print while the TUI was up. Called after
/// the terminal is restored, so a background thread's panic is still
/// diagnosable rather than merely silent.
fn report_withheld_panics() {
    let withheld = std::mem::take(
        &mut *WITHHELD_PANICS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    );
    for report in withheld {
        eprintln!("{report}");
    }
}

fn run(
    terminal: &mut DefaultTerminal,
    paths: Paths,
    config_lock: ConfigLock,
    server_port: u16,
    smb: cli::SmbOptions,
    no_keychain: bool,
) -> Result<()> {
    let mut app = App::boot(paths, config_lock, server_port, smb, no_keychain)?;

    while !app.quit {
        terminal.draw(|f| render(f, &mut app))?;

        if matches!(app.screen, Screen::Loading) {
            let idx = app.loading_index;
            let Some((_, profile)) = app.config.profile_at(idx) else {
                app.screen = Screen::Error("Selected profile no longer exists.".into());
                continue;
            };
            match load_snapshots(profile) {
                Ok(snaps) => {
                    app.snapshots = snaps;
                    let len = app.visible_snapshot_indices().len();
                    if len > 0 {
                        let idx = app
                            .post_delete_select
                            .map(|i| i.min(len - 1))
                            .unwrap_or(0);
                        app.list_state.select(Some(idx));
                    } else {
                        app.list_state.select(None);
                    }
                    app.post_delete_select = None;
                    app.screen = Screen::Snapshots;
                }
                Err(e) => {
                    app.screen = Screen::Error(format!("{e:#}"));
                }
            }
            continue;
        }

        // Drawn as "starting…" on the pass above; opening the repository reads
        // the full index, which is slow enough on a large remote repository to
        // look like a hang if the frame were not already on screen.
        if matches!(app.screen, Screen::SnapshotSmbStarting) {
            app.start_smb_share();
            continue;
        }

        if matches!(app.screen, Screen::PassphraseDerivingKey) {
            app.derive_passphrase_key();
            continue;
        }

        if matches!(app.screen, Screen::Verifying) {
            let profile = app.build_profile();
            match verify_profile(&profile) {
                Ok(()) => app.commit_profile(),
                Err(e) => app.screen = Screen::VerifyFailed(format!("{e:#}")),
            }
            continue;
        }

        if matches!(app.screen, Screen::OpeningSnapshot) {
            let idx = app.loading_index;
            let Some((_, profile)) = app.config.profile_at(idx) else {
                app.screen = Screen::Error("Selected profile no longer exists.".into());
                continue;
            };
            let snap_id = app.browse_snapshot_id.clone();
            let refresh_path = app.pending_refresh_path.take();
            match open_and_walk(profile, &snap_id, refresh_path.as_deref()) {
                Ok((repo, stack)) => {
                    app.repo_session = Some(repo);
                    app.browse_stack = stack;
                    app.screen = Screen::SnapshotContents;
                }
                Err(e) => {
                    app.repo_session = None;
                    app.browse_stack.clear();
                    app.screen = Screen::Error(format!("{e:#}"));
                }
            }
            continue;
        }

        if matches!(app.screen, Screen::SnapshotDeleteLoading) {
            let Some(snap_id) = app.delete_target.clone() else {
                app.screen = Screen::SnapshotDeleteError(
                    "No snapshot selected for deletion.".into(),
                );
                continue;
            };
            let idx = app.loading_index;
            let Some((_, profile)) = app.config.profile_at(idx) else {
                app.screen = Screen::SnapshotDeleteError(
                    "Selected profile no longer exists.".into(),
                );
                continue;
            };
            let limit = app.delete_preview_limit;
            let need_details = app.delete_info.is_none();
            let result = (|| -> anyhow::Result<_> {
                let repo = open_indexed(profile)?;
                let info = if need_details {
                    Some(snapshot_delete_info(&repo, &snap_id)?)
                } else {
                    None
                };
                let preview = preview_snapshot_contents(&repo, &snap_id, limit)?;
                Ok((info, preview))
            })();
            match result {
                Ok((info, preview)) => {
                    let has_entries = !preview.entries.is_empty();
                    if let Some(info) = info {
                        app.delete_info = Some(info);
                    }
                    app.delete_root_listing = Some(preview);
                    app.delete_preview_state = TableState::default();
                    if has_entries {
                        app.delete_preview_state.select(Some(0));
                    }
                    app.screen = Screen::SnapshotDeleteConfirm;
                }
                Err(e) => {
                    app.screen = Screen::SnapshotDeleteError(format!("{e:#}"));
                }
            }
            continue;
        }

        if matches!(app.screen, Screen::SnapshotDeleting) {
            let Some(snapshot_id) = app.delete_target.take() else {
                app.screen = Screen::SnapshotDeleteError(
                    "No snapshot selected for deletion.".into(),
                );
                continue;
            };
            let idx = app.loading_index;
            let Some((_, profile)) = app.config.profile_at(idx) else {
                app.screen = Screen::SnapshotDeleteError(
                    "Selected profile no longer exists.".into(),
                );
                continue;
            };
            match delete_snapshot(profile, &snapshot_id) {
                Ok(()) => {
                    app.post_delete_select = app.list_state.selected();
                    app.snapshots.clear();
                    app.screen = Screen::Loading;
                }
                Err(e) => {
                    // Keep the target so an `unlock`-and-retry from the error
                    // screen lands back on the same snapshot.
                    app.delete_target = Some(snapshot_id);
                    app.screen = Screen::SnapshotDeleteError(format!("{e:#}"));
                }
            }
            continue;
        }

        if matches!(app.screen, Screen::SnapshotTagSaving) {
            let (Some(snapshot_id), Some(tags)) =
                (app.tag_edit_target.clone(), app.tag_edit_pending.clone())
            else {
                app.screen =
                    Screen::SnapshotTagError("No snapshot selected for tag editing.".into());
                continue;
            };
            let idx = app.loading_index;
            let Some((_, profile)) = app.config.profile_at(idx) else {
                app.screen = Screen::SnapshotTagError("Selected profile no longer exists.".into());
                continue;
            };
            match edit_snapshot_tags(profile, &snapshot_id, &tags) {
                // Unchanged: nothing was written, the list is still accurate.
                Ok(None) => {
                    app.clear_tag_edit_scratch();
                    app.screen = Screen::Snapshots;
                }
                // The retag minted a new snapshot id — reload the list, keeping
                // the cursor where it was (same mechanism as after a delete).
                Ok(Some(_new_id)) => {
                    app.clear_tag_edit_scratch();
                    app.post_delete_select = app.list_state.selected();
                    app.snapshots.clear();
                    app.screen = Screen::Loading;
                }
                // Keep target and tags so an `unlock`-and-retry from the error
                // screen redoes the same edit.
                Err(e) => {
                    app.screen = Screen::SnapshotTagError(format!("{e:#}"));
                }
            }
            continue;
        }

        if matches!(app.screen, Screen::Unlocking) {
            // Which flow asked for the unlock decides where its outcome goes:
            // the SMB share retries its operation (a lock conflict is why `u`
            // was offered), the delete flow re-enters its confirmation.
            let return_to = std::mem::take(&mut app.unlock_return);
            let idx = app.loading_index;
            let Some((_, profile)) = app.config.profile_at(idx) else {
                let msg = "Selected profile no longer exists.".to_string();
                app.screen = match return_to {
                    UnlockReturn::Smb => {
                        app.smb_error = Some(msg);
                        Screen::SnapshotSmb
                    }
                    UnlockReturn::Delete => Screen::SnapshotDeleteError(msg),
                    UnlockReturn::TagEdit => Screen::SnapshotTagError(msg),
                };
                continue;
            };
            match unlock(profile) {
                Ok(_removed) => {
                    app.screen = match return_to {
                        UnlockReturn::Smb => Screen::SnapshotSmbStarting,
                        // Redo the same edit; target and tags survived the
                        // error screen.
                        UnlockReturn::TagEdit => Screen::SnapshotTagSaving,
                        // Re-enter the delete flow so details/preview are
                        // rebuilt and the confirmation is asked again; without
                        // a pending target there is nothing to retry, so just
                        // refresh the list.
                        UnlockReturn::Delete => {
                            app.delete_info = None;
                            if app.delete_target.is_some() {
                                Screen::SnapshotDeleteLoading
                            } else {
                                Screen::Loading
                            }
                        }
                    };
                }
                Err(e) => {
                    let msg = format!("unlock failed: {e:#}");
                    app.screen = match return_to {
                        UnlockReturn::Smb => {
                            app.smb_error = Some(msg);
                            Screen::SnapshotSmb
                        }
                        UnlockReturn::Delete => Screen::SnapshotDeleteError(msg),
                        UnlockReturn::TagEdit => Screen::SnapshotTagError(msg),
                    };
                }
            }
            continue;
        }

        if matches!(app.screen, Screen::SnapshotCompareLoading) {
            let first = app.compare_first_id.clone();
            let second = app.compare_second_id.clone();
            let idx = app.loading_index;
            let Some((_, profile)) = app.config.profile_at(idx) else {
                app.clear_compare_scratch();
                app.screen = Screen::Error("Selected profile no longer exists.".into());
                continue;
            };
            let (Some(first), Some(second)) = (first, second) else {
                app.clear_compare_scratch();
                app.screen =
                    Screen::Error("Compare flow lost a snapshot id mid-flight.".into());
                continue;
            };
            let diff_result = (|| {
                let repo = open_indexed(profile)?;
                diff_snapshots(&repo, &first, &second)
            })();
            match diff_result {
                Ok((sum, changes)) => {
                    let has_rows = !changes.is_empty();
                    app.compare_results = Some((sum, changes));
                    app.compare_results_state = TableState::default();
                    if has_rows {
                        app.compare_results_state.select(Some(0));
                    }
                    app.screen = Screen::SnapshotCompareResults;
                }
                Err(e) => {
                    app.clear_compare_scratch();
                    app.screen = Screen::Error(format!("{e:#}"));
                }
            }
            continue;
        }

        if matches!(app.screen, Screen::LoadingDir) {
            let Some((tree_id, name)) = app.pending_descend.take() else {
                app.screen = Screen::SnapshotContents;
                continue;
            };
            let Some(repo) = app.repo_session.as_ref() else {
                app.screen = Screen::Error("Repository session was dropped.".into());
                continue;
            };
            match list_tree(repo, tree_id) {
                Ok(items) => {
                    let (items, table_state) = with_parent(items);
                    app.browse_stack.push(BrowseFrame {
                        name,
                        tree_id,
                        items,
                        table_state,
                    });
                    app.screen = Screen::SnapshotContents;
                }
                Err(e) => {
                    app.repo_session = None;
                    app.browse_stack.clear();
                    app.screen = Screen::Error(format!("{e:#}"));
                }
            }
            continue;
        }

        if matches!(app.screen, Screen::LoadingFileDetails) {
            let Some((tree_id, name, full_path)) = app.pending_file_lookup.take() else {
                app.screen = Screen::SnapshotContents;
                continue;
            };
            let Some(repo) = app.repo_session.as_ref() else {
                app.screen = Screen::Error("Repository session was dropped.".into());
                continue;
            };
            match get_file_details(repo, tree_id, &name, full_path) {
                Ok(details) => {
                    app.file_details = Some(details);
                    app.screen = Screen::FileDetails;
                }
                Err(e) => {
                    app.screen = Screen::Error(format!("{e:#}"));
                }
            }
            continue;
        }

        if matches!(app.screen, Screen::PruneRunning) {
            if app.prune_rx.is_none() {
                let idx = app.loading_index;
                let Some((_, profile)) = app.config.profile_at(idx) else {
                    app.screen = Screen::PruneError("Selected profile no longer exists.".into());
                    continue;
                };
                let profile = profile.clone();
                let (tx, rx) = std::sync::mpsc::channel();
                let tracker = std::sync::Arc::new(restic::ChildTracker::default());
                let progress = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
                let worker_tracker = tracker.clone();
                let worker_progress = progress.clone();
                std::thread::spawn(move || {
                    let result = (|| -> Result<Vec<u8>> {
                        if let Err(e) = restic::detect() {
                            return Err(anyhow::anyhow!(e.user_message()));
                        }
                        // No `--json`: restic 0.19 has no JSON output for
                        // prune (the flag is accepted and ignored). The
                        // report is displayed verbatim, never parsed.
                        restic::run_unsticking_locks_streaming(
                            &profile,
                            &["prune"],
                            &worker_tracker,
                            &worker_progress,
                        )
                    })();
                    // The receiver is gone only if the app quit; nothing to do.
                    let _ = tx.send(result.map_err(|e| format!("{e:#}")));
                });
                app.prune_rx = Some(rx);
                app.prune_tracker = Some(tracker);
                app.prune_progress = Some(progress);
                app.prune_cancel_requested = false;
                app.prune_started = Some(std::time::Instant::now());
            }
            let rx = app.prune_rx.as_ref().expect("receiver set above");
            match rx.try_recv() {
                Ok(outcome) => {
                    let cancelled = app.prune_cancel_requested;
                    app.prune_rx = None;
                    app.prune_tracker = None;
                    app.prune_progress = None;
                    app.prune_cancel_requested = false;
                    app.prune_started = None;
                    app.prune_scroll = 0;
                    app.screen = match outcome {
                        // A cancel that raced restic's own finish is still a
                        // finish — the report is real either way.
                        Ok(stdout) => {
                            let report = String::from_utf8_lossy(&stdout).into_owned();
                            Screen::PruneDone(if report.trim().is_empty() {
                                "prune finished (restic produced no output)".into()
                            } else {
                                report
                            })
                        }
                        Err(msg) if cancelled => Screen::PruneError(format!(
                            "Prune cancelled — restic was interrupted before finishing.\n\n\
                             The repository stays valid: restic never removes data still \
                             in use, and the next prune redoes the remaining work.\n\n\
                             restic said: {msg}"
                        )),
                        Err(msg) => Screen::PruneError(msg),
                    };
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    // Wait briefly so the loop redraws the elapsed clock and
                    // streamed progress without spinning. Ctrl+C interrupts
                    // the restic child (safe: restic never removes data still
                    // in use); every other event is swallowed, with resize
                    // picked up by the redraw. A press that lands before the
                    // child exists (detect / the unstick pre-check) is
                    // latched by the tracker, and the runner refuses to
                    // spawn restic after it — the cancel lands either way.
                    if event::poll(std::time::Duration::from_millis(150))?
                        && let Event::Key(key) = event::read()?
                        && key.kind == KeyEventKind::Press
                        && key.modifiers.contains(KeyModifiers::CONTROL)
                        && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
                        && let Some(tracker) = &app.prune_tracker
                    {
                        tracker.interrupt();
                        app.prune_cancel_requested = true;
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    app.prune_rx = None;
                    app.prune_tracker = None;
                    app.prune_progress = None;
                    app.prune_started = None;
                    app.screen =
                        Screen::PruneError("prune worker exited without reporting".into());
                }
            }
            continue;
        }

        // A running SMB share holds a repo lock that refreshes on a background
        // thread; instead of blocking on input indefinitely, wake once a
        // second to enforce restic's refreshability rule — an unrefreshable
        // lock means the server must stop before other processes remove the
        // lock as stale and a prune deletes data mid-read.
        if matches!(app.screen, Screen::SnapshotSmb) && app.smb_handle.is_some() {
            if event::poll(std::time::Duration::from_secs(1))? {
                match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => app.handle_key(key),
                    Event::Mouse(m) => app.handle_mouse(m),
                    _ => {}
                }
            }
            // After every wakeup, not just the timeout: a steady stream of
            // events (scrolling, focus/resize churn) would otherwise starve
            // the poison check for as long as it kept arriving.
            app.poll_smb_lock();
            app.poll_smb_logons();
            continue;
        }

        // Idle: block on events and only break out (to redraw) for ones
        // that can change what's on screen. Ignoring focus/mouse/key-release
        // events keeps the terminal quiet when the app has nothing to do.
        loop {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    app.handle_key(key);
                    break;
                }
                Event::Mouse(m) => {
                    app.handle_mouse(m);
                    break;
                }
                Event::Resize(_, _) => break,
                _ => {}
            }
        }
    }
    Ok(())
}

fn open_and_walk(
    profile: &crate::config::Profile,
    snapshot_id: &str,
    refresh_path: Option<&[String]>,
) -> Result<(
    rustic_core::Repository<rustic_core::IndexedIdsStatus>,
    Vec<BrowseFrame>,
)> {
    let repo = open_indexed(profile)?;
    let root_tree = snapshot_root_tree(&repo, snapshot_id)?;
    let root_items = list_tree(&repo, root_tree)?;
    let (root_items, root_table_state) = with_parent(root_items);
    let mut stack = vec![BrowseFrame {
        name: String::new(),
        tree_id: root_tree,
        items: root_items,
        table_state: root_table_state,
    }];

    if let Some(path) = refresh_path {
        for name in path {
            let top = stack.last().expect("root frame present");
            let next = top
                .items
                .iter()
                .find(|row| row.name == *name && row.subtree.is_some())
                .map(|row| (row.subtree.unwrap(), row.name.clone()));
            match next {
                Some((tree_id, name)) => {
                    let items = list_tree(&repo, tree_id)?;
                    let (items, table_state) = with_parent(items);
                    stack.push(BrowseFrame {
                        name,
                        tree_id,
                        items,
                        table_state,
                    });
                }
                None => break,
            }
        }
    }

    Ok((repo, stack))
}

// Prepend a synthetic `..` row and pick a default selection: the first real
// entry if any, otherwise the `..` row itself.
fn with_parent(items: Vec<ContentRow>) -> (Vec<ContentRow>, TableState) {
    let mut out = Vec::with_capacity(items.len() + 1);
    out.push(ContentRow::parent());
    out.extend(items);
    let mut table_state = TableState::default();
    let initial = if out.len() > 1 { 1 } else { 0 };
    table_state.select(Some(initial));
    (out, table_state)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A dying thread pool withholds one report per worker and they all say
    // the same thing, so the buffer is capped rather than unbounded.
    #[test]
    fn withheld_reports_are_capped_and_drained_once() {
        WITHHELD_PANICS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();

        for i in 0..MAX_WITHHELD_PANICS * 3 {
            withhold_panic(format!("report {i}"));
        }
        assert_eq!(
            WITHHELD_PANICS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            MAX_WITHHELD_PANICS
        );

        report_withheld_panics();
        assert!(
            WITHHELD_PANICS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty(),
            "draining must empty the buffer, or a later call reprints it"
        );
    }
}
