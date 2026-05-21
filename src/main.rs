mod app;
mod cli;
mod config;
mod crypto;
mod repo;
mod ui;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use ratatui::{
    DefaultTerminal,
    crossterm::event::{self, Event, KeyEventKind},
};

use ratatui::widgets::ListState;

use crate::app::{App, BrowseFrame, Screen};
use crate::cli::{USAGE, parse_cli};
use crate::repo::{list_tree, load_snapshots, open_indexed, snapshot_root_tree, verify_profile};
use crate::ui::render;

fn main() -> Result<()> {
    let cli = match parse_cli() {
        Ok(cli) => cli,
        Err(e) => {
            eprintln!("{e:#}");
            eprintln!("\n{USAGE}");
            std::process::exit(2);
        }
    };
    if cli.show_help {
        println!("{USAGE}");
        return Ok(());
    }

    let mut terminal = ratatui::init();
    let result = run(&mut terminal, cli.config_dir);
    ratatui::restore();
    result
}

fn run(terminal: &mut DefaultTerminal, config_dir: Option<PathBuf>) -> Result<()> {
    let mut app = App::boot(config_dir)?;

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
                    if !app.snapshots.is_empty() {
                        app.list_state.select(Some(0));
                    }
                    app.screen = Screen::Snapshots;
                }
                Err(e) => {
                    app.screen = Screen::Error(format!("{e:#}"));
                }
            }
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
                    let mut list_state = ListState::default();
                    if !items.is_empty() {
                        list_state.select(Some(0));
                    }
                    app.browse_stack.push(BrowseFrame {
                        name,
                        items,
                        list_state,
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

        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            app.handle_key(key);
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
    let mut items = list_tree(&repo, root_tree)?;
    let mut list_state = ListState::default();
    if !items.is_empty() {
        list_state.select(Some(0));
    }
    let mut stack = vec![BrowseFrame {
        name: String::new(),
        items: std::mem::take(&mut items),
        list_state,
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
                    let mut ls = ListState::default();
                    if !items.is_empty() {
                        ls.select(Some(0));
                    }
                    stack.push(BrowseFrame {
                        name,
                        items,
                        list_state: ls,
                    });
                }
                None => break,
            }
        }
    }

    Ok((repo, stack))
}
