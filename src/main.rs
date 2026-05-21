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

use crate::app::{App, Screen};
use crate::cli::{USAGE, parse_cli};
use crate::repo::{load_snapshots, verify_profile};
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

        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            app.handle_key(key);
        }
    }
    Ok(())
}
