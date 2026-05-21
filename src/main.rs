use std::time::Duration;

use anyhow::Result;
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, List, ListItem, ListState, Paragraph, Wrap},
};
use rustic_backend::BackendOptions;
use rustic_core::{Credentials, Repository, RepositoryOptions};

enum Screen {
    RepoPath,
    Password,
    Loading,
    Snapshots,
    Error(String),
}

struct SnapshotRow {
    short_id: String,
    time: String,
    host: String,
    tags: String,
    paths: String,
}

struct App {
    screen: Screen,
    repo_path: String,
    password: String,
    snapshots: Vec<SnapshotRow>,
    list_state: ListState,
    quit: bool,
}

impl App {
    fn new() -> Self {
        Self {
            screen: Screen::RepoPath,
            repo_path: String::new(),
            password: String::new(),
            snapshots: Vec::new(),
            list_state: ListState::default(),
            quit: false,
        }
    }

    fn handle_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }

        match &self.screen {
            Screen::RepoPath => match key.code {
                KeyCode::Enter => {
                    let trimmed = self.repo_path.trim().to_string();
                    if !trimmed.is_empty() {
                        self.repo_path = trimmed;
                        self.screen = Screen::Password;
                    }
                }
                KeyCode::Esc => self.quit = true,
                KeyCode::Backspace => {
                    self.repo_path.pop();
                }
                KeyCode::Char(c) => self.repo_path.push(c),
                _ => {}
            },
            Screen::Password => match key.code {
                KeyCode::Enter => self.screen = Screen::Loading,
                KeyCode::Esc => {
                    self.password.clear();
                    self.screen = Screen::RepoPath;
                }
                KeyCode::Backspace => {
                    self.password.pop();
                }
                KeyCode::Char(c) => self.password.push(c),
                _ => {}
            },
            Screen::Loading => {}
            Screen::Snapshots => match key.code {
                KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
                KeyCode::Down | KeyCode::Char('j') => self.list_state.select_next(),
                KeyCode::Up | KeyCode::Char('k') => self.list_state.select_previous(),
                KeyCode::Home | KeyCode::Char('g') => self.list_state.select(Some(0)),
                KeyCode::End | KeyCode::Char('G') => {
                    if !self.snapshots.is_empty() {
                        self.list_state.select(Some(self.snapshots.len() - 1));
                    }
                }
                _ => {}
            },
            Screen::Error(_) => {
                self.screen = Screen::RepoPath;
            }
        }
    }
}

fn main() -> Result<()> {
    let mut terminal = ratatui::init();
    let result = run(&mut terminal);
    ratatui::restore();
    result
}

fn run(terminal: &mut DefaultTerminal) -> Result<()> {
    let mut app = App::new();

    while !app.quit {
        terminal.draw(|f| render(f, &mut app))?;

        if matches!(app.screen, Screen::Loading) {
            // We just rendered the Loading screen; now do the blocking load.
            match load_snapshots(&app.repo_path, &app.password) {
                Ok(snaps) => {
                    app.snapshots = snaps;
                    if !app.snapshots.is_empty() {
                        app.list_state.select(Some(0));
                    }
                    app.screen = Screen::Snapshots;
                }
                Err(e) => {
                    app.password.clear();
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

fn load_snapshots(repo_path: &str, password: &str) -> Result<Vec<SnapshotRow>> {
    let backends = BackendOptions::default()
        .repository(repo_path)
        .to_backends()?;
    let repo_opts = RepositoryOptions::default();
    let creds = Credentials::password(password);
    let repo = Repository::new(&repo_opts, &backends)?.open(&creds)?;

    let mut snaps = repo.get_all_snapshots()?;
    snaps.sort_by(|a, b| a.time.cmp(&b.time));

    Ok(snaps
        .into_iter()
        .map(|s| SnapshotRow {
            short_id: s.id.to_string(),
            time: s
                .time
                .strftime("%Y-%m-%d %H:%M:%S")
                .to_string(),
            host: s.hostname.clone(),
            tags: s.tags.to_string(),
            paths: s.paths.to_string(),
        })
        .collect())
}

fn render(frame: &mut Frame, app: &mut App) {
    match &app.screen {
        Screen::RepoPath => render_input(
            frame,
            "Repository path",
            &app.repo_path,
            "Enter the local restic repository path, then press Enter (Esc to quit)",
        ),
        Screen::Password => {
            let masked = "*".repeat(app.password.chars().count());
            render_input(
                frame,
                "Password",
                &masked,
                "Enter the repository password, then press Enter (Esc to go back)",
            );
        }
        Screen::Loading => {
            let para = Paragraph::new("Opening repository and reading snapshots…")
                .block(Block::bordered().title("Loading"));
            frame.render_widget(para, frame.area());
        }
        Screen::Snapshots => render_snapshots(frame, app),
        Screen::Error(msg) => {
            let para = Paragraph::new(msg.as_str())
                .style(Style::new().fg(Color::Red))
                .wrap(Wrap { trim: false })
                .block(
                    Block::bordered()
                        .title("Error — press any key to retry"),
                );
            frame.render_widget(para, frame.area());
        }
    }
}

fn render_input(frame: &mut Frame, title: &str, value: &str, help: &str) {
    let [_top, input_area, help_area, _bottom] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(frame.area());

    let input = Paragraph::new(format!("{value}_"))
        .block(Block::bordered().title(title));
    frame.render_widget(input, input_area);

    let help = Paragraph::new(help).style(Style::new().fg(Color::DarkGray));
    frame.render_widget(help, help_area);
}

fn render_snapshots(frame: &mut Frame, app: &mut App) {
    let title = format!("Snapshots ({}) — j/k to move, q to quit", app.snapshots.len());
    let items: Vec<ListItem> = app
        .snapshots
        .iter()
        .map(|s| {
            let tags = if s.tags.is_empty() { String::new() } else { format!("[{}]", s.tags) };
            ListItem::new(format!(
                "{:<8}  {:<19}  {:<20}  {:<20}  {}",
                s.short_id, s.time, s.host, tags, s.paths
            ))
        })
        .collect();

    let list = List::new(items)
        .block(Block::bordered().title(title))
        .highlight_style(
            Style::new()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    frame.render_stateful_widget(list, frame.area(), &mut app.list_state);
}
