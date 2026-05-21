use std::collections::BTreeMap;
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

#[derive(Clone, Copy)]
enum BackendKind {
    Local,
    Rest,
    S3,
}

impl BackendKind {
    fn label(self) -> &'static str {
        match self {
            BackendKind::Local => "Local filesystem",
            BackendKind::Rest => "REST server",
            BackendKind::S3 => "S3 (any S3-compatible endpoint)",
        }
    }
}

const BACKEND_ORDER: [BackendKind; 3] = [BackendKind::Local, BackendKind::Rest, BackendKind::S3];

enum Screen {
    BackendChoice,
    LocalPath,
    RestUrl,
    S3Endpoint,
    S3Bucket,
    S3Region,
    S3AccessKey,
    S3SecretKey,
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
    backend_kind: BackendKind,
    backend_list: ListState,
    local_path: String,
    rest_url: String,
    s3_endpoint: String,
    s3_bucket: String,
    s3_region: String,
    s3_access_key: String,
    s3_secret_key: String,
    password: String,
    snapshots: Vec<SnapshotRow>,
    list_state: ListState,
    quit: bool,
}

impl App {
    fn new() -> Self {
        let mut backend_list = ListState::default();
        backend_list.select(Some(0));
        Self {
            screen: Screen::BackendChoice,
            backend_kind: BackendKind::Local,
            backend_list,
            local_path: String::new(),
            rest_url: String::new(),
            s3_endpoint: String::new(),
            s3_bucket: String::new(),
            s3_region: String::new(),
            s3_access_key: String::new(),
            s3_secret_key: String::new(),
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
            Screen::BackendChoice => match key.code {
                KeyCode::Down | KeyCode::Char('j') => self.backend_list.select_next(),
                KeyCode::Up | KeyCode::Char('k') => self.backend_list.select_previous(),
                KeyCode::Enter => {
                    let idx = self.backend_list.selected().unwrap_or(0).min(BACKEND_ORDER.len() - 1);
                    self.backend_kind = BACKEND_ORDER[idx];
                    self.screen = match self.backend_kind {
                        BackendKind::Local => Screen::LocalPath,
                        BackendKind::Rest => Screen::RestUrl,
                        BackendKind::S3 => Screen::S3Endpoint,
                    };
                }
                KeyCode::Esc => self.quit = true,
                _ => {}
            },

            Screen::LocalPath => match text_input(&mut self.local_path, key) {
                TextAction::Submit if !self.local_path.trim().is_empty() => {
                    self.local_path = self.local_path.trim().to_string();
                    self.screen = Screen::Password;
                }
                TextAction::Cancel => self.screen = Screen::BackendChoice,
                _ => {}
            },

            Screen::RestUrl => match text_input(&mut self.rest_url, key) {
                TextAction::Submit if !self.rest_url.trim().is_empty() => {
                    self.rest_url = self.rest_url.trim().to_string();
                    self.screen = Screen::Password;
                }
                TextAction::Cancel => self.screen = Screen::BackendChoice,
                _ => {}
            },

            Screen::S3Endpoint => match text_input(&mut self.s3_endpoint, key) {
                TextAction::Submit => {
                    self.s3_endpoint = self.s3_endpoint.trim().to_string();
                    self.screen = Screen::S3Bucket;
                }
                TextAction::Cancel => self.screen = Screen::BackendChoice,
                _ => {}
            },

            Screen::S3Bucket => match text_input(&mut self.s3_bucket, key) {
                TextAction::Submit if !self.s3_bucket.trim().is_empty() => {
                    self.s3_bucket = self.s3_bucket.trim().to_string();
                    self.screen = Screen::S3Region;
                }
                TextAction::Cancel => self.screen = Screen::S3Endpoint,
                _ => {}
            },

            Screen::S3Region => match text_input(&mut self.s3_region, key) {
                TextAction::Submit => {
                    self.s3_region = self.s3_region.trim().to_string();
                    self.screen = Screen::S3AccessKey;
                }
                TextAction::Cancel => self.screen = Screen::S3Bucket,
                _ => {}
            },

            Screen::S3AccessKey => match text_input(&mut self.s3_access_key, key) {
                TextAction::Submit if !self.s3_access_key.trim().is_empty() => {
                    self.s3_access_key = self.s3_access_key.trim().to_string();
                    self.screen = Screen::S3SecretKey;
                }
                TextAction::Cancel => self.screen = Screen::S3Region,
                _ => {}
            },

            Screen::S3SecretKey => match text_input(&mut self.s3_secret_key, key) {
                TextAction::Submit if !self.s3_secret_key.trim().is_empty() => {
                    self.s3_secret_key = self.s3_secret_key.trim().to_string();
                    self.screen = Screen::Password;
                }
                TextAction::Cancel => self.screen = Screen::S3AccessKey,
                _ => {}
            },

            Screen::Password => match text_input(&mut self.password, key) {
                TextAction::Submit => self.screen = Screen::Loading,
                TextAction::Cancel => {
                    self.password.clear();
                    self.screen = match self.backend_kind {
                        BackendKind::Local => Screen::LocalPath,
                        BackendKind::Rest => Screen::RestUrl,
                        BackendKind::S3 => Screen::S3SecretKey,
                    };
                }
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
                self.screen = Screen::BackendChoice;
                self.password.clear();
                self.s3_secret_key.clear();
            }
        }
    }

    fn build_backend_config(&self) -> BackendConfig {
        match self.backend_kind {
            BackendKind::Local => BackendConfig::Local {
                path: self.local_path.clone(),
            },
            BackendKind::Rest => BackendConfig::Rest {
                url: self.rest_url.clone(),
            },
            BackendKind::S3 => BackendConfig::S3 {
                endpoint: self.s3_endpoint.clone(),
                bucket: self.s3_bucket.clone(),
                region: if self.s3_region.is_empty() {
                    "us-east-1".into()
                } else {
                    self.s3_region.clone()
                },
                access_key: self.s3_access_key.clone(),
                secret_key: self.s3_secret_key.clone(),
            },
        }
    }
}

enum TextAction {
    None,
    Submit,
    Cancel,
}

fn text_input(buf: &mut String, key: KeyEvent) -> TextAction {
    match key.code {
        KeyCode::Enter => TextAction::Submit,
        KeyCode::Esc => TextAction::Cancel,
        KeyCode::Backspace => {
            buf.pop();
            TextAction::None
        }
        KeyCode::Char(c) => {
            buf.push(c);
            TextAction::None
        }
        _ => TextAction::None,
    }
}

enum BackendConfig {
    Local {
        path: String,
    },
    Rest {
        url: String,
    },
    S3 {
        endpoint: String,
        bucket: String,
        region: String,
        access_key: String,
        secret_key: String,
    },
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
            let cfg = app.build_backend_config();
            match load_snapshots(&cfg, &app.password) {
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

fn load_snapshots(cfg: &BackendConfig, password: &str) -> Result<Vec<SnapshotRow>> {
    let mut opts = BackendOptions::default();
    match cfg {
        BackendConfig::Local { path } => {
            opts = opts.repository(path.clone());
        }
        BackendConfig::Rest { url } => {
            opts = opts.repository(format!("rest:{url}"));
        }
        BackendConfig::S3 {
            endpoint,
            bucket,
            region,
            access_key,
            secret_key,
        } => {
            opts = opts.repository("opendal:s3:");
            let mut s3_opts = BTreeMap::new();
            s3_opts.insert("bucket".to_string(), bucket.clone());
            s3_opts.insert("region".to_string(), region.clone());
            s3_opts.insert("access_key_id".to_string(), access_key.clone());
            s3_opts.insert("secret_access_key".to_string(), secret_key.clone());
            if !endpoint.is_empty() {
                s3_opts.insert("endpoint".to_string(), endpoint.clone());
            }
            opts = opts.options(s3_opts);
        }
    }

    let backends = opts.to_backends()?;
    let repo = Repository::new(&RepositoryOptions::default(), &backends)?
        .open(&Credentials::password(password))?;

    let mut snaps = repo.get_all_snapshots()?;
    snaps.sort_by(|a, b| a.time.cmp(&b.time));

    Ok(snaps
        .into_iter()
        .map(|s| SnapshotRow {
            short_id: s.id.to_string(),
            time: s.time.strftime("%Y-%m-%d %H:%M:%S").to_string(),
            host: s.hostname.clone(),
            tags: s.tags.to_string(),
            paths: s.paths.to_string(),
        })
        .collect())
}

fn render(frame: &mut Frame, app: &mut App) {
    match &app.screen {
        Screen::BackendChoice => render_backend_choice(frame, app),
        Screen::LocalPath => render_input(
            frame,
            "Local repository path",
            &app.local_path,
            "Filesystem path, e.g. /tmp/wrustic-test-repo (Esc back)",
            false,
        ),
        Screen::RestUrl => render_input(
            frame,
            "REST URL",
            &app.rest_url,
            "e.g. http://localhost:8000/  or  https://user:pass@host/path/ (Esc back)",
            false,
        ),
        Screen::S3Endpoint => render_input(
            frame,
            "S3 endpoint (optional)",
            &app.s3_endpoint,
            "Leave blank for AWS. For MinIO / rclone: http://127.0.0.1:8333 (Esc back)",
            false,
        ),
        Screen::S3Bucket => render_input(
            frame,
            "S3 bucket",
            &app.s3_bucket,
            "Bucket / top-level directory name (Esc back)",
            false,
        ),
        Screen::S3Region => render_input(
            frame,
            "S3 region (optional)",
            &app.s3_region,
            "Defaults to us-east-1 if left blank (Esc back)",
            false,
        ),
        Screen::S3AccessKey => render_input(
            frame,
            "S3 access key ID",
            &app.s3_access_key,
            "AWS_ACCESS_KEY_ID equivalent (Esc back)",
            false,
        ),
        Screen::S3SecretKey => {
            let masked = "*".repeat(app.s3_secret_key.chars().count());
            render_input(
                frame,
                "S3 secret access key",
                &masked,
                "AWS_SECRET_ACCESS_KEY equivalent (Esc back)",
                true,
            );
        }
        Screen::Password => {
            let masked = "*".repeat(app.password.chars().count());
            render_input(
                frame,
                "Repository password",
                &masked,
                "Restic repository password (Esc back)",
                true,
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
                .block(Block::bordered().title("Error — press any key to start over"));
            frame.render_widget(para, frame.area());
        }
    }
}

fn render_backend_choice(frame: &mut Frame, app: &mut App) {
    let items: Vec<ListItem> = BACKEND_ORDER
        .iter()
        .map(|k| ListItem::new(k.label()))
        .collect();

    let list = List::new(items)
        .block(Block::bordered().title("Choose backend — j/k to move, Enter to pick, Esc/Ctrl-C to quit"))
        .highlight_style(
            Style::new()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    frame.render_stateful_widget(list, frame.area(), &mut app.backend_list);
}

fn render_input(frame: &mut Frame, title: &str, value: &str, help: &str, _masked: bool) {
    let [_top, input_area, help_area, _bottom] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(frame.area());

    let input = Paragraph::new(format!("{value}_")).block(Block::bordered().title(title));
    frame.render_widget(input, input_area);

    let help = Paragraph::new(help).style(Style::new().fg(Color::DarkGray));
    frame.render_widget(help, help_area);
}

fn render_snapshots(frame: &mut Frame, app: &mut App) {
    let title = format!(
        "Snapshots ({}) — j/k to move, q to quit",
        app.snapshots.len()
    );
    let items: Vec<ListItem> = app
        .snapshots
        .iter()
        .map(|s| {
            let tags = if s.tags.is_empty() {
                String::new()
            } else {
                format!("[{}]", s.tags)
            };
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
