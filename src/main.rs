mod config;
mod crypto;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, List, ListItem, ListState, Paragraph, Wrap},
};
use rustic_backend::BackendOptions;
use rustic_core::{Credentials, Repository, RepositoryOptions};

use crate::config::{BackendKind, Config, Paths, Profile};

const BACKEND_ORDER: [BackendKind; 3] = [BackendKind::Local, BackendKind::Rest, BackendKind::S3];
const MAIN_MENU: [&str; 3] = ["Work with a repo", "Manage profiles", "Quit"];
const MANAGE_MENU: [&str; 4] = [
    "Create new profile",
    "Edit a profile",
    "Delete a profile",
    "Back",
];
const FIRST_RUN_MENU: [&str; 3] = [
    "Create a new age key",
    "Restore an existing age key",
    "Quit",
];

enum Screen {
    FirstRunChoice,
    RestoreKeyWait,
    KeyCreated,
    MainMenu,
    SelectProfileForOpen,
    Snapshots,
    ManageMenu,
    CreateProfileName,
    BackendChoice,
    LocalPath,
    RestUrl,
    RestUser,
    RestPassword,
    S3Endpoint,
    S3Bucket,
    S3Region,
    S3AccessKey,
    S3SecretKey,
    Password,
    SelectProfileForDelete,
    SelectProfileForEdit,
    ConfirmDelete,
    Loading,
    Verifying,
    VerifyFailed(String),
    Error(String),
}

enum ProfileRollback {
    Pop,
    Replace(usize, Profile),
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

    paths: Paths,
    config: Config,

    first_run_state: ListState,
    main_menu_state: ListState,
    manage_menu_state: ListState,
    backend_list: ListState,
    profile_list_state: ListState,
    list_state: ListState,

    new_profile_name: String,
    backend_kind: BackendKind,
    local_path: String,
    rest_url: String,
    rest_user: String,
    rest_password: String,
    s3_endpoint: String,
    s3_bucket: String,
    s3_region: String,
    s3_access_key: String,
    s3_secret_key: String,
    password: String,

    loading_index: usize,
    pending_delete: Option<usize>,
    editing_index: Option<usize>,

    restore_error: Option<String>,
    created_pubkey: String,

    snapshots: Vec<SnapshotRow>,
    error_is_fatal: bool,
    quit: bool,
}

impl App {
    fn boot(config_dir: Option<PathBuf>) -> Result<Self> {
        let paths = config::paths(config_dir)?;
        let mut first_run_state = ListState::default();
        first_run_state.select(Some(0));
        let mut main_menu_state = ListState::default();
        main_menu_state.select(Some(0));
        let mut manage_menu_state = ListState::default();
        manage_menu_state.select(Some(0));
        let mut backend_list = ListState::default();
        backend_list.select(Some(0));

        let identity_exists = paths.identity.exists();
        let mut app = Self {
            screen: Screen::MainMenu,
            paths,
            config: Config::default(),
            first_run_state,
            main_menu_state,
            manage_menu_state,
            backend_list,
            profile_list_state: ListState::default(),
            list_state: ListState::default(),
            new_profile_name: String::new(),
            backend_kind: BackendKind::Local,
            local_path: String::new(),
            rest_url: String::new(),
            rest_user: String::new(),
            rest_password: String::new(),
            s3_endpoint: String::new(),
            s3_bucket: String::new(),
            s3_region: String::new(),
            s3_access_key: String::new(),
            s3_secret_key: String::new(),
            password: String::new(),
            loading_index: 0,
            pending_delete: None,
            editing_index: None,
            restore_error: None,
            created_pubkey: String::new(),
            snapshots: Vec::new(),
            error_is_fatal: false,
            quit: false,
        };

        if !identity_exists {
            app.screen = Screen::FirstRunChoice;
            return Ok(app);
        }

        app.load_config_or_set_fatal();
        Ok(app)
    }

    fn load_config_or_set_fatal(&mut self) {
        match config::load(&self.paths) {
            Ok(cfg) => {
                self.config = cfg;
                self.screen = Screen::MainMenu;
            }
            Err(e) => {
                self.error_is_fatal = true;
                self.screen = Screen::Error(format!("{e:#}"));
            }
        }
    }

    fn clear_creation_scratch(&mut self) {
        self.new_profile_name.clear();
        self.local_path.clear();
        self.rest_url.clear();
        self.rest_user.clear();
        self.rest_password.clear();
        self.s3_endpoint.clear();
        self.s3_bucket.clear();
        self.s3_region.clear();
        self.s3_access_key.clear();
        self.s3_secret_key.clear();
        self.password.clear();
        self.editing_index = None;
    }

    fn load_profile_into_scratch(&mut self, idx: usize) {
        let p = &self.config.profiles[idx];
        self.new_profile_name = p.name().to_string();
        self.password = p.password().to_string();
        self.backend_kind = p.backend_kind();
        self.local_path.clear();
        self.rest_url.clear();
        self.rest_user.clear();
        self.rest_password.clear();
        self.s3_endpoint.clear();
        self.s3_bucket.clear();
        self.s3_region.clear();
        self.s3_access_key.clear();
        self.s3_secret_key.clear();
        match p {
            Profile::Local { local_path, .. } => {
                self.local_path = local_path.clone();
            }
            Profile::Rest {
                rest_url,
                rest_user,
                rest_password,
                ..
            } => {
                self.rest_url = rest_url.clone();
                self.rest_user = rest_user.clone();
                self.rest_password = rest_password.clone();
            }
            Profile::S3 {
                s3_endpoint,
                s3_bucket,
                s3_region,
                s3_access_key,
                s3_secret_key,
                ..
            } => {
                self.s3_endpoint = s3_endpoint.clone();
                self.s3_bucket = s3_bucket.clone();
                self.s3_region = s3_region.clone();
                self.s3_access_key = s3_access_key.clone();
                self.s3_secret_key = s3_secret_key.clone();
            }
        }
    }

    fn build_profile(&self) -> Profile {
        let name = self.new_profile_name.clone();
        let password = self.password.clone();
        match self.backend_kind {
            BackendKind::Local => Profile::Local {
                name,
                password,
                local_path: self.local_path.clone(),
            },
            BackendKind::Rest => Profile::Rest {
                name,
                password,
                rest_url: self.rest_url.clone(),
                rest_user: self.rest_user.clone(),
                rest_password: self.rest_password.clone(),
            },
            BackendKind::S3 => Profile::S3 {
                name,
                password,
                s3_endpoint: self.s3_endpoint.clone(),
                s3_bucket: self.s3_bucket.clone(),
                s3_region: if self.s3_region.is_empty() {
                    "us-east-1".into()
                } else {
                    self.s3_region.clone()
                },
                s3_access_key: self.s3_access_key.clone(),
                s3_secret_key: self.s3_secret_key.clone(),
            },
        }
    }

    fn cancel_from_first_backend_input(&mut self) {
        if self.editing_index.is_some() {
            self.clear_creation_scratch();
            self.screen = Screen::ManageMenu;
        } else {
            self.screen = Screen::BackendChoice;
        }
    }

    fn commit_profile(&mut self) {
        let profile = self.build_profile();

        if self.editing_index.is_none() && self.config.has_profile(profile.name()) {
            self.screen = Screen::Error(format!(
                "A profile named '{}' already exists.",
                profile.name()
            ));
            return;
        }

        let restore = match self.editing_index {
            Some(idx) => ProfileRollback::Replace(
                idx,
                std::mem::replace(&mut self.config.profiles[idx], profile),
            ),
            None => {
                self.config.profiles.push(profile);
                ProfileRollback::Pop
            }
        };

        match config::save(&self.config, &self.paths) {
            Ok(()) => {
                self.clear_creation_scratch();
                self.screen = Screen::MainMenu;
            }
            Err(e) => {
                match restore {
                    ProfileRollback::Replace(idx, old) => {
                        self.config.profiles[idx] = old;
                    }
                    ProfileRollback::Pop => {
                        self.config.profiles.pop();
                    }
                }
                self.screen = Screen::Error(format!("Saving config failed: {e:#}"));
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }

        match &self.screen {
            Screen::FirstRunChoice => match key.code {
                KeyCode::Down | KeyCode::Char('j') => self.first_run_state.select_next(),
                KeyCode::Up | KeyCode::Char('k') => self.first_run_state.select_previous(),
                KeyCode::Esc => self.quit = true,
                KeyCode::Enter => match self.first_run_state.selected().unwrap_or(0) {
                    0 => match config::generate_identity(&self.paths.identity) {
                        Ok(pubkey) => {
                            self.created_pubkey = pubkey;
                            self.screen = Screen::KeyCreated;
                        }
                        Err(e) => {
                            self.error_is_fatal = true;
                            self.screen = Screen::Error(format!("{e:#}"));
                        }
                    },
                    1 => {
                        self.restore_error = None;
                        self.screen = Screen::RestoreKeyWait;
                    }
                    _ => self.quit = true,
                },
                _ => {}
            },

            Screen::RestoreKeyWait => match key.code {
                KeyCode::Esc => {
                    self.restore_error = None;
                    self.screen = Screen::FirstRunChoice;
                }
                KeyCode::Enter => {
                    if !self.paths.identity.exists() {
                        self.restore_error = Some(format!(
                            "No file found at {}. Place your age.key there, then press Enter.",
                            self.paths.identity.display()
                        ));
                    } else {
                        match config::validate_identity(&self.paths.identity) {
                            Ok(_) => {
                                self.restore_error = None;
                                self.load_config_or_set_fatal();
                            }
                            Err(e) => {
                                self.restore_error = Some(format!(
                                    "Could not read identity at {}: {e:#}",
                                    self.paths.identity.display()
                                ));
                            }
                        }
                    }
                }
                _ => {}
            },

            Screen::KeyCreated => match key.code {
                KeyCode::Enter => {
                    self.created_pubkey.clear();
                    self.load_config_or_set_fatal();
                }
                KeyCode::Esc => self.quit = true,
                _ => {}
            },

            Screen::MainMenu => match key.code {
                KeyCode::Down | KeyCode::Char('j') => self.main_menu_state.select_next(),
                KeyCode::Up | KeyCode::Char('k') => self.main_menu_state.select_previous(),
                KeyCode::Esc | KeyCode::Char('q') => self.quit = true,
                KeyCode::Enter => match self.main_menu_state.selected().unwrap_or(0) {
                    0 => {
                        self.profile_list_state.select(Some(0));
                        self.screen = Screen::SelectProfileForOpen;
                    }
                    1 => {
                        self.manage_menu_state.select(Some(0));
                        self.screen = Screen::ManageMenu;
                    }
                    _ => self.quit = true,
                },
                _ => {}
            },

            Screen::SelectProfileForOpen => match key.code {
                KeyCode::Down | KeyCode::Char('j') => self.profile_list_state.select_next(),
                KeyCode::Up | KeyCode::Char('k') => self.profile_list_state.select_previous(),
                KeyCode::Esc => self.screen = Screen::MainMenu,
                KeyCode::Enter if !self.config.profiles.is_empty() => {
                    let idx = self
                        .profile_list_state
                        .selected()
                        .unwrap_or(0)
                        .min(self.config.profiles.len() - 1);
                    self.loading_index = idx;
                    self.screen = Screen::Loading;
                }
                _ => {}
            },

            Screen::Snapshots => match key.code {
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.snapshots.clear();
                    self.screen = Screen::MainMenu;
                }
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

            Screen::ManageMenu => match key.code {
                KeyCode::Down | KeyCode::Char('j') => self.manage_menu_state.select_next(),
                KeyCode::Up | KeyCode::Char('k') => self.manage_menu_state.select_previous(),
                KeyCode::Esc => self.screen = Screen::MainMenu,
                KeyCode::Enter => match self.manage_menu_state.selected().unwrap_or(0) {
                    0 => {
                        self.clear_creation_scratch();
                        self.screen = Screen::CreateProfileName;
                    }
                    1 => {
                        self.profile_list_state.select(Some(0));
                        self.screen = Screen::SelectProfileForEdit;
                    }
                    2 => {
                        self.profile_list_state.select(Some(0));
                        self.screen = Screen::SelectProfileForDelete;
                    }
                    _ => self.screen = Screen::MainMenu,
                },
                _ => {}
            },

            Screen::CreateProfileName => match text_input(&mut self.new_profile_name, key) {
                TextAction::Submit => {
                    let name = self.new_profile_name.trim().to_string();
                    if name.is_empty() {
                        return;
                    }
                    if self.config.has_profile(&name) {
                        self.screen = Screen::Error(format!(
                            "A profile named '{name}' already exists."
                        ));
                        return;
                    }
                    self.new_profile_name = name;
                    self.backend_list.select(Some(0));
                    self.screen = Screen::BackendChoice;
                }
                TextAction::Cancel => {
                    self.clear_creation_scratch();
                    self.screen = Screen::ManageMenu;
                }
                _ => {}
            },

            Screen::BackendChoice => match key.code {
                KeyCode::Down | KeyCode::Char('j') => self.backend_list.select_next(),
                KeyCode::Up | KeyCode::Char('k') => self.backend_list.select_previous(),
                KeyCode::Enter => {
                    let idx = self
                        .backend_list
                        .selected()
                        .unwrap_or(0)
                        .min(BACKEND_ORDER.len() - 1);
                    self.backend_kind = BACKEND_ORDER[idx];
                    self.screen = match self.backend_kind {
                        BackendKind::Local => Screen::LocalPath,
                        BackendKind::Rest => Screen::RestUrl,
                        BackendKind::S3 => Screen::S3Endpoint,
                    };
                }
                KeyCode::Esc => self.screen = Screen::CreateProfileName,
                _ => {}
            },

            Screen::LocalPath => match text_input(&mut self.local_path, key) {
                TextAction::Submit if !self.local_path.trim().is_empty() => {
                    self.local_path = self.local_path.trim().to_string();
                    self.screen = Screen::Password;
                }
                TextAction::Cancel => self.cancel_from_first_backend_input(),
                _ => {}
            },

            Screen::RestUrl => match text_input(&mut self.rest_url, key) {
                TextAction::Submit if !self.rest_url.trim().is_empty() => {
                    self.rest_url = self.rest_url.trim().to_string();
                    self.screen = Screen::RestUser;
                }
                TextAction::Cancel => self.cancel_from_first_backend_input(),
                _ => {}
            },

            Screen::RestUser => match text_input(&mut self.rest_user, key) {
                TextAction::Submit => {
                    self.rest_user = self.rest_user.trim().to_string();
                    self.screen = Screen::RestPassword;
                }
                TextAction::Cancel => self.screen = Screen::RestUrl,
                _ => {}
            },

            Screen::RestPassword => match text_input(&mut self.rest_password, key) {
                TextAction::Submit => {
                    self.screen = Screen::Password;
                }
                TextAction::Cancel => self.screen = Screen::RestUser,
                _ => {}
            },

            Screen::S3Endpoint => match text_input(&mut self.s3_endpoint, key) {
                TextAction::Submit => {
                    self.s3_endpoint = self.s3_endpoint.trim().to_string();
                    self.screen = Screen::S3Bucket;
                }
                TextAction::Cancel => self.cancel_from_first_backend_input(),
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
                TextAction::Submit if !self.password.is_empty() => {
                    self.screen = Screen::Verifying;
                }
                TextAction::Cancel => {
                    self.password.clear();
                    self.screen = match self.backend_kind {
                        BackendKind::Local => Screen::LocalPath,
                        BackendKind::Rest => Screen::RestPassword,
                        BackendKind::S3 => Screen::S3SecretKey,
                    };
                }
                _ => {}
            },

            Screen::SelectProfileForDelete => match key.code {
                KeyCode::Down | KeyCode::Char('j') => self.profile_list_state.select_next(),
                KeyCode::Up | KeyCode::Char('k') => self.profile_list_state.select_previous(),
                KeyCode::Esc => self.screen = Screen::ManageMenu,
                KeyCode::Enter if !self.config.profiles.is_empty() => {
                    let idx = self
                        .profile_list_state
                        .selected()
                        .unwrap_or(0)
                        .min(self.config.profiles.len() - 1);
                    self.pending_delete = Some(idx);
                    self.screen = Screen::ConfirmDelete;
                }
                _ => {}
            },

            Screen::SelectProfileForEdit => match key.code {
                KeyCode::Down | KeyCode::Char('j') => self.profile_list_state.select_next(),
                KeyCode::Up | KeyCode::Char('k') => self.profile_list_state.select_previous(),
                KeyCode::Esc => self.screen = Screen::ManageMenu,
                KeyCode::Enter if !self.config.profiles.is_empty() => {
                    let idx = self
                        .profile_list_state
                        .selected()
                        .unwrap_or(0)
                        .min(self.config.profiles.len() - 1);
                    self.load_profile_into_scratch(idx);
                    self.editing_index = Some(idx);
                    self.screen = match self.backend_kind {
                        BackendKind::Local => Screen::LocalPath,
                        BackendKind::Rest => Screen::RestUrl,
                        BackendKind::S3 => Screen::S3Endpoint,
                    };
                }
                _ => {}
            },

            Screen::ConfirmDelete => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    if let Some(idx) = self.pending_delete.take() {
                        if idx < self.config.profiles.len() {
                            let removed = self.config.profiles.remove(idx);
                            match config::save(&self.config, &self.paths) {
                                Ok(()) => self.screen = Screen::MainMenu,
                                Err(e) => {
                                    self.config.profiles.insert(idx, removed);
                                    self.screen =
                                        Screen::Error(format!("Saving config failed: {e:#}"));
                                }
                            }
                        } else {
                            self.screen = Screen::ManageMenu;
                        }
                    } else {
                        self.screen = Screen::ManageMenu;
                    }
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.pending_delete = None;
                    self.screen = Screen::SelectProfileForDelete;
                }
                _ => {}
            },

            Screen::Loading | Screen::Verifying => {}

            Screen::VerifyFailed(_) => match key.code {
                KeyCode::Char('r') | KeyCode::Char('R') => {
                    self.screen = match self.backend_kind {
                        BackendKind::Local => Screen::LocalPath,
                        BackendKind::Rest => Screen::RestUrl,
                        BackendKind::S3 => Screen::S3Endpoint,
                    };
                }
                KeyCode::Char('s') | KeyCode::Char('S') => {
                    self.commit_profile();
                }
                KeyCode::Esc => {
                    self.clear_creation_scratch();
                    self.screen = Screen::ManageMenu;
                }
                _ => {}
            },

            Screen::Error(_) => {
                if self.error_is_fatal {
                    self.quit = true;
                } else {
                    self.screen = Screen::MainMenu;
                }
            }
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

const USAGE: &str = "\
Usage: wrustic [OPTIONS]

Options:
  -c, --config-dir <PATH>  Use <PATH> as the wrustic config directory instead
                           of the platform default (~/.config/wrustic on Linux).
                           The directory will be created on first run.
  -h, --help               Print this help text.
";

#[derive(Default)]
struct Cli {
    config_dir: Option<PathBuf>,
    show_help: bool,
}

fn parse_cli() -> Result<Cli> {
    let mut cli = Cli::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => cli.show_help = true,
            "-c" | "--config-dir" => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("{arg} requires a path argument"))?;
                cli.config_dir = Some(PathBuf::from(value));
            }
            other if other.starts_with("--config-dir=") => {
                cli.config_dir = Some(PathBuf::from(&other["--config-dir=".len()..]));
            }
            other => bail!("unknown argument: {other}"),
        }
    }
    Ok(cli)
}

fn run(terminal: &mut DefaultTerminal, config_dir: Option<PathBuf>) -> Result<()> {
    let mut app = App::boot(config_dir)?;

    while !app.quit {
        terminal.draw(|f| render(f, &mut app))?;

        if matches!(app.screen, Screen::Loading) {
            let idx = app.loading_index;
            let profile = &app.config.profiles[idx];
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

fn build_backend_opts(profile: &Profile) -> Result<BackendOptions> {
    let mut opts = BackendOptions::default();
    match profile {
        Profile::Local { local_path, .. } => {
            opts = opts.repository(local_path.clone());
        }
        Profile::Rest {
            rest_url,
            rest_user,
            rest_password,
            ..
        } => {
            let mut url = url::Url::parse(rest_url)
                .with_context(|| format!("parsing REST URL `{rest_url}`"))?;
            if rest_user.is_empty() && !rest_password.is_empty() {
                bail!("REST profile has a password but no username");
            }
            if !rest_user.is_empty() {
                url.set_username(rest_user)
                    .map_err(|_| anyhow!("REST URL `{rest_url}` cannot carry a username"))?;
            }
            if !rest_password.is_empty() {
                url.set_password(Some(rest_password))
                    .map_err(|_| anyhow!("REST URL `{rest_url}` cannot carry a password"))?;
            }
            opts = opts.repository(format!("rest:{url}"));
        }
        Profile::S3 {
            s3_endpoint,
            s3_bucket,
            s3_region,
            s3_access_key,
            s3_secret_key,
            ..
        } => {
            opts = opts.repository("opendal:s3:");
            let mut s3_opts = BTreeMap::new();
            s3_opts.insert("bucket".to_string(), s3_bucket.clone());
            s3_opts.insert("region".to_string(), s3_region.clone());
            s3_opts.insert("access_key_id".to_string(), s3_access_key.clone());
            s3_opts.insert("secret_access_key".to_string(), s3_secret_key.clone());
            if !s3_endpoint.is_empty() {
                s3_opts.insert("endpoint".to_string(), s3_endpoint.clone());
            }
            opts = opts.options(s3_opts);
        }
    }
    Ok(opts)
}

fn verify_profile(profile: &Profile) -> Result<()> {
    let backends = build_backend_opts(profile)?.to_backends()?;
    Repository::new(&RepositoryOptions::default(), &backends)?
        .open(&Credentials::password(profile.password()))?;
    Ok(())
}

fn load_snapshots(profile: &Profile) -> Result<Vec<SnapshotRow>> {
    let backends = build_backend_opts(profile)?.to_backends()?;
    let repo = Repository::new(&RepositoryOptions::default(), &backends)?
        .open(&Credentials::password(profile.password()))?;

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
        Screen::FirstRunChoice => render_first_run_choice(frame, app),
        Screen::RestoreKeyWait => render_restore_wait(frame, app),
        Screen::KeyCreated => render_key_created(frame, app),
        Screen::MainMenu => render_menu(frame, app, MainOrManage::Main),
        Screen::SelectProfileForOpen => {
            render_profile_list(frame, app, "Select profile to open (Esc back)")
        }
        Screen::SelectProfileForDelete => {
            render_profile_list(frame, app, "Select profile to delete (Esc back)")
        }
        Screen::SelectProfileForEdit => {
            render_profile_list(frame, app, "Select profile to edit (Esc back)")
        }
        Screen::ManageMenu => render_menu(frame, app, MainOrManage::Manage),
        Screen::CreateProfileName => render_input(
            frame,
            "Profile name",
            &app.new_profile_name,
            "Give this profile a short name, e.g. 'laptop-local' (Esc cancels)",
        ),
        Screen::BackendChoice => render_backend_choice(frame, app),
        Screen::LocalPath => render_input(
            frame,
            "Local repository path",
            &app.local_path,
            "Filesystem path, e.g. /tmp/wrustic-test-repo (Esc back)",
        ),
        Screen::RestUrl => render_input(
            frame,
            "REST URL",
            &app.rest_url,
            "e.g. http://localhost:8000/ — credentials go on the next two screens (Esc back)",
        ),
        Screen::RestUser => render_input(
            frame,
            "REST username (optional)",
            &app.rest_user,
            "Leave blank for anonymous REST server (Esc back)",
        ),
        Screen::RestPassword => {
            let masked = "*".repeat(app.rest_password.chars().count());
            render_input(
                frame,
                "REST password (optional)",
                &masked,
                "Leave blank if the REST server has no password (Esc back)",
            );
        }
        Screen::S3Endpoint => render_input(
            frame,
            "S3 endpoint (optional)",
            &app.s3_endpoint,
            "Leave blank for AWS. For MinIO / rclone: http://127.0.0.1:8333 (Esc back)",
        ),
        Screen::S3Bucket => render_input(
            frame,
            "S3 bucket",
            &app.s3_bucket,
            "Bucket / top-level directory name (Esc back)",
        ),
        Screen::S3Region => render_input(
            frame,
            "S3 region (optional)",
            &app.s3_region,
            "Defaults to us-east-1 if left blank (Esc back)",
        ),
        Screen::S3AccessKey => render_input(
            frame,
            "S3 access key ID",
            &app.s3_access_key,
            "AWS_ACCESS_KEY_ID equivalent (Esc back)",
        ),
        Screen::S3SecretKey => {
            let masked = "*".repeat(app.s3_secret_key.chars().count());
            render_input(
                frame,
                "S3 secret access key",
                &masked,
                "AWS_SECRET_ACCESS_KEY equivalent (Esc back)",
            );
        }
        Screen::Password => {
            let masked = "*".repeat(app.password.chars().count());
            render_input(
                frame,
                "Repository password",
                &masked,
                "Restic repository password (Esc back; profile saves on Enter)",
            );
        }
        Screen::ConfirmDelete => {
            let name = app
                .pending_delete
                .and_then(|i| app.config.profiles.get(i))
                .map(|p| p.name())
                .unwrap_or("(unknown)");
            let body = format!("Delete profile '{name}'? Press y to confirm, n/Esc to cancel.");
            let para = Paragraph::new(body)
                .style(Style::new().fg(Color::Yellow))
                .block(Block::bordered().title("Confirm delete"));
            frame.render_widget(para, frame.area());
        }
        Screen::Loading => {
            let para = Paragraph::new("Opening repository and reading snapshots…")
                .block(Block::bordered().title("Loading"));
            frame.render_widget(para, frame.area());
        }
        Screen::Verifying => {
            let para = Paragraph::new("Verifying profile — opening repository with the entered credentials…")
                .wrap(Wrap { trim: false })
                .block(Block::bordered().title("Verifying"));
            frame.render_widget(para, frame.area());
        }
        Screen::VerifyFailed(msg) => {
            let body = format!(
                "Could not open the repository with this profile:\n\n{msg}\n\nPress r to re-enter the fields, s to save the profile anyway, or Esc to discard it.",
            );
            let para = Paragraph::new(body)
                .style(Style::new().fg(Color::Yellow))
                .wrap(Wrap { trim: false })
                .block(Block::bordered().title("Verification failed"));
            frame.render_widget(para, frame.area());
        }
        Screen::Snapshots => render_snapshots(frame, app),
        Screen::Error(msg) => {
            let title = if app.error_is_fatal {
                "Error — press any key to quit"
            } else {
                "Error — press any key to return to menu"
            };
            let para = Paragraph::new(msg.as_str())
                .style(Style::new().fg(Color::Red))
                .wrap(Wrap { trim: false })
                .block(Block::bordered().title(title));
            frame.render_widget(para, frame.area());
        }
    }
}

fn render_first_run_choice(frame: &mut Frame, app: &mut App) {
    let [intro_area, list_area] = Layout::vertical([
        Constraint::Length(5),
        Constraint::Fill(1),
    ])
    .areas(frame.area());

    let intro = Paragraph::new(format!(
        "No age identity found at {}.\n\nEither restore an existing key to that path, or create a new one. Without a key, wrustic cannot decrypt or save profiles.",
        app.paths.identity.display()
    ))
    .wrap(Wrap { trim: false })
    .block(Block::bordered().title("Welcome to wrustic"));
    frame.render_widget(intro, intro_area);

    let items: Vec<ListItem> = FIRST_RUN_MENU.iter().map(|s| ListItem::new(*s)).collect();
    let list = List::new(items)
        .block(Block::bordered().title("j/k to move, Enter to pick, Esc to quit"))
        .highlight_style(
            Style::new()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");
    frame.render_stateful_widget(list, list_area, &mut app.first_run_state);
}

fn render_restore_wait(frame: &mut Frame, app: &App) {
    let mut body = format!(
        "Place your existing age.key file at:\n\n    {}\n\nMake sure it is mode 0600 (only readable by you). Press Enter once it is in place, or Esc to go back.",
        app.paths.identity.display()
    );
    if let Some(msg) = &app.restore_error {
        body.push_str("\n\n");
        body.push_str(msg);
    }
    let style = if app.restore_error.is_some() {
        Style::new().fg(Color::Red)
    } else {
        Style::new()
    };
    let para = Paragraph::new(body)
        .style(style)
        .wrap(Wrap { trim: false })
        .block(Block::bordered().title("Restore existing age key"));
    frame.render_widget(para, frame.area());
}

fn render_key_created(frame: &mut Frame, app: &App) {
    let body = format!(
        "A new age key was created.\n\nKey file (back this up now!):\n    {}\n\nPublic key (recipient):\n    {}\n\nIf you lose the key file, every saved profile becomes unrecoverable. Copy it to a safe place before adding profiles.\n\nPress Enter to continue.",
        app.paths.identity.display(),
        app.created_pubkey,
    );
    let para = Paragraph::new(body)
        .wrap(Wrap { trim: false })
        .block(Block::bordered().title("New age key created"));
    frame.render_widget(para, frame.area());
}

enum MainOrManage {
    Main,
    Manage,
}

fn render_menu(frame: &mut Frame, app: &mut App, which: MainOrManage) {
    let (entries, state, title) = match which {
        MainOrManage::Main => (
            &MAIN_MENU[..],
            &mut app.main_menu_state,
            "wrustic — j/k to move, Enter to pick, q/Esc to quit",
        ),
        MainOrManage::Manage => (
            &MANAGE_MENU[..],
            &mut app.manage_menu_state,
            "Manage profiles — j/k to move, Enter to pick, Esc back",
        ),
    };
    let items: Vec<ListItem> = entries.iter().map(|s| ListItem::new(*s)).collect();
    let list = List::new(items)
        .block(Block::bordered().title(title))
        .highlight_style(
            Style::new()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");
    frame.render_stateful_widget(list, frame.area(), state);
}

fn render_profile_list(frame: &mut Frame, app: &mut App, title: &str) {
    if app.config.profiles.is_empty() {
        let para = Paragraph::new(
            "No profiles yet. Go back (Esc) and choose 'Manage profiles' → 'Create new profile'.",
        )
        .wrap(Wrap { trim: false })
        .block(Block::bordered().title(title));
        frame.render_widget(para, frame.area());
        return;
    }

    let items: Vec<ListItem> = app
        .config
        .profiles
        .iter()
        .map(|p| ListItem::new(format!("{:<24} [{}]", p.name(), p.backend_kind().label())))
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

    frame.render_stateful_widget(list, frame.area(), &mut app.profile_list_state);
}

fn render_backend_choice(frame: &mut Frame, app: &mut App) {
    let items: Vec<ListItem> = BACKEND_ORDER
        .iter()
        .map(|k| ListItem::new(k.label()))
        .collect();

    let list = List::new(items)
        .block(
            Block::bordered()
                .title("Choose backend — j/k to move, Enter to pick, Esc back"),
        )
        .highlight_style(
            Style::new()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    frame.render_stateful_widget(list, frame.area(), &mut app.backend_list);
}

fn render_input(frame: &mut Frame, title: &str, value: &str, help: &str) {
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
        "Snapshots ({}) — j/k to move, q/Esc back to menu",
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
