use std::path::PathBuf;

use anyhow::Result;
use ratatui::{
    crossterm::event::{KeyCode, KeyEvent, KeyModifiers},
    widgets::ListState,
};

use crate::config::{self, BackendKind, Config, Paths, Profile};
use crate::repo::SnapshotRow;

pub(crate) const BACKEND_ORDER: [BackendKind; 3] =
    [BackendKind::Local, BackendKind::Rest, BackendKind::S3];
pub(crate) const FIRST_RUN_MENU: [&str; 3] = [
    "Create a new age key",
    "Restore an existing age key",
    "Quit",
];

pub(crate) enum Screen {
    FirstRunChoice,
    RestoreKeyWait,
    KeyCreated,
    Home,
    Snapshots,
    CreateProfileName,
    BackendChoice,
    LocalPath,
    RestConfig,
    S3Location,
    S3Credentials,
    Password,
    ConfirmDelete,
    Loading,
    Verifying,
    VerifyFailed(String),
    Error(String),
}

enum ProfileRollback {
    Remove(String),
    Restore(String, Profile),
}

pub(crate) struct App {
    pub(crate) screen: Screen,

    pub(crate) paths: Paths,
    pub(crate) config: Config,

    pub(crate) first_run_state: ListState,
    pub(crate) backend_list: ListState,
    pub(crate) profile_list_state: ListState,
    pub(crate) list_state: ListState,

    pub(crate) new_profile_name: String,
    pub(crate) backend_kind: BackendKind,
    pub(crate) local_path: String,
    pub(crate) rest_url: String,
    pub(crate) rest_user: String,
    pub(crate) rest_password: String,
    pub(crate) s3_endpoint: String,
    pub(crate) s3_bucket: String,
    pub(crate) s3_region: String,
    pub(crate) s3_root: String,
    pub(crate) s3_access_key: String,
    pub(crate) s3_secret_key: String,
    pub(crate) password: String,

    pub(crate) loading_index: usize,
    pub(crate) pending_delete: Option<usize>,
    pub(crate) editing_original_name: Option<String>,
    pub(crate) field_focus: usize,

    pub(crate) restore_error: Option<String>,
    pub(crate) created_pubkey: String,

    pub(crate) snapshots: Vec<SnapshotRow>,
    pub(crate) error_is_fatal: bool,
    pub(crate) quit: bool,
}

impl App {
    pub(crate) fn boot(config_dir: Option<PathBuf>) -> Result<Self> {
        let paths = config::paths(config_dir)?;
        let mut first_run_state = ListState::default();
        first_run_state.select(Some(0));
        let mut backend_list = ListState::default();
        backend_list.select(Some(0));

        let identity_exists = paths.identity.exists();
        let mut app = Self {
            screen: Screen::Home,
            paths,
            config: Config::default(),
            first_run_state,
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
            s3_root: String::new(),
            s3_access_key: String::new(),
            s3_secret_key: String::new(),
            password: String::new(),
            loading_index: 0,
            pending_delete: None,
            editing_original_name: None,
            field_focus: 0,
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
                self.enter_home();
            }
            Err(e) => {
                self.error_is_fatal = true;
                self.screen = Screen::Error(format!("{e:#}"));
            }
        }
    }

    // Single writer for `Screen::Home`. Clears profile-creation scratch and
    // clamps `profile_list_state` so a stale selection (e.g. after deleting
    // the last row) doesn't highlight a phantom index on the next render.
    fn enter_home(&mut self) {
        self.clear_creation_scratch();
        let len = self.config.profiles.len();
        if len == 0 {
            self.profile_list_state.select(None);
        } else {
            let cur = self.profile_list_state.selected().unwrap_or(0);
            self.profile_list_state.select(Some(cur.min(len - 1)));
        }
        self.screen = Screen::Home;
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
        self.s3_root.clear();
        self.s3_access_key.clear();
        self.s3_secret_key.clear();
        self.password.clear();
        self.editing_original_name = None;
        self.field_focus = 0;
    }

    fn load_profile_into_scratch(&mut self, idx: usize) {
        let Some((name, p)) = self.config.profile_at(idx) else { return };
        self.new_profile_name = name.clone();
        self.password = p.password().to_string();
        self.backend_kind = p.backend_kind();
        self.local_path.clear();
        self.rest_url.clear();
        self.rest_user.clear();
        self.rest_password.clear();
        self.s3_endpoint.clear();
        self.s3_bucket.clear();
        self.s3_region.clear();
        self.s3_root.clear();
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
                s3_root,
                s3_access_key,
                s3_secret_key,
                ..
            } => {
                self.s3_endpoint = s3_endpoint.clone();
                self.s3_bucket = s3_bucket.clone();
                self.s3_region = s3_region.clone();
                self.s3_root = s3_root.clone();
                self.s3_access_key = s3_access_key.clone();
                self.s3_secret_key = s3_secret_key.clone();
            }
        }
    }

    pub(crate) fn build_profile(&self) -> Profile {
        let password = self.password.clone();
        match self.backend_kind {
            BackendKind::Local => Profile::Local {
                password,
                local_path: self.local_path.clone(),
            },
            BackendKind::Rest => Profile::Rest {
                password,
                rest_url: self.rest_url.clone(),
                rest_user: self.rest_user.clone(),
                rest_password: self.rest_password.clone(),
            },
            BackendKind::S3 => Profile::S3 {
                password,
                s3_endpoint: self.s3_endpoint.clone(),
                s3_bucket: self.s3_bucket.clone(),
                s3_region: if self.s3_region.is_empty() {
                    "us-east-1".into()
                } else {
                    self.s3_region.clone()
                },
                s3_root: self.s3_root.clone(),
                s3_access_key: self.s3_access_key.clone(),
                s3_secret_key: self.s3_secret_key.clone(),
            },
        }
    }

    fn cancel_from_first_backend_input(&mut self) {
        if self.editing_original_name.is_some() {
            self.enter_home();
        } else {
            self.screen = Screen::BackendChoice;
        }
    }

    pub(crate) fn commit_profile(&mut self) {
        let profile = self.build_profile();
        let name = self.new_profile_name.clone();

        if self.editing_original_name.is_none() && self.config.has_profile(&name) {
            self.screen = Screen::Error(format!(
                "A profile named '{name}' already exists."
            ));
            return;
        }

        let restore = match self.editing_original_name.clone() {
            Some(original) => {
                // Rename during edit is not exposed in the current UI; the edit
                // flow skips the name screen. If a future screen lets the name
                // drift, this catches it before we silently drop the new value.
                debug_assert_eq!(
                    original, name,
                    "edit flow must not change the profile name; \
                     add rename handling (remove old key, collision-check, insert new) to commit_profile",
                );
                let old = self
                    .config
                    .profiles
                    .insert(original.clone(), profile)
                    .expect("editing target should exist");
                ProfileRollback::Restore(original, old)
            }
            None => {
                self.config.profiles.insert(name.clone(), profile);
                ProfileRollback::Remove(name)
            }
        };

        match config::save(&self.config, &self.paths) {
            Ok(()) => {
                self.enter_home();
            }
            Err(e) => {
                match restore {
                    ProfileRollback::Restore(key, old) => {
                        self.config.profiles.insert(key, old);
                    }
                    ProfileRollback::Remove(key) => {
                        self.config.profiles.remove(&key);
                    }
                }
                self.screen = Screen::Error(format!("Saving config failed: {e:#}"));
            }
        }
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) {
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

            Screen::Home => match key.code {
                KeyCode::Down | KeyCode::Char('j') => self.profile_list_state.select_next(),
                KeyCode::Up | KeyCode::Char('k') => self.profile_list_state.select_previous(),
                KeyCode::Esc | KeyCode::Char('q') => self.quit = true,
                KeyCode::Char('n') => {
                    self.clear_creation_scratch();
                    self.screen = Screen::CreateProfileName;
                }
                KeyCode::Enter if !self.config.profiles.is_empty() => {
                    let idx = self
                        .profile_list_state
                        .selected()
                        .unwrap_or(0)
                        .min(self.config.profiles.len() - 1);
                    self.loading_index = idx;
                    self.screen = Screen::Loading;
                }
                KeyCode::Char('e') if !self.config.profiles.is_empty() => {
                    let idx = self
                        .profile_list_state
                        .selected()
                        .unwrap_or(0)
                        .min(self.config.profiles.len() - 1);
                    self.load_profile_into_scratch(idx);
                    self.editing_original_name = Some(self.new_profile_name.clone());
                    self.field_focus = 0;
                    self.screen = match self.backend_kind {
                        BackendKind::Local => Screen::LocalPath,
                        BackendKind::Rest => Screen::RestConfig,
                        BackendKind::S3 => Screen::S3Location,
                    };
                }
                KeyCode::Char('d') if !self.config.profiles.is_empty() => {
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

            Screen::Snapshots => match key.code {
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.snapshots.clear();
                    self.enter_home();
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
                TextAction::Cancel => self.enter_home(),
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
                    self.field_focus = 0;
                    self.screen = match self.backend_kind {
                        BackendKind::Local => Screen::LocalPath,
                        BackendKind::Rest => Screen::RestConfig,
                        BackendKind::S3 => Screen::S3Location,
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

            Screen::RestConfig => {
                const N: usize = 3;
                match key.code {
                    KeyCode::Tab | KeyCode::Down => {
                        self.field_focus = (self.field_focus + 1) % N;
                    }
                    KeyCode::BackTab | KeyCode::Up => {
                        self.field_focus = (self.field_focus + N - 1) % N;
                    }
                    KeyCode::Esc => self.cancel_from_first_backend_input(),
                    KeyCode::Enter => {
                        self.rest_url = self.rest_url.trim().to_string();
                        self.rest_user = self.rest_user.trim().to_string();
                        if !self.rest_url.is_empty() {
                            self.screen = Screen::Password;
                        }
                    }
                    _ => {
                        let buf: &mut String = match self.field_focus {
                            0 => &mut self.rest_url,
                            1 => &mut self.rest_user,
                            _ => &mut self.rest_password,
                        };
                        let _ = text_input(buf, key);
                    }
                }
            }

            Screen::S3Location => {
                const N: usize = 4;
                match key.code {
                    KeyCode::Tab | KeyCode::Down => {
                        self.field_focus = (self.field_focus + 1) % N;
                    }
                    KeyCode::BackTab | KeyCode::Up => {
                        self.field_focus = (self.field_focus + N - 1) % N;
                    }
                    KeyCode::Esc => self.cancel_from_first_backend_input(),
                    KeyCode::Enter => {
                        self.s3_endpoint = self.s3_endpoint.trim().to_string();
                        self.s3_bucket = self.s3_bucket.trim().to_string();
                        self.s3_region = self.s3_region.trim().to_string();
                        self.s3_root = self.s3_root.trim().to_string();
                        if !self.s3_bucket.is_empty() {
                            self.field_focus = 0;
                            self.screen = Screen::S3Credentials;
                        }
                    }
                    _ => {
                        let buf: &mut String = match self.field_focus {
                            0 => &mut self.s3_endpoint,
                            1 => &mut self.s3_bucket,
                            2 => &mut self.s3_region,
                            _ => &mut self.s3_root,
                        };
                        let _ = text_input(buf, key);
                    }
                }
            }

            Screen::S3Credentials => {
                const N: usize = 2;
                match key.code {
                    KeyCode::Tab | KeyCode::Down => {
                        self.field_focus = (self.field_focus + 1) % N;
                    }
                    KeyCode::BackTab | KeyCode::Up => {
                        self.field_focus = (self.field_focus + N - 1) % N;
                    }
                    KeyCode::Esc => {
                        self.field_focus = 0;
                        self.screen = Screen::S3Location;
                    }
                    KeyCode::Enter => {
                        self.s3_access_key = self.s3_access_key.trim().to_string();
                        if !self.s3_access_key.is_empty() && !self.s3_secret_key.is_empty() {
                            self.screen = Screen::Password;
                        }
                    }
                    _ => {
                        let buf: &mut String = match self.field_focus {
                            0 => &mut self.s3_access_key,
                            _ => &mut self.s3_secret_key,
                        };
                        let _ = text_input(buf, key);
                    }
                }
            }

            Screen::Password => match text_input(&mut self.password, key) {
                TextAction::Submit if !self.password.is_empty() => {
                    self.screen = Screen::Verifying;
                }
                TextAction::Cancel => {
                    self.password.clear();
                    self.field_focus = 0;
                    self.screen = match self.backend_kind {
                        BackendKind::Local => Screen::LocalPath,
                        BackendKind::Rest => Screen::RestConfig,
                        BackendKind::S3 => Screen::S3Credentials,
                    };
                }
                _ => {}
            },

            Screen::ConfirmDelete => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    if let Some(idx) = self.pending_delete.take()
                        && let Some(name) = self.config.name_at(idx).cloned()
                    {
                        let removed = self
                            .config
                            .profiles
                            .remove(&name)
                            .expect("name_at hit must exist");
                        match config::save(&self.config, &self.paths) {
                            Ok(()) => self.enter_home(),
                            Err(e) => {
                                self.config.profiles.insert(name, removed);
                                self.screen =
                                    Screen::Error(format!("Saving config failed: {e:#}"));
                            }
                        }
                    } else {
                        self.enter_home();
                    }
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.pending_delete = None;
                    self.screen = Screen::Home;
                }
                _ => {}
            },

            Screen::Loading | Screen::Verifying => {}

            Screen::VerifyFailed(_) => match key.code {
                KeyCode::Char('r') | KeyCode::Char('R') => {
                    self.field_focus = 0;
                    self.screen = match self.backend_kind {
                        BackendKind::Local => Screen::LocalPath,
                        BackendKind::Rest => Screen::RestConfig,
                        BackendKind::S3 => Screen::S3Location,
                    };
                }
                KeyCode::Char('s') | KeyCode::Char('S') => {
                    self.commit_profile();
                }
                KeyCode::Esc => self.enter_home(),
                _ => {}
            },

            Screen::Error(_) => {
                if self.error_is_fatal {
                    self.quit = true;
                } else {
                    self.enter_home();
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
