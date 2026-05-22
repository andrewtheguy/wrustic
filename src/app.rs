use std::path::PathBuf;

use anyhow::Result;
use ratatui::{
    crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers},
    widgets::ListState,
};
use rustic_core::{IndexedIdsStatus, Repository, TreeId};
use tui_input::Input;
use tui_input::backend::crossterm::EventHandler;

use crate::config::{self, BackendKind, Config, Paths, Profile};
use crate::repo::{ContentKind, ContentRow, SnapshotRow};
use crate::restic::{self, ResticError, ResticInfo, SnapshotDetails};

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
    SnapshotFilterDim,
    SnapshotFilterValue,
    SnapshotDeleteInfo,
    SnapshotDeleteConfirm,
    SnapshotDeleting,
    SnapshotDeleteError(String),
    OpeningSnapshot,
    SnapshotContents,
    LoadingDir,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilterKind {
    Host,
    Tag,
    Path,
}

impl FilterKind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            FilterKind::Host => "host",
            FilterKind::Tag => "tag",
            FilterKind::Path => "path",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum SnapshotFilter {
    Host(String),
    Tag(String),
    Path(String),
}

impl SnapshotFilter {
    pub(crate) fn kind(&self) -> FilterKind {
        match self {
            SnapshotFilter::Host(_) => FilterKind::Host,
            SnapshotFilter::Tag(_) => FilterKind::Tag,
            SnapshotFilter::Path(_) => FilterKind::Path,
        }
    }

    pub(crate) fn value(&self) -> &str {
        match self {
            SnapshotFilter::Host(v) | SnapshotFilter::Tag(v) | SnapshotFilter::Path(v) => v,
        }
    }

    pub(crate) fn matches(&self, row: &SnapshotRow) -> bool {
        match self {
            SnapshotFilter::Host(h) => &row.host == h,
            SnapshotFilter::Tag(t) => row.tags.iter().any(|x| x == t),
            SnapshotFilter::Path(p) => row.paths.iter().any(|x| x == p),
        }
    }
}

pub(crate) struct BrowseFrame {
    pub(crate) name: String,
    pub(crate) items: Vec<ContentRow>,
    pub(crate) list_state: ListState,
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

    pub(crate) new_profile_name: Input,
    pub(crate) backend_kind: BackendKind,
    pub(crate) local_path: Input,
    pub(crate) rest_url: Input,
    pub(crate) rest_user: Input,
    pub(crate) rest_password: Input,
    pub(crate) s3_endpoint: Input,
    pub(crate) s3_bucket: Input,
    pub(crate) s3_region: Input,
    pub(crate) s3_root: Input,
    pub(crate) s3_access_key: Input,
    pub(crate) s3_secret_key: Input,
    pub(crate) password: Input,

    pub(crate) loading_index: usize,
    pub(crate) pending_delete: Option<usize>,
    pub(crate) editing_original_name: Option<String>,
    pub(crate) field_focus: usize,

    pub(crate) restore_error: Option<String>,
    pub(crate) created_pubkey: String,

    pub(crate) snapshots: Vec<SnapshotRow>,
    pub(crate) snapshot_filter: Option<SnapshotFilter>,
    pub(crate) filter_picker_state: ListState,
    pub(crate) filter_values: Vec<String>,
    pub(crate) filter_pending_kind: Option<FilterKind>,
    pub(crate) active_profile_name: Option<String>,
    pub(crate) repo_session: Option<Repository<IndexedIdsStatus>>,
    pub(crate) browse_snapshot_id: String,
    pub(crate) browse_stack: Vec<BrowseFrame>,
    pub(crate) pending_descend: Option<(TreeId, String)>,
    pub(crate) pending_refresh_path: Option<Vec<String>>,
    pub(crate) error_is_fatal: bool,
    pub(crate) quit: bool,

    pub(crate) restic_check: Option<Result<ResticInfo, ResticError>>,
    pub(crate) delete_target: Option<String>,
    pub(crate) delete_details_parsed: Option<SnapshotDetails>,
    pub(crate) delete_details_raw: Option<String>,
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
            new_profile_name: Input::default(),
            backend_kind: BackendKind::Local,
            local_path: Input::default(),
            rest_url: Input::default(),
            rest_user: Input::default(),
            rest_password: Input::default(),
            s3_endpoint: Input::default(),
            s3_bucket: Input::default(),
            s3_region: Input::default(),
            s3_root: Input::default(),
            s3_access_key: Input::default(),
            s3_secret_key: Input::default(),
            password: Input::default(),
            loading_index: 0,
            pending_delete: None,
            editing_original_name: None,
            field_focus: 0,
            restore_error: None,
            created_pubkey: String::new(),
            snapshots: Vec::new(),
            snapshot_filter: None,
            filter_picker_state: ListState::default(),
            filter_values: Vec::new(),
            filter_pending_kind: None,
            active_profile_name: None,
            repo_session: None,
            browse_snapshot_id: String::new(),
            browse_stack: Vec::new(),
            pending_descend: None,
            pending_refresh_path: None,
            error_is_fatal: false,
            quit: false,
            restic_check: None,
            delete_target: None,
            delete_details_parsed: None,
            delete_details_raw: None,
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
        self.active_profile_name = None;
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
        self.new_profile_name.reset();
        self.local_path.reset();
        self.rest_url.reset();
        self.rest_user.reset();
        self.rest_password.reset();
        self.s3_endpoint.reset();
        self.s3_bucket.reset();
        self.s3_region.reset();
        self.s3_root.reset();
        self.s3_access_key.reset();
        self.s3_secret_key.reset();
        self.password.reset();
        self.editing_original_name = None;
        self.field_focus = 0;
    }

    fn load_profile_into_scratch(&mut self, idx: usize) {
        let Some((name, p)) = self.config.profile_at(idx) else { return };
        self.new_profile_name = Input::new(name.clone());
        self.password = Input::new(p.password().to_string());
        self.backend_kind = p.backend_kind();
        self.local_path.reset();
        self.rest_url.reset();
        self.rest_user.reset();
        self.rest_password.reset();
        self.s3_endpoint.reset();
        self.s3_bucket.reset();
        self.s3_region.reset();
        self.s3_root.reset();
        self.s3_access_key.reset();
        self.s3_secret_key.reset();
        match p {
            Profile::Local { local_path, .. } => {
                self.local_path = Input::new(local_path.clone());
            }
            Profile::Rest {
                rest_url,
                rest_user,
                rest_password,
                ..
            } => {
                self.rest_url = Input::new(rest_url.clone());
                self.rest_user = Input::new(rest_user.clone());
                self.rest_password = Input::new(rest_password.clone());
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
                self.s3_endpoint = Input::new(s3_endpoint.clone());
                self.s3_bucket = Input::new(s3_bucket.clone());
                self.s3_region = Input::new(s3_region.clone());
                self.s3_root = Input::new(s3_root.clone());
                self.s3_access_key = Input::new(s3_access_key.clone());
                self.s3_secret_key = Input::new(s3_secret_key.clone());
            }
        }
    }

    pub(crate) fn build_profile(&self) -> Profile {
        let password = self.password.value().to_string();
        match self.backend_kind {
            BackendKind::Local => Profile::Local {
                password,
                local_path: self.local_path.value().to_string(),
            },
            BackendKind::Rest => Profile::Rest {
                password,
                rest_url: self.rest_url.value().to_string(),
                rest_user: self.rest_user.value().to_string(),
                rest_password: self.rest_password.value().to_string(),
            },
            BackendKind::S3 => Profile::S3 {
                password,
                s3_endpoint: self.s3_endpoint.value().to_string(),
                s3_bucket: self.s3_bucket.value().to_string(),
                s3_region: if self.s3_region.value().is_empty() {
                    "us-east-1".into()
                } else {
                    self.s3_region.value().to_string()
                },
                s3_root: self.s3_root.value().to_string(),
                s3_access_key: self.s3_access_key.value().to_string(),
                s3_secret_key: self.s3_secret_key.value().to_string(),
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
        let name = self.new_profile_name.value().to_string();

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

    // Indices into `self.snapshots` for rows that pass the current filter,
    // preserving the underlying time-desc order.
    pub(crate) fn visible_snapshot_indices(&self) -> Vec<usize> {
        match &self.snapshot_filter {
            None => (0..self.snapshots.len()).collect(),
            Some(f) => self
                .snapshots
                .iter()
                .enumerate()
                .filter(|(_, r)| f.matches(r))
                .map(|(i, _)| i)
                .collect(),
        }
    }

    fn enter_snapshots_from_filter(&mut self) {
        let visible = self.visible_snapshot_indices().len();
        self.list_state
            .select(if visible == 0 { None } else { Some(0) });
        self.screen = Screen::Snapshots;
    }

    fn open_filter_value_picker(&mut self, kind: FilterKind) {
        let values = distinct_values(&self.snapshots, kind);
        if values.is_empty() {
            return;
        }
        self.filter_values = values;
        self.filter_pending_kind = Some(kind);
        self.filter_picker_state = ListState::default();
        self.filter_picker_state.select(Some(0));
        self.screen = Screen::SnapshotFilterValue;
    }

    fn clear_delete_scratch(&mut self) {
        self.delete_target = None;
        self.delete_details_parsed = None;
        self.delete_details_raw = None;
    }

    // Run version detection lazily (cached) and, if restic is available, fetch
    // the snapshot's `restic snapshots --json` details. On any failure, stash
    // a user-facing message and transition to SnapshotDeleteError. On success,
    // populate delete_target/details and transition to SnapshotDeleteInfo.
    fn begin_delete_flow(&mut self, snapshot_id: String) {
        if self.restic_check.is_none() {
            self.restic_check = Some(restic::detect());
        }
        if let Some(Err(e)) = &self.restic_check {
            self.screen = Screen::SnapshotDeleteError(e.user_message());
            return;
        }
        let Some((_, profile)) = self.config.profile_at(self.loading_index) else {
            self.screen = Screen::SnapshotDeleteError(
                "Selected profile no longer exists.".into(),
            );
            return;
        };
        match restic::snapshot_details_json(profile, &snapshot_id) {
            Ok((parsed, raw)) => {
                self.delete_target = Some(snapshot_id);
                self.delete_details_parsed = Some(parsed);
                self.delete_details_raw = Some(raw);
                self.screen = Screen::SnapshotDeleteInfo;
            }
            Err(e) => {
                self.screen = Screen::SnapshotDeleteError(format!("{e:#}"));
            }
        }
    }

    fn go_up(&mut self) {
        if self.browse_stack.len() > 1 {
            self.browse_stack.pop();
        } else {
            self.repo_session = None;
            self.browse_stack.clear();
            self.browse_snapshot_id.clear();
            self.pending_descend = None;
            self.pending_refresh_path = None;
            self.screen = Screen::Snapshots;
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
                    self.active_profile_name =
                        self.config.name_at(idx).cloned();
                    self.screen = Screen::Loading;
                }
                KeyCode::Char('e') if !self.config.profiles.is_empty() => {
                    let idx = self
                        .profile_list_state
                        .selected()
                        .unwrap_or(0)
                        .min(self.config.profiles.len() - 1);
                    self.load_profile_into_scratch(idx);
                    self.editing_original_name = Some(self.new_profile_name.value().to_string());
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
                    self.snapshot_filter = None;
                    self.enter_home();
                }
                KeyCode::Down | KeyCode::Char('j') => self.list_state.select_next(),
                KeyCode::Up | KeyCode::Char('k') => self.list_state.select_previous(),
                KeyCode::Home | KeyCode::Char('g') => self.list_state.select(Some(0)),
                KeyCode::End | KeyCode::Char('G') => {
                    let visible = self.visible_snapshot_indices();
                    if !visible.is_empty() {
                        self.list_state.select(Some(visible.len() - 1));
                    }
                }
                KeyCode::Enter => {
                    let visible = self.visible_snapshot_indices();
                    if let Some(pos) = self.list_state.selected()
                        && let Some(&abs) = visible.get(pos)
                        && let Some(s) = self.snapshots.get(abs)
                    {
                        self.browse_snapshot_id = s.id.clone();
                        self.pending_refresh_path = None;
                        self.screen = Screen::OpeningSnapshot;
                    }
                }
                KeyCode::Char('r') => {
                    self.snapshots.clear();
                    self.snapshot_filter = None;
                    self.screen = Screen::Loading;
                }
                KeyCode::Char('f') => {
                    self.filter_picker_state = ListState::default();
                    self.filter_picker_state.select(Some(0));
                    self.filter_pending_kind = None;
                    self.screen = Screen::SnapshotFilterDim;
                }
                KeyCode::Char('d') => {
                    let visible = self.visible_snapshot_indices();
                    if let Some(pos) = self.list_state.selected()
                        && let Some(&abs) = visible.get(pos)
                        && let Some(s) = self.snapshots.get(abs)
                    {
                        let id = s.id.clone();
                        self.begin_delete_flow(id);
                    }
                }
                _ => {}
            },

            Screen::SnapshotFilterDim => match key.code {
                KeyCode::Down | KeyCode::Char('j') => self.filter_picker_state.select_next(),
                KeyCode::Up | KeyCode::Char('k') => self.filter_picker_state.select_previous(),
                KeyCode::Esc | KeyCode::Char('q') => self.screen = Screen::Snapshots,
                KeyCode::Enter => {
                    let entries = filter_dim_entries(self.snapshot_filter.is_some());
                    let idx = self
                        .filter_picker_state
                        .selected()
                        .unwrap_or(0)
                        .min(entries.len().saturating_sub(1));
                    match entries.get(idx) {
                        Some(FilterDimEntry::Clear) => {
                            self.snapshot_filter = None;
                            self.enter_snapshots_from_filter();
                        }
                        Some(FilterDimEntry::Kind(k)) => {
                            self.open_filter_value_picker(*k);
                        }
                        None => {}
                    }
                }
                _ => {}
            },

            Screen::SnapshotFilterValue => match key.code {
                KeyCode::Down | KeyCode::Char('j') => self.filter_picker_state.select_next(),
                KeyCode::Up | KeyCode::Char('k') => self.filter_picker_state.select_previous(),
                KeyCode::Home | KeyCode::Char('g') => self.filter_picker_state.select(Some(0)),
                KeyCode::End | KeyCode::Char('G') => {
                    if !self.filter_values.is_empty() {
                        self.filter_picker_state
                            .select(Some(self.filter_values.len() - 1));
                    }
                }
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.filter_pending_kind = None;
                    self.filter_picker_state = ListState::default();
                    self.filter_picker_state.select(Some(0));
                    self.screen = Screen::SnapshotFilterDim;
                }
                KeyCode::Enter => {
                    if let (Some(kind), Some(idx)) =
                        (self.filter_pending_kind, self.filter_picker_state.selected())
                        && let Some(value) = self.filter_values.get(idx).cloned()
                    {
                        self.snapshot_filter = Some(match kind {
                            FilterKind::Host => SnapshotFilter::Host(value),
                            FilterKind::Tag => SnapshotFilter::Tag(value),
                            FilterKind::Path => SnapshotFilter::Path(value),
                        });
                        self.filter_pending_kind = None;
                        self.enter_snapshots_from_filter();
                    }
                }
                _ => {}
            },

            Screen::SnapshotDeleteInfo => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.screen = Screen::SnapshotDeleteConfirm;
                }
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('n') | KeyCode::Char('N') => {
                    self.clear_delete_scratch();
                    self.screen = Screen::Snapshots;
                }
                _ => {}
            },

            Screen::SnapshotDeleteConfirm => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.screen = Screen::SnapshotDeleting;
                }
                KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                    self.clear_delete_scratch();
                    self.screen = Screen::Snapshots;
                }
                _ => {}
            },

            Screen::SnapshotDeleteError(_) => {
                self.clear_delete_scratch();
                self.screen = Screen::Snapshots;
            }

            Screen::SnapshotContents => match key.code {
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.repo_session = None;
                    self.browse_stack.clear();
                    self.browse_snapshot_id.clear();
                    self.pending_descend = None;
                    self.pending_refresh_path = None;
                    self.screen = Screen::Snapshots;
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if let Some(f) = self.browse_stack.last_mut() {
                        f.list_state.select_next();
                    }
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    if let Some(f) = self.browse_stack.last_mut() {
                        f.list_state.select_previous();
                    }
                }
                KeyCode::Home | KeyCode::Char('g') => {
                    if let Some(f) = self.browse_stack.last_mut() {
                        f.list_state.select(Some(0));
                    }
                }
                KeyCode::End | KeyCode::Char('G') => {
                    if let Some(f) = self.browse_stack.last_mut()
                        && !f.items.is_empty()
                    {
                        f.list_state.select(Some(f.items.len() - 1));
                    }
                }
                KeyCode::Enter => {
                    if let Some(f) = self.browse_stack.last()
                        && let Some(idx) = f.list_state.selected()
                        && let Some(row) = f.items.get(idx)
                    {
                        match row.kind {
                            ContentKind::Parent => self.go_up(),
                            ContentKind::Dir => {
                                if let Some(subtree) = row.subtree {
                                    self.pending_descend = Some((subtree, row.name.clone()));
                                    self.screen = Screen::LoadingDir;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                KeyCode::Backspace => self.go_up(),
                KeyCode::Char('r') => {
                    let path: Vec<String> = self
                        .browse_stack
                        .iter()
                        .skip(1)
                        .map(|f| f.name.clone())
                        .collect();
                    self.pending_refresh_path = Some(path);
                    self.repo_session = None;
                    self.browse_stack.clear();
                    self.pending_descend = None;
                    self.screen = Screen::OpeningSnapshot;
                }
                _ => {}
            },

            Screen::OpeningSnapshot | Screen::LoadingDir | Screen::SnapshotDeleting => {}

            Screen::CreateProfileName => match key.code {
                KeyCode::Enter => {
                    let name = self.new_profile_name.value().trim().to_string();
                    if name.is_empty() {
                        return;
                    }
                    if self.config.has_profile(&name) {
                        self.screen = Screen::Error(format!(
                            "A profile named '{name}' already exists."
                        ));
                        return;
                    }
                    self.new_profile_name = Input::new(name);
                    self.backend_list.select(Some(0));
                    self.screen = Screen::BackendChoice;
                }
                KeyCode::Esc => self.enter_home(),
                _ => {
                    self.new_profile_name.handle_event(&Event::Key(key));
                }
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

            Screen::LocalPath => match key.code {
                KeyCode::Enter if !self.local_path.value().trim().is_empty() => {
                    let trimmed = self.local_path.value().trim().to_string();
                    self.local_path = Input::new(trimmed);
                    self.screen = Screen::Password;
                }
                KeyCode::Esc => self.cancel_from_first_backend_input(),
                _ => {
                    self.local_path.handle_event(&Event::Key(key));
                }
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
                        self.rest_url = Input::new(self.rest_url.value().trim().to_string());
                        self.rest_user = Input::new(self.rest_user.value().trim().to_string());
                        if !self.rest_url.value().is_empty() {
                            self.screen = Screen::Password;
                        }
                    }
                    _ => {
                        let buf: &mut Input = match self.field_focus {
                            0 => &mut self.rest_url,
                            1 => &mut self.rest_user,
                            _ => &mut self.rest_password,
                        };
                        buf.handle_event(&Event::Key(key));
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
                        self.s3_endpoint =
                            Input::new(self.s3_endpoint.value().trim().to_string());
                        self.s3_bucket = Input::new(self.s3_bucket.value().trim().to_string());
                        self.s3_region = Input::new(self.s3_region.value().trim().to_string());
                        self.s3_root = Input::new(self.s3_root.value().trim().to_string());
                        if !self.s3_bucket.value().is_empty() {
                            self.field_focus = 0;
                            self.screen = Screen::S3Credentials;
                        }
                    }
                    _ => {
                        let buf: &mut Input = match self.field_focus {
                            0 => &mut self.s3_endpoint,
                            1 => &mut self.s3_bucket,
                            2 => &mut self.s3_region,
                            _ => &mut self.s3_root,
                        };
                        buf.handle_event(&Event::Key(key));
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
                        self.s3_access_key =
                            Input::new(self.s3_access_key.value().trim().to_string());
                        self.s3_secret_key =
                            Input::new(self.s3_secret_key.value().trim().to_string());
                        if !self.s3_access_key.value().is_empty()
                            && !self.s3_secret_key.value().is_empty()
                        {
                            self.screen = Screen::Password;
                        }
                    }
                    _ => {
                        let buf: &mut Input = match self.field_focus {
                            0 => &mut self.s3_access_key,
                            _ => &mut self.s3_secret_key,
                        };
                        buf.handle_event(&Event::Key(key));
                    }
                }
            }

            Screen::Password => match key.code {
                KeyCode::Enter if !self.password.value().is_empty() => {
                    self.screen = Screen::Verifying;
                }
                KeyCode::Esc => {
                    self.password.reset();
                    self.field_focus = 0;
                    self.screen = match self.backend_kind {
                        BackendKind::Local => Screen::LocalPath,
                        BackendKind::Rest => Screen::RestConfig,
                        BackendKind::S3 => Screen::S3Credentials,
                    };
                }
                _ => {
                    self.password.handle_event(&Event::Key(key));
                }
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

#[derive(Clone, Copy)]
pub(crate) enum FilterDimEntry {
    Kind(FilterKind),
    Clear,
}

impl FilterDimEntry {
    pub(crate) fn label(self) -> &'static str {
        match self {
            FilterDimEntry::Kind(FilterKind::Host) => "Host",
            FilterDimEntry::Kind(FilterKind::Tag) => "Tag",
            FilterDimEntry::Kind(FilterKind::Path) => "Path",
            FilterDimEntry::Clear => "Clear filter",
        }
    }
}

pub(crate) fn filter_dim_entries(has_active: bool) -> Vec<FilterDimEntry> {
    let mut v = vec![
        FilterDimEntry::Kind(FilterKind::Host),
        FilterDimEntry::Kind(FilterKind::Tag),
        FilterDimEntry::Kind(FilterKind::Path),
    ];
    if has_active {
        v.push(FilterDimEntry::Clear);
    }
    v
}

// Distinct values present in `rows` for the given dimension, sorted ascending.
// Tags and paths are flattened (a snapshot with multiple tags contributes each).
pub(crate) fn distinct_values(rows: &[SnapshotRow], kind: FilterKind) -> Vec<String> {
    use std::collections::BTreeSet;
    let mut set: BTreeSet<String> = BTreeSet::new();
    for r in rows {
        match kind {
            FilterKind::Host => {
                if !r.host.is_empty() {
                    set.insert(r.host.clone());
                }
            }
            FilterKind::Tag => {
                for t in &r.tags {
                    if !t.is_empty() {
                        set.insert(t.clone());
                    }
                }
            }
            FilterKind::Path => {
                for p in &r.paths {
                    if !p.is_empty() {
                        set.insert(p.clone());
                    }
                }
            }
        }
    }
    set.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(host: &str, tags: &[&str], paths: &[&str]) -> SnapshotRow {
        SnapshotRow {
            id: "0".into(),
            time: String::new(),
            host: host.into(),
            tags: tags.iter().map(|s| (*s).to_string()).collect(),
            paths: paths.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    #[test]
    fn distinct_values_dedupe_and_sort() {
        let rows = vec![
            row("laptop", &["weekly", "auto"], &["/home", "/etc"]),
            row("server", &["auto"], &["/etc"]),
            row("laptop", &[], &["/home"]),
        ];
        assert_eq!(distinct_values(&rows, FilterKind::Host), vec!["laptop", "server"]);
        assert_eq!(distinct_values(&rows, FilterKind::Tag), vec!["auto", "weekly"]);
        assert_eq!(distinct_values(&rows, FilterKind::Path), vec!["/etc", "/home"]);
    }

    #[test]
    fn filter_matches() {
        let r = row("laptop", &["weekly"], &["/home", "/etc"]);
        assert!(SnapshotFilter::Host("laptop".into()).matches(&r));
        assert!(!SnapshotFilter::Host("server".into()).matches(&r));
        assert!(SnapshotFilter::Tag("weekly".into()).matches(&r));
        assert!(!SnapshotFilter::Tag("daily".into()).matches(&r));
        assert!(SnapshotFilter::Path("/etc".into()).matches(&r));
        assert!(!SnapshotFilter::Path("/var".into()).matches(&r));
    }

    #[test]
    fn dim_entries_include_clear_only_when_active() {
        assert_eq!(filter_dim_entries(false).len(), 3);
        let entries = filter_dim_entries(true);
        assert_eq!(entries.len(), 4);
        assert!(matches!(entries.last(), Some(FilterDimEntry::Clear)));
    }
}
