use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Result;
use ratatui::{
    crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind},
    layout::Rect,
    widgets::ListState,
};
use rustic_core::{IndexedIdsStatus, Repository, TreeId};
use tui_input::Input;
use tui_input::backend::crossterm::EventHandler;

use crate::config::{self, BackendKind, Config, Paths, Profile};
use crate::repo::{ContentKind, ContentRow, ContentsPreview, FileDetails, SnapshotRow};
use crate::restic::{self, DiffChange, DiffSummary, ResticError, ResticInfo, SnapshotDetails};
use crate::share::{self, SHARE_TTL, ShareHandle, ShareTarget};

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
    SnapshotDeleteContentsLoading,
    SnapshotDeleteConfirm,
    SnapshotDeleting,
    SnapshotDeleteError(String),
    OpeningSnapshot,
    SnapshotContents,
    LoadingDir,
    LoadingFileDetails,
    FileDetails,
    ShareUrl,
    SnapshotCompareFirst,
    SnapshotCompareSecond,
    SnapshotCompareLoading,
    SnapshotCompareResults,
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

// Translate a left-click at `(row, col)` (terminal coordinates) into an
// index into the visible list. Returns None when the click misses the
// list's bordered interior, when the list is empty, or when the click
// lands past the last populated row. `offset` is the first-visible index
// from `ListState::offset()`.
fn click_to_index(
    list_area: Rect,
    offset: usize,
    len: usize,
    row: u16,
    col: u16,
) -> Option<usize> {
    if len == 0 {
        return None;
    }
    // Bordered interior: skip the top/left border and stop before the
    // bottom/right border.
    let inner_top = list_area.y.checked_add(1)?;
    let inner_left = list_area.x.checked_add(1)?;
    let inner_bottom = list_area.y.saturating_add(list_area.height.saturating_sub(1));
    let inner_right = list_area.x.saturating_add(list_area.width.saturating_sub(1));
    if row < inner_top || row >= inner_bottom {
        return None;
    }
    if col < inner_left || col >= inner_right {
        return None;
    }
    let row_in_list = (row - inner_top) as usize;
    let idx = row_in_list.checked_add(offset)?;
    (idx < len).then_some(idx)
}

// Advance the viewport by exactly one page and put the cursor on the first
// item of the new page. Used by PageUp/PageDown handlers.
//
// On PageDown, if a full page can't be advanced (already on the last/partial
// page), the cursor moves to the last item instead of paging past the end.
// PageUp mirrors this against the previous page; if already on the first
// page, it clamps to index 0.
fn page_select(state: &mut ListState, len: usize, forward: bool, page_size: usize) {
    if len == 0 {
        state.select(None);
        return;
    }
    let page_size = page_size.max(1);
    let cur_offset = state.offset();
    if forward {
        let next_offset = cur_offset.saturating_add(page_size);
        if next_offset >= len {
            state.select(Some(len - 1));
        } else {
            *state.offset_mut() = next_offset;
            state.select(Some(next_offset));
        }
    } else {
        let prev_offset = cur_offset.saturating_sub(page_size);
        *state.offset_mut() = prev_offset;
        state.select(Some(prev_offset));
    }
}

pub(crate) struct BrowseFrame {
    pub(crate) name: String,
    pub(crate) tree_id: TreeId,
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
    pub(crate) pending_file_lookup: Option<(TreeId, String, String)>,
    pub(crate) file_details: Option<FileDetails>,
    pub(crate) file_details_scroll: u16,
    // What `Screen::ShareUrl` would serve if started. Captured at the moment
    // 'd' is pressed on FileDetails so we don't need to walk back into the
    // browse stack later.
    pub(crate) share_target: Option<ShareTarget>,
    pub(crate) share_handle: Option<ShareHandle>,
    // Last minted URL — kept around even after the server is stopped so the
    // user can still read/copy it; the URL stays cryptographically valid
    // until its embedded exp passes.
    pub(crate) share_url: Option<String>,
    pub(crate) share_short_url: Option<String>,
    pub(crate) share_exp_unix: Option<u64>,
    // Inline error for the Share screen (e.g. EADDRINUSE on start) — keeps
    // the user on the Share screen instead of jumping to the global Error.
    pub(crate) share_error: Option<String>,
    pub(crate) error_is_fatal: bool,
    pub(crate) quit: bool,

    pub(crate) restic_check: Option<Result<ResticInfo, ResticError>>,
    pub(crate) delete_target: Option<String>,
    pub(crate) delete_details_parsed: Option<SnapshotDetails>,
    pub(crate) delete_details_raw: Option<String>,
    pub(crate) delete_root_listing: Option<ContentsPreview>,

    pub(crate) compare_first_id: Option<String>,
    pub(crate) compare_first_row_idx: Option<usize>,
    pub(crate) compare_second_id: Option<String>,
    pub(crate) compare_only_related: bool,
    pub(crate) compare_picker_state: ListState,
    pub(crate) compare_results: Option<(DiffSummary, Vec<DiffChange>)>,
    pub(crate) compare_results_state: ListState,

    // Outer rect of the currently-rendered list/paragraph (bordered area).
    // Used by PageUp/PageDown to size the jump and by the mouse handler
    // to translate click coordinates into a row index. Set by the renderer
    // each frame; read by the key/mouse handler on the next event.
    pub(crate) list_area: Option<Rect>,

    // Last left-click on the SnapshotContents list: timestamp + clicked row
    // index. Used to detect a double-click for opening file info.
    pub(crate) last_content_click: Option<(Instant, usize)>,
}

// Two clicks on the same row within this window count as a double-click.
const DOUBLE_CLICK: Duration = Duration::from_millis(400);

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
            pending_file_lookup: None,
            file_details: None,
            file_details_scroll: 0,
            share_target: None,
            share_handle: None,
            share_url: None,
            share_short_url: None,
            share_exp_unix: None,
            share_error: None,
            error_is_fatal: false,
            quit: false,
            restic_check: None,
            delete_target: None,
            delete_details_parsed: None,
            delete_details_raw: None,
            delete_root_listing: None,
            compare_first_id: None,
            compare_first_row_idx: None,
            compare_second_id: None,
            compare_only_related: true,
            compare_picker_state: ListState::default(),
            compare_results: None,
            compare_results_state: ListState::default(),
            list_area: None,
            last_content_click: None,
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

    // Inner visible rows of the currently-rendered list/paragraph — one full
    // page's worth, used by PageDown/PageUp to advance the viewport.
    fn page_step(&self) -> usize {
        let h = self.list_area.map(|r| r.height).unwrap_or(0);
        // height - 2 borders, with a floor of 1 row.
        h.saturating_sub(2).max(1) as usize
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
        self.delete_root_listing = None;
    }

    pub(crate) fn clear_compare_scratch(&mut self) {
        self.compare_first_id = None;
        self.compare_first_row_idx = None;
        self.compare_second_id = None;
        self.compare_only_related = true;
        self.compare_picker_state = ListState::default();
        self.compare_results = None;
        self.compare_results_state = ListState::default();
    }

    // Indices into `self.snapshots` for step 2 of the compare flow: start from
    // the active snapshot_filter, exclude the first-picked row, and (when
    // `compare_only_related` is true) restrict to rows sharing host + paths
    // with the first pick — restic's incremental parent chain is per
    // host+paths, so this is the practical "same lineage" proxy.
    pub(crate) fn compare_second_visible_indices(&self) -> Vec<usize> {
        let base = self.visible_snapshot_indices();
        let Some(first_idx) = self.compare_first_row_idx else {
            return base;
        };
        let Some(first) = self.snapshots.get(first_idx) else {
            return base;
        };
        let first_paths: std::collections::BTreeSet<&str> =
            first.paths.iter().map(String::as_str).collect();
        base.into_iter()
            .filter(|&i| i != first_idx)
            .filter(|&i| {
                if !self.compare_only_related {
                    return true;
                }
                let r = &self.snapshots[i];
                if r.host != first.host {
                    return false;
                }
                let other: std::collections::BTreeSet<&str> =
                    r.paths.iter().map(String::as_str).collect();
                other == first_paths
            })
            .collect()
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
        // Any pending double-click pair belonged to the old frame; drop it.
        self.last_content_click = None;
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

    // ──── Activation helpers ────────────────────────────────────────────
    // Each helper holds the body of one screen's "Enter" action so that the
    // keyboard handler and the mouse-click handler both go through the same
    // code path. The mouse handler updates the relevant selection first,
    // then calls the matching helper.

    fn activate_first_run(&mut self) {
        match self.first_run_state.selected().unwrap_or(0) {
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
        }
    }

    fn activate_home_profile(&mut self) {
        if self.config.profiles.is_empty() {
            return;
        }
        let idx = self
            .profile_list_state
            .selected()
            .unwrap_or(0)
            .min(self.config.profiles.len() - 1);
        self.loading_index = idx;
        self.active_profile_name = self.config.name_at(idx).cloned();
        self.screen = Screen::Loading;
    }

    fn activate_selected_snapshot(&mut self) {
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

    fn activate_compare_first(&mut self) {
        let visible = self.visible_snapshot_indices();
        if let Some(pos) = self.compare_picker_state.selected()
            && let Some(&abs) = visible.get(pos)
            && let Some(s) = self.snapshots.get(abs)
        {
            self.compare_first_id = Some(s.id.clone());
            self.compare_first_row_idx = Some(abs);
            self.compare_only_related = true;
            // Reset picker selection — index meaning changes with the new
            // (related-only) visible set.
            self.compare_picker_state = ListState::default();
            if !self.compare_second_visible_indices().is_empty() {
                self.compare_picker_state.select(Some(0));
            }
            self.screen = Screen::SnapshotCompareSecond;
        }
    }

    fn activate_compare_second(&mut self) {
        let visible = self.compare_second_visible_indices();
        if let Some(pos) = self.compare_picker_state.selected()
            && let Some(&abs) = visible.get(pos)
            && let Some(s) = self.snapshots.get(abs)
        {
            self.compare_second_id = Some(s.id.clone());
            self.screen = Screen::SnapshotCompareLoading;
        }
    }

    fn activate_filter_dim(&mut self) {
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

    fn activate_filter_value(&mut self) {
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

    fn activate_snapshot_content(&mut self) {
        let Some(f) = self.browse_stack.last() else {
            return;
        };
        let Some(idx) = f.list_state.selected() else {
            return;
        };
        let Some(row) = f.items.get(idx) else {
            return;
        };
        match row.kind {
            ContentKind::Parent => self.go_up(),
            ContentKind::Dir => {
                if let Some(subtree) = row.subtree {
                    // Descending — drop any pending double-click pair so the
                    // new frame can't inherit a stale match.
                    self.last_content_click = None;
                    self.pending_descend = Some((subtree, row.name.clone()));
                    self.screen = Screen::LoadingDir;
                }
            }
            // Enter on a file (or symlink/other) opens its details screen.
            ContentKind::File | ContentKind::Symlink | ContentKind::Other => {
                self.open_selected_file_details();
            }
        }
    }

    fn open_selected_file_details(&mut self) {
        let Some(f) = self.browse_stack.last() else {
            return;
        };
        let Some(idx) = f.list_state.selected() else {
            return;
        };
        let Some(row) = f.items.get(idx) else {
            return;
        };
        if !matches!(
            row.kind,
            ContentKind::File | ContentKind::Symlink | ContentKind::Other
        ) {
            return;
        }
        let dir_path = self
            .browse_stack
            .iter()
            .skip(1)
            .map(|fr| fr.name.as_str())
            .collect::<Vec<_>>()
            .join("/");
        let full_path = if dir_path.is_empty() {
            format!("/{}", row.name)
        } else {
            format!("/{}/{}", dir_path, row.name)
        };
        self.share_target = Some(ShareTarget {
            snap_id: self.browse_snapshot_id.clone(),
            tree_id: f.tree_id,
            name: row.name.clone(),
            display_path: full_path.clone(),
        });
        self.pending_file_lookup = Some((f.tree_id, row.name.clone(), full_path));
        self.file_details_scroll = 0;
        self.screen = Screen::LoadingFileDetails;
    }

    // Tear down any running share server and clear all share-related state.
    // Called when leaving FileDetails (back to SnapshotContents) and on app
    // exit — the share server is bound to the lifetime of viewing one file.
    pub(crate) fn stop_share(&mut self) {
        self.stop_share_keep_target();
        self.share_target = None;
    }

    // Stop the server and drop the minted URL but keep `share_target` so
    // re-entering the share dialog from FileDetails still has the file
    // info it needs. Used when leaving the share dialog back to file
    // details.
    fn stop_share_keep_target(&mut self) {
        if let Some(h) = self.share_handle.take() {
            h.stop();
        }
        self.share_url = None;
        self.share_short_url = None;
        self.share_exp_unix = None;
        self.share_error = None;
    }

    // Start the share server for the currently-loaded file. Called when
    // entering the Share screen via `d` on FileDetails. No-op if a server
    // is already running (shouldn't happen — we stop on every Esc — but
    // defensive). Surfaces start errors inline on the Share screen.
    fn start_share_server(&mut self) {
        if self.share_handle.is_some() {
            return;
        }
        let Some(target) = self.share_target.clone() else {
            self.share_error = Some("No file selected to share.".into());
            return;
        };
        let Some((_, profile)) = self.config.profile_at(self.loading_index) else {
            self.share_error = Some("Selected profile no longer exists.".into());
            return;
        };
        let profile = profile.clone();
        let key = match share::derive_signing_key(&self.paths.identity) {
            Ok(k) => k,
            Err(e) => {
                self.share_error = Some(format!("Deriving signing key: {e:#}"));
                return;
            }
        };
        let port = self.config.server.port;
        match share::start(port, profile, key, target, SHARE_TTL) {
            Ok(h) => {
                self.share_url = Some(h.url.clone());
                self.share_short_url = Some(h.short_url.clone());
                self.share_exp_unix = Some(h.exp_unix);
                self.share_error = None;
                self.share_handle = Some(h);
            }
            Err(e) => {
                self.share_error = Some(format!("{e:#}"));
            }
        }
    }


    fn activate_backend(&mut self) {
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

    pub(crate) fn handle_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }

        match &self.screen {
            Screen::FirstRunChoice => match key.code {
                KeyCode::Down | KeyCode::Char('j') => self.first_run_state.select_next(),
                KeyCode::Up | KeyCode::Char('k') => self.first_run_state.select_previous(),
                KeyCode::PageDown => {
                    let step = self.page_step();
                    page_select(&mut self.first_run_state, FIRST_RUN_MENU.len(), true, step);
                }
                KeyCode::PageUp => {
                    let step = self.page_step();
                    page_select(&mut self.first_run_state, FIRST_RUN_MENU.len(), false, step);
                }
                KeyCode::Esc => self.quit = true,
                KeyCode::Enter => self.activate_first_run(),
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
                KeyCode::PageDown => {
                    let step = self.page_step();
                    page_select(
                        &mut self.profile_list_state,
                        self.config.profiles.len(),
                        true,
                        step,
                    );
                }
                KeyCode::PageUp => {
                    let step = self.page_step();
                    page_select(
                        &mut self.profile_list_state,
                        self.config.profiles.len(),
                        false,
                        step,
                    );
                }
                KeyCode::Esc | KeyCode::Char('q') => self.quit = true,
                KeyCode::Char('n') => {
                    self.clear_creation_scratch();
                    self.screen = Screen::CreateProfileName;
                }
                KeyCode::Enter if !self.config.profiles.is_empty() => self.activate_home_profile(),
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
                KeyCode::PageDown => {
                    let step = self.page_step();
                    let len = self.visible_snapshot_indices().len();
                    page_select(&mut self.list_state, len, true, step);
                }
                KeyCode::PageUp => {
                    let step = self.page_step();
                    let len = self.visible_snapshot_indices().len();
                    page_select(&mut self.list_state, len, false, step);
                }
                KeyCode::Enter => self.activate_selected_snapshot(),
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
                KeyCode::Char('c') => {
                    // Need at least two snapshots in the current visible set to
                    // compare anything; otherwise the flow has no second pick.
                    let visible = self.visible_snapshot_indices();
                    if visible.len() < 2 {
                        return;
                    }
                    self.clear_compare_scratch();
                    let start = self.list_state.selected().unwrap_or(0).min(visible.len() - 1);
                    self.compare_picker_state.select(Some(start));
                    self.screen = Screen::SnapshotCompareFirst;
                }
                _ => {}
            },

            Screen::SnapshotCompareFirst => match key.code {
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.clear_compare_scratch();
                    self.screen = Screen::Snapshots;
                }
                KeyCode::Down | KeyCode::Char('j') => self.compare_picker_state.select_next(),
                KeyCode::Up | KeyCode::Char('k') => self.compare_picker_state.select_previous(),
                KeyCode::Home | KeyCode::Char('g') => {
                    self.compare_picker_state.select(Some(0));
                }
                KeyCode::End | KeyCode::Char('G') => {
                    let visible = self.visible_snapshot_indices();
                    if !visible.is_empty() {
                        self.compare_picker_state.select(Some(visible.len() - 1));
                    }
                }
                KeyCode::PageDown => {
                    let step = self.page_step();
                    let len = self.visible_snapshot_indices().len();
                    page_select(&mut self.compare_picker_state, len, true, step);
                }
                KeyCode::PageUp => {
                    let step = self.page_step();
                    let len = self.visible_snapshot_indices().len();
                    page_select(&mut self.compare_picker_state, len, false, step);
                }
                KeyCode::Enter => self.activate_compare_first(),
                _ => {}
            },

            Screen::SnapshotCompareSecond => match key.code {
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.compare_second_id = None;
                    self.compare_only_related = true;
                    // Restore picker to first-pick position so user lands where
                    // they were.
                    self.compare_picker_state = ListState::default();
                    if let Some(idx) = self.compare_first_row_idx {
                        let visible = self.visible_snapshot_indices();
                        if let Some(pos) = visible.iter().position(|&i| i == idx) {
                            self.compare_picker_state.select(Some(pos));
                        }
                    }
                    self.compare_first_id = None;
                    self.compare_first_row_idx = None;
                    self.screen = Screen::SnapshotCompareFirst;
                }
                KeyCode::Down | KeyCode::Char('j') => self.compare_picker_state.select_next(),
                KeyCode::Up | KeyCode::Char('k') => self.compare_picker_state.select_previous(),
                KeyCode::Home | KeyCode::Char('g') => {
                    self.compare_picker_state.select(Some(0));
                }
                KeyCode::End | KeyCode::Char('G') => {
                    let visible = self.compare_second_visible_indices();
                    if !visible.is_empty() {
                        self.compare_picker_state.select(Some(visible.len() - 1));
                    }
                }
                KeyCode::PageDown => {
                    let step = self.page_step();
                    let len = self.compare_second_visible_indices().len();
                    page_select(&mut self.compare_picker_state, len, true, step);
                }
                KeyCode::PageUp => {
                    let step = self.page_step();
                    let len = self.compare_second_visible_indices().len();
                    page_select(&mut self.compare_picker_state, len, false, step);
                }
                KeyCode::Char('a') => {
                    self.compare_only_related = !self.compare_only_related;
                    // Selection index meaning changes with the toggle; reset
                    // to the top to avoid pointing at a row that fell out of
                    // (or wasn't in) the new set.
                    let visible = self.compare_second_visible_indices();
                    self.compare_picker_state = ListState::default();
                    if !visible.is_empty() {
                        self.compare_picker_state.select(Some(0));
                    }
                }
                KeyCode::Enter => self.activate_compare_second(),
                _ => {}
            },

            Screen::SnapshotCompareResults => match key.code {
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.clear_compare_scratch();
                    self.screen = Screen::Snapshots;
                }
                KeyCode::Down | KeyCode::Char('j') => self.compare_results_state.select_next(),
                KeyCode::Up | KeyCode::Char('k') => self.compare_results_state.select_previous(),
                KeyCode::Home | KeyCode::Char('g') => {
                    self.compare_results_state.select(Some(0));
                }
                KeyCode::End | KeyCode::Char('G') => {
                    if let Some((_, changes)) = &self.compare_results
                        && !changes.is_empty()
                    {
                        self.compare_results_state.select(Some(changes.len() - 1));
                    }
                }
                KeyCode::PageDown => {
                    let step = self.page_step();
                    let len = self
                        .compare_results
                        .as_ref()
                        .map(|(_, c)| c.len())
                        .unwrap_or(0);
                    page_select(&mut self.compare_results_state, len, true, step);
                }
                KeyCode::PageUp => {
                    let step = self.page_step();
                    let len = self
                        .compare_results
                        .as_ref()
                        .map(|(_, c)| c.len())
                        .unwrap_or(0);
                    page_select(&mut self.compare_results_state, len, false, step);
                }
                _ => {}
            },

            Screen::SnapshotFilterDim => match key.code {
                KeyCode::Down | KeyCode::Char('j') => self.filter_picker_state.select_next(),
                KeyCode::Up | KeyCode::Char('k') => self.filter_picker_state.select_previous(),
                KeyCode::PageDown => {
                    let step = self.page_step();
                    let len = filter_dim_entries(self.snapshot_filter.is_some()).len();
                    page_select(&mut self.filter_picker_state, len, true, step);
                }
                KeyCode::PageUp => {
                    let step = self.page_step();
                    let len = filter_dim_entries(self.snapshot_filter.is_some()).len();
                    page_select(&mut self.filter_picker_state, len, false, step);
                }
                KeyCode::Esc | KeyCode::Char('q') => self.screen = Screen::Snapshots,
                KeyCode::Enter => self.activate_filter_dim(),
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
                KeyCode::PageDown => {
                    let step = self.page_step();
                    let len = self.filter_values.len();
                    page_select(&mut self.filter_picker_state, len, true, step);
                }
                KeyCode::PageUp => {
                    let step = self.page_step();
                    let len = self.filter_values.len();
                    page_select(&mut self.filter_picker_state, len, false, step);
                }
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.filter_pending_kind = None;
                    self.filter_picker_state = ListState::default();
                    self.filter_picker_state.select(Some(0));
                    self.screen = Screen::SnapshotFilterDim;
                }
                KeyCode::Enter => self.activate_filter_value(),
                _ => {}
            },

            Screen::SnapshotDeleteInfo => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.screen = Screen::SnapshotDeleteContentsLoading;
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
                    self.last_content_click = None;
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
                KeyCode::PageDown => {
                    let step = self.page_step();
                    if let Some(f) = self.browse_stack.last_mut() {
                        page_select(&mut f.list_state, f.items.len(), true, step);
                    }
                }
                KeyCode::PageUp => {
                    let step = self.page_step();
                    if let Some(f) = self.browse_stack.last_mut() {
                        page_select(&mut f.list_state, f.items.len(), false, step);
                    }
                }
                KeyCode::Enter => self.activate_snapshot_content(),
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
                    self.last_content_click = None;
                    self.screen = Screen::OpeningSnapshot;
                }
                _ => {}
            },

            Screen::OpeningSnapshot
            | Screen::LoadingDir
            | Screen::LoadingFileDetails
            | Screen::SnapshotDeleting
            | Screen::SnapshotDeleteContentsLoading
            | Screen::SnapshotCompareLoading => {}

            Screen::FileDetails => match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') | KeyCode::Backspace => {
                    self.stop_share();
                    self.file_details = None;
                    self.file_details_scroll = 0;
                    self.screen = Screen::SnapshotContents;
                }
                KeyCode::Char('s') => {
                    let is_file = self
                        .file_details
                        .as_ref()
                        .map(|d| matches!(d.kind, ContentKind::File))
                        .unwrap_or(false);
                    if is_file && self.share_target.is_some() {
                        // Auto-start the server when entering the share
                        // screen. Errors stay inline on ShareUrl.
                        self.start_share_server();
                        self.screen = Screen::ShareUrl;
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.file_details_scroll = self.file_details_scroll.saturating_add(1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.file_details_scroll = self.file_details_scroll.saturating_sub(1);
                }
                KeyCode::Home | KeyCode::Char('g') => {
                    self.file_details_scroll = 0;
                }
                KeyCode::PageDown => {
                    let step = self.page_step() as u16;
                    self.file_details_scroll = self.file_details_scroll.saturating_add(step);
                }
                KeyCode::PageUp => {
                    let step = self.page_step() as u16;
                    self.file_details_scroll = self.file_details_scroll.saturating_sub(step);
                }
                _ => {}
            },

            Screen::ShareUrl => match key.code {
                KeyCode::Esc | KeyCode::Backspace | KeyCode::Char('q') => {
                    // Open ↔ server running: pressing `d` starts the
                    // server and opens this screen; any back key stops it
                    // and returns to FileDetails.
                    self.stop_share_keep_target();
                    self.screen = Screen::FileDetails;
                }
                _ => {}
            },

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
                KeyCode::PageDown => {
                    let step = self.page_step();
                    page_select(&mut self.backend_list, BACKEND_ORDER.len(), true, step);
                }
                KeyCode::PageUp => {
                    let step = self.page_step();
                    page_select(&mut self.backend_list, BACKEND_ORDER.len(), false, step);
                }
                KeyCode::Enter => self.activate_backend(),
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

    pub(crate) fn handle_mouse(&mut self, m: MouseEvent) {
        // Only left-click and the vertical scroll wheel are wired up;
        // right/middle/drag/motion are ignored.
        match m.kind {
            MouseEventKind::Down(MouseButton::Left) => self.handle_left_click(m.row, m.column),
            MouseEventKind::ScrollDown => self.handle_wheel(true),
            MouseEventKind::ScrollUp => self.handle_wheel(false),
            _ => {}
        }
    }

    fn handle_left_click(&mut self, row: u16, col: u16) {
        let Some(area) = self.list_area else {
            return;
        };
        match &self.screen {
            Screen::FirstRunChoice => {
                if let Some(idx) =
                    click_to_index(area, self.first_run_state.offset(), FIRST_RUN_MENU.len(), row, col)
                {
                    self.first_run_state.select(Some(idx));
                    self.activate_first_run();
                }
            }
            Screen::Home => {
                let len = self.config.profiles.len();
                if let Some(idx) =
                    click_to_index(area, self.profile_list_state.offset(), len, row, col)
                {
                    self.profile_list_state.select(Some(idx));
                    self.activate_home_profile();
                }
            }
            Screen::BackendChoice => {
                if let Some(idx) =
                    click_to_index(area, self.backend_list.offset(), BACKEND_ORDER.len(), row, col)
                {
                    self.backend_list.select(Some(idx));
                    self.activate_backend();
                }
            }
            Screen::Snapshots => {
                let len = self.visible_snapshot_indices().len();
                if let Some(idx) = click_to_index(area, self.list_state.offset(), len, row, col) {
                    self.list_state.select(Some(idx));
                    self.activate_selected_snapshot();
                }
            }
            Screen::SnapshotCompareFirst => {
                let len = self.visible_snapshot_indices().len();
                if let Some(idx) =
                    click_to_index(area, self.compare_picker_state.offset(), len, row, col)
                {
                    self.compare_picker_state.select(Some(idx));
                    self.activate_compare_first();
                }
            }
            Screen::SnapshotCompareSecond => {
                let len = self.compare_second_visible_indices().len();
                if let Some(idx) =
                    click_to_index(area, self.compare_picker_state.offset(), len, row, col)
                {
                    self.compare_picker_state.select(Some(idx));
                    self.activate_compare_second();
                }
            }
            Screen::SnapshotCompareResults => {
                let len = self
                    .compare_results
                    .as_ref()
                    .map(|(_, c)| c.len())
                    .unwrap_or(0);
                if let Some(idx) =
                    click_to_index(area, self.compare_results_state.offset(), len, row, col)
                {
                    self.compare_results_state.select(Some(idx));
                }
            }
            Screen::SnapshotFilterDim => {
                let len = filter_dim_entries(self.snapshot_filter.is_some()).len();
                if let Some(idx) =
                    click_to_index(area, self.filter_picker_state.offset(), len, row, col)
                {
                    self.filter_picker_state.select(Some(idx));
                    self.activate_filter_dim();
                }
            }
            Screen::SnapshotFilterValue => {
                let len = self.filter_values.len();
                if let Some(idx) =
                    click_to_index(area, self.filter_picker_state.offset(), len, row, col)
                {
                    self.filter_picker_state.select(Some(idx));
                    self.activate_filter_value();
                }
            }
            Screen::SnapshotContents => {
                let Some(f) = self.browse_stack.last_mut() else {
                    return;
                };
                let len = f.items.len();
                let offset = f.list_state.offset();
                if let Some(idx) = click_to_index(area, offset, len, row, col) {
                    f.list_state.select(Some(idx));
                    let now = Instant::now();
                    let is_double = self
                        .last_content_click
                        .is_some_and(|(t, i)| i == idx && now.duration_since(t) < DOUBLE_CLICK);
                    if is_double {
                        // Consume the pair so a third click doesn't re-fire.
                        self.last_content_click = None;
                        self.open_selected_file_details();
                    } else {
                        self.last_content_click = Some((now, idx));
                        self.activate_snapshot_content();
                    }
                }
            }
            // FileDetails has no list; clicks are ignored.
            // All other screens (Loading/Verifying/inputs/confirm dialogs)
            // don't have a selectable list.
            _ => {}
        }
    }

    fn handle_wheel(&mut self, down: bool) {
        match &self.screen {
            Screen::FirstRunChoice => {
                if down {
                    self.first_run_state.select_next();
                } else {
                    self.first_run_state.select_previous();
                }
            }
            Screen::Home => {
                if down {
                    self.profile_list_state.select_next();
                } else {
                    self.profile_list_state.select_previous();
                }
            }
            Screen::BackendChoice => {
                if down {
                    self.backend_list.select_next();
                } else {
                    self.backend_list.select_previous();
                }
            }
            Screen::Snapshots => {
                if down {
                    self.list_state.select_next();
                } else {
                    self.list_state.select_previous();
                }
            }
            Screen::SnapshotCompareFirst | Screen::SnapshotCompareSecond => {
                if down {
                    self.compare_picker_state.select_next();
                } else {
                    self.compare_picker_state.select_previous();
                }
            }
            Screen::SnapshotCompareResults => {
                if down {
                    self.compare_results_state.select_next();
                } else {
                    self.compare_results_state.select_previous();
                }
            }
            Screen::SnapshotFilterDim | Screen::SnapshotFilterValue => {
                if down {
                    self.filter_picker_state.select_next();
                } else {
                    self.filter_picker_state.select_previous();
                }
            }
            Screen::SnapshotContents => {
                if let Some(f) = self.browse_stack.last_mut() {
                    if down {
                        f.list_state.select_next();
                    } else {
                        f.list_state.select_previous();
                    }
                }
            }
            Screen::FileDetails => {
                if down {
                    self.file_details_scroll = self.file_details_scroll.saturating_add(1);
                } else {
                    self.file_details_scroll = self.file_details_scroll.saturating_sub(1);
                }
            }
            _ => {}
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

    fn boot_app_with_snapshots(snaps: Vec<SnapshotRow>) -> App {
        let tmp = std::env::temp_dir().join(format!(
            "wrustic-app-test-{}-{}",
            std::process::id(),
            uniq()
        ));
        let mut app = App::boot(Some(tmp)).expect("boot");
        app.snapshots = snaps;
        app
    }

    // Cheap monotonic counter for unique config-dir names per test.
    fn uniq() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        N.fetch_add(1, Ordering::Relaxed)
    }

    #[test]
    fn compare_related_filter_matches_host_and_paths() {
        let mut app = boot_app_with_snapshots(vec![
            row("laptop", &[], &["/home"]),  // 0 — picked as first
            row("laptop", &[], &["/home"]),  // 1 — related
            row("laptop", &[], &["/etc"]),   // 2 — same host, different paths
            row("server", &[], &["/home"]),  // 3 — different host
        ]);
        app.compare_first_row_idx = Some(0);
        app.compare_only_related = true;
        assert_eq!(app.compare_second_visible_indices(), vec![1]);
    }

    #[test]
    fn compare_related_filter_ignores_path_order() {
        let mut app = boot_app_with_snapshots(vec![
            row("laptop", &[], &["/home", "/etc"]),
            row("laptop", &[], &["/etc", "/home"]),
        ]);
        app.compare_first_row_idx = Some(0);
        app.compare_only_related = true;
        assert_eq!(app.compare_second_visible_indices(), vec![1]);
    }

    #[test]
    fn compare_show_all_includes_everything_except_first() {
        let mut app = boot_app_with_snapshots(vec![
            row("laptop", &[], &["/home"]),
            row("laptop", &[], &["/etc"]),
            row("server", &[], &["/home"]),
        ]);
        app.compare_first_row_idx = Some(0);
        app.compare_only_related = false;
        assert_eq!(app.compare_second_visible_indices(), vec![1, 2]);
    }

    #[test]
    fn compare_second_respects_active_snapshot_filter() {
        let mut app = boot_app_with_snapshots(vec![
            row("laptop", &[], &["/home"]),
            row("laptop", &[], &["/home"]),
            row("server", &[], &["/home"]),
        ]);
        app.snapshot_filter = Some(SnapshotFilter::Host("laptop".into()));
        app.compare_first_row_idx = Some(0);
        app.compare_only_related = false;
        // Even with related=off, the host filter narrows to laptop rows only.
        assert_eq!(app.compare_second_visible_indices(), vec![1]);
    }

    #[test]
    fn click_to_index_maps_interior_rows_through_offset() {
        // A bordered 20×10 list at terminal (5, 2): borders consume row 2,
        // row 11, col 5 and col 24. Interior rows are 3..=10.
        let area = Rect { x: 5, y: 2, width: 20, height: 10 };
        // Clicking the first interior row (row=3) with offset=0 → idx 0.
        assert_eq!(click_to_index(area, 0, 100, 3, 10), Some(0));
        // Last interior row (row=10) with offset=0 → idx 7.
        assert_eq!(click_to_index(area, 0, 100, 10, 10), Some(7));
        // Same click with offset=4 → idx 11.
        assert_eq!(click_to_index(area, 4, 100, 10, 10), Some(11));
    }

    #[test]
    fn click_to_index_rejects_borders_and_outside() {
        let area = Rect { x: 5, y: 2, width: 20, height: 10 };
        // Top border row.
        assert_eq!(click_to_index(area, 0, 100, 2, 10), None);
        // Bottom border row.
        assert_eq!(click_to_index(area, 0, 100, 11, 10), None);
        // Left border column.
        assert_eq!(click_to_index(area, 0, 100, 5, 5), None);
        // Right border column.
        assert_eq!(click_to_index(area, 0, 100, 5, 24), None);
        // Above and below the rect entirely.
        assert_eq!(click_to_index(area, 0, 100, 0, 10), None);
        assert_eq!(click_to_index(area, 0, 100, 99, 10), None);
    }

    #[test]
    fn click_to_index_clamps_to_list_length() {
        let area = Rect { x: 0, y: 0, width: 10, height: 10 };
        // Interior rows 1..=8, but only 3 items in the list.
        assert_eq!(click_to_index(area, 0, 3, 1, 5), Some(0));
        assert_eq!(click_to_index(area, 0, 3, 3, 5), Some(2));
        // Row 4 is the empty area past the last item.
        assert_eq!(click_to_index(area, 0, 3, 4, 5), None);
        // Empty list rejects all clicks.
        assert_eq!(click_to_index(area, 0, 0, 1, 5), None);
    }

    fn list_state_at(offset: usize, selected: usize) -> ListState {
        ListState::default().with_offset(offset).with_selected(Some(selected))
    }

    #[test]
    fn page_select_forward_advances_viewport_and_selects_top() {
        // First PageDown from the top: viewport jumps from 0 to page_size,
        // cursor lands on the first item of the new page.
        let mut s = list_state_at(0, 0);
        page_select(&mut s, 25, true, 10);
        assert_eq!(s.offset(), 10);
        assert_eq!(s.selected(), Some(10));
        // Subsequent PageDown advances another full page.
        page_select(&mut s, 25, true, 10);
        assert_eq!(s.offset(), 20);
        assert_eq!(s.selected(), Some(20));
    }

    #[test]
    fn page_select_forward_clamps_to_last_item_on_last_page() {
        // Already on the last (partial) page — can't advance a full page,
        // so cursor moves to the last item.
        let mut s = list_state_at(20, 20);
        page_select(&mut s, 25, true, 10);
        assert_eq!(s.selected(), Some(24));
        // Pressing again is a no-op.
        page_select(&mut s, 25, true, 10);
        assert_eq!(s.selected(), Some(24));
    }

    #[test]
    fn page_select_forward_handles_list_shorter_than_page() {
        // Whole list fits on one page — first PageDown goes straight to last.
        let mut s = list_state_at(0, 0);
        page_select(&mut s, 5, true, 10);
        assert_eq!(s.selected(), Some(4));
    }

    #[test]
    fn page_select_backward_advances_viewport_and_selects_top() {
        // PageUp from a deep page rewinds the viewport by page_size and
        // selects the first item of the new viewport.
        let mut s = list_state_at(15, 24);
        page_select(&mut s, 25, false, 10);
        assert_eq!(s.offset(), 5);
        assert_eq!(s.selected(), Some(5));
        // Another PageUp clamps to offset 0, cursor on index 0.
        page_select(&mut s, 25, false, 10);
        assert_eq!(s.offset(), 0);
        assert_eq!(s.selected(), Some(0));
    }

    #[test]
    fn page_select_handles_empty_list() {
        let mut s = list_state_at(0, 0);
        page_select(&mut s, 0, true, 10);
        assert_eq!(s.selected(), None);
    }
}
