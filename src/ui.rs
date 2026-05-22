use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, List, ListItem, Paragraph, Wrap},
};
use tui_input::Input;

use crate::app::{App, BACKEND_ORDER, FIRST_RUN_MENU, Screen, filter_dim_entries};
use crate::repo::ContentKind;

pub(crate) fn render(frame: &mut Frame, app: &mut App) {
    let [top, body, bottom] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    render_top_bar(frame, app, top);
    render_body(frame, app, body);
    render_bottom_bar(frame, app, bottom);
}

fn render_top_bar(frame: &mut Frame, app: &App, area: Rect) {
    let text = match &app.active_profile_name {
        Some(name) => format!(" wrustic — profile: {name}"),
        None => " wrustic".to_string(),
    };
    let para = Paragraph::new(text).style(
        Style::new()
            .fg(Color::Black)
            .bg(Color::Green)
            .add_modifier(Modifier::BOLD),
    );
    frame.render_widget(para, area);
}

fn render_bottom_bar(frame: &mut Frame, app: &App, area: Rect) {
    let text = bottom_bar_text(&app.screen);
    let para = Paragraph::new(format!(" {text}"))
        .style(Style::new().fg(Color::Black).bg(Color::DarkGray));
    frame.render_widget(para, area);
}

fn bottom_bar_text(screen: &Screen) -> &'static str {
    match screen {
        Screen::FirstRunChoice => "j/k move  Enter pick  Esc quit",
        Screen::RestoreKeyWait => "Enter retry  Esc back",
        Screen::KeyCreated => "Enter continue  Esc quit",
        Screen::Home => "j/k move  Enter open  n new  e edit  d delete  q quit",
        Screen::Snapshots => {
            "j/k move  g/G top/bottom  Enter browse  c compare  f filter  d delete  r refresh  q/Esc back"
        }
        Screen::SnapshotFilterDim => "j/k move  Enter pick  Esc back",
        Screen::SnapshotFilterValue => "j/k move  g/G top/bottom  Enter pick  Esc back",
        Screen::SnapshotDeleteInfo => "y proceed  n/Esc cancel",
        Screen::SnapshotDeleteConfirm => "y confirm delete  n/Esc cancel",
        Screen::SnapshotDeleteError(_) => "any key to continue",
        Screen::SnapshotContents => {
            "j/k move  g/G top/bottom  Enter open  Backspace up  r reload  q/Esc back"
        }
        Screen::SnapshotCompareFirst => {
            "j/k move  g/G top/bottom  Enter pick FIRST  Esc cancel"
        }
        Screen::SnapshotCompareSecond => {
            "j/k move  g/G top/bottom  Enter pick SECOND  a toggle related/all  Esc back"
        }
        Screen::SnapshotCompareResults => "j/k move  g/G top/bottom  q/Esc back",
        Screen::OpeningSnapshot
        | Screen::LoadingDir
        | Screen::Loading
        | Screen::Verifying
        | Screen::SnapshotDeleting
        | Screen::SnapshotCompareLoading => "working…",
        Screen::CreateProfileName => "type  Enter submit  Esc cancel",
        Screen::BackendChoice => "j/k move  Enter pick  Esc back",
        Screen::LocalPath => "type  Enter submit  Esc back",
        Screen::RestConfig | Screen::S3Location | Screen::S3Credentials => {
            "Tab/Shift+Tab field  Enter continue  Esc back"
        }
        Screen::Password => "type  Enter save  Esc back",
        Screen::ConfirmDelete => "y confirm  n/Esc cancel",
        Screen::VerifyFailed(_) => "r retry  s save anyway  Esc discard",
        Screen::Error(_) => "any key to continue",
    }
}

fn render_body(frame: &mut Frame, app: &mut App, area: Rect) {
    match &app.screen {
        Screen::FirstRunChoice => render_first_run_choice(frame, app, area),
        Screen::RestoreKeyWait => render_restore_wait(frame, app, area),
        Screen::KeyCreated => render_key_created(frame, app, area),
        Screen::Home => render_home(frame, app, area),
        Screen::CreateProfileName => render_input(
            frame,
            area,
            "Profile name",
            &app.new_profile_name,
            false,
            "Give this profile a short name, e.g. 'laptop-local'",
        ),
        Screen::BackendChoice => render_backend_choice(frame, app, area),
        Screen::LocalPath => render_input(
            frame,
            area,
            &profile_title("Local repository path", app),
            &app.local_path,
            false,
            "Filesystem path, e.g. /tmp/wrustic-test-repo",
        ),
        Screen::RestConfig => render_rest_config(frame, app, area),
        Screen::S3Location => render_s3_location(frame, app, area),
        Screen::S3Credentials => render_s3_credentials(frame, app, area),
        Screen::Password => {
            render_input(
                frame,
                area,
                &profile_title("Repository password", app),
                &app.password,
                true,
                "Restic repository password",
            );
        }
        Screen::ConfirmDelete => {
            let name = app
                .pending_delete
                .and_then(|i| app.config.name_at(i))
                .map(String::as_str)
                .unwrap_or("(unknown)");
            let body = format!("Delete profile '{name}'?");
            let para = Paragraph::new(body)
                .style(Style::new().fg(Color::Yellow))
                .block(Block::bordered().title("Confirm delete"));
            frame.render_widget(para, area);
        }
        Screen::Loading => {
            let para = Paragraph::new("Opening repository and reading snapshots…")
                .block(Block::bordered().title("Loading"));
            frame.render_widget(para, area);
        }
        Screen::Verifying => {
            let para = Paragraph::new("Verifying profile — opening repository with the entered credentials…")
                .wrap(Wrap { trim: false })
                .block(Block::bordered().title("Verifying"));
            frame.render_widget(para, area);
        }
        Screen::VerifyFailed(msg) => {
            let body = format!(
                "Could not open the repository with this profile:\n\n{msg}",
            );
            let para = Paragraph::new(body)
                .style(Style::new().fg(Color::Yellow))
                .wrap(Wrap { trim: false })
                .block(Block::bordered().title("Verification failed"));
            frame.render_widget(para, area);
        }
        Screen::Snapshots => render_snapshots(frame, app, area),
        Screen::SnapshotFilterDim => render_filter_dim(frame, app, area),
        Screen::SnapshotFilterValue => render_filter_value(frame, app, area),
        Screen::SnapshotDeleteInfo => render_snapshot_delete_info(frame, app, area),
        Screen::SnapshotDeleteConfirm => render_snapshot_delete_confirm(frame, app, area),
        Screen::SnapshotDeleting => {
            let para = Paragraph::new("Running `restic forget`…")
                .block(Block::bordered().title("Deleting snapshot"));
            frame.render_widget(para, area);
        }
        Screen::SnapshotDeleteError(msg) => {
            let body = format!("{msg}\n\nPress any key to return to the snapshot list.");
            let para = Paragraph::new(body)
                .style(Style::new().fg(Color::Red))
                .wrap(Wrap { trim: false })
                .block(Block::bordered().title("Delete unavailable"));
            frame.render_widget(para, area);
        }
        Screen::OpeningSnapshot => {
            let para = Paragraph::new("Opening snapshot — reading root tree…")
                .block(Block::bordered().title("Loading"));
            frame.render_widget(para, area);
        }
        Screen::LoadingDir => {
            let para = Paragraph::new("Loading directory…")
                .block(Block::bordered().title("Loading"));
            frame.render_widget(para, area);
        }
        Screen::SnapshotContents => render_snapshot_contents(frame, app, area),
        Screen::SnapshotCompareFirst => render_compare_first(frame, app, area),
        Screen::SnapshotCompareSecond => render_compare_second(frame, app, area),
        Screen::SnapshotCompareLoading => render_compare_loading(frame, app, area),
        Screen::SnapshotCompareResults => render_compare_results(frame, app, area),
        Screen::Error(msg) => {
            let title = if app.error_is_fatal {
                "Error — fatal"
            } else {
                "Error"
            };
            let para = Paragraph::new(msg.as_str())
                .style(Style::new().fg(Color::Red))
                .wrap(Wrap { trim: false })
                .block(Block::bordered().title(title));
            frame.render_widget(para, area);
        }
    }
}

fn render_first_run_choice(frame: &mut Frame, app: &mut App, area: Rect) {
    let [intro_area, list_area] = Layout::vertical([
        Constraint::Length(5),
        Constraint::Fill(1),
    ])
    .areas(area);

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
        .highlight_style(selection_highlight())
        .highlight_symbol(">> ");
    frame.render_stateful_widget(list, list_area, &mut app.first_run_state);
}

fn render_restore_wait(frame: &mut Frame, app: &App, area: Rect) {
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
    frame.render_widget(para, area);
}

fn render_key_created(frame: &mut Frame, app: &App, area: Rect) {
    let body = format!(
        "A new age key was created.\n\nKey file (back this up now!):\n    {}\n\nPublic key (recipient):\n    {}\n\nIf you lose the key file, every saved profile becomes unrecoverable. Copy it to a safe place before adding profiles.\n\nPress Enter to continue.",
        app.paths.identity.display(),
        app.created_pubkey,
    );
    let para = Paragraph::new(body)
        .wrap(Wrap { trim: false })
        .block(Block::bordered().title("New age key created"));
    frame.render_widget(para, area);
}

fn selection_highlight() -> Style {
    Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD)
}

// Decorate a creation/edit screen title with the in-progress profile name so
// the user can always see which profile they are editing.
fn profile_title(base: &str, app: &App) -> String {
    let name = app.new_profile_name.value();
    if name.is_empty() {
        base.to_string()
    } else {
        format!("{base} — profile '{name}'")
    }
}

fn render_home(frame: &mut Frame, app: &mut App, area: Rect) {
    let title = "Profiles";

    if app.config.profiles.is_empty() {
        let para = Paragraph::new("No profiles yet. Press 'n' to create one, 'q' to quit.")
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(title));
        frame.render_widget(para, area);
        return;
    }

    let items: Vec<ListItem> = app
        .config
        .profiles
        .iter()
        .map(|(name, p)| ListItem::new(format!("{:<24} [{}]", name, p.backend_kind().label())))
        .collect();

    let list = List::new(items)
        .block(Block::bordered().title(title))
        .highlight_style(selection_highlight())
        .highlight_symbol(">> ");

    frame.render_stateful_widget(list, area, &mut app.profile_list_state);
}

fn render_backend_choice(frame: &mut Frame, app: &mut App, area: Rect) {
    let items: Vec<ListItem> = BACKEND_ORDER
        .iter()
        .map(|k| ListItem::new(k.label()))
        .collect();

    let name = app.new_profile_name.value();
    let title = if name.is_empty() {
        "Choose backend".to_string()
    } else {
        format!("Choose backend for '{name}'")
    };

    let list = List::new(items)
        .block(Block::bordered().title(title))
        .highlight_style(selection_highlight())
        .highlight_symbol(">> ");

    frame.render_stateful_widget(list, area, &mut app.backend_list);
}

fn render_input(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    input: &Input,
    masked: bool,
    help: &str,
) {
    let [_top, input_area, help_area, _bottom] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(area);

    draw_input_field(frame, input_area, title, input, masked, true);

    let help = Paragraph::new(help).style(Style::new().fg(Color::DarkGray));
    frame.render_widget(help, help_area);
}

fn render_grouped_input(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    fields: &[(&str, &Input, bool)],
    focus: usize,
    help: &str,
) {
    let outer = Block::bordered().title(title);
    let inner_area = outer.inner(area);
    frame.render_widget(outer, area);

    let mut constraints: Vec<Constraint> = fields.iter().map(|_| Constraint::Length(3)).collect();
    constraints.push(Constraint::Length(1));
    constraints.push(Constraint::Fill(1));
    let areas = Layout::vertical(constraints).split(inner_area);

    for (i, (label, input, masked)) in fields.iter().enumerate() {
        draw_input_field(frame, areas[i], label, input, *masked, i == focus);
    }

    let help_para = Paragraph::new(help).style(Style::new().fg(Color::DarkGray));
    frame.render_widget(help_para, areas[fields.len()]);
}

// Render a single bordered input box. When `focused`, paints a yellow border
// and places the terminal cursor at the input's column position, scrolling
// horizontally so the cursor stays visible.
fn draw_input_field(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    input: &Input,
    masked: bool,
    focused: bool,
) {
    let value = input.value();
    let display: String = if masked {
        "*".repeat(value.chars().count())
    } else {
        value.to_string()
    };

    // For masked fields every char is a single column, so cursor and scroll
    // are simple codepoint math. For non-masked fields use the Input's own
    // grapheme-aware visual computation.
    let inner_width = area.width.saturating_sub(2);
    let (cursor_col, scroll) = if masked {
        let cur = input.cursor();
        let w = inner_width as usize;
        let scroll = if w == 0 { 0 } else { cur.saturating_sub(w - 1) };
        (cur, scroll)
    } else {
        let w = inner_width.max(1) as usize;
        let scroll = input.visual_scroll(w);
        (input.visual_cursor(), scroll)
    };

    let mut block = Block::bordered().title(title);
    if focused {
        block = block.border_style(Style::new().fg(Color::Yellow));
    }
    let para = Paragraph::new(display)
        .scroll((0, scroll as u16))
        .block(block);
    frame.render_widget(para, area);

    if focused {
        let visible_col = cursor_col.saturating_sub(scroll) as u16;
        frame.set_cursor_position((area.x + 1 + visible_col, area.y + 1));
    }
}

fn render_rest_config(frame: &mut Frame, app: &App, area: Rect) {
    let title = profile_title("REST backend", app);
    let fields = [
        ("URL (required)", &app.rest_url, false),
        ("Username (optional)", &app.rest_user, false),
        ("Password (optional)", &app.rest_password, true),
    ];
    render_grouped_input(
        frame,
        area,
        &title,
        &fields,
        app.field_focus,
        "Anonymous server? Leave user/password blank.",
    );
}

fn render_s3_location(frame: &mut Frame, app: &App, area: Rect) {
    let title = profile_title("S3 location", app);
    let fields = [
        ("Endpoint (optional)", &app.s3_endpoint, false),
        ("Bucket (required)", &app.s3_bucket, false),
        (
            "Region (optional, defaults to us-east-1)",
            &app.s3_region,
            false,
        ),
        ("Path within bucket (optional)", &app.s3_root, false),
    ];
    render_grouped_input(
        frame,
        area,
        &title,
        &fields,
        app.field_focus,
        "Leave Endpoint blank for AWS. Backblaze B2 uses region 'auto'. MinIO/rclone: http://127.0.0.1:8333",
    );
}

fn render_s3_credentials(frame: &mut Frame, app: &App, area: Rect) {
    let title = profile_title("S3 credentials", app);
    let fields = [
        ("Access key ID", &app.s3_access_key, false),
        ("Secret access key", &app.s3_secret_key, true),
    ];
    render_grouped_input(
        frame,
        area,
        &title,
        &fields,
        app.field_focus,
        "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY equivalents.",
    );
}

fn render_snapshots(frame: &mut Frame, app: &mut App, area: Rect) {
    let visible = app.visible_snapshot_indices();
    let total = app.snapshots.len();
    let title = match &app.snapshot_filter {
        None => format!("Snapshots ({total})"),
        Some(f) => format!(
            "Snapshots ({} of {}, {}={})",
            visible.len(),
            total,
            f.kind().label(),
            f.value()
        ),
    };

    render_snapshot_picker(frame, area, &title, &app.snapshots, &visible, &mut app.list_state);
}

// Shared picker rendering for the Snapshots screen and the two compare-flow
// pick screens. Indices are absolute into `snapshots`; the picker's own
// `ListState` is positional within `visible`.
fn render_snapshot_picker(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    snapshots: &[crate::repo::SnapshotRow],
    visible: &[usize],
    state: &mut ratatui::widgets::ListState,
) {
    let items: Vec<ListItem> = visible
        .iter()
        .map(|&i| &snapshots[i])
        .map(|s| {
            let tags = if s.tags.is_empty() {
                String::new()
            } else {
                format!("[{}]", s.tags.join(","))
            };
            ListItem::new(format!(
                "{:<8}  {:<19}  {:<20}  {:<20}  {}",
                short_snap_id(&s.id),
                s.time,
                s.host,
                tags,
                s.paths.join(",")
            ))
        })
        .collect();

    let list = List::new(items)
        .block(Block::bordered().title(title))
        .highlight_style(selection_highlight())
        .highlight_symbol(">> ");

    frame.render_stateful_widget(list, area, state);
}

fn render_compare_first(frame: &mut Frame, app: &mut App, area: Rect) {
    let visible = app.visible_snapshot_indices();
    let title = format!("Compare — pick FIRST snapshot ({})", visible.len());
    render_snapshot_picker(
        frame,
        area,
        &title,
        &app.snapshots,
        &visible,
        &mut app.compare_picker_state,
    );
}

fn render_compare_second(frame: &mut Frame, app: &mut App, area: Rect) {
    let visible = app.compare_second_visible_indices();
    let scope = if app.compare_only_related { "related" } else { "all" };
    let first_short = app
        .compare_first_id
        .as_deref()
        .map(short_snap_id)
        .unwrap_or("?");
    let title = format!(
        "Compare {first_short}.. — pick SECOND snapshot ({}, {scope})",
        visible.len()
    );
    render_snapshot_picker(
        frame,
        area,
        &title,
        &app.snapshots,
        &visible,
        &mut app.compare_picker_state,
    );
}

fn render_compare_loading(frame: &mut Frame, app: &App, area: Rect) {
    let first = app.compare_first_id.as_deref().map(short_snap_id).unwrap_or("?");
    let second = app.compare_second_id.as_deref().map(short_snap_id).unwrap_or("?");
    let body = format!("Running `restic diff {first}..{second} --json`…");
    let para = Paragraph::new(body).block(Block::bordered().title("Computing diff"));
    frame.render_widget(para, area);
}

fn render_compare_results(frame: &mut Frame, app: &mut App, area: Rect) {
    let first = app.compare_first_id.as_deref().map(short_snap_id).unwrap_or("?");
    let second = app.compare_second_id.as_deref().map(short_snap_id).unwrap_or("?");
    let title = format!("Diff {first}..{second}");

    let outer = Block::bordered().title(title);
    let inner = outer.inner(area);
    frame.render_widget(outer, area);

    let [header, body] = Layout::vertical([Constraint::Length(3), Constraint::Fill(1)]).areas(inner);

    let (summary_text, changes_len) = match &app.compare_results {
        Some((sum, changes)) => (
            format!(
                "+{} files / -{} / M{}  |  +{} / -{}  ({} change{})",
                sum.added_files,
                sum.removed_files,
                sum.changed_files,
                human_size(sum.added_bytes),
                human_size(sum.removed_bytes),
                changes.len(),
                if changes.len() == 1 { "" } else { "s" },
            ),
            changes.len(),
        ),
        None => ("(no diff loaded)".to_string(), 0),
    };

    let summary_para = Paragraph::new(summary_text)
        .wrap(Wrap { trim: false })
        .block(Block::bordered().title("Summary"));
    frame.render_widget(summary_para, header);

    if changes_len == 0 {
        let para = Paragraph::new("No file-level changes between these snapshots.")
            .style(Style::new().fg(Color::DarkGray))
            .block(Block::bordered().title("Changes"));
        frame.render_widget(para, body);
        return;
    }

    let items: Vec<ListItem> = app
        .compare_results
        .as_ref()
        .unwrap()
        .1
        .iter()
        .map(|c| ListItem::new(format!("{}  {}", c.modifier.as_char(), c.path)))
        .collect();
    let list = List::new(items)
        .block(Block::bordered().title(format!("Changes ({changes_len})")))
        .highlight_style(selection_highlight())
        .highlight_symbol(">> ");
    frame.render_stateful_widget(list, body, &mut app.compare_results_state);
}

fn render_filter_dim(frame: &mut Frame, app: &mut App, area: Rect) {
    let entries = filter_dim_entries(app.snapshot_filter.is_some());
    let items: Vec<ListItem> = entries
        .iter()
        .map(|e| ListItem::new(e.label()))
        .collect();
    let list = List::new(items)
        .block(Block::bordered().title("Filter snapshots by"))
        .highlight_style(selection_highlight())
        .highlight_symbol(">> ");
    frame.render_stateful_widget(list, area, &mut app.filter_picker_state);
}

fn render_filter_value(frame: &mut Frame, app: &mut App, area: Rect) {
    let kind_label = app
        .filter_pending_kind
        .map(|k| k.label())
        .unwrap_or("value");
    let title = format!("Pick {} ({})", kind_label, app.filter_values.len());
    let items: Vec<ListItem> = app
        .filter_values
        .iter()
        .map(|v| ListItem::new(v.as_str()))
        .collect();
    let list = List::new(items)
        .block(Block::bordered().title(title))
        .highlight_style(selection_highlight())
        .highlight_symbol(">> ");
    frame.render_stateful_widget(list, area, &mut app.filter_picker_state);
}

fn render_snapshot_contents(frame: &mut Frame, app: &mut App, area: Rect) {
    if app.browse_stack.is_empty() {
        let para = Paragraph::new("No content loaded.")
            .block(Block::bordered().title("Snapshot contents"));
        frame.render_widget(para, area);
        return;
    }

    let path = app
        .browse_stack
        .iter()
        .skip(1)
        .map(|f| f.name.as_str())
        .collect::<Vec<_>>()
        .join("/");
    let path_display = if path.is_empty() { "/".to_string() } else { format!("/{path}") };
    let title = format!(
        "Snap {} {}",
        short_snap_id(&app.browse_snapshot_id),
        path_display,
    );

    let frame_idx = app.browse_stack.len() - 1;
    let top = &app.browse_stack[frame_idx];
    let items: Vec<ListItem> = top
        .items
        .iter()
        .map(|row| {
            if matches!(row.kind, ContentKind::Parent) {
                return ListItem::new("..".to_string());
            }
            let kind_char = match row.kind {
                ContentKind::Dir => 'd',
                ContentKind::File => '-',
                ContentKind::Symlink => 'l',
                ContentKind::Other => '?',
                ContentKind::Parent => '^',
            };
            let display_name = if matches!(row.kind, ContentKind::Dir) {
                format!("{}/", row.name)
            } else {
                row.name.clone()
            };
            let size_col = if matches!(row.kind, ContentKind::File) {
                format!("{:>10}", human_size(row.size))
            } else {
                String::from("          ")
            };
            ListItem::new(format!(
                "{}  {:<40}  {}  {}",
                kind_char, display_name, size_col, row.mtime
            ))
        })
        .collect();

    let list = List::new(items)
        .block(Block::bordered().title(title))
        .highlight_style(selection_highlight())
        .highlight_symbol(">> ");

    let top_mut = &mut app.browse_stack[frame_idx];
    frame.render_stateful_widget(list, area, &mut top_mut.list_state);
}

fn short_snap_id(id: &str) -> &str {
    let end = id.char_indices().nth(8).map(|(i, _)| i).unwrap_or(id.len());
    &id[..end]
}

// 1024-based suffixes matching `ls -h` (e.g. "4.2K", "1.7M"). Bytes are shown
// raw; larger values keep one decimal place.
fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "K", "M", "G", "T", "P"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{:.1} {}", v, UNITS[i])
}

fn render_snapshot_delete_info(frame: &mut Frame, app: &App, area: Rect) {
    let parsed = app.delete_details_parsed.as_ref();
    let raw = app.delete_details_raw.as_deref().unwrap_or("(no raw JSON)");

    let mut lines = String::new();
    if let Some(p) = parsed {
        lines.push_str(&format!("ID:       {}\n", p.id));
        if let Some(s) = &p.short_id {
            lines.push_str(&format!("Short ID: {s}\n"));
        }
        if let Some(t) = &p.time {
            lines.push_str(&format!("Time:     {t}\n"));
        }
        if let Some(h) = &p.hostname {
            lines.push_str(&format!("Host:     {h}\n"));
        }
        if let Some(u) = &p.username {
            lines.push_str(&format!("User:     {u}\n"));
        }
        if !p.paths.is_empty() {
            lines.push_str(&format!("Paths:    {}\n", p.paths.join(", ")));
        }
        if !p.tags.is_empty() {
            lines.push_str(&format!("Tags:     {}\n", p.tags.join(", ")));
        }
        if let Some(par) = &p.parent {
            lines.push_str(&format!("Parent:   {par}\n"));
        }
        if let Some(tree) = &p.tree {
            lines.push_str(&format!("Tree:     {tree}\n"));
        }
        if let Some(pv) = &p.program_version {
            lines.push_str(&format!("Program:  {pv}\n"));
        }
        if let Some(sum) = &p.summary {
            if let Some(n) = sum.total_files_processed {
                lines.push_str(&format!("Files:    {n}\n"));
            }
            if let Some(b) = sum.total_bytes_processed {
                lines.push_str(&format!("Bytes:    {b}\n"));
            }
            if let Some(b) = sum.data_added {
                lines.push_str(&format!("Added:    {b}\n"));
            }
            if let Some(b) = sum.data_added_packed {
                lines.push_str(&format!("Packed:   {b}\n"));
            }
            if let Some(s) = &sum.backup_start {
                lines.push_str(&format!("Start:    {s}\n"));
            }
            if let Some(s) = &sum.backup_end {
                lines.push_str(&format!("End:      {s}\n"));
            }
        }
    } else {
        lines.push_str("(no parsed details)\n");
    }

    let outer = Block::bordered().title("Snapshot details — press y to proceed");
    let inner = outer.inner(area);
    frame.render_widget(outer, area);

    // Half parsed, half raw JSON.
    let [top, bottom] = Layout::vertical([Constraint::Percentage(45), Constraint::Percentage(55)])
        .areas(inner);

    let parsed_para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(Block::bordered().title("Parsed"));
    frame.render_widget(parsed_para, top);

    let raw_para = Paragraph::new(raw)
        .wrap(Wrap { trim: false })
        .block(Block::bordered().title("Raw `restic snapshots --json`"));
    frame.render_widget(raw_para, bottom);
}

fn render_snapshot_delete_confirm(frame: &mut Frame, app: &App, area: Rect) {
    let id = app.delete_target.as_deref().unwrap_or("(unknown)");
    let paths = app
        .delete_details_parsed
        .as_ref()
        .map(|p| {
            if p.paths.is_empty() {
                "(no paths)".to_string()
            } else {
                p.paths.join(", ")
            }
        })
        .unwrap_or_else(|| "(unknown)".into());
    let body = format!(
        "Delete snapshot {id}?\n\nPaths: {paths}\n\nThis runs `restic forget {id}` (no prune). The snapshot reference will be removed; storage is reclaimed on a separate prune."
    );
    let para = Paragraph::new(body)
        .style(Style::new().fg(Color::Yellow))
        .wrap(Wrap { trim: false })
        .block(Block::bordered().title("Confirm snapshot delete"));
    frame.render_widget(para, area);
}

#[cfg(test)]
mod tests {
    use super::human_size;

    #[test]
    fn human_size_formats() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1023), "1023 B");
        assert_eq!(human_size(1024), "1.0 K");
        assert_eq!(human_size(1536), "1.5 K");
        assert_eq!(human_size(1024 * 1024), "1.0 M");
        assert_eq!(human_size(3 * 1024 * 1024 * 1024), "3.0 G");
    }
}
