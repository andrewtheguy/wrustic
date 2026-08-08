use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, HighlightSpacing, List, ListItem, Paragraph, Row, Table, TableState, Wrap},
};
use tui_input::Input;

use crate::app::{App, BACKEND_ORDER, Screen, filter_dim_entries};
use crate::repo::ContentKind;

pub(crate) fn render(frame: &mut Frame, app: &mut App) {
    let [top, body, bottom] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Fill(1),
        Constraint::Length(3),
    ])
    .areas(frame.area());

    render_top_bar(frame, app, top);
    render_body(frame, app, body);
    render_bottom_bar(frame, app, bottom);
    // Last, and over the body only: the top and bottom bars stay readable so
    // the user can still see which profile they are in and that a key dismisses
    // the overlay.
    if app.help_overlay && let Some(rows) = help_rows(&app.screen) {
        render_help_overlay(frame, body, rows);
    }
    if app.snapshot_info_overlay
        && matches!(app.screen, Screen::Snapshots)
        && let Some(s) = app.selected_snapshot()
    {
        render_snapshot_info_overlay(frame, body, s);
    }
}

/// The full key list for a screen, shown by `?`. `None` means the screen has no
/// keys beyond what its footer already spells out, and `?` does nothing there.
///
/// Lives next to `bottom_bar_text` on purpose: the footer is the abbreviation of
/// this list, and the two drifting apart is the failure mode worth designing
/// against.
pub(crate) fn help_rows(screen: &Screen) -> Option<&'static [(&'static str, &'static str)]> {
    Some(match screen {
        Screen::Home => &[
            ("Up/Dn", "move between profiles"),
            ("PgUp/PgDn", "page"),
            ("Enter", "open — lists this profile's snapshots"),
            ("n", "new profile"),
            ("e", "edit the selected profile"),
            ("d", "delete the selected profile"),
            ("q", "quit"),
        ],
        Screen::Snapshots => &[
            ("Up/Dn", "move between snapshots"),
            ("PgUp/PgDn", "page"),
            ("g / G", "jump to the first / last snapshot"),
            ("Enter", "browse this snapshot's files"),
            ("i", "show this snapshot's full details (untruncated paths)"),
            ("s", "share this snapshot as a read-only SMB mount"),
            ("c", "compare this snapshot against another"),
            ("f", "filter the list by host, tag or path"),
            ("d", "delete this snapshot (no prune)"),
            ("t", "edit this snapshot's tags"),
            ("p", "prune the repository"),
            ("r", "reload the snapshot list"),
            ("q / Esc", "back to the profile list"),
        ],
        Screen::SnapshotContents => &[
            ("Up/Dn", "move between entries"),
            ("PgUp/PgDn", "page"),
            ("g / G", "jump to the first / last entry"),
            ("Enter", "open a directory, or show a file's details"),
            ("Backspace", "up one directory"),
            ("r", "reload this directory"),
            ("q / Esc", "back to the snapshot list"),
        ],
        Screen::FileDetails => &[
            ("Up/Dn", "scroll"),
            ("PgUp/PgDn", "page"),
            ("g", "back to the top"),
            ("s", "share this one file over HTTP (expiring signed URL)"),
            ("Esc / Backspace / q", "back to the directory listing"),
        ],
        _ => return None,
    })
}

/// Where the help box goes: centred on `area`, sized to its content, and never
/// larger than `area`. The clamp is what keeps the box on an 80x24 terminal
/// where the longest description alone is wider than the screen.
fn help_popup_rect(area: Rect, rows: &[(&str, &str)]) -> Rect {
    let key_width = rows.iter().map(|(k, _)| k.chars().count()).max().unwrap_or(0);
    // Each line renders as " <key padded to key_width>  <description>".
    let longest_desc = rows.iter().map(|(_, d)| d.chars().count()).max().unwrap_or(0);
    let content_width = 1 + key_width + 2 + longest_desc;

    // +2 for the border, +1 for a right-hand margin.
    let want_w = (content_width + 3) as u16;
    // +2 for the border, +2 for the trailing blank line and the dismiss hint.
    let want_h = (rows.len() + 4) as u16;
    let w = want_w.min(area.width);
    let h = want_h.min(area.height);
    Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    }
}

/// A centred box over the body area. Sized to its content and clamped to the
/// area, so it neither wastes space on a big terminal nor overflows a small one.
fn render_help_overlay(frame: &mut Frame, area: Rect, rows: &[(&str, &str)]) {
    let key_width = rows.iter().map(|(k, _)| k.chars().count()).max().unwrap_or(0);
    let popup = help_popup_rect(area, rows);

    let mut lines: Vec<Line> = rows
        .iter()
        .map(|(k, d)| {
            Line::from(vec![
                Span::styled(
                    format!(" {k:key_width$}  "),
                    Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                ),
                Span::styled((*d).to_string(), Style::new().fg(Color::White)),
            ])
        })
        .collect();
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        " press any key to close this",
        Style::new().fg(Color::DarkGray),
    )));

    // Clear what is underneath first: without it the list behind the box shows
    // through wherever a help line is shorter than the box is wide.
    frame.render_widget(ratatui::widgets::Clear, popup);
    let para = Paragraph::new(lines).block(
        Block::bordered()
            .title("Keys")
            .border_style(Style::new().fg(Color::Cyan)),
    );
    frame.render_widget(para, popup);
}

/// A centred box with every field of the selected snapshot in full — the
/// escape hatch for when the table truncates a column (long path lists, most
/// commonly). Long values wrap onto continuation lines instead of truncating;
/// showing them whole is the point of the overlay.
fn render_snapshot_info_overlay(frame: &mut Frame, area: Rect, s: &crate::repo::SnapshotRow) {
    let tags = if s.tags.is_empty() {
        "-".to_string()
    } else {
        s.tags.join(", ")
    };
    let size = s.size.map(human_size).unwrap_or_else(|| "-".to_string());

    let mut rows: Vec<(&str, String)> = vec![
        ("ID", s.id.clone()),
        ("Time", s.time.clone()),
        ("Host", s.host.clone()),
        ("Tags", tags),
        ("Size", size),
    ];
    if s.paths.is_empty() {
        rows.push(("Paths", "-".to_string()));
    } else {
        rows.push(("Paths", s.paths[0].clone()));
        for p in &s.paths[1..] {
            rows.push(("", p.clone()));
        }
    }

    let key_width = "Paths".len();
    // Each line renders as " <label padded to key_width>  <value>".
    let longest = rows.iter().map(|(_, v)| v.chars().count()).max().unwrap_or(0);
    let content_width = 1 + key_width + 2 + longest;
    // +2 for the border, +1 for a right-hand margin.
    let w = ((content_width + 3) as u16).min(area.width);
    let inner_w = (w.saturating_sub(2) as usize).max(1);

    // Height accounts for wrapping: a value wider than the popup folds onto
    // extra lines, and those lines need rows or the dismiss hint scrolls off.
    let text_rows: usize = rows
        .iter()
        .map(|(_, v)| (1 + key_width + 2 + v.chars().count()).div_ceil(inner_w).max(1))
        .sum();
    // +2 for the border, +2 for the trailing blank line and the dismiss hint.
    let h = ((text_rows + 4) as u16).min(area.height);
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    };

    let mut lines: Vec<Line> = rows
        .iter()
        .map(|(k, v)| {
            Line::from(vec![
                Span::styled(
                    format!(" {k:key_width$}  "),
                    Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                ),
                Span::styled(v.clone(), Style::new().fg(Color::White)),
            ])
        })
        .collect();
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        " press any key to close this",
        Style::new().fg(Color::DarkGray),
    )));

    frame.render_widget(ratatui::widgets::Clear, popup);
    let para = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::bordered()
            .title("Snapshot")
            .border_style(Style::new().fg(Color::Cyan)),
    );
    frame.render_widget(para, popup);
}

fn render_top_bar(frame: &mut Frame, app: &App, area: Rect) {
    let text = match &app.active_profile_name {
        Some(name) => format!("wrustic — profile: {name}"),
        None => "wrustic".to_string(),
    };
    let para = Paragraph::new(text)
        .style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(para, area);
}

fn render_bottom_bar(frame: &mut Frame, app: &App, area: Rect) {
    let text = bottom_bar_text(app);
    let content_width = area.width.saturating_sub(2) as usize;
    let segments: Vec<&str> = text.split("  ").collect();
    let footer_line = build_footer_line(&segments, content_width);
    let para = Paragraph::new(footer_line)
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(para, area);
}

fn build_footer_line(segments: &[&str], width: usize) -> Line<'static> {
    let style = Style::default().fg(Color::White);

    if segments.is_empty() {
        return Line::from(Span::styled("", style));
    }

    let sep = " | ";
    let sep_len = sep.len();

    let mut total_width = 0usize;
    let mut fit_count = 0usize;
    for (i, seg) in segments.iter().enumerate() {
        let needed = if i == 0 { seg.len() } else { sep_len + seg.len() };
        if total_width + needed > width {
            break;
        }
        total_width += needed;
        fit_count += 1;
    }

    if fit_count == 0 {
        let first = segments[0];
        let truncated: String = first.chars().take(width).collect();
        return Line::from(Span::styled(truncated, style));
    }

    let joined = segments[..fit_count].join(sep);
    Line::from(Span::styled(joined, style))
}

fn bottom_bar_text(app: &App) -> &'static str {
    footer_text(&app.screen, app.keychain_enabled())
}

/// The footer hint for a screen. Split out from `bottom_bar_text` so it can be
/// checked against `help_rows` without building an `App`.
fn footer_text(screen: &Screen, keychain_enabled: bool) -> &'static str {
    match screen {
        // These footers list only what a first-time user needs to get moving;
        // `?` opens the full key list, which is what keeps them from growing
        // past the width of a terminal again.
        Screen::Home => "Enter open  n new  e edit  d delete  ? keys  q quit",
        Screen::Snapshots => {
            "Enter browse  i info  s share  c compare  f filter  d delete  t tags  p prune  r reload  ? keys  q/Esc back"
        }
        Screen::SnapshotFilterDim => "Up/Dn move  PgUp/PgDn page  Enter pick  Esc back",
        Screen::SnapshotFilterValue => {
            "Up/Dn move  PgUp/PgDn page  g/G top/bottom  Enter pick  Esc back"
        }
        Screen::SnapshotDeleteConfirm => {
            "y confirm delete  Up/Dn scroll  PgUp/PgDn page  r raw JSON  n/Esc cancel"
        }
        Screen::SnapshotDeleteError(msg) => {
            if crate::lock::is_lock_error(msg) {
                "u remove stale locks and retry  any other key to continue"
            } else {
                "any key to continue"
            }
        }
        Screen::SnapshotTagEdit => "type  Enter save  Esc cancel",
        Screen::SnapshotTagError(msg) => {
            if crate::lock::is_lock_error(msg) {
                "u remove stale locks and retry  any other key to continue"
            } else {
                "any key to continue"
            }
        }
        Screen::SnapshotContents => {
            "Enter open  Backspace up  r reload  ? keys  q/Esc back"
        }
        Screen::FileDetails => {
            "s share  Up/Dn scroll  ? keys  Esc/Backspace/q back"
        }
        Screen::ShareUrl => "Esc/Backspace/q back (stops the server)",
        Screen::SnapshotSmbStarting => "starting the SMB server…",
        Screen::SnapshotSmb => "Esc/Backspace/q back (stops the server)",
        Screen::PassphraseInstancePrompt => "type  Enter submit  Esc quit",
        Screen::PassphraseSetup => if keychain_enabled {
            "Tab/Shift+Tab field  Space toggle  Enter submit  Esc back"
        } else {
            "Tab/Shift+Tab field  Enter submit  Esc back"
        },
        Screen::PassphraseUnlock => if keychain_enabled {
            "Tab/Shift+Tab field  Space toggle  Enter submit  Esc quit"
        } else {
            "type  Enter submit  Esc quit"
        },
        Screen::PassphraseDerivingKey => "working…",
        Screen::AuthMethodChoice => "Up/Dn move  Enter pick  Esc back",
        Screen::SnapshotCompareSecond => {
            "Up/Dn move  PgUp/PgDn page  g/G top/bottom  Enter pick SECOND  a toggle related/all  Esc cancel"
        }
        Screen::SnapshotCompareResults => "Up/Dn move  PgUp/PgDn page  g/G top/bottom  q/Esc back",
        Screen::OpeningSnapshot
        | Screen::LoadingDir
        | Screen::LoadingFileDetails
        | Screen::Loading
        | Screen::Verifying
        | Screen::SnapshotDeleting
        | Screen::SnapshotDeleteLoading
        | Screen::SnapshotTagSaving
        | Screen::Unlocking
        | Screen::SnapshotCompareLoading => "working…",
        Screen::PruneConfirm => "y start prune  n/Esc cancel",
        Screen::PruneRunning => "pruning natively — Ctrl+C cancels (again force-quits)",
        Screen::PruneDone(_) => "Up/Dn scroll  PgUp/PgDn page  g/G top/bottom  q/Esc back",
        Screen::PruneError(msg) => {
            if crate::lock::is_lock_error(msg) {
                "u remove stale locks and retry  any other key to continue"
            } else {
                "any key to continue"
            }
        }
        Screen::CreateProfileName => "type  Enter submit  Esc cancel",
        Screen::BackendChoice => "Up/Dn move  PgUp/PgDn page  Enter pick  Esc back",
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
    app.list_header_rows = 0;
    match &app.screen {
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
        Screen::SnapshotDeleteConfirm => render_snapshot_delete_confirm(frame, &mut *app, area),
        Screen::SnapshotDeleting => {
            let para = Paragraph::new("Deleting snapshot under an exclusive repository lock…")
                .block(Block::bordered().title("Deleting snapshot"));
            frame.render_widget(para, area);
        }
        Screen::SnapshotDeleteLoading => {
            let para = Paragraph::new("Loading snapshot details…")
                .block(Block::bordered().title("Loading"));
            frame.render_widget(para, area);
        }
        Screen::SnapshotDeleteError(msg) => {
            let body = if crate::lock::is_lock_error(msg) {
                format!(
                    "{msg}\n\nPress u to remove stale repository locks (live locks are \
                     kept) and retry, or any other key to return to the snapshot list."
                )
            } else {
                format!("{msg}\n\nPress any key to return to the snapshot list.")
            };
            let para = Paragraph::new(body)
                .style(Style::new().fg(Color::Red))
                .wrap(Wrap { trim: false })
                .block(Block::bordered().title("Delete unavailable"));
            frame.render_widget(para, area);
        }
        Screen::SnapshotTagEdit => {
            let short = app
                .tag_edit_target
                .as_deref()
                .map(|id| &id[..id.len().min(8)])
                .unwrap_or("?");
            render_input(
                frame,
                area,
                &format!("Edit tags — snapshot {short}"),
                &app.tag_edit_input,
                false,
                "Comma-separated tags; leave empty to clear all tags",
            );
        }
        Screen::SnapshotTagSaving => {
            let para = Paragraph::new("Rewriting snapshot tags under an exclusive repository lock…")
                .block(Block::bordered().title("Saving tags"));
            frame.render_widget(para, area);
        }
        Screen::SnapshotTagError(msg) => {
            let body = if crate::lock::is_lock_error(msg) {
                format!(
                    "{msg}\n\nPress u to remove stale repository locks (live locks are \
                     kept) and retry, or any other key to return to the snapshot list."
                )
            } else {
                format!("{msg}\n\nPress any key to return to the snapshot list.")
            };
            let para = Paragraph::new(body)
                .style(Style::new().fg(Color::Red))
                .wrap(Wrap { trim: false })
                .block(Block::bordered().title("Tag edit failed"));
            frame.render_widget(para, area);
        }
        Screen::Unlocking => {
            let para = Paragraph::new("Removing stale repository locks…")
                .block(Block::bordered().title("Unlocking repository"));
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
        Screen::LoadingFileDetails => {
            let para = Paragraph::new("Reading file details…")
                .block(Block::bordered().title("Loading"));
            frame.render_widget(para, area);
        }
        Screen::SnapshotContents => render_snapshot_contents(frame, app, area),
        Screen::FileDetails => render_file_details(frame, app, area),
        Screen::ShareUrl => render_share_url(frame, app, area),
        Screen::SnapshotSmbStarting => {
            let para = Paragraph::new(
                "Opening the repository and starting the SMB server…\n\n\
                 Reading the index, which can take a moment on a large repository.",
            )
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title("Share over SMB"));
            frame.render_widget(para, area);
        }
        Screen::SnapshotSmb => render_snapshot_smb(frame, app, area),
        Screen::PassphraseInstancePrompt => {
            let banner = format!(
                "No config found at {}. Setting up a new instance.",
                app.paths.config.display(),
            );
            let [_top, banner_area, input_area, help_area, _bottom] = Layout::vertical([
                Constraint::Fill(1),
                Constraint::Length(1),
                Constraint::Length(3),
                Constraint::Length(1),
                Constraint::Fill(1),
            ])
            .areas(area);
            let banner_p = Paragraph::new(banner).style(Style::new().fg(Color::White));
            frame.render_widget(banner_p, banner_area);
            draw_input_field(frame, input_area, "Instance name", &app.passphrase_instance_input, false, true);
            let help_p = Paragraph::new("Lowercase letters, digits, and hyphens (max 32 chars).").style(Style::new().fg(Color::White));
            frame.render_widget(help_p, help_area);
        }
        Screen::AuthMethodChoice => render_auth_method_choice(frame, app, area),
        Screen::PassphraseSetup => render_passphrase_setup(frame, app, area),
        Screen::PassphraseUnlock => render_passphrase_unlock(frame, app, area),
        Screen::PassphraseDerivingKey => {
            let para = Paragraph::new("Deriving key…")
                .block(Block::bordered().title("Passphrase"));
            frame.render_widget(para, area);
        }
        Screen::SnapshotCompareSecond => render_compare_second(frame, app, area),
        Screen::SnapshotCompareLoading => render_compare_loading(frame, app, area),
        Screen::SnapshotCompareResults => render_compare_results(frame, app, area),
        Screen::PruneConfirm => render_prune_confirm(frame, app, area),
        Screen::PruneRunning => render_prune_running(frame, app, area),
        Screen::PruneDone(report) => {
            let report = report.clone();
            render_prune_done(frame, app, area, &report);
        }
        Screen::PruneError(msg) => {
            let body = if crate::lock::is_lock_error(msg) {
                format!(
                    "{msg}\n\nPress u to remove stale repository locks (live locks are \
                     kept) and retry the prune, or any other key to return to the \
                     snapshot list."
                )
            } else {
                format!("{msg}\n\nPress any key to return to the snapshot list.")
            };
            let para = Paragraph::new(body)
                .style(Style::new().fg(Color::Red))
                .wrap(Wrap { trim: false })
                .block(Block::bordered().title("Prune failed"));
            frame.render_widget(para, area);
        }
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

fn selection_highlight() -> Style {
    Style::new()
        .bg(Color::Rgb(40, 40, 80))
        .add_modifier(Modifier::BOLD)
}

// Stash the outer rect of the currently-rendered scrollable area so the
// key handler can size PageUp/PageDown jumps and the mouse handler can
// translate clicks into row indices. `area` is the outer rect that gets
// `Block::bordered()`; the bordered interior is `area` shrunk by 1 on
// each side.
fn record_list_area(app: &mut App, area: Rect) {
    app.list_area = Some(area);
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

    app.list_header_rows = 1;

    let rows: Vec<Row> = app
        .config
        .profiles
        .iter()
        .map(|(name, p)| Row::new([Cell::from(name.clone()), Cell::from(p.backend_kind().label())]))
        .collect();

    let header = Row::new(["Name", "Backend"])
        .style(Style::new().fg(Color::DarkGray).add_modifier(Modifier::BOLD));

    let table = Table::new(rows, [Constraint::Length(24), Constraint::Fill(1)])
        .header(header)
        .block(Block::bordered().title(title))
        .row_highlight_style(selection_highlight())
        .highlight_symbol(">> ")
        .highlight_spacing(HighlightSpacing::Always)
        .column_spacing(2);

    record_list_area(app, area);
    frame.render_stateful_widget(table, area, &mut app.profile_list_state);
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

    record_list_area(app, area);
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

    let help = Paragraph::new(help).style(Style::new().fg(Color::White));
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

    let help_para = Paragraph::new(help).style(Style::new().fg(Color::White));
    frame.render_widget(help_para, areas[fields.len()]);
}

fn render_keychain_checkbox(frame: &mut Frame, area: Rect, checked: bool, focused: bool) {
    let mark = if checked { "[x]" } else { "[ ]" };
    let style = if focused {
        Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(Color::White)
    };
    let text = format!(" {mark} Save passphrase to keychain");
    frame.render_widget(Paragraph::new(text).style(style), area);
}

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

    record_list_area(app, area);
    app.list_header_rows = 1;
    render_snapshot_picker(frame, area, &title, &app.snapshots, &visible, &mut app.list_state);
}

// Shared picker rendering for the Snapshots screen and the two compare-flow
// pick screens. Indices are absolute into `snapshots`; the picker's own
// `TableState` is positional within `visible`.
fn render_snapshot_picker(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    snapshots: &[crate::repo::SnapshotRow],
    visible: &[usize],
    state: &mut TableState,
) {
    let rows: Vec<Row> = visible
        .iter()
        .map(|&i| &snapshots[i])
        .map(|s| {
            let tags = if s.tags.is_empty() {
                String::new()
            } else {
                format!("[{}]", s.tags.join(","))
            };
            let size = s.size.map(human_size).unwrap_or_else(|| "-".to_string());
            Row::new([
                Cell::from(short_snap_id(&s.id)),
                Cell::from(s.time.as_str()),
                Cell::from(s.host.as_str()),
                Cell::from(tags),
                Cell::from(size),
                Cell::from(s.paths.join(",")),
            ])
        })
        .collect();

    let header = Row::new(["ID", "Time", "Host", "Tags", "Size", "Paths"])
        .style(Style::new().fg(Color::DarkGray).add_modifier(Modifier::BOLD));

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(19),
            Constraint::Length(20),
            Constraint::Length(20),
            Constraint::Length(9),
            Constraint::Fill(1),
        ],
    )
    .header(header)
    .block(Block::bordered().title(title))
    .row_highlight_style(selection_highlight())
    .highlight_symbol(">> ")
    .highlight_spacing(HighlightSpacing::Always)
    .column_spacing(2);

    frame.render_stateful_widget(table, area, state);
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
    record_list_area(app, area);
    app.list_header_rows = 1;
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
    let body = format!("Comparing snapshots {first}..{second}…");
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

    let (summary_text, rows) = match &app.compare_results {
        Some((sum, changes)) => {
            let text = format!(
                "+{} files / -{} / M{}  |  +{} / -{}  ({} change{})",
                sum.added_files,
                sum.removed_files,
                sum.changed_files,
                human_size(sum.added_bytes),
                human_size(sum.removed_bytes),
                changes.len(),
                if changes.len() == 1 { "" } else { "s" },
            );
            let rows: Vec<Row> = changes
                .iter()
                .map(|c| Row::new([
                    Cell::from(c.modifier.as_char().to_string()),
                    Cell::from(c.path.clone()),
                ]))
                .collect();
            (text, rows)
        }
        None => ("(no diff loaded)".to_string(), Vec::new()),
    };

    let summary_para = Paragraph::new(summary_text)
        .wrap(Wrap { trim: false })
        .block(Block::bordered().title("Summary"));
    frame.render_widget(summary_para, header);

    if rows.is_empty() {
        let para = Paragraph::new("No file-level changes between these snapshots.")
            .style(Style::new().fg(Color::DarkGray))
            .block(Block::bordered().title("Changes"));
        frame.render_widget(para, body);
        return;
    }

    let count = rows.len();
    app.list_header_rows = 1;

    let col_header = Row::new(["M", "Path"])
        .style(Style::new().fg(Color::DarkGray).add_modifier(Modifier::BOLD));

    let table = Table::new(rows, [Constraint::Length(1), Constraint::Fill(1)])
        .header(col_header)
        .block(Block::bordered().title(format!("Changes ({count})")))
        .row_highlight_style(selection_highlight())
        .highlight_symbol(">> ")
        .highlight_spacing(HighlightSpacing::Always)
        .column_spacing(2);

    record_list_area(app, body);
    frame.render_stateful_widget(table, body, &mut app.compare_results_state);
}

fn render_prune_confirm(frame: &mut Frame, app: &App, area: Rect) {
    let profile = app.active_profile_name.as_deref().unwrap_or("?");
    let body = format!(
        "Prune repository of profile `{profile}`?\n\n\
         This prunes natively, rewriting and deleting pack files to reclaim\n\
         the space left behind by deleted snapshots. It takes an exclusive\n\
         repository lock — concurrent backups are blocked while it runs —\n\
         and can take a long time on a large or remote repository.\n\
         Progress is shown live, and Ctrl+C cancels a run in progress:\n\
         it stops at the next progress tick and releases the lock. That is\n\
         safe at any point — nothing old is deleted before everything new\n\
         is written — and the next prune finishes the work.\n\n\
         y/Enter start   n/Esc cancel"
    );
    let para = Paragraph::new(body)
        .wrap(Wrap { trim: false })
        .block(Block::bordered().title("Prune repository"));
    frame.render_widget(para, area);
}

fn render_prune_running(frame: &mut Frame, app: &App, area: Rect) {
    const FRAMES: [char; 4] = ['|', '/', '-', '\\'];
    let elapsed = app
        .prune_started
        .map(|t| t.elapsed())
        .unwrap_or_default();
    let spinner = FRAMES[(elapsed.as_millis() / 150) as usize % FRAMES.len()];
    let secs = elapsed.as_secs();
    let mut body = format!(
        "{spinner} Pruning repository…  elapsed {}m{:02}s\n\n",
        secs / 60,
        secs % 60
    );
    if app.prune_cancelling.is_some() {
        body.push_str(
            "Cancelling — the prune stops at its next progress tick and\n\
             releases the lock. The repository stays valid; the next prune\n\
             finishes the work. Ctrl+C again force-quits wrustic instead,\n\
             which leaves a stale lock for a later unlock.\n\n",
        );
    } else {
        body.push_str(
            "Ctrl+C cancels this prune. It stops at the next progress tick\n\
             and releases the lock; the repository stays valid either way.\n\n",
        );
    }
    // One line per prune phase, rewritten in place as the phase advances
    // (newest phases at the bottom).
    if let Some(progress) = &app.prune_progress {
        let progress = progress.lock().unwrap_or_else(|p| p.into_inner());
        // Reserve the 2 border rows plus however many rows the header text
        // built above actually occupies (it differs by cancel state), so the
        // newest progress line is never pushed past the bottom border.
        let header_rows = body.lines().count();
        let avail = (area.height as usize).saturating_sub(2 + header_rows);
        if avail > 0 && !progress.is_empty() {
            let lines: Vec<&str> = progress.lines().collect();
            let start = lines.len().saturating_sub(avail);
            for line in &lines[start..] {
                body.push_str(line);
                body.push('\n');
            }
        }
    }
    let para = Paragraph::new(body)
        .wrap(Wrap { trim: false })
        .block(Block::bordered().title("Pruning"));
    frame.render_widget(para, area);
}

fn render_prune_done(frame: &mut Frame, app: &mut App, area: Rect, report: &str) {
    let max_scroll = (report.lines().count() as u16).saturating_sub(1);
    app.prune_scroll = app.prune_scroll.min(max_scroll);
    let para = Paragraph::new(report)
        .scroll((app.prune_scroll, 0))
        .block(Block::bordered().title("Prune finished"));
    record_list_area(app, area);
    frame.render_widget(para, area);
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
    record_list_area(app, area);
    frame.render_stateful_widget(list, area, &mut app.filter_picker_state);
}

fn render_filter_value(frame: &mut Frame, app: &mut App, area: Rect) {
    record_list_area(app, area);
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

    app.list_header_rows = 1;

    let frame_idx = app.browse_stack.len() - 1;
    let top = &app.browse_stack[frame_idx];
    let rows: Vec<Row> = top
        .items
        .iter()
        .map(|row| {
            if matches!(row.kind, ContentKind::Parent) {
                return Row::new(["", "..", "", ""]);
            }
            let kind_char = match row.kind {
                ContentKind::Dir => "d",
                ContentKind::File => "-",
                ContentKind::Symlink => "l",
                ContentKind::Other => "?",
                ContentKind::Parent => "^",
            };
            let display_name = if matches!(row.kind, ContentKind::Dir) {
                format!("{}/", row.name)
            } else {
                row.name.clone()
            };
            let size_col = if matches!(row.kind, ContentKind::File) {
                human_size(row.size)
            } else {
                String::new()
            };
            Row::new([
                Cell::from(kind_char),
                Cell::from(display_name),
                Cell::from(Line::from(size_col).alignment(Alignment::Right)),
                Cell::from(row.mtime.clone()),
            ])
        })
        .collect();

    let header = Row::new([
        Cell::from("T"),
        Cell::from("Name"),
        Cell::from(Line::from("Size").alignment(Alignment::Right)),
        Cell::from("Modified"),
    ])
        .style(Style::new().fg(Color::DarkGray).add_modifier(Modifier::BOLD));

    let table = Table::new(
        rows,
        [
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Length(10),
            Constraint::Length(19),
        ],
    )
    .header(header)
    .block(Block::bordered().title(title))
    .row_highlight_style(selection_highlight())
    .highlight_symbol(">> ")
    .highlight_spacing(HighlightSpacing::Always)
    .column_spacing(2);

    record_list_area(app, area);
    let top_mut = &mut app.browse_stack[frame_idx];
    frame.render_stateful_widget(table, area, &mut top_mut.table_state);
}

fn render_file_details(frame: &mut Frame, app: &mut App, area: Rect) {
    let Some(d) = app.file_details.as_ref() else {
        let para = Paragraph::new("(no file selected)")
            .block(Block::bordered().title("File details"));
        frame.render_widget(para, area);
        return;
    };

    let mut lines = String::new();
    lines.push_str(&format!("Name:  {}\n", d.name));
    lines.push_str(&format!("Path:  {}\n", d.full_path));
    lines.push_str(&format!("Type:  {}\n", d.kind_label));
    lines.push_str(&format!("Size:  {} ({} bytes)\n", human_size(d.size), d.size));
    if let Some(m) = d.mode {
        lines.push_str(&format!("Mode:  0{m:o}\n"));
    }
    if let Some(t) = &d.mtime {
        lines.push_str(&format!("mtime: {t}\n"));
    }
    if let Some(t) = &d.atime {
        lines.push_str(&format!("atime: {t}\n"));
    }
    if let Some(t) = &d.ctime {
        lines.push_str(&format!("ctime: {t}\n"));
    }
    let owner = match (d.user.as_deref(), d.uid) {
        (Some(u), Some(n)) => format!("{u} ({n})"),
        (Some(u), None) => u.to_string(),
        (None, Some(n)) => n.to_string(),
        (None, None) => String::new(),
    };
    let group = match (d.group.as_deref(), d.gid) {
        (Some(g), Some(n)) => format!("{g} ({n})"),
        (Some(g), None) => g.to_string(),
        (None, Some(n)) => n.to_string(),
        (None, None) => String::new(),
    };
    if !owner.is_empty() || !group.is_empty() {
        lines.push_str(&format!("Owner: {owner} / {group}\n"));
    }
    if let Some(t) = &d.linktarget {
        lines.push_str(&format!("Link target: {t}\n"));
    }
    if !d.content_hashes.is_empty() {
        // Cap the displayed list so deeply-chunked files don't push the rest
        // of the metadata off-screen. Show the first MAX hashes; the count
        // in the header already tells the reader how many are hidden.
        const MAX: usize = 10;
        lines.push_str(&format!(
            "\nContent blob SHA-256 ({} chunk{}):\n",
            d.content_hashes.len(),
            if d.content_hashes.len() == 1 { "" } else { "s" },
        ));
        for h in d.content_hashes.iter().take(MAX) {
            lines.push_str("  ");
            lines.push_str(h);
            lines.push('\n');
        }
        if d.content_hashes.len() > MAX {
            lines.push_str(&format!(
                "  … ({} more)\n",
                d.content_hashes.len() - MAX
            ));
        }
    } else if matches!(d.kind, ContentKind::File) {
        lines.push_str("\n(empty file — no content blobs)\n");
    }

    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((app.file_details_scroll, 0))
        .block(
            Block::bordered().title(format!("File details — {}", short_path(&d.full_path))),
        );
    record_list_area(app, area);
    frame.render_widget(para, area);
}

fn render_auth_method_choice(frame: &mut Frame, app: &mut App, area: Rect) {
    let items = vec![
        ListItem::new("Use passphrase from keychain"),
        ListItem::new("Enter passphrase manually"),
    ];
    let list = List::new(items)
        .block(Block::bordered().title("Choose unlock method"))
        .highlight_style(selection_highlight())
        .highlight_symbol(">> ");
    record_list_area(app, area);
    frame.render_stateful_widget(list, area, &mut app.auth_method_list);
}

fn render_passphrase_setup(frame: &mut Frame, app: &App, area: Rect) {
    let title = if app.passphrase_instance_value.is_empty() {
        "Set passphrase".to_string()
    } else {
        format!("Set passphrase \u{2014} {}", app.passphrase_instance_value)
    };
    let help = app
        .passphrase_error
        .as_deref()
        .unwrap_or("Min 12 chars, requires lowercase, uppercase, digit, and special character.");

    if app.keychain_enabled() {
        let outer = Block::bordered().title(title);
        let inner_area = outer.inner(area);
        frame.render_widget(outer, area);

        let areas = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Fill(1),
        ])
        .split(inner_area);

        draw_input_field(frame, areas[0], "Passphrase", &app.passphrase_input, true, app.field_focus == 0);
        draw_input_field(frame, areas[1], "Confirm passphrase", &app.passphrase_confirm, true, app.field_focus == 1);
        render_keychain_checkbox(frame, areas[2], app.save_to_keychain, app.field_focus == 2);
        let help_para = Paragraph::new(help).style(Style::new().fg(Color::White));
        frame.render_widget(help_para, areas[3]);
    } else {
        let fields = [
            ("Passphrase", &app.passphrase_input, true),
            ("Confirm passphrase", &app.passphrase_confirm, true),
        ];
        render_grouped_input(frame, area, &title, &fields, app.field_focus, help);
    }
}

fn render_passphrase_unlock(frame: &mut Frame, app: &App, area: Rect) {
    let meta = app.config.passphrase.as_ref();
    let title = match meta.map(|m| m.instance.as_str()).filter(|s| !s.is_empty()) {
        Some(inst) => format!("Unlock \u{2014} {inst}"),
        None => "Unlock".to_string(),
    };
    let help = if let Some(err) = &app.passphrase_error {
        err.clone()
    } else if let Some(sig) = meta.map(|m| m.instance_sig.as_str()).filter(|s| !s.is_empty()) {
        format!("Signature: {sig}")
    } else {
        "Enter the passphrase to decrypt the config.".to_string()
    };

    if app.keychain_enabled() {
        let outer = Block::bordered().title(title);
        let inner_area = outer.inner(area);
        frame.render_widget(outer, area);

        let areas = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Fill(1),
        ])
        .split(inner_area);

        draw_input_field(frame, areas[1], "Passphrase", &app.passphrase_input, true, app.field_focus == 0);
        render_keychain_checkbox(frame, areas[2], app.save_to_keychain, app.field_focus == 1);
        let help_para = Paragraph::new(help).style(Style::new().fg(Color::White));
        frame.render_widget(help_para, areas[3]);
    } else {
        render_input(frame, area, &title, &app.passphrase_input, true, &help);
    }
}

fn render_share_url(frame: &mut Frame, app: &mut App, area: Rect) {
    let port = app.server_port;
    let target_label = app
        .share_target
        .as_ref()
        .map(|t| short_path(&t.display_path))
        .unwrap_or_else(|| "(no file)".to_string());

    let mut lines = String::new();
    let running = app.share_handle.is_some();
    if running {
        lines.push_str(&format!("Server: listening on localhost:{port}\n"));
    } else {
        lines.push_str("Server: not running\n");
    }
    lines.push('\n');

    match (&app.share_short_url, &app.share_url) {
        (Some(short), Some(long)) => {
            lines.push_str("Short URL (302 redirects to the long URL):\n");
            lines.push_str(short);
            lines.push_str("\n\n");
            lines.push_str("Long URL:\n");
            lines.push_str(long);
            lines.push_str("\n\n");
        }
        _ => {
            lines.push_str("URL: (none yet — start the server with `s`)\n\n");
        }
    }

    if let Some(exp) = app.share_exp_unix {
        // Absolute timestamp in local time — doesn't need re-rendering as
        // the clock advances. `exp` is a u64 unix-seconds; convert via i64.
        let when = jiff::Timestamp::from_second(exp as i64)
            .and_then(|t| t.in_tz("UTC").map(|z| z.strftime("%Y-%m-%d %H:%M:%S UTC").to_string()))
            .unwrap_or_else(|_| format!("unix {exp}"));
        let local = jiff::Timestamp::from_second(exp as i64)
            .map(|t| t.to_zoned(jiff::tz::TimeZone::system()))
            .map(|z| z.strftime("%Y-%m-%d %H:%M:%S %Z").to_string())
            .unwrap_or_default();
        if local.is_empty() || local == when {
            lines.push_str(&format!("Expires: {when}\n"));
        } else {
            lines.push_str(&format!("Expires: {local}  ({when})\n"));
        }
    }

    if let Some(err) = &app.share_error {
        lines.push_str(&format!("\nError: {err}\n"));
    }

    lines.push_str(
        "\nServer is bound to this file only. Leaving this screen stops it.",
    );

    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(Block::bordered().title(format!("Share — {target_label}")));
    record_list_area(app, area);
    frame.render_widget(para, area);
}

fn render_snapshot_smb(frame: &mut Frame, app: &mut App, area: Rect) {
    let snap = app
        .smb_snapshot_id
        .as_deref()
        .map(short_snap_id)
        .unwrap_or("(none)");
    let title = format!("Share over SMB — snapshot {snap}");

    let mut lines = String::new();
    match (app.smb_handle.as_ref(), app.smb_password.as_deref()) {
        (Some(h), Some(pw)) => {
            let user = crate::smb::DEFAULT_SHARE_USER;
            let share = &h.share_name;
            // Not `h.port`: with the tun transport that is the private loopback
            // socket the proxy talks to, and printing it would send the reader
            // to an endpoint no mount command should ever name.
            let host = &h.mount().host;
            let port = h.mount().port;
            lines.push_str(&format!(
                "Server: listening on {host}:{port}  (read-only, this machine only)\n"
            ));
            // Keyed on the transport actually in use, not on the port number:
            // `--smb-port 445` reaches 445 without a tun anywhere (on platforms
            // where that bind succeeds), and claiming a private adapter exists
            // when none does would be simply wrong. The addresses come from
            // `--smb-tun-ip` rather than a hardcoded default.
            if app.smb.tun {
                lines.push_str(&format!(
                    "Tun:    private adapter, standard SMB port. The machine's own file \
                     sharing is untouched; {} route here until this screen closes.\n",
                    app.smb.tun_addrs
                ));
            }
            lines.push_str(
                "Lock:   holding restic's non-exclusive repository lock — concurrent \
                 backups keep working; prune/forget are blocked until this screen \
                 closes.\n\n",
            );
            lines.push_str(&format!("Username: {user}\n"));
            lines.push_str(&format!("Password: {pw}\n"));
            // Every command below prompts for the password rather than taking
            // it as an argument. A password on a command line is readable by
            // every process on the machine for as long as the command runs, and
            // stays in shell history — or console history on Windows — long
            // after. Type in the one shown above when asked.
            lines.push_str("\nMount it with (each prompts for the password above):\n\n");
            if h.on_standard_port() {
                // On the standard port there is no port option to carry, which
                // is the entire reason the tun exists: a UNC path works in
                // Explorer's address bar and in any program that takes one,
                // not only as a mapped drive letter.
                lines.push_str(&format!(
                    "  Linux    sudo mount -t cifs -o vers=2.1,username={user},ro,uid=$(id -u),gid=$(id -g),file_mode=0444,dir_mode=0555 //{host}/{share} /mnt/snap\n\n"
                ));
                lines.push_str(&format!(
                    "  macOS    Finder → Go → Connect to Server (Cmd+K), then enter:\n\
                     \x20          smb://{user}@{host}/{share}\n\n"
                ));
                lines.push_str(&format!(
                    "  Windows  net use Z: {} * /user:{user}\n",
                    h.unc()
                ));
                lines.push_str(&format!(
                    "           Or paste {} straight into Explorer's address bar.\n",
                    h.unc()
                ));
            } else {
                lines.push_str(&format!(
                    "  Linux    sudo mount -t cifs -o port={port},vers=2.1,username={user},ro,uid=$(id -u),gid=$(id -g),file_mode=0444,dir_mode=0555 //{host}/{share} /mnt/snap\n\n"
                ));
                lines.push_str(&format!(
                    "  macOS    Finder → Go → Connect to Server (Cmd+K), then enter:\n\
                     \x20          smb://{user}@{host}:{port}/{share}\n\n"
                ));
                lines.push_str(&format!(
                    "  Windows  net use Z: {} * /user:{user} /TCPPORT:{port}\n",
                    h.unc()
                ));
                // A custom port is reachable only as a mapped drive, and only
                // from 24H2 or newer — two separate limits, both lifted by
                // serving the standard port, so --smb-tun is not just the
                // older-Windows fallback.
                lines.push_str(&format!(
                    "           A mapped drive is the only way in: no UNC path can carry a \
                     port, so {} on its own goes to 445 and never reaches this share.\n",
                    h.unc()
                ));
                lines.push_str(
                    "           /TCPPORT: also needs Windows 11 24H2 or newer. Starting \
                     wrustic with --smb-tun serves the standard port instead — a UNC path \
                     Explorer accepts, and the only way in from older builds.\n",
                );
            }
        }
        _ => {
            lines.push_str("Server: not running\n");
        }
    }

    if let Some(err) = &app.smb_error {
        lines.push_str(&format!("\nError: {err}\n"));
        // The share needs restic's non-exclusive lock; an exclusive holder
        // (prune, forget — possibly one that crashed) blocks it. `u` mirrors
        // the delete flow: stale locks are removed, live ones survive.
        if app.smb_handle.is_none() && crate::lock::is_lock_error(err) {
            lines.push_str(
                "\nPress u to remove stale locks and retry. A lock held by a live \
                 process is left alone (the retry reports its holder).\n",
            );
        }
    }

    lines.push_str(
        "\nEvery client authenticates and authenticated session messages are signed. \
         Writes are refused at the protocol level, and so is opening a file for execute — \
         this is a way to browse a snapshot rather than to restore one. The Linux mount \
         options above additionally display files as 0444 and directories as 0555; a \
         Finder mount shows the client's default modes, but the server refuses writes \
         either way. Leaving this screen stops the server, and any mount still using it.",
    );

    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(Block::bordered().title(title));
    record_list_area(app, area);
    frame.render_widget(para, area);
}

// Truncate a path for a title — keep the tail since the basename is usually
// the most identifying piece. Returns the full path if it already fits.
// Operates on character counts (not bytes) so multi-byte filenames don't
// panic from slicing inside a codepoint.
fn short_path(p: &str) -> String {
    const MAX_CHARS: usize = 60;
    let nchars = p.chars().count();
    if nchars <= MAX_CHARS {
        return p.to_string();
    }
    // Keep the trailing (MAX_CHARS - 1) chars; the leading "…" takes the
    // remaining char-width, so total displayed width stays at MAX_CHARS.
    let skip = nchars - (MAX_CHARS - 1);
    let byte_offset = p
        .char_indices()
        .nth(skip)
        .map(|(i, _)| i)
        .unwrap_or(p.len());
    format!("…{}", &p[byte_offset..])
}

// restic's standard short id: 8 hex chars (`internal/restic/id.go` shortStr),
// the same form `restic snapshots` prints. Every short id the program renders
// — here, the SMB share's top-level directory, the volume label, lock storage
// ids — uses this length, so any of them pastes straight into a restic
// command.
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

fn render_snapshot_delete_confirm(frame: &mut Frame, app: &mut App, area: Rect) {
    let id = app.delete_target.as_deref().unwrap_or("(unknown)");
    let info = app.delete_info.as_ref();
    let paths = info
        .map(|i| {
            if i.paths.is_empty() {
                "(no paths)".to_string()
            } else {
                i.paths.join(", ")
            }
        })
        .unwrap_or_else(|| "(unknown)".into());
    let host = info.map(|i| i.hostname.as_str()).unwrap_or("?");

    let outer = Block::bordered().title("Confirm snapshot delete");
    let inner = outer.inner(area);
    frame.render_widget(outer, area);

    let [header, body] = Layout::vertical([Constraint::Length(8), Constraint::Fill(1)]).areas(inner);

    let tags = info
        .filter(|i| !i.tags.is_empty())
        .map(|i| i.tags.join(", "));
    let mut summary = format!("Delete snapshot {id}?\n\nHost: {host}\nPaths: {paths}");
    if let Some(tags) = tags {
        summary.push_str(&format!("\nTags: {tags}"));
    }
    if let Some(info) = info {
        let files = info.files.map(|n| n.to_string()).unwrap_or_else(|| "?".into());
        let bytes = info.bytes.map(human_size).unwrap_or_else(|| "?".into());
        summary.push_str(&format!("\n\nContents: {files} files, {bytes}"));
    }
    summary.push_str(&format!(
        "\n\nThis deletes snapshot {id} under an exclusive repository lock (no prune)."
    ));
    let header_para = Paragraph::new(summary)
        .style(Style::new().fg(Color::Yellow))
        .wrap(Wrap { trim: false });
    frame.render_widget(header_para, header);

    if app.delete_show_json {
        let raw = info.map(|i| i.raw_json.as_str()).unwrap_or("(no raw JSON)");
        let raw_para = Paragraph::new(raw)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title("Raw snapshot JSON"));
        frame.render_widget(raw_para, body);
        return;
    }

    let Some(preview) = app.delete_root_listing.as_ref() else {
        let para = Paragraph::new("(no preview)")
            .style(Style::new().fg(Color::DarkGray))
            .block(Block::bordered().title("Contents"));
        frame.render_widget(para, body);
        return;
    };
    if preview.entries.is_empty() {
        let para = Paragraph::new("(snapshot is empty)")
            .style(Style::new().fg(Color::DarkGray))
            .block(Block::bordered().title("Contents"));
        frame.render_widget(para, body);
        return;
    }

    let mut rows: Vec<Row> = preview
        .entries
        .iter()
        .map(|row| {
            let kind_char = match row.kind {
                ContentKind::Dir => "d",
                ContentKind::File => "-",
                ContentKind::Symlink => "l",
                ContentKind::Other => "?",
                ContentKind::Parent => "^",
            };
            let display_path = if matches!(row.kind, ContentKind::Dir) {
                format!("{}/", row.path)
            } else {
                row.path.clone()
            };
            let size_col = if matches!(row.kind, ContentKind::File) {
                human_size(row.size)
            } else {
                String::new()
            };
            Row::new([
                Cell::from(kind_char),
                Cell::from(Line::from(size_col).alignment(Alignment::Right)),
                Cell::from(display_path),
            ])
        })
        .collect();
    if preview.truncated {
        rows.push(
            Row::new([Cell::from(""), Cell::from(""), Cell::from("…load more")])
                .style(Style::new().fg(Color::DarkGray)),
        );
    }
    let title = if preview.truncated {
        format!("Contents (first {} entries)", preview.entries.len())
    } else {
        format!("Contents ({} entries)", preview.entries.len())
    };

    let col_header = Row::new([
        Cell::from("T"),
        Cell::from(Line::from("Size").alignment(Alignment::Right)),
        Cell::from("Path"),
    ])
    .style(Style::new().fg(Color::DarkGray).add_modifier(Modifier::BOLD));

    let table = Table::new(
        rows,
        [
            Constraint::Length(1),
            Constraint::Length(10),
            Constraint::Fill(1),
        ],
    )
    .header(col_header)
    .block(Block::bordered().title(title))
    .row_highlight_style(Style::new().bg(Color::DarkGray))
    .column_spacing(2);

    app.list_header_rows = 1;
    frame.render_stateful_widget(table, body, &mut app.delete_preview_state);
}

#[cfg(test)]
mod tests {
    use super::{Rect, Screen, footer_text, help_popup_rect, help_rows, human_size, short_path};

    /// The screens these checks cover. `Screen` has no way to enumerate itself,
    /// so this is by hand: a screen added later is not checked until it is added
    /// here too.
    fn every_screen() -> Vec<Screen> {
        vec![
            Screen::Home,
            Screen::Snapshots,
            Screen::SnapshotContents,
            Screen::FileDetails,
            Screen::ShareUrl,
            Screen::SnapshotSmb,
            Screen::SnapshotSmbStarting,
            Screen::SnapshotFilterDim,
            Screen::SnapshotFilterValue,
            Screen::SnapshotDeleteConfirm,
            Screen::SnapshotTagEdit,
            Screen::SnapshotTagError(String::new()),
            Screen::SnapshotCompareSecond,
            Screen::SnapshotCompareResults,
            Screen::PruneConfirm,
            Screen::BackendChoice,
            Screen::Password,
            Screen::ConfirmDelete,
            Screen::Error(String::new()),
        ]
    }

    /// "q / Esc" in the help and "q/Esc" in the footer are the same binding.
    fn normalize(key: &str) -> String {
        key.chars().filter(|c| !c.is_whitespace()).collect()
    }

    #[test]
    fn footer_advertises_the_help_key_exactly_where_help_exists() {
        for screen in every_screen() {
            let footer = footer_text(&screen, false);
            let advertises = footer.contains("? keys");
            let has_help = help_rows(&screen).is_some();
            assert_eq!(
                advertises, has_help,
                "footer {footer:?} and help_rows disagree about whether ? does anything",
            );
        }
    }

    #[test]
    fn every_footer_key_appears_in_the_help() {
        for screen in every_screen() {
            let Some(rows) = help_rows(&screen) else {
                continue;
            };
            let keys: Vec<String> = rows.iter().map(|(k, _)| normalize(k)).collect();
            for segment in footer_text(&screen, false).split("  ") {
                let key = normalize(segment.split_whitespace().next().unwrap_or(""));
                // `?` opens the overlay; listing it inside the overlay would be
                // circular, so it is the one footer key with no help row.
                if key.is_empty() || key == "?" {
                    continue;
                }
                assert!(
                    keys.contains(&key),
                    "footer key {key:?} is missing from the help for this screen; \
                     help has {keys:?}",
                );
            }
        }
    }

    #[test]
    fn help_rows_are_populated_and_have_no_duplicate_keys() {
        for screen in every_screen() {
            let Some(rows) = help_rows(&screen) else {
                continue;
            };
            assert!(!rows.is_empty());
            let mut seen: Vec<String> = Vec::new();
            for (k, d) in rows {
                assert!(!k.is_empty() && !d.is_empty(), "empty help row: {k:?} {d:?}");
                let k = normalize(k);
                assert!(!seen.contains(&k), "duplicate help key {k:?}");
                seen.push(k);
            }
        }
    }

    #[test]
    fn help_popup_is_centred_and_fits_its_content() {
        let rows: &[(&str, &str)] = &[("Enter", "open"), ("q", "quit")];
        let area = Rect { x: 4, y: 2, width: 80, height: 24 };
        let popup = help_popup_rect(area, rows);

        // " Enter  open" = 12 columns, +3 for borders and margin.
        assert_eq!(popup.width, 15);
        // 2 rows + blank + hint + 2 border rows.
        assert_eq!(popup.height, 6);
        assert!(popup.x >= area.x && popup.x + popup.width <= area.x + area.width);
        assert!(popup.y >= area.y && popup.y + popup.height <= area.y + area.height);
        assert_eq!(popup.x - area.x, (area.width - popup.width) / 2);
    }

    #[test]
    fn help_popup_never_exceeds_a_small_terminal() {
        // Every real help list is wider and taller than this.
        let area = Rect { x: 0, y: 0, width: 20, height: 5 };
        for screen in every_screen() {
            let Some(rows) = help_rows(&screen) else {
                continue;
            };
            let popup = help_popup_rect(area, rows);
            assert!(popup.width <= area.width, "{popup:?} wider than {area:?}");
            assert!(popup.height <= area.height, "{popup:?} taller than {area:?}");
            assert!(popup.x + popup.width <= area.x + area.width);
            assert!(popup.y + popup.height <= area.y + area.height);
        }
    }

    #[test]
    fn snapshot_help_documents_the_smb_share_key() {
        let rows = help_rows(&Screen::Snapshots).expect("snapshots has help");
        let (_, desc) = rows
            .iter()
            .find(|(k, _)| *k == "s")
            .expect("`s` is bound on the snapshot list");
        assert!(desc.contains("SMB"), "{desc:?} should say what `s` shares");
    }

    #[test]
    fn human_size_formats() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1023), "1023 B");
        assert_eq!(human_size(1024), "1.0 K");
        assert_eq!(human_size(1536), "1.5 K");
        assert_eq!(human_size(1024 * 1024), "1.0 M");
        assert_eq!(human_size(3 * 1024 * 1024 * 1024), "3.0 G");
    }

    #[test]
    fn short_path_passes_short_inputs_through() {
        let s = "/home/x/foo.txt";
        assert_eq!(short_path(s), s);
    }

    #[test]
    fn short_path_truncates_long_paths_from_the_head() {
        let s: String = std::iter::repeat_n('a', 120).collect();
        let out = short_path(&s);
        assert_eq!(out.chars().count(), 60);
        assert!(out.starts_with('…'));
    }

    #[test]
    fn short_path_handles_multibyte_chars_without_panicking() {
        // 80 emoji (4 bytes each in UTF-8) — the previous byte-indexed slice
        // would land mid-codepoint and panic.
        let s: String = std::iter::repeat_n('🦀', 80).collect();
        let out = short_path(&s);
        assert_eq!(out.chars().count(), 60);
        assert!(out.starts_with('…'));
    }
}
