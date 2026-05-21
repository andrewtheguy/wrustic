use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, List, ListItem, Paragraph, Wrap},
};

use crate::app::{App, BACKEND_ORDER, FIRST_RUN_MENU, Screen};
use crate::repo::ContentKind;

pub(crate) fn render(frame: &mut Frame, app: &mut App) {
    match &app.screen {
        Screen::FirstRunChoice => render_first_run_choice(frame, app),
        Screen::RestoreKeyWait => render_restore_wait(frame, app),
        Screen::KeyCreated => render_key_created(frame, app),
        Screen::Home => render_home(frame, app),
        Screen::CreateProfileName => render_input(
            frame,
            "Profile name",
            &app.new_profile_name,
            "Give this profile a short name, e.g. 'laptop-local' (Esc cancels)",
        ),
        Screen::BackendChoice => render_backend_choice(frame, app),
        Screen::LocalPath => render_input(
            frame,
            &profile_title("Local repository path", app),
            &app.local_path,
            "Filesystem path, e.g. /tmp/wrustic-test-repo (Esc back)",
        ),
        Screen::RestConfig => render_rest_config(frame, app),
        Screen::S3Location => render_s3_location(frame, app),
        Screen::S3Credentials => render_s3_credentials(frame, app),
        Screen::Password => {
            let masked = "*".repeat(app.password.chars().count());
            render_input(
                frame,
                &profile_title("Repository password", app),
                &masked,
                "Restic repository password (Esc back; profile saves on Enter)",
            );
        }
        Screen::ConfirmDelete => {
            let name = app
                .pending_delete
                .and_then(|i| app.config.name_at(i))
                .map(String::as_str)
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
        Screen::OpeningSnapshot => {
            let para = Paragraph::new("Opening snapshot — reading root tree…")
                .block(Block::bordered().title("Loading"));
            frame.render_widget(para, frame.area());
        }
        Screen::LoadingDir => {
            let para = Paragraph::new("Loading directory…")
                .block(Block::bordered().title("Loading"));
            frame.render_widget(para, frame.area());
        }
        Screen::SnapshotContents => render_snapshot_contents(frame, app),
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
        .highlight_style(selection_highlight())
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

fn selection_highlight() -> Style {
    Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD)
}

// Decorate a creation/edit screen title with the in-progress profile name so
// the user can always see which profile they are editing.
fn profile_title(base: &str, app: &App) -> String {
    if app.new_profile_name.is_empty() {
        base.to_string()
    } else {
        format!("{base} — profile '{}'", app.new_profile_name)
    }
}

fn render_home(frame: &mut Frame, app: &mut App) {
    let title = "wrustic — j/k move, Enter open, n new, e edit, d delete, q quit";

    if app.config.profiles.is_empty() {
        let para = Paragraph::new("No profiles yet. Press 'n' to create one, 'q' to quit.")
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(title));
        frame.render_widget(para, frame.area());
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

    frame.render_stateful_widget(list, frame.area(), &mut app.profile_list_state);
}

fn render_backend_choice(frame: &mut Frame, app: &mut App) {
    let items: Vec<ListItem> = BACKEND_ORDER
        .iter()
        .map(|k| ListItem::new(k.label()))
        .collect();

    let title = if app.new_profile_name.is_empty() {
        "Choose backend — j/k to move, Enter to pick, Esc to rename".to_string()
    } else {
        format!(
            "Choose backend for '{}' — j/k to move, Enter to pick, Esc to rename",
            app.new_profile_name
        )
    };

    let list = List::new(items)
        .block(Block::bordered().title(title))
        .highlight_style(selection_highlight())
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

fn render_grouped_input(
    frame: &mut Frame,
    title: &str,
    fields: &[(&str, &str, bool)],
    focus: usize,
    help: &str,
) {
    let outer = Block::bordered().title(title);
    let inner_area = outer.inner(frame.area());
    frame.render_widget(outer, frame.area());

    let mut constraints: Vec<Constraint> = fields.iter().map(|_| Constraint::Length(3)).collect();
    constraints.push(Constraint::Length(1));
    constraints.push(Constraint::Fill(1));
    let areas = Layout::vertical(constraints).split(inner_area);

    for (i, (label, value, masked)) in fields.iter().enumerate() {
        let display: String = if *masked {
            "*".repeat(value.chars().count())
        } else {
            (*value).to_string()
        };
        let value_str = if i == focus {
            format!("{display}_")
        } else {
            display
        };
        let mut block = Block::bordered().title(*label);
        if i == focus {
            block = block.border_style(Style::new().fg(Color::Yellow));
        }
        let para = Paragraph::new(value_str).block(block);
        frame.render_widget(para, areas[i]);
    }

    let help_para = Paragraph::new(help).style(Style::new().fg(Color::DarkGray));
    frame.render_widget(help_para, areas[fields.len()]);
}

fn render_rest_config(frame: &mut Frame, app: &App) {
    let title = profile_title(
        "REST backend — Tab/Shift+Tab move, Enter continue, Esc back",
        app,
    );
    let fields = [
        ("URL (required)", app.rest_url.as_str(), false),
        ("Username (optional)", app.rest_user.as_str(), false),
        ("Password (optional)", app.rest_password.as_str(), true),
    ];
    render_grouped_input(
        frame,
        &title,
        &fields,
        app.field_focus,
        "Anonymous server? Leave user/password blank. Enter advances to the repository password.",
    );
}

fn render_s3_location(frame: &mut Frame, app: &App) {
    let title = profile_title(
        "S3 location — Tab/Shift+Tab move, Enter continue, Esc back",
        app,
    );
    let fields = [
        (
            "Endpoint (optional)",
            app.s3_endpoint.as_str(),
            false,
        ),
        ("Bucket (required)", app.s3_bucket.as_str(), false),
        (
            "Region (optional, defaults to us-east-1)",
            app.s3_region.as_str(),
            false,
        ),
        (
            "Path within bucket (optional)",
            app.s3_root.as_str(),
            false,
        ),
    ];
    render_grouped_input(
        frame,
        &title,
        &fields,
        app.field_focus,
        "Leave Endpoint blank for AWS. Backblaze B2 uses region 'auto'. MinIO/rclone: http://127.0.0.1:8333",
    );
}

fn render_s3_credentials(frame: &mut Frame, app: &App) {
    let title = profile_title(
        "S3 credentials — Tab/Shift+Tab move, Enter continue, Esc back",
        app,
    );
    let fields = [
        ("Access key ID", app.s3_access_key.as_str(), false),
        ("Secret access key", app.s3_secret_key.as_str(), true),
    ];
    render_grouped_input(
        frame,
        &title,
        &fields,
        app.field_focus,
        "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY equivalents.",
    );
}

fn render_snapshots(frame: &mut Frame, app: &mut App) {
    let title = format!(
        "Snapshots ({}) — j/k move, Enter browse, r refresh, q/Esc back to menu",
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
        .highlight_style(selection_highlight())
        .highlight_symbol(">> ");

    frame.render_stateful_widget(list, frame.area(), &mut app.list_state);
}

fn render_snapshot_contents(frame: &mut Frame, app: &mut App) {
    if app.browse_stack.is_empty() {
        let para = Paragraph::new("No content loaded.")
            .block(Block::bordered().title("Snapshot contents"));
        frame.render_widget(para, frame.area());
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
        "Snap {} {} — j/k move, Enter open, Backspace up, r reload, q/Esc back",
        short_snap_id(&app.browse_snapshot_id),
        path_display,
    );

    let frame_idx = app.browse_stack.len() - 1;
    let top = &app.browse_stack[frame_idx];
    let items: Vec<ListItem> = top
        .items
        .iter()
        .map(|row| {
            let kind_char = match row.kind {
                ContentKind::Dir => 'd',
                ContentKind::File => '-',
                ContentKind::Symlink => 'l',
                ContentKind::Other => '?',
            };
            let display_name = if matches!(row.kind, ContentKind::Dir) {
                format!("{}/", row.name)
            } else {
                row.name.clone()
            };
            let size_col = if matches!(row.kind, ContentKind::File) {
                format!("{:>10}", row.size)
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
    frame.render_stateful_widget(list, frame.area(), &mut top_mut.list_state);
}

fn short_snap_id(id: &str) -> &str {
    let end = id.char_indices().nth(8).map(|(i, _)| i).unwrap_or(id.len());
    &id[..end]
}
