use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, List, ListItem, Paragraph, Wrap},
};

use crate::app::{App, BACKEND_ORDER, FIRST_RUN_MENU, MAIN_MENU, MANAGE_MENU, Screen};

pub(crate) fn render(frame: &mut Frame, app: &mut App) {
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
            "Defaults to us-east-1 if left blank. Backblaze B2 uses 'auto'. (Esc back)",
        ),
        Screen::S3Root => render_input(
            frame,
            "Path within bucket (optional)",
            &app.s3_root,
            "e.g. /proxmox_vm_backup — leave blank to use the bucket root (Esc back)",
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

enum MainOrManage {
    Main,
    Manage,
}

fn selection_highlight() -> Style {
    Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD)
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
        .highlight_style(selection_highlight())
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

    let list = List::new(items)
        .block(
            Block::bordered()
                .title("Choose backend — j/k to move, Enter to pick, Esc back"),
        )
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
        .highlight_style(selection_highlight())
        .highlight_symbol(">> ");

    frame.render_stateful_widget(list, frame.area(), &mut app.list_state);
}
