use std::time::{Duration, Instant};

use arboard::Clipboard;
use color_eyre::eyre::eyre;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::DefaultTerminal;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::event::{AppEvent, Event, EventHandler};
use crate::vault::{
    Connection, Project, SecretDetail, SecretDraft, SecretListing, SecretValue, Vault, VaultError,
    web_vault_base,
};

/// How long a copied value stays on the clipboard before it is cleared.
pub const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(30);

/// Application state.
pub struct App {
    pub running: bool,
    pub events: EventHandler,
    /// Web vault origin, such as `https://vault.bitwarden.com`.
    pub vault_base: String,
    pub organization: Uuid,
    /// The session, once login has finished.
    pub vault: Option<Vault>,
    /// Projects the machine account can read, sorted by name.
    pub projects: Vec<Project>,
    /// Open screens. The first is always [`Screen::Projects`]; the last is shown.
    pub screens: Vec<Screen>,
    pub modal: Option<Modal>,
    pub status: Status,
    /// `None` when the system offers no clipboard.
    pub clipboard: Option<Clipboard>,
    /// The value this app last copied, until it is cleared.
    pub copied: Option<Copied>,
}

/// One screen of the stack.
pub enum Screen {
    /// Row 0 is "all secrets"; row `i + 1` is `projects[i]`.
    Projects {
        selected: usize,
    },
    Secrets(SecretsScreen),
    Secret(SecretScreen),
    Form(SecretForm),
    WebVault,
}

/// Secrets of one project, or of every project the machine account can read.
pub struct SecretsScreen {
    pub project: Option<Uuid>,
    /// `None` until the first listing arrives.
    pub items: Option<Vec<SecretListing>>,
    /// Index into [`SecretsScreen::visible`].
    pub selected: usize,
    pub filter: String,
    pub filtering: bool,
}

impl SecretsScreen {
    /// Listings whose key contains the filter, ignoring case.
    pub fn visible(&self) -> Vec<&SecretListing> {
        let needle = self.filter.to_lowercase();
        self.items
            .iter()
            .flatten()
            .filter(|item| item.key.to_lowercase().contains(&needle))
            .collect()
    }

    fn selected_item(&self) -> Option<&SecretListing> {
        self.visible().get(self.selected).copied()
    }
}

/// One secret, value and note hidden until revealed.
pub struct SecretScreen {
    /// `None` while the read is in flight.
    pub detail: Option<SecretDetail>,
    pub revealed: bool,
    /// Open the edit form as soon as the read arrives.
    pub edit_on_load: bool,
}

/// Fields of the secret form, in tab order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Key,
    Value,
    Note,
    Project,
}

impl Field {
    const ORDER: [Self; 4] = [Self::Key, Self::Value, Self::Note, Self::Project];

    fn step(self, forward: Direction) -> Self {
        let index = Self::ORDER
            .iter()
            .position(|field| *field == self)
            .unwrap_or(0);
        let next = match forward {
            Direction::Next => (index + 1) % Self::ORDER.len(),
            Direction::Previous => (index + Self::ORDER.len() - 1) % Self::ORDER.len(),
        };
        Self::ORDER[next]
    }
}

#[derive(Clone, Copy)]
enum Direction {
    Next,
    Previous,
}

/// Create or edit form for one secret.
pub struct SecretForm {
    /// The secret being edited, or `None` for a new one.
    pub editing: Option<Uuid>,
    pub key: String,
    pub value: SecretValue,
    pub note: SecretValue,
    /// Index into [`App::projects`].
    pub project: usize,
    pub focus: Field,
    /// Keys type into the focused field. Otherwise keys move, reveal, and save.
    pub typing: bool,
    pub revealed: bool,
    pub saving: bool,
}

/// A dialog drawn over the current screen.
pub enum Modal {
    Help,
    /// Name input for a new project, or for renaming the project with this ID.
    ProjectName {
        renaming: Option<Uuid>,
        input: String,
    },
    Delete {
        target: DeleteTarget,
        typed: String,
    },
}

/// What a delete confirmation would remove.
#[derive(Clone)]
pub enum DeleteTarget {
    /// `listing` is the project filter of the secrets list to refresh afterwards.
    Secret {
        id: Uuid,
        key: String,
        listing: Option<Uuid>,
    },
    Project {
        id: Uuid,
        name: String,
    },
}

impl DeleteTarget {
    /// The text the owner must type to enable the delete.
    pub fn name(&self) -> &str {
        match self {
            Self::Secret { key, .. } => key,
            Self::Project { name, .. } => name,
        }
    }
}

/// The status line.
pub enum Status {
    Info(String),
    Error(String),
}

/// A value this app put on the clipboard.
pub struct Copied {
    pub text: Zeroizing<String>,
    pub deadline: Instant,
}

impl App {
    /// Builds the app and starts logging in off the UI loop.
    pub fn new(connection: Connection) -> Self {
        let vault_base = web_vault_base(&connection.api_url);
        let organization = connection.organization;
        let events = EventHandler::new();
        events.spawn(async move { AppEvent::Connected(Vault::connect(connection).await) });
        Self {
            running: true,
            events,
            vault_base,
            organization,
            vault: None,
            projects: Vec::new(),
            screens: vec![Screen::Projects { selected: 0 }],
            modal: None,
            status: Status::Info("Connecting to Secrets Manager".to_owned()),
            clipboard: Clipboard::new().ok(),
            copied: None,
        }
    }

    /// Runs the main loop, then clears the clipboard if it still holds a copied value.
    ///
    /// # Errors
    ///
    /// Fails when drawing fails, the event task dies, or login fails.
    pub async fn run(mut self, mut terminal: DefaultTerminal) -> color_eyre::Result<()> {
        let result = self.event_loop(&mut terminal).await;
        self.clear_clipboard();
        result
    }

    async fn event_loop(&mut self, terminal: &mut DefaultTerminal) -> color_eyre::Result<()> {
        while self.running {
            terminal.draw(|frame| frame.render_widget(&*self, frame.area()))?;
            match self.events.next().await? {
                Event::Tick => self.tick(),
                Event::Crossterm(crossterm::event::Event::Key(key))
                    if key.kind == KeyEventKind::Press =>
                {
                    self.handle_key_event(key);
                }
                Event::Crossterm(_) => {}
                Event::App(app_event) => self.handle_app_event(app_event)?,
            }
        }
        Ok(())
    }

    fn handle_app_event(&mut self, event: AppEvent) -> color_eyre::Result<()> {
        match event {
            AppEvent::Connected(Ok(vault)) => {
                self.status = Status::Info("Connected. Loading projects".to_owned());
                self.load_projects(&vault);
                self.vault = Some(vault);
            }
            AppEvent::Connected(Err(err)) => {
                return Err(eyre!("could not connect to Secrets Manager: {err}"));
            }
            AppEvent::Projects {
                result,
                select,
                done,
            } => self.on_projects(result, select, done),
            AppEvent::Secrets {
                project,
                result,
                done,
            } => self.on_secrets(project, result, done),
            AppEvent::Secret(result) => self.on_secret(result),
            AppEvent::SecretSaved(result) => self.on_secret_saved(result),
            AppEvent::WriteFailed { action, error } => {
                if let Some(Screen::Form(form)) = self.screens.last_mut() {
                    form.saving = false;
                }
                self.status = Status::Error(format!("Could not {action}: {error}"));
            }
            AppEvent::Quit => self.running = false,
        }
        Ok(())
    }

    fn on_projects(
        &mut self,
        result: Result<Vec<Project>, VaultError>,
        select: Option<Uuid>,
        done: Option<String>,
    ) {
        let projects = match result {
            Ok(projects) => projects,
            Err(err) => {
                self.status = Status::Error(format!("Could not list projects: {err}"));
                return;
            }
        };
        self.status = Status::Info(done.unwrap_or_else(|| match projects.len() {
            1 => "1 project".to_owned(),
            count => format!("{count} projects"),
        }));
        let row_count = projects.len() + 1;
        let selected_row = select
            .and_then(|id| projects.iter().position(|project| project.id == id))
            .map(|index| index + 1);
        self.projects = projects;
        if let Some(Screen::Projects { selected }) = self.screens.first_mut() {
            *selected = selected_row.unwrap_or(*selected).min(row_count - 1);
        }
    }

    fn on_secrets(
        &mut self,
        project: Option<Uuid>,
        result: Result<Vec<SecretListing>, VaultError>,
        done: Option<String>,
    ) {
        let items = match result {
            Ok(items) => items,
            Err(err) => {
                self.status = Status::Error(format!("Could not list secrets: {err}"));
                return;
            }
        };
        self.status = Status::Info(done.unwrap_or_else(|| match items.len() {
            1 => "1 secret".to_owned(),
            count => format!("{count} secrets"),
        }));
        for screen in &mut self.screens {
            if let Screen::Secrets(list) = screen
                && list.project == project
            {
                list.items = Some(items.clone());
                let visible = list.visible().len();
                list.selected = list.selected.min(visible.saturating_sub(1));
            }
        }
    }

    fn on_secret(&mut self, result: Result<SecretDetail, VaultError>) {
        let Some(Screen::Secret(screen)) = self.screens.last_mut() else {
            return;
        };
        match result {
            Ok(detail) => {
                let edit = screen.edit_on_load;
                screen.edit_on_load = false;
                self.status = Status::Info(format!("Read {}", detail.key));
                if edit {
                    let form = edit_form(&self.projects, &detail);
                    screen.detail = Some(detail);
                    self.screens.push(Screen::Form(form));
                } else {
                    screen.detail = Some(detail);
                }
            }
            Err(err) => {
                self.screens.pop();
                self.status = Status::Error(format!("Could not read the secret: {err}"));
            }
        }
    }

    fn on_secret_saved(&mut self, result: Result<SecretDetail, VaultError>) {
        if matches!(self.screens.last(), Some(Screen::Form(_))) {
            self.screens.pop();
        }
        let detail = match result {
            Ok(detail) => detail,
            Err(err) => {
                self.status =
                    Status::Error(format!("Saved, but could not read the secret back: {err}"));
                return;
            }
        };
        self.status = Status::Info(format!(
            "Saved {}. Showing what the server returned",
            detail.key
        ));
        match self.screens.last_mut() {
            Some(Screen::Secret(screen)) => {
                screen.detail = Some(detail);
                screen.revealed = false;
            }
            _ => self.screens.push(Screen::Secret(SecretScreen {
                detail: Some(detail),
                revealed: false,
                edit_on_load: false,
            })),
        }
        if let Some(vault) = self.vault.clone() {
            for screen in &self.screens {
                if let Screen::Secrets(list) = screen {
                    self.load_secrets(&vault, list.project);
                }
            }
        }
    }

    /// Handles a key press. Ctrl-C always quits.
    pub fn handle_key_event(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Char('c') && key.modifiers == KeyModifiers::CONTROL {
            self.events.send(AppEvent::Quit);
            return;
        }
        if let Some(modal) = self.modal.take() {
            self.modal = self.handle_modal_key(modal, key);
            return;
        }
        match self.screens.last() {
            Some(Screen::Form(_)) => self.handle_form_key(key),
            Some(Screen::Secrets(list)) if list.filtering => self.handle_filter_key(key),
            _ => self.handle_screen_key(key),
        }
    }

    fn handle_screen_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.back(),
            KeyCode::Char('?') => self.modal = Some(Modal::Help),
            KeyCode::Char('w') => {
                if !matches!(self.screens.last(), Some(Screen::WebVault)) {
                    self.screens.push(Screen::WebVault);
                }
            }
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(Direction::Previous),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(Direction::Next),
            _ => match self.screens.last() {
                Some(Screen::Projects { .. }) => self.handle_projects_key(key),
                Some(Screen::Secrets(_)) => self.handle_secrets_key(key),
                Some(Screen::Secret(_)) => self.handle_secret_key(key),
                _ => {}
            },
        }
    }

    fn back(&mut self) {
        if self.screens.len() > 1 {
            self.screens.pop();
        } else {
            self.events.send(AppEvent::Quit);
        }
    }

    fn move_selection(&mut self, direction: Direction) {
        let project_rows = self.projects.len() + 1;
        let (selected, rows) = match self.screens.last_mut() {
            Some(Screen::Projects { selected }) => (selected, project_rows),
            Some(Screen::Secrets(list)) => {
                let rows = list.visible().len();
                (&mut list.selected, rows)
            }
            _ => return,
        };
        *selected = match direction {
            Direction::Next => (*selected + 1).min(rows.saturating_sub(1)),
            Direction::Previous => selected.saturating_sub(1),
        };
    }

    fn selected_project(&self) -> Option<&Project> {
        match self.screens.first() {
            Some(Screen::Projects { selected }) => {
                selected.checked_sub(1).and_then(|i| self.projects.get(i))
            }
            _ => None,
        }
    }

    /// The project filter of the innermost open secrets list, if a list is open.
    fn open_listing(&self) -> Option<Option<Uuid>> {
        self.screens.iter().rev().find_map(|screen| match screen {
            Screen::Secrets(list) => Some(list.project),
            _ => None,
        })
    }

    /// The project in view: the open secrets list's project, else the highlighted project.
    pub fn context_project(&self) -> Option<&Project> {
        match self.open_listing() {
            Some(Some(id)) => self.projects.iter().find(|project| project.id == id),
            Some(None) => None,
            None => self.selected_project(),
        }
    }

    fn connected(&mut self) -> Option<Vault> {
        if self.vault.is_none() {
            self.status = Status::Info("Still connecting to Secrets Manager".to_owned());
        }
        self.vault.clone()
    }

    fn handle_projects_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => {
                let Some(vault) = self.connected() else {
                    return;
                };
                let project = self.selected_project().map(|project| project.id);
                self.screens.push(Screen::Secrets(SecretsScreen {
                    project,
                    items: None,
                    selected: 0,
                    filter: String::new(),
                    filtering: false,
                }));
                self.load_secrets(&vault, project);
            }
            KeyCode::Char('n') => {
                self.modal = Some(Modal::ProjectName {
                    renaming: None,
                    input: String::new(),
                });
            }
            KeyCode::Char('e') => {
                if let Some(project) = self.selected_project() {
                    self.modal = Some(Modal::ProjectName {
                        renaming: Some(project.id),
                        input: project.name.clone(),
                    });
                }
            }
            KeyCode::Char('d') => {
                if let Some(project) = self.selected_project() {
                    self.modal = Some(Modal::Delete {
                        target: DeleteTarget::Project {
                            id: project.id,
                            name: project.name.clone(),
                        },
                        typed: String::new(),
                    });
                }
            }
            _ => {}
        }
    }

    fn handle_secrets_key(&mut self, key: KeyEvent) {
        let Some(Screen::Secrets(list)) = self.screens.last_mut() else {
            return;
        };
        let listing = list.project;
        let selected = list.selected_item().map(|item| (item.id, item.key.clone()));
        match key.code {
            KeyCode::Char('/') => list.filtering = true,
            KeyCode::Enter => {
                if let Some((id, _)) = selected {
                    self.open_secret(id, false);
                }
            }
            KeyCode::Char('e') => {
                if let Some((id, _)) = selected {
                    self.open_secret(id, true);
                }
            }
            KeyCode::Char('n') => self.open_new_form(),
            KeyCode::Char('d') => {
                if let Some((id, key)) = selected {
                    self.modal = Some(Modal::Delete {
                        target: DeleteTarget::Secret { id, key, listing },
                        typed: String::new(),
                    });
                }
            }
            _ => {}
        }
    }

    fn handle_filter_key(&mut self, key: KeyEvent) {
        let Some(Screen::Secrets(list)) = self.screens.last_mut() else {
            return;
        };
        match key.code {
            KeyCode::Enter => list.filtering = false,
            KeyCode::Esc => {
                list.filtering = false;
                list.filter.clear();
            }
            KeyCode::Backspace => {
                list.filter.pop();
            }
            KeyCode::Char(ch) if is_typing(key) => list.filter.push(ch),
            _ => {}
        }
        list.selected = 0;
    }

    fn handle_secret_key(&mut self, key: KeyEvent) {
        let listing = self.open_listing().flatten();
        let Some(Screen::Secret(screen)) = self.screens.last_mut() else {
            return;
        };
        let Some(detail) = &screen.detail else {
            return;
        };
        match key.code {
            KeyCode::Char('r') => screen.revealed = !screen.revealed,
            KeyCode::Char('c') => {
                let key_name = detail.key.clone();
                let text = Zeroizing::new(detail.value.expose().to_owned());
                self.copy(&key_name, text);
            }
            KeyCode::Char('e') => {
                let form = edit_form(&self.projects, detail);
                self.screens.push(Screen::Form(form));
            }
            KeyCode::Char('d') => {
                let target = DeleteTarget::Secret {
                    id: detail.id,
                    key: detail.key.clone(),
                    listing,
                };
                self.modal = Some(Modal::Delete {
                    target,
                    typed: String::new(),
                });
            }
            _ => {}
        }
    }

    fn open_secret(&mut self, id: Uuid, edit_on_load: bool) {
        let Some(vault) = self.connected() else {
            return;
        };
        self.screens.push(Screen::Secret(SecretScreen {
            detail: None,
            revealed: false,
            edit_on_load,
        }));
        self.status = Status::Info("Reading the secret".to_owned());
        self.events
            .spawn(async move { AppEvent::Secret(vault.get_secret(id).await) });
    }

    fn open_new_form(&mut self) {
        if self.projects.is_empty() {
            self.status = Status::Error(
                "A machine account must put each secret in a project. Create a project first"
                    .to_owned(),
            );
            return;
        }
        let project = self
            .context_project()
            .and_then(|current| self.projects.iter().position(|p| p.id == current.id))
            .unwrap_or(0);
        self.screens.push(Screen::Form(SecretForm {
            editing: None,
            key: String::new(),
            value: SecretValue::default(),
            note: SecretValue::default(),
            project,
            focus: Field::Key,
            typing: true,
            revealed: false,
            saving: false,
        }));
    }

    fn handle_form_key(&mut self, key: KeyEvent) {
        let project_count = self.projects.len();
        let Some(Screen::Form(form)) = self.screens.last_mut() else {
            return;
        };
        if form.saving {
            return;
        }
        let ctrl = key.modifiers == KeyModifiers::CONTROL;
        if form.typing {
            match key.code {
                KeyCode::Char('s') if ctrl => self.save_form(),
                KeyCode::Esc | KeyCode::Enter => form.typing = false,
                KeyCode::Tab => {
                    form.typing = false;
                    form.focus = form.focus.step(Direction::Next);
                }
                KeyCode::Backspace => match form.focus {
                    Field::Key => {
                        form.key.pop();
                    }
                    Field::Value => form.value.pop(),
                    Field::Note => form.note.pop(),
                    Field::Project => {}
                },
                KeyCode::Char(ch) if is_typing(key) => match form.focus {
                    Field::Key => form.key.push(ch),
                    Field::Value => form.value.push(ch),
                    Field::Note => form.note.push(ch),
                    Field::Project => {}
                },
                _ => {}
            }
            return;
        }
        match key.code {
            KeyCode::Esc => {
                self.screens.pop();
            }
            KeyCode::Char('r') => form.revealed = !form.revealed,
            KeyCode::Char('s') if ctrl => self.save_form(),
            KeyCode::Enter if form.focus == Field::Project => self.save_form(),
            KeyCode::Enter => form.typing = true,
            KeyCode::Tab | KeyCode::Down | KeyCode::Char('j') => {
                form.focus = form.focus.step(Direction::Next);
            }
            KeyCode::BackTab | KeyCode::Up | KeyCode::Char('k') => {
                form.focus = form.focus.step(Direction::Previous);
            }
            KeyCode::Left | KeyCode::Char('h')
                if form.focus == Field::Project && project_count > 0 =>
            {
                form.project = (form.project + project_count - 1) % project_count;
            }
            KeyCode::Right | KeyCode::Char('l')
                if form.focus == Field::Project && project_count > 0 =>
            {
                form.project = (form.project + 1) % project_count;
            }
            _ => {}
        }
    }

    fn save_form(&mut self) {
        let Some(vault) = self.connected() else {
            return;
        };
        let Some(Screen::Form(form)) = self.screens.last_mut() else {
            return;
        };
        let Some(project) = self.projects.get(form.project) else {
            self.status = Status::Error("Pick a project for the secret".to_owned());
            return;
        };
        let draft = SecretDraft {
            key: form.key.trim().to_owned(),
            value: form.value.clone(),
            note: form.note.clone(),
            project_id: project.id,
        };
        form.saving = true;
        self.status = Status::Info(format!("Saving {}", draft.key));
        let editing = form.editing;
        self.events.spawn(async move {
            let action = format!("save {}", draft.key);
            let written = match editing {
                Some(id) => vault.update_secret(id, &draft).await,
                None => vault.create_secret(&draft).await,
            };
            match written {
                Ok(stored) => AppEvent::SecretSaved(vault.get_secret(stored.id).await),
                Err(error) => AppEvent::WriteFailed { action, error },
            }
        });
    }

    fn handle_modal_key(&mut self, modal: Modal, key: KeyEvent) -> Option<Modal> {
        match modal {
            Modal::Help => None,
            Modal::ProjectName {
                renaming,
                mut input,
            } => match key.code {
                KeyCode::Esc => None,
                KeyCode::Enter => {
                    let name = input.trim().to_owned();
                    if name.is_empty() {
                        return Some(Modal::ProjectName { renaming, input });
                    }
                    self.write_project(renaming, name);
                    None
                }
                KeyCode::Backspace => {
                    input.pop();
                    Some(Modal::ProjectName { renaming, input })
                }
                KeyCode::Char(ch) if is_typing(key) => {
                    input.push(ch);
                    Some(Modal::ProjectName { renaming, input })
                }
                _ => Some(Modal::ProjectName { renaming, input }),
            },
            Modal::Delete { target, mut typed } => match key.code {
                KeyCode::Esc => None,
                KeyCode::Enter if typed == target.name() => {
                    self.delete(target);
                    None
                }
                KeyCode::Backspace => {
                    typed.pop();
                    Some(Modal::Delete { target, typed })
                }
                KeyCode::Char(ch) if is_typing(key) => {
                    typed.push(ch);
                    Some(Modal::Delete { target, typed })
                }
                _ => Some(Modal::Delete { target, typed }),
            },
        }
    }

    fn write_project(&mut self, renaming: Option<Uuid>, name: String) {
        let Some(vault) = self.connected() else {
            return;
        };
        self.status = Status::Info(format!("Saving project {name}"));
        self.events.spawn(async move {
            let (action, written) = match renaming {
                Some(id) => (
                    format!("rename the project to {name}"),
                    vault.rename_project(id, &name).await,
                ),
                None => (
                    format!("create project {name}"),
                    vault.create_project(&name).await,
                ),
            };
            match written {
                Ok(stored) => AppEvent::Projects {
                    result: vault.list_projects().await,
                    select: Some(stored.id),
                    done: Some(format!(
                        "Server saved project {}. List re-read from the server",
                        stored.name
                    )),
                },
                Err(error) => AppEvent::WriteFailed { action, error },
            }
        });
    }

    fn delete(&mut self, target: DeleteTarget) {
        let Some(vault) = self.connected() else {
            return;
        };
        match target {
            DeleteTarget::Secret { id, key, listing } => {
                if matches!(self.screens.last(), Some(Screen::Secret(_))) {
                    self.screens.pop();
                }
                self.status = Status::Info(format!("Deleting {key}"));
                let trash = self.trash_url();
                self.events.spawn(async move {
                    match vault.delete_secret(id).await {
                        Ok(()) => AppEvent::Secrets {
                            project: listing,
                            result: vault.list_secrets(listing).await,
                            done: Some(format!("Moved {key} to trash. Restore it at {trash}")),
                        },
                        Err(error) => AppEvent::WriteFailed {
                            action: format!("delete {key}"),
                            error,
                        },
                    }
                });
            }
            DeleteTarget::Project { id, name } => {
                self.status = Status::Info(format!("Deleting project {name}"));
                self.events.spawn(async move {
                    match vault.delete_project(id).await {
                        Ok(()) => AppEvent::Projects {
                            result: vault.list_projects().await,
                            select: None,
                            done: Some(format!("Deleted project {name}")),
                        },
                        Err(error) => AppEvent::WriteFailed {
                            action: format!("delete project {name}"),
                            error,
                        },
                    }
                });
            }
        }
    }

    fn load_projects(&self, vault: &Vault) {
        let vault = vault.clone();
        self.events.spawn(async move {
            AppEvent::Projects {
                result: vault.list_projects().await,
                select: None,
                done: None,
            }
        });
    }

    fn load_secrets(&self, vault: &Vault, project: Option<Uuid>) {
        let vault = vault.clone();
        self.events.spawn(async move {
            AppEvent::Secrets {
                project,
                result: vault.list_secrets(project).await,
                done: None,
            }
        });
    }

    /// The trash page, where deleted secrets can be restored.
    pub fn trash_url(&self) -> String {
        format!("{}/#/sm/{}/trash", self.vault_base, self.organization)
    }

    fn copy(&mut self, key_name: &str, text: Zeroizing<String>) {
        let Some(clipboard) = self.clipboard.as_mut() else {
            self.status = Status::Error("No clipboard is available here".to_owned());
            return;
        };
        match clipboard.set_text(text.as_str()) {
            Ok(()) => {
                self.copied = Some(Copied {
                    text,
                    deadline: Instant::now() + CLIPBOARD_CLEAR_AFTER,
                });
                self.status = Status::Info(format!("Copied the value of {key_name}"));
            }
            Err(_) => self.status = Status::Error("Could not write the clipboard".to_owned()),
        }
    }

    /// Clears the clipboard once the copied value's time is up.
    pub fn tick(&mut self) {
        if self
            .copied
            .as_ref()
            .is_some_and(|copied| Instant::now() >= copied.deadline)
        {
            self.clear_clipboard();
        }
    }

    /// Clears the clipboard only if it still holds the value this app copied.
    fn clear_clipboard(&mut self) {
        let (Some(copied), Some(clipboard)) = (self.copied.take(), self.clipboard.as_mut()) else {
            return;
        };
        let current = clipboard.get_text().map(Zeroizing::new);
        let ours = current.is_ok_and(|text| text.as_str() == copied.text.as_str());
        self.status = if !ours {
            Status::Info("The clipboard changed since the copy, so it was left alone".to_owned())
        } else if clipboard.clear().is_ok() {
            Status::Info("Cleared the copied value from the clipboard".to_owned())
        } else {
            Status::Error("Could not clear the clipboard".to_owned())
        };
    }
}

/// A form prefilled from a secret the server returned.
fn edit_form(projects: &[Project], detail: &SecretDetail) -> SecretForm {
    let project = detail
        .project_id
        .and_then(|id| projects.iter().position(|p| p.id == id))
        .unwrap_or(0);
    SecretForm {
        editing: Some(detail.id),
        key: detail.key.clone(),
        value: detail.value.clone(),
        note: detail.note.clone(),
        project,
        focus: Field::Key,
        typing: false,
        revealed: false,
        saving: false,
    }
}

/// A key that types its character: no modifier other than Shift.
fn is_typing(key: KeyEvent) -> bool {
    key.modifiers.difference(KeyModifiers::SHIFT).is_empty()
}
