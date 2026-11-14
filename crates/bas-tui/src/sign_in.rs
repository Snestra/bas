//! The sign-in screen shown when the profile does not exist yet.
//!
//! It takes one pasted machine token, signs it in the way `bas auth login` does without
//! flags, and saves the profile before the main app opens.

use std::mem;

use bas_core::credential::{MachineToken, SecretText};
use bas_core::lock::ConfigLock;
use bas_core::login::{self, LoginRequest};
use bas_core::profile::{CredentialSource, Profiles};
use bas_core::reference::ProfileName;
use bas_core::secrets::Session;
use crossterm::event::{Event as CrosstermEvent, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::DefaultTerminal;
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Widget, Wrap};

use crate::USER_AGENT;
use crate::app::{Status, is_typing};
use crate::event::{AppEvent, Event, EventHandler};
use crate::ui::{HIDDEN, panel};

/// State of the sign-in screen.
struct SignIn {
    name: ProfileName,
    token: SecretText,
    /// A sign-in is in flight, so keys are ignored until it answers.
    busy: bool,
    status: Status,
}

/// What a key press asks for.
enum Action {
    Stay,
    Quit,
    Submit(MachineToken),
}

/// Shows the sign-in screen until a token signs in and its profile is saved, or the user
/// quits. Returns the signed-in session, or `None` when the user quit.
///
/// # Errors
///
/// Fails when drawing fails or the event task dies. A refused token is shown on the
/// status line instead, so the user can paste again.
pub async fn run(
    terminal: &mut DefaultTerminal,
    events: &mut EventHandler,
    name: ProfileName,
) -> color_eyre::Result<Option<Session>> {
    let mut screen = SignIn {
        name,
        token: SecretText::default(),
        busy: false,
        status: Status::Info("Paste the token, then press Enter".to_owned()),
    };
    loop {
        terminal.draw(|frame| frame.render_widget(&screen, frame.area()))?;
        match events.next().await? {
            Event::Crossterm(CrosstermEvent::Key(key)) if key.kind == KeyEventKind::Press => {
                match screen.handle_key(key) {
                    Action::Stay => {}
                    Action::Quit => return Ok(None),
                    Action::Submit(token) => {
                        screen.busy = true;
                        screen.status = Status::Info(
                            "Signing in at bitwarden.com, then bitwarden.eu if needed".to_owned(),
                        );
                        let name = screen.name.clone();
                        events.spawn(async move {
                            match sign_in(name, &token).await {
                                Ok(session) => AppEvent::SignedIn(Box::new((session, token))),
                                Err(err) => AppEvent::Connected(Box::new(Err(err))),
                            }
                        });
                    }
                }
            }
            Event::App(AppEvent::SignedIn(signed_in)) => {
                let (session, token) = *signed_in;
                match ConfigLock::try_acquire() {
                    Ok(lock) => {
                        if lock.is_none() {
                            screen.status = Status::Info(
                                "Waiting for another bas process that is changing grants or \
                                 profiles, or delivering a secret"
                                    .to_owned(),
                            );
                        }
                        events.spawn(save(lock, session, token));
                    }
                    Err(err) => {
                        screen.busy = false;
                        screen.status = Status::Error(format!("{err}. Paste the token again"));
                    }
                }
            }
            Event::App(AppEvent::Connected(result)) => match *result {
                Ok(session) => return Ok(Some(session)),
                Err(err) => {
                    screen.busy = false;
                    screen.status = Status::Error(format!("{err}. Paste the token again"));
                }
            },
            Event::App(AppEvent::Quit) => return Ok(None),
            Event::Tick | Event::Crossterm(_) | Event::App(_) => {}
        }
    }
}

/// Signs the token in, learning the organization and region.
async fn sign_in(name: ProfileName, token: &MachineToken) -> color_eyre::Result<Session> {
    let request = LoginRequest {
        name,
        organization: None,
        endpoints: None,
        credential: CredentialSource::OsStore,
    };
    let profiles = tokio::task::spawn_blocking(Profiles::load).await??;
    let previous = request.check(&profiles)?;
    Ok(request
        .sign_in(previous.as_ref(), token, USER_AGENT)
        .await?)
}

/// Saves the signed-in profile with the token in the OS credential store, first waiting
/// for the configuration lock when `lock` is `None`.
async fn save(lock: Option<ConfigLock>, session: Session, token: MachineToken) -> AppEvent {
    let saved = tokio::task::spawn_blocking(move || -> color_eyre::Result<Session> {
        let lock = lock.map_or_else(ConfigLock::acquire, Ok)?;
        login::save(&lock, session.profile(), &token)?;
        Ok(session)
    })
    .await;
    AppEvent::Connected(Box::new(saved.unwrap_or_else(|err| Err(err.into()))))
}

impl SignIn {
    fn handle_key(&mut self, key: KeyEvent) -> Action {
        if key.code == KeyCode::Char('c') && key.modifiers == KeyModifiers::CONTROL {
            return Action::Quit;
        }
        if self.busy {
            return Action::Stay;
        }
        match key.code {
            KeyCode::Esc => Action::Quit,
            KeyCode::Enter if self.token.is_empty() => Action::Stay,
            KeyCode::Enter => match MachineToken::parse(mem::take(&mut self.token)) {
                Ok(token) => Action::Submit(token),
                Err(err) => {
                    self.status = Status::Error(format!(
                        "{err}. Copy the whole access token and paste it again"
                    ));
                    Action::Stay
                }
            },
            KeyCode::Backspace => {
                self.token.pop();
                Action::Stay
            }
            KeyCode::Char(ch) if is_typing(key) => {
                self.token.push(ch);
                Action::Stay
            }
            _ => Action::Stay,
        }
    }
}

impl Widget for &SignIn {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let [header, body, status, keys] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(area);
        Line::from(vec![
            " bas-tui ".bold().reversed(),
            Span::raw(format!(" Sign in | new profile {}", self.name)),
        ])
        .render(header, buf);
        let masked = if self.token.is_empty() { "" } else { HIDDEN };
        let cursor = if self.busy { "" } else { "_" };
        let lines = vec![
            Line::from(format!("Profile '{}' does not exist yet.", self.name)),
            Line::from(""),
            Line::from("Paste the access token of a Bitwarden machine account and press Enter."),
            Line::from(
                "bas learns the organization from Bitwarden and tries bitwarden.com, then \
                 bitwarden.eu.",
            ),
            Line::from("The token is saved in the OS credential store, as `bas auth login` does."),
            Line::from(""),
            Line::from(vec![
                Span::raw("Access token: ").bold(),
                Span::raw(format!("{masked}{cursor}")),
            ]),
        ];
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(panel("Sign in"))
            .render(body, buf);
        match &self.status {
            Status::Info(text) => Line::from(format!(" {text}")),
            Status::Error(text) => Line::from(format!(" {text}")).fg(Color::Red).bold(),
        }
        .render(status, buf);
        Line::from(" paste the token  Enter sign in  Backspace erase  Esc quit")
            .dim()
            .render(keys, buf);
    }
}
