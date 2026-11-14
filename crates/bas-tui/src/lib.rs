//! Terminal UI for Bitwarden Secrets Manager, limited to what a machine account token can do,
//! or, in broker mode, for the policy of a bas broker, which needs no token and shows no
//! value.
//!
//! `bas tui` calls [`run`]. Keys are listed inside the app with `?`.

use bas_core::credential::MachineToken;
use bas_core::profile::Profile;
use bas_core::reference::ProfileName;
use bas_core::secrets::Session;

use crate::app::App;
use crate::event::{AppEvent, EventHandler};

mod app;
#[cfg(unix)]
mod broker;
#[cfg(unix)]
mod broker_ui;
mod event;
mod sign_in;
mod ui;

/// User agent sent with every Secrets Manager request.
const USER_AGENT: &str = concat!("bas-tui/", env!("CARGO_PKG_VERSION"));

/// How the app begins.
#[derive(Debug)]
pub enum Start {
    /// Sign in to a configured direct profile with its stored token.
    Open(Box<Profile>, MachineToken),
    /// Ask for a machine token on a sign-in screen and save it as a new profile of this
    /// name, the same way `bas auth login` does.
    SignIn(ProfileName),
    /// Manage the policy of the bas broker at this socket. No token is needed, and no
    /// value is shown.
    #[cfg(unix)]
    Broker(std::path::PathBuf),
}

/// Runs the app in the current terminal until the user quits.
///
/// # Errors
///
/// Fails when the async runtime or terminal cannot start, drawing fails, or signing in to a
/// configured profile fails.
pub fn run(start: Start) -> color_eyre::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(async {
        let mut terminal = match ratatui::try_init() {
            Ok(terminal) => terminal,
            Err(err) => {
                // try_init can fail after it enabled raw mode.
                ratatui::restore();
                return Err(
                    color_eyre::eyre::eyre!(err).wrap_err("bas tui needs an interactive terminal")
                );
            }
        };
        let result = run_in(&mut terminal, start).await;
        ratatui::restore();
        result
    });
    // A sign-in can still be waiting for another bas process's lock. Dropping the runtime
    // would wait for it, so the user could not quit.
    runtime.shutdown_background();
    result
}

async fn run_in(terminal: &mut ratatui::DefaultTerminal, start: Start) -> color_eyre::Result<()> {
    let mut events = EventHandler::new()?;
    let profile = match start {
        Start::Open(profile, token) => {
            let profile = *profile;
            let signing_in = profile.clone();
            events.spawn(async move {
                AppEvent::Connected(Box::new(
                    Session::open(&signing_in, &token, USER_AGENT)
                        .await
                        .map_err(color_eyre::Report::new),
                ))
            });
            profile
        }
        #[cfg(unix)]
        Start::Broker(socket) => {
            return broker::BrokerApp::new(&socket, events).run(terminal).await;
        }
        Start::SignIn(name) => {
            let Some(session) = sign_in::run(terminal, &mut events, name).await? else {
                return Ok(());
            };
            let profile = session.profile().clone();
            events.send(AppEvent::Connected(Box::new(Ok(session))));
            profile
        }
    };
    App::new(&profile, events).run(terminal).await
}
