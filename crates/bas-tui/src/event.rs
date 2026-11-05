use std::future::Future;
use std::time::Duration;

use color_eyre::eyre::OptionExt;
use crossterm::event::Event as CrosstermEvent;
use futures::{FutureExt, StreamExt};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::vault::{Project, SecretDetail, SecretListing, Vault, VaultError};

/// How often tick events fire. Ticks drive the clipboard countdown.
const TICK_FPS: f64 = 4.0;

/// Everything the main loop reacts to.
#[derive(Clone, Debug)]
pub enum Event {
    /// Emitted on a fixed schedule.
    Tick,
    /// A terminal event.
    Crossterm(CrosstermEvent),
    /// A result reported back by a spawned network task, or a request from the app itself.
    App(AppEvent),
}

/// Results of network tasks, each sent once the server has answered.
#[derive(Clone, Debug)]
pub enum AppEvent {
    /// Login finished.
    Connected(Result<Vault, VaultError>),
    /// A project listing arrived. When it follows a write, `select` names the project to
    /// highlight and `done` is the status line text.
    Projects {
        result: Result<Vec<Project>, VaultError>,
        select: Option<Uuid>,
        done: Option<String>,
    },
    /// A secret listing arrived for the given project, or for all projects.
    Secrets {
        project: Option<Uuid>,
        result: Result<Vec<SecretListing>, VaultError>,
        done: Option<String>,
    },
    /// One secret was read.
    Secret(Result<SecretDetail, VaultError>),
    /// A create or update finished and the secret was read back from the server.
    SecretSaved(Result<SecretDetail, VaultError>),
    /// A write was refused or failed. `action` completes "Could not ...".
    WriteFailed { action: String, error: VaultError },
    /// Leave the application.
    Quit,
}

/// Terminal event handler.
#[derive(Debug)]
pub struct EventHandler {
    sender: mpsc::UnboundedSender<Event>,
    receiver: mpsc::UnboundedReceiver<Event>,
}

impl EventHandler {
    /// Creates the handler and spawns the task that reads terminal events and emits ticks.
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();
        let actor = EventTask::new(sender.clone());
        tokio::spawn(async { actor.run().await });
        Self { sender, receiver }
    }

    /// Waits for the next event.
    ///
    /// # Errors
    ///
    /// Fails when every sender is gone, which happens only if the event task died.
    pub async fn next(&mut self) -> color_eyre::Result<Event> {
        self.receiver
            .recv()
            .await
            .ok_or_eyre("Failed to receive event")
    }

    /// Queues an app event for the next loop iteration.
    pub fn send(&mut self, app_event: AppEvent) {
        // The receiver lives as long as this struct, so the send cannot fail.
        let _ = self.sender.send(Event::App(app_event));
    }

    /// Runs a network task off the UI loop and delivers its result as an app event.
    pub fn spawn(&self, task: impl Future<Output = AppEvent> + Send + 'static) {
        let sender = self.sender.clone();
        tokio::spawn(async move {
            // The app may have quit while the task ran; the result is then unwanted.
            let _ = sender.send(Event::App(task.await));
        });
    }
}

/// Reads crossterm events and emits ticks.
struct EventTask {
    sender: mpsc::UnboundedSender<Event>,
}

impl EventTask {
    fn new(sender: mpsc::UnboundedSender<Event>) -> Self {
        Self { sender }
    }

    async fn run(self) -> color_eyre::Result<()> {
        let tick_rate = Duration::from_secs_f64(1.0 / TICK_FPS);
        let mut reader = crossterm::event::EventStream::new();
        let mut tick = tokio::time::interval(tick_rate);
        loop {
            let tick_delay = tick.tick();
            let crossterm_event = reader.next().fuse();
            tokio::select! {
              _ = self.sender.closed() => {
                break;
              }
              _ = tick_delay => {
                self.send(Event::Tick);
              }
              Some(Ok(evt)) = crossterm_event => {
                self.send(Event::Crossterm(evt));
              }
            };
        }
        Ok(())
    }

    fn send(&self, event: Event) {
        // Shutting down drops the receiver, so a failed send is expected then.
        let _ = self.sender.send(event);
    }
}
