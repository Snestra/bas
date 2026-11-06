//! Terminal UI for Bitwarden Secrets Manager, limited to what a machine account token can do.

use bas_core::credential;
use bas_core::profile::Profiles;
use bas_core::reference::ProfileName;
use clap::Parser;

use crate::app::App;

mod app;
mod event;
mod ui;

/// bas-tui: browse and edit Bitwarden Secrets Manager secrets and projects with the machine
/// account token of a bas profile.
#[derive(Parser)]
#[command(
    name = "bas-tui",
    version,
    after_help = "Create the profile first with `bas auth login <profile> --help`. bas-tui reads \
        the profile's organization and endpoints from the bas configuration and its token \
        from the same place bas does.\n\nPress ? inside the app to list the keys."
)]
struct Cli {
    /// Name of a direct bas profile.
    #[arg(long)]
    profile: String,
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::config::HookBuilder::default()
        .display_env_section(false)
        .display_location_section(false)
        .install()?;
    let cli = Cli::parse();
    let name: ProfileName = cli.profile.parse()?;
    let profile = Profiles::load()?.get(&name)?;
    let token = credential::load_token(&profile)?;
    let terminal = ratatui::init();
    let result = App::new(profile, token).run(terminal).await;
    ratatui::restore();
    result
}
