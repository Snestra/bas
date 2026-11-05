//! Terminal UI for Bitwarden Secrets Manager, limited to what a machine account token can do.

use std::env;

use clap::Parser;
use color_eyre::eyre::{bail, eyre};
use uuid::Uuid;

use crate::app::App;
use crate::vault::{Connection, SecretValue};

mod app;
mod event;
mod ui;
mod vault;

const ACCESS_TOKEN_VAR: &str = "BWS_ACCESS_TOKEN";
const ORGANIZATION_VAR: &str = "BAS_TUI_ORGANIZATION";
const REGION_VAR: &str = "BAS_TUI_REGION";

/// bas-tui: browse and edit Bitwarden Secrets Manager secrets and projects with a machine
/// account access token.
#[derive(Parser)]
#[command(
    name = "bas-tui",
    version,
    after_help = "Configuration comes from the environment:\n  \
        BWS_ACCESS_TOKEN      machine account access token (required)\n  \
        BAS_TUI_ORGANIZATION  organization ID the token belongs to (required)\n  \
        BAS_TUI_REGION        us or eu (default us)\n\n\
        Press ? inside the app to list the keys."
)]
struct Cli {}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::config::HookBuilder::default()
        .display_env_section(false)
        .display_location_section(false)
        .install()?;
    Cli::parse();
    let connection = connection_from_env()?;
    let terminal = ratatui::init();
    let result = App::new(connection).run(terminal).await;
    ratatui::restore();
    result
}

/// Builds the connection from the environment. This is the only place that reads configuration.
fn connection_from_env() -> color_eyre::Result<Connection> {
    let token = env::var(ACCESS_TOKEN_VAR).map_err(|_| {
        eyre!("{ACCESS_TOKEN_VAR} is not set; set it to a machine account access token")
    })?;
    let organization: Uuid = env::var(ORGANIZATION_VAR)
        .map_err(|_| eyre!("{ORGANIZATION_VAR} is not set; set it to your organization ID"))?
        .parse()
        .map_err(|_| eyre!("{ORGANIZATION_VAR} is not an organization ID (a UUID)"))?;
    let region = env::var(REGION_VAR).unwrap_or_else(|_| "us".to_owned());
    let (api_url, identity_url) = match region.as_str() {
        "us" => (
            "https://api.bitwarden.com",
            "https://identity.bitwarden.com",
        ),
        "eu" => ("https://api.bitwarden.eu", "https://identity.bitwarden.eu"),
        _ => bail!("{REGION_VAR} must be us or eu"),
    };
    Ok(Connection {
        api_url: api_url.to_owned(),
        identity_url: identity_url.to_owned(),
        organization,
        token: SecretValue::new(token),
        user_agent: concat!("bas-tui/", env!("CARGO_PKG_VERSION")).to_owned(),
    })
}
