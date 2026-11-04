//! Diagnostics that never read, print, or retrieve secret values.

use std::env;

use ap_client::MemoryIdentityProvider;
use bitwarden::secrets_manager::{ClientSettings, SecretsManagerClient};

use crate::credential::{self, ACCESS_TOKEN_VAR};
use crate::output::{Check, Status};
use crate::profile::{Profile, Profiles};
use crate::secrets::Session;

/// Runs every offline check and returns the results in display order.
///
/// No check opens a network connection or authenticates. Environment variables are
/// tested for presence only and their values are never read into output.
pub fn offline() -> Vec<Check> {
    vec![
        build(),
        secrets_manager_sdk(),
        agent_access_sdk(),
        profile_configuration(),
        access_token_variable(),
    ]
}

/// Authenticates one profile and confirms its organization without retrieving secrets.
pub async fn authenticated(profile: &Profile) -> Check {
    let label = "profile";
    let session = match credential::load_token(profile) {
        Ok(token) => Session::open(profile, &token).await,
        Err(err) => Err(err),
    };
    match session {
        Ok(_) => Check {
            status: Status::Ready,
            label,
            detail: format!(
                "'{}' authenticated to organization {} at {} using the {}",
                profile.name,
                profile.organization,
                profile.endpoints.api(),
                profile.credential
            ),
        },
        Err(err) => Check {
            status: Status::Failed,
            label,
            detail: err.to_string(),
        },
    }
}

fn build() -> Check {
    Check {
        status: Status::Ready,
        label: "build",
        detail: format!(
            "bas {} on {}-{}",
            env!("CARGO_PKG_VERSION"),
            env::consts::OS,
            env::consts::ARCH
        ),
    }
}

fn secrets_manager_sdk() -> Check {
    let settings = ClientSettings::default();
    let identity_url = settings.identity_url.clone();
    let api_url = settings.api_url.clone();
    let client = SecretsManagerClient::new(Some(settings));
    let session = match client.get_access_token_organization() {
        Some(_) => "authenticated",
        None => "no session",
    };
    Check {
        status: Status::Ready,
        label: "secrets manager sdk",
        detail: format!("{session}; SDK default endpoints {identity_url} and {api_url}"),
    }
}

fn agent_access_sdk() -> Check {
    let identity = MemoryIdentityProvider::new();
    drop(identity);
    Check {
        status: Status::Ready,
        label: "agent access sdk",
        detail: "ephemeral device identity can be generated".to_owned(),
    }
}

fn profile_configuration() -> Check {
    let label = "profiles";
    match Profiles::load() {
        Ok(profiles) if profiles.is_empty() => Check {
            status: Status::NotConfigured,
            label,
            detail: format!(
                "none in {}; run `bas auth login --help`. Never paste tokens into a chat.",
                profiles.path().display()
            ),
        },
        Ok(profiles) => Check {
            status: Status::Ready,
            label,
            detail: format!("{} in {}", profiles.len(), profiles.path().display()),
        },
        Err(err) => Check {
            status: Status::Failed,
            label,
            detail: err.to_string(),
        },
    }
}

fn access_token_variable() -> Check {
    if env::var_os(ACCESS_TOKEN_VAR).is_some() {
        Check {
            status: Status::Ready,
            label: "machine token",
            detail: format!(
                "{ACCESS_TOKEN_VAR} is set; value hidden. Only --from-env profiles read it, and \
                 child processes never inherit it"
            ),
        }
    } else {
        Check {
            status: Status::NotConfigured,
            label: "machine token",
            detail: format!(
                "{ACCESS_TOKEN_VAR} is not set; only profiles created with --from-env need it"
            ),
        }
    }
}
