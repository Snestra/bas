//! Machine settings from `/etc/bas/broker.toml`, which root owns and nothing syncs.
//!
//! ```toml
//! allow-uids = [1000]
//! proxy = "127.0.0.1:3128"
//!
//! [profile]
//! name = "home"
//! organization = "<organization-id>"
//! api-url = "https://api.bitwarden.com"
//! identity-url = "https://identity.bitwarden.com"
//! ```

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::Path;

use bas_core::Uuid;
use bas_core::profile::{CredentialSource, EndpointFlags, Endpoints, Profile};
use bas_core::reference::ProfileName;
use serde::Deserialize;

use crate::Error;

/// Proxy address used when `broker.toml` names none.
const DEFAULT_PROXY: &str = "127.0.0.1:3128";

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ConfigFile {
    allow_uids: Vec<u32>,
    proxy: Option<SocketAddr>,
    profile: ProfileFile,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ProfileFile {
    name: ProfileName,
    organization: Uuid,
    api_url: String,
    identity_url: String,
}

/// Validated machine settings.
#[derive(Debug)]
pub struct Config {
    /// Unix user IDs that may use the socket API.
    pub allow_uids: BTreeSet<u32>,
    /// Loopback address of the HTTPS proxy.
    pub proxy: SocketAddr,
    /// The one Secrets Manager profile the broker reads secrets through. Its token comes
    /// from the systemd credential `bws`.
    pub profile: Profile,
}

impl Config {
    /// Reads and checks the settings file.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path)
            .map_err(|err| Error::new(format!("could not read {}: {err}", path.display())))?;
        let file: ConfigFile = toml::from_str(&text)
            .map_err(|err| Error::new(format!("{} is malformed: {err}", path.display())))?;
        if file.allow_uids.is_empty() {
            return Err(Error::new(format!(
                "{} must list at least one uid in allow-uids",
                path.display()
            )));
        }
        let proxy = match file.proxy {
            Some(proxy) => proxy,
            None => DEFAULT_PROXY
                .parse()
                .map_err(|_| Error::new("the default proxy address is invalid"))?,
        };
        if !proxy.ip().is_loopback() {
            return Err(Error::new(format!(
                "{}: proxy must be a loopback address",
                path.display()
            )));
        }
        let endpoints = Endpoints::from_flags(&EndpointFlags {
            api_url: Some(file.profile.api_url),
            identity_url: Some(file.profile.identity_url),
            ..EndpointFlags::default()
        })
        .map_err(|err| Error::new(format!("{}: {err}", path.display())))?;
        Ok(Self {
            allow_uids: file.allow_uids.into_iter().collect(),
            proxy,
            profile: Profile {
                name: file.profile.name,
                organization: file.profile.organization,
                endpoints,
                credential: CredentialSource::SystemdCredential,
            },
        })
    }
}
