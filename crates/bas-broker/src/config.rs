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
//! project = "<project-id>"          # where `bas add` creates secrets
//!
//! [approvals]
//! listen = "127.0.0.1:793"
//! origin = "https://bas.example.ts.net"
//! ```

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::Path;

use bas_core::Uuid;
use bas_core::profile::{CredentialSource, EndpointFlags, Endpoints, Profile};
use bas_core::reference::ProfileName;
use serde::Deserialize;
use webauthn_rs::prelude::Url;

use crate::Error;

/// Proxy address used when `broker.toml` names none.
const DEFAULT_PROXY: &str = "127.0.0.1:3128";
/// Approval page address used when `broker.toml` names none. The port is below 1024, so
/// only a process with `CAP_NET_BIND_SERVICE` can take it while the broker is down.
const DEFAULT_APPROVALS: &str = "127.0.0.1:793";

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ConfigFile {
    allow_uids: Vec<u32>,
    proxy: Option<SocketAddr>,
    profile: ProfileFile,
    approvals: ApprovalsFile,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ProfileFile {
    name: ProfileName,
    organization: Uuid,
    api_url: String,
    identity_url: String,
    project: Option<Uuid>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ApprovalsFile {
    listen: Option<SocketAddr>,
    origin: Url,
}

/// Validated machine settings.
#[derive(Debug)]
pub struct Config {
    /// Unix user IDs that may use the socket API and the ssh-agent socket.
    pub allow_uids: BTreeSet<u32>,
    /// Loopback address of the HTTPS proxy.
    pub proxy: SocketAddr,
    /// The one Secrets Manager profile the broker reads secrets through. Its token comes
    /// from the systemd credential `bws`.
    pub profile: Profile,
    /// Project that `bas add` creates secrets in. Without it, `bas add` is refused.
    pub project: Option<Uuid>,
    /// Loopback address of the approval pages.
    pub approvals_listen: SocketAddr,
    /// HTTPS origin the phone opens the approval pages on. Its host is the WebAuthn
    /// relying party ID.
    pub approvals_origin: Url,
}

impl Config {
    /// Reads and checks the settings file.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path)
            .map_err(|err| Error::new(format!("could not read {}: {err}", path.display())))?;
        let file: ConfigFile = toml::from_str(&text)
            .map_err(|err| Error::new(format!("{} is malformed: {err}", path.display())))?;
        let invalid = |reason: &str| Error::new(format!("{}: {reason}", path.display()));
        if file.allow_uids.is_empty() {
            return Err(invalid("allow-uids must list at least one uid"));
        }
        let proxy = loopback(file.proxy, DEFAULT_PROXY)
            .ok_or_else(|| invalid("proxy must be a loopback address"))?;
        let approvals_listen = loopback(file.approvals.listen, DEFAULT_APPROVALS)
            .ok_or_else(|| invalid("approvals.listen must be a loopback address"))?;
        let origin = file.approvals.origin;
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || origin.path() != "/"
            || origin.query().is_some()
        {
            return Err(invalid(
                "approvals.origin must look like https://bas.example.ts.net, with no path",
            ));
        }
        let endpoints = Endpoints::from_flags(&EndpointFlags {
            api_url: Some(file.profile.api_url),
            identity_url: Some(file.profile.identity_url),
            ..EndpointFlags::default()
        })
        .map_err(|err| invalid(&err.to_string()))?;
        Ok(Self {
            allow_uids: file.allow_uids.into_iter().collect(),
            proxy,
            profile: Profile {
                name: file.profile.name,
                organization: file.profile.organization,
                endpoints,
                credential: CredentialSource::SystemdCredential,
            },
            project: file.profile.project,
            approvals_listen,
            approvals_origin: origin,
        })
    }

    /// The approval page for one request, as the phone opens it.
    pub fn approval_url(&self, id: Uuid) -> String {
        format!("{}a/{}", self.approvals_origin, id.hyphenated())
    }
}

fn loopback(given: Option<SocketAddr>, default: &str) -> Option<SocketAddr> {
    let addr = match given {
        Some(addr) => addr,
        None => default.parse().ok()?,
    };
    addr.ip().is_loopback().then_some(addr)
}
