//! Profiles bind a name either to trusted Secrets Manager endpoints, one organization, and
//! one credential source (direct), or to one relay and one pinned listener (remote).
//!
//! Profiles live in user configuration outside any repository. References and templates
//! name a profile but can never supply endpoints, relays, or credentials.

use std::collections::BTreeMap;
use std::env;
use std::fmt::{self, Display};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use ap_client::IdentityFingerprint;
use serde::{Deserialize, Serialize};
use url::{Host, Url};
use uuid::Uuid;

use crate::Error;
use crate::lock::ConfigLock;
use crate::reference::ProfileName;

/// Environment variable that relocates profile configuration, mainly for headless use.
pub const CONFIG_DIR_VAR: &str = "BAS_CONFIG_DIR";

const CONFIG_FILE: &str = "config.toml";

/// Hosted Bitwarden region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Region {
    /// bitwarden.com
    Us,
    /// bitwarden.eu
    Eu,
}

/// Endpoint choices exactly as the user gave them, before validation.
///
/// [`Endpoints::from_flags`] accepts exactly one choice: a region, a server URL, or both
/// an API and an identity URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EndpointFlags {
    /// Hosted region.
    pub region: Option<Region>,
    /// Self-hosted base URL, which serves `/api` and `/identity`.
    pub server_url: Option<String>,
    /// Explicit API URL, given together with `identity_url`.
    pub api_url: Option<String>,
    /// Explicit identity URL, given together with `api_url`.
    pub identity_url: Option<String>,
}

/// Validated HTTPS endpoints for one Bitwarden deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    api_url: Url,
    identity_url: Url,
}

impl Endpoints {
    /// Resolves exactly one endpoint choice into API and identity URLs.
    ///
    /// # Errors
    ///
    /// Returns a usage error when no choice, several choices, or a non-HTTPS URL is given.
    pub fn from_flags(flags: &EndpointFlags) -> Result<Self, Error> {
        let endpoints = match flags {
            EndpointFlags {
                region: Some(region),
                server_url: None,
                api_url: None,
                identity_url: None,
            } => {
                let (api, identity) = match region {
                    Region::Us => (
                        "https://api.bitwarden.com",
                        "https://identity.bitwarden.com",
                    ),
                    Region::Eu => ("https://api.bitwarden.eu", "https://identity.bitwarden.eu"),
                };
                Self {
                    api_url: parse_endpoint(api)?,
                    identity_url: parse_endpoint(identity)?,
                }
            }
            EndpointFlags {
                region: None,
                server_url: Some(server),
                api_url: None,
                identity_url: None,
            } => {
                let server = parse_endpoint(server)?;
                let base = server.as_str().trim_end_matches('/');
                Self {
                    api_url: parse_endpoint(&format!("{base}/api"))?,
                    identity_url: parse_endpoint(&format!("{base}/identity"))?,
                }
            }
            EndpointFlags {
                region: None,
                server_url: None,
                api_url: Some(api),
                identity_url: Some(identity),
            } => Self {
                api_url: parse_endpoint(api)?,
                identity_url: parse_endpoint(identity)?,
            },
            _ => {
                return Err(Error::usage(
                    "choose exactly one endpoint: --region, --server-url, or both --api-url and \
                     --identity-url",
                ));
            }
        };
        Ok(endpoints)
    }

    /// API URL without a trailing slash, as the SDK expects.
    #[must_use]
    pub fn api(&self) -> &str {
        self.api_url.as_str().trim_end_matches('/')
    }

    /// Identity URL without a trailing slash, as the SDK expects.
    #[must_use]
    pub fn identity(&self) -> &str {
        self.identity_url.as_str().trim_end_matches('/')
    }

    fn validate(&self) -> Result<(), Error> {
        check_endpoint(&self.api_url)?;
        check_endpoint(&self.identity_url)
    }
}

fn parse_endpoint(raw: &str) -> Result<Url, Error> {
    let url = Url::parse(raw).map_err(|_| Error::usage("an endpoint must be an absolute URL"))?;
    check_endpoint(&url)?;
    Ok(url)
}

fn check_endpoint(url: &Url) -> Result<(), Error> {
    let plain = url.scheme() == "https"
        && url.host().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none();
    if plain {
        Ok(())
    } else {
        Err(Error::usage(
            "an endpoint must be an https:// URL without credentials, query, or fragment",
        ))
    }
}

/// Agent Access relay URL: `wss://`, or `ws://` only to a loopback host for a local relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayUrl(Url);

impl RelayUrl {
    fn check(url: &Url) -> Result<(), Error> {
        let loopback = match url.host() {
            Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
            Some(Host::Ipv4(address)) => address.is_loopback(),
            Some(Host::Ipv6(address)) => address.is_loopback(),
            None => false,
        };
        let scheme = url.scheme() == "wss" || (url.scheme() == "ws" && loopback);
        let plain = url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none();
        if scheme && plain {
            Ok(())
        } else {
            Err(Error::usage(
                "a relay must be a wss:// URL, or ws:// to a loopback address, without \
                 credentials, query, or fragment",
            ))
        }
    }
}

impl FromStr for RelayUrl {
    type Err = Error;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(raw).map_err(|_| Error::usage("a relay must be an absolute URL"))?;
        Self::check(&url)?;
        Ok(Self(url))
    }
}

impl Display for RelayUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

/// A remote binding: secrets come from one pinned listener through one relay.
///
/// It holds no Secrets Manager endpoint or machine token. The listener decides what the
/// referenced IDs resolve to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteProfile {
    /// Name used in references.
    pub name: ProfileName,
    /// Relay the listener is reached through.
    pub relay: RelayUrl,
    /// Identity of the pinned listener.
    pub listener: IdentityFingerprint,
}

/// How a profile name resolves.
#[derive(Debug, Clone)]
pub enum Connection {
    /// Secrets Manager access with a machine token.
    Direct(Profile),
    /// Access through a paired listener.
    Remote(RemoteProfile),
}

/// A remote device paired with a listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairedPeer {
    /// Identity of the device.
    pub fingerprint: IdentityFingerprint,
    /// Label the listener operator gave the device, if any.
    pub name: Option<ProfileName>,
}

/// Where a profile's machine token comes from. Exactly one source per profile, no fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum CredentialSource {
    /// The operating system credential store.
    OsStore,
    /// `BWS_ACCESS_TOKEN` in the environment of each invocation, for headless automation.
    Environment,
}

impl Display for CredentialSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OsStore => "os credential store",
            Self::Environment => "BWS_ACCESS_TOKEN environment variable",
        })
    }
}

/// One trusted direct Secrets Manager binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// Name used in references.
    pub name: ProfileName,
    /// Organization the machine token must belong to.
    pub organization: Uuid,
    /// Trusted Secrets Manager endpoints.
    pub endpoints: Endpoints,
    /// The single place the machine token comes from.
    pub credential: CredentialSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct StoredProfile {
    organization: Uuid,
    api_url: Url,
    identity_url: Url,
    credential: CredentialSource,
}

impl StoredProfile {
    fn endpoints(&self) -> Endpoints {
        Endpoints {
            api_url: self.api_url.clone(),
            identity_url: self.identity_url.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct StoredRemote {
    relay: Url,
    /// Hex identity fingerprint of the pinned listener.
    listener: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct StoredPeer {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<ProfileName>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct StoredListener {
    /// Paired devices keyed by hex identity fingerprint.
    #[serde(default)]
    peers: BTreeMap<String, StoredPeer>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    #[serde(default)]
    profiles: BTreeMap<ProfileName, StoredProfile>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    remotes: BTreeMap<ProfileName, StoredRemote>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    listeners: BTreeMap<ProfileName, StoredListener>,
}

fn parse_fingerprint(hex: &str) -> Option<IdentityFingerprint> {
    IdentityFingerprint::from_hex(hex).ok()
}

/// All configured profiles and the file they came from.
#[derive(Debug)]
pub struct Profiles {
    path: PathBuf,
    file: ConfigFile,
}

impl Profiles {
    /// Loads profile configuration. A missing file means no profiles.
    ///
    /// # Errors
    ///
    /// Fails when the configuration directory is unusable or inside a repository, or the
    /// file is unreadable or malformed.
    pub fn load() -> Result<Self, Error> {
        let path = config_dir()?.join(CONFIG_FILE);
        let file = match fs::read_to_string(&path) {
            Ok(text) => toml::from_str::<ConfigFile>(&text).map_err(|_| {
                Error::new(format!(
                    "profile configuration {} is malformed",
                    path.display()
                ))
            })?,
            Err(err) if err.kind() == io::ErrorKind::NotFound => ConfigFile::default(),
            Err(_) => {
                return Err(Error::new(format!(
                    "could not read profile configuration {}",
                    path.display()
                )));
            }
        };
        for stored in file.profiles.values() {
            stored.endpoints().validate().map_err(|_| {
                Error::new(format!(
                    "profile configuration {} has a non-HTTPS endpoint",
                    path.display()
                ))
            })?;
        }
        let malformed = || {
            Error::new(format!(
                "profile configuration {} has a malformed remote or listener entry",
                path.display()
            ))
        };
        for (name, remote) in &file.remotes {
            RelayUrl::check(&remote.relay).map_err(|_| malformed())?;
            parse_fingerprint(&remote.listener).ok_or_else(malformed)?;
            if file.profiles.contains_key(name) {
                return Err(malformed());
            }
        }
        for (name, listener) in &file.listeners {
            if !file.profiles.contains_key(name) {
                return Err(malformed());
            }
            for fingerprint in listener.peers.keys() {
                parse_fingerprint(fingerprint).ok_or_else(malformed)?;
            }
        }
        Ok(Self { path, file })
    }

    /// The configuration file, which may not exist yet.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Number of direct profiles.
    #[must_use]
    pub fn len(&self) -> usize {
        self.file.profiles.len()
    }

    /// Whether no direct profile is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.file.profiles.is_empty()
    }

    /// Looks up a profile by name. Returns `None` when it is not configured.
    pub fn find(&self, name: &ProfileName) -> Option<Profile> {
        self.file.profiles.get(name).map(|stored| Profile {
            name: name.clone(),
            organization: stored.organization,
            endpoints: stored.endpoints(),
            credential: stored.credential,
        })
    }

    /// Looks up a direct profile that must exist.
    ///
    /// # Errors
    ///
    /// Fails with setup guidance when the profile is not configured, or is a remote
    /// profile, which cannot find, write, or authenticate.
    pub fn get(&self, name: &ProfileName) -> Result<Profile, Error> {
        match self.connection(name)? {
            Connection::Direct(profile) => Ok(profile),
            Connection::Remote(_) => Err(Error::new(format!(
                "profile '{name}' is a remote profile; it only resolves references for `bas \
                 run` and `bas env run` through its paired listener"
            ))),
        }
    }

    /// Resolves a profile name to its direct or remote binding.
    ///
    /// # Errors
    ///
    /// Fails with setup guidance when the name is not configured.
    pub fn connection(&self, name: &ProfileName) -> Result<Connection, Error> {
        if let Some(profile) = self.find(name) {
            return Ok(Connection::Direct(profile));
        }
        self.remote(name).map(Connection::Remote).ok_or_else(|| {
            Error::new(format!(
                "profile '{name}' is not configured; run `bas auth login {name} --help` or `bas \
                 pair {name} --help`"
            ))
        })
    }

    /// Direct profiles in name order.
    pub fn iter(&self) -> impl Iterator<Item = Profile> + '_ {
        self.file.profiles.keys().filter_map(|name| self.find(name))
    }

    /// Looks up a remote profile. Returns `None` when it is not configured.
    pub fn remote(&self, name: &ProfileName) -> Option<RemoteProfile> {
        let stored = self.file.remotes.get(name)?;
        Some(RemoteProfile {
            name: name.clone(),
            relay: RelayUrl(stored.relay.clone()),
            listener: parse_fingerprint(&stored.listener)?,
        })
    }

    /// Remote profiles in name order.
    pub fn remotes(&self) -> impl Iterator<Item = RemoteProfile> + '_ {
        self.file
            .remotes
            .keys()
            .filter_map(|name| self.remote(name))
    }

    /// Whether the name is taken by a direct or a remote profile.
    pub fn is_configured(&self, name: &ProfileName) -> bool {
        self.file.profiles.contains_key(name) || self.file.remotes.contains_key(name)
    }

    /// Adds or replaces a remote profile in memory. [`Profiles::save`] writes it.
    pub fn insert_remote(&mut self, remote: RemoteProfile) {
        self.file.remotes.insert(
            remote.name,
            StoredRemote {
                relay: remote.relay.0,
                listener: remote.listener.to_hex(),
            },
        );
    }

    /// Removes a remote profile in memory. Returns `false` when it was not configured.
    pub fn remove_remote(&mut self, name: &ProfileName) -> bool {
        self.file.remotes.remove(name).is_some()
    }

    /// Devices paired with the listener of a direct profile.
    pub fn listener_peers(&self, name: &ProfileName) -> Vec<PairedPeer> {
        self.file
            .listeners
            .get(name)
            .into_iter()
            .flat_map(|listener| &listener.peers)
            .filter_map(|(hex, peer)| {
                Some(PairedPeer {
                    fingerprint: parse_fingerprint(hex)?,
                    name: peer.name.clone(),
                })
            })
            .collect()
    }

    /// Records a device paired with the listener of a direct profile, in memory.
    pub fn insert_listener_peer(&mut self, name: &ProfileName, peer: PairedPeer) {
        self.file
            .listeners
            .entry(name.clone())
            .or_default()
            .peers
            .insert(peer.fingerprint.to_hex(), StoredPeer { name: peer.name });
    }

    /// Removes the listener record of a direct profile and returns its paired devices.
    pub fn remove_listener(&mut self, name: &ProfileName) -> Vec<PairedPeer> {
        let peers = self.listener_peers(name);
        self.file.listeners.remove(name);
        peers
    }

    /// Adds or replaces a direct profile in memory. [`Profiles::save`] writes it.
    pub fn insert(&mut self, profile: Profile) {
        self.file.profiles.insert(
            profile.name,
            StoredProfile {
                organization: profile.organization,
                api_url: profile.endpoints.api_url,
                identity_url: profile.endpoints.identity_url,
                credential: profile.credential,
            },
        );
    }

    /// Removes a direct profile in memory. Returns `false` when it was not configured.
    pub fn remove(&mut self, name: &ProfileName) -> bool {
        self.file.profiles.remove(name).is_some()
    }

    /// Writes the configuration atomically with owner-only permissions where supported.
    ///
    /// Callers hold the [`ConfigLock`] from their [`Profiles::load`] through this save, so
    /// concurrent writers cannot lose each other's changes and a listener's delivery
    /// check never straddles a change.
    ///
    /// # Errors
    ///
    /// Fails when the directory or file cannot be written.
    pub fn save(&self, _lock: &ConfigLock) -> Result<(), Error> {
        let failed = || {
            Error::new(format!(
                "could not write profile configuration {}",
                self.path.display()
            ))
        };
        let dir = self.path.parent().ok_or_else(failed)?;
        create_private_dir(dir).map_err(|_| failed())?;
        let text = toml::to_string(&self.file).map_err(|_| failed())?;
        replace_private_file(&self.path, text.as_bytes()).map_err(|_| failed())
    }
}

/// Resolves the configuration directory and refuses locations inside a Git repository.
///
/// # Errors
///
/// Fails when no directory can be determined, `BAS_CONFIG_DIR` is relative, or the
/// directory is inside a repository.
pub fn config_dir() -> Result<PathBuf, Error> {
    let dir = match env::var_os(CONFIG_DIR_VAR) {
        Some(dir) => {
            let dir = PathBuf::from(dir);
            if !dir.is_absolute() {
                return Err(Error::usage(format!(
                    "{CONFIG_DIR_VAR} must be an absolute path"
                )));
            }
            dir
        }
        None => dirs::config_dir()
            .ok_or_else(|| {
                Error::new(format!(
                    "no user configuration directory is available; set {CONFIG_DIR_VAR}"
                ))
            })?
            .join("bas"),
    };
    #[cfg(unix)]
    if dir.exists() {
        check_private_dir(&dir).map_err(|_| Error::new("the bas configuration directory must be a private directory accessible only to its owner"))?;
    }
    if let Some(repository) = enclosing_repository(&dir) {
        return Err(Error::new(format!(
            "profile configuration must live outside a repository, but {} is inside {}; set \
             {CONFIG_DIR_VAR} to another directory",
            dir.display(),
            repository.display()
        )));
    }
    Ok(dir)
}

fn enclosing_repository(dir: &Path) -> Option<PathBuf> {
    let existing = dir.ancestors().find(|path| path.exists())?;
    let resolved = existing.canonicalize().ok()?;
    resolved
        .ancestors()
        .find(|path| path.join(".git").exists())
        .map(Path::to_path_buf)
}

/// Creates a directory and its parents, accessible only to the owner where supported.
///
/// # Errors
///
/// Fails when the directory cannot be created, or on Unix when it is not a directory
/// owned by this user with no group or other permissions.
#[cfg(unix)]
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    check_private_dir(dir)
}

/// Creates a directory and its parents, accessible only to the owner where supported.
///
/// # Errors
///
/// Fails when the directory cannot be created.
#[cfg(not(unix))]
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)
}

#[cfg(unix)]
fn check_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = fs::symlink_metadata(dir)?;
    if !metadata.is_dir()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "configuration directory must be private",
        ));
    }
    Ok(())
}

/// Replaces a private file atomically and asks the OS to persist the replacement.
///
/// # Errors
///
/// Fails when the replacement cannot be written, renamed into place, or flushed.
pub fn replace_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    atomicwrites::AtomicFile::new(path, atomicwrites::AllowOverwrite)
        .write_with_options(|file| file.write_all(contents), options)
        .map_err(io::Error::from)
}
