//! Machine tokens, secret text, and Agent Access key material, kept out of output and
//! debug formatting and stored only in the OS credential store.

use std::env;
use std::fmt;

use ap_client::IdentityFingerprint;
use bitwarden::secrets_manager::AccessToken;
use zeroize::Zeroizing;

use crate::Error;
use crate::profile::{CredentialSource, Profile};
use crate::reference::ProfileName;

mod store;

/// Environment variable that supplies a machine token to `environment` profiles.
pub const ACCESS_TOKEN_VAR: &str = "BWS_ACCESS_TOKEN";

/// Pairing token variable read by the upstream Agent Access CLI.
const AGENT_ACCESS_TOKEN_VAR: &str = "AAC_TOKEN";

/// Name of the systemd credential that holds the machine token of `systemd-credential`
/// profiles.
const SYSTEMD_CREDENTIAL: &str = "bws";

/// Directory where systemd puts the credentials of a service. The broker's launchd plist
/// on macOS sets it to a directory only the broker's account can read.
const CREDENTIALS_DIRECTORY_VAR: &str = "CREDENTIALS_DIRECTORY";

/// Bootstrap and pairing credentials that `bas` removes from every child environment.
pub const BOOTSTRAP_CREDENTIAL_VARS: &[&str] = &[ACCESS_TOKEN_VAR, AGENT_ACCESS_TOKEN_VAR];

/// Secret text whose memory is zeroed on drop and whose `Debug` output is redacted.
#[derive(Default)]
pub struct SecretText(Zeroizing<String>);

impl SecretText {
    /// Takes ownership of the text, which is zeroed when this value drops.
    #[must_use]
    pub fn new(text: String) -> Self {
        Self(Zeroizing::new(text))
    }

    /// The secret text. Callers must not print or log it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Wraps text that is already zeroed on drop.
    #[must_use]
    pub fn from_zeroizing(text: Zeroizing<String>) -> Self {
        Self(text)
    }

    /// Appends one typed character.
    ///
    /// The text is first moved into a buffer big enough for it, and the old buffer is
    /// zeroed, so growing never leaves an unzeroed copy behind.
    pub fn push(&mut self, ch: char) {
        if self.0.len() + ch.len_utf8() > self.0.capacity() {
            let mut grown = Zeroizing::new(String::with_capacity(
                (self.0.len() + ch.len_utf8()).max(32) * 2,
            ));
            grown.push_str(&self.0);
            self.0 = grown;
        }
        self.0.push(ch);
    }

    /// Removes the last character, if any.
    pub fn pop(&mut self) {
        self.0.pop();
    }

    /// Whether the text is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Hands the text on without an unzeroed copy.
    #[must_use]
    pub fn into_zeroizing(self) -> Zeroizing<String> {
        self.0
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretText(<redacted>)")
    }
}

/// A Secrets Manager machine token whose format has been checked offline.
pub struct MachineToken(SecretText);

impl MachineToken {
    /// Checks the token format without contacting a server.
    ///
    /// # Errors
    ///
    /// Returns an error that does not repeat the token when its format is invalid.
    pub fn parse(mut text: SecretText) -> Result<Self, Error> {
        let token_length = text.expose().trim_end_matches(['\r', '\n']).len();
        text.0.truncate(token_length);
        match text.expose().parse::<AccessToken>() {
            Ok(_) => Ok(Self(text)),
            Err(_) => Err(Error::new(
                "the machine token is not in Secrets Manager access-token format",
            )),
        }
    }

    /// The token text. Callers must not print or log it.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }
}

impl fmt::Debug for MachineToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MachineToken(<redacted>)")
    }
}

/// Loads the machine token from the profile's single configured source.
///
/// # Errors
///
/// Fails when that source has no usable token. Never consults another source.
pub fn load_token(profile: &Profile) -> Result<MachineToken, Error> {
    match profile.credential {
        CredentialSource::Environment => load_environment_token(&profile.name),
        CredentialSource::SystemdCredential => load_systemd_token(&profile.name),
        CredentialSource::OsStore => {
            let token = store_entry(&profile.name)?
                .get_password()
                .map_err(|err| store_error(&profile.name, &err))?;
            MachineToken::parse(SecretText::new(token))
        }
    }
}

/// Loads the machine token from `BWS_ACCESS_TOKEN` for the named profile.
///
/// # Errors
///
/// Fails when the variable is not set or does not hold a machine token.
pub fn load_environment_token(profile: &ProfileName) -> Result<MachineToken, Error> {
    let token = env::var(ACCESS_TOKEN_VAR).map_err(|_| {
        Error::new(format!(
            "profile '{profile}' reads its token from {ACCESS_TOKEN_VAR}, which is not set"
        ))
    })?;
    MachineToken::parse(SecretText::new(token))
}

/// Loads the machine token from the file `bws` in `$CREDENTIALS_DIRECTORY` for the named
/// profile. systemd fills that directory on Linux, and the broker's launchd plist names it
/// on macOS.
///
/// # Errors
///
/// Fails when the process has no credentials directory, or the file is missing, unreadable,
/// or does not hold a machine token.
fn load_systemd_token(profile: &ProfileName) -> Result<MachineToken, Error> {
    let missing = || {
        Error::new(format!(
            "profile '{profile}' reads its token from the credential \
             {SYSTEMD_CREDENTIAL} in ${CREDENTIALS_DIRECTORY_VAR}, which this process was not \
             given"
        ))
    };
    let dir = env::var_os(CREDENTIALS_DIRECTORY_VAR).ok_or_else(missing)?;
    let token = std::fs::read_to_string(std::path::Path::new(&dir).join(SYSTEMD_CREDENTIAL))
        .map_err(|_| missing())?;
    MachineToken::parse(SecretText::new(token))
}

/// Saves a machine token in the operating system credential store.
///
/// # Errors
///
/// Fails when no credential store is usable. There is no plaintext fallback.
pub fn store_token(profile: &ProfileName, token: &MachineToken) -> Result<(), Error> {
    store_entry(profile)?
        .set_password(token.expose())
        .map_err(|err| store_error(profile, &err))
}

/// Deletes a stored machine token. Returns `false` when none was stored.
///
/// # Errors
///
/// Fails when the credential store is unusable.
pub fn delete_token(profile: &ProfileName) -> Result<bool, Error> {
    match store_entry(profile)?.delete_credential() {
        Ok(()) => Ok(true),
        Err(keyring_core::Error::NoEntry) => Ok(false),
        Err(err) => Err(store_error(profile, &err)),
    }
}

fn store_entry(profile: &ProfileName) -> Result<keyring_core::Entry, Error> {
    store::entry(profile.as_str()).map_err(|err| store_error(profile, &err))
}

fn store_error(profile: &ProfileName, err: &keyring_core::Error) -> Error {
    let reason = match err {
        keyring_core::Error::NoEntry => {
            return Error::new(format!(
                "no machine token is stored for profile '{profile}'; run `bas auth login \
                 {profile} --help`"
            ));
        }
        _ => store_reason(err),
    };
    Error::new(format!(
        "the OS credential store {reason} for profile '{profile}'; headless systems can use \
         --from-env instead"
    ))
}

/// Says how the OS credential store failed. Only platform errors add their own detail,
/// because other variants can carry stored bytes.
fn store_reason(err: &keyring_core::Error) -> String {
    match err {
        keyring_core::Error::NoStorageAccess(detail) => {
            format!("is locked or denied access ({detail})")
        }
        keyring_core::Error::PlatformFailure(detail) => format!("failed ({detail})"),
        keyring_core::Error::NoDefaultStore => "is not available on this system".to_owned(),
        _ => "failed".to_owned(),
    }
}

/// Agent Access key material, kept only in the OS credential store.
///
/// Identity keys and session transport keys let a device act as a paired peer, so they
/// are never written to configuration files and have no plaintext fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Material {
    /// The trusted listener's identity key pair for a direct profile.
    ListenerIdentity(ProfileName),
    /// The listener's session keys for one paired remote device.
    ListenerPeer(ProfileName, IdentityFingerprint),
    /// A remote profile's identity key pair.
    RemoteIdentity(ProfileName),
    /// A remote profile's session keys for its pinned listener.
    RemoteConnection(ProfileName),
}

impl Material {
    /// Credential-store account name. Profile names cannot contain `/`, so these never
    /// collide with machine-token entries.
    fn account(&self) -> String {
        match self {
            Self::ListenerIdentity(profile) => format!("listener/{profile}/identity"),
            Self::ListenerPeer(profile, peer) => {
                format!("listener/{profile}/peer/{}", peer.to_hex())
            }
            Self::RemoteIdentity(profile) => format!("remote/{profile}/identity"),
            Self::RemoteConnection(profile) => format!("remote/{profile}/connection"),
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::ListenerIdentity(profile) => format!("the listener identity of '{profile}'"),
            Self::ListenerPeer(profile, peer) => format!(
                "the session of paired device {} on listener '{profile}'",
                peer.to_hex()
            ),
            Self::RemoteIdentity(profile) => format!("the identity of remote profile '{profile}'"),
            Self::RemoteConnection(profile) => {
                format!("the listener session of remote profile '{profile}'")
            }
        }
    }

    fn entry(&self) -> Result<keyring_core::Entry, Error> {
        store::entry(&self.account()).map_err(|err| self.error(&err))
    }

    fn error(&self, err: &keyring_core::Error) -> Error {
        let reason = store_reason(err);
        Error::new(format!(
            "the OS credential store {reason} for {}; Agent Access key material is never \
             stored elsewhere",
            self.describe()
        ))
    }

    /// Saves the material, replacing any previous value.
    ///
    /// # Errors
    ///
    /// Fails when no credential store is usable. There is no plaintext fallback.
    pub fn store(&self, bytes: &[u8]) -> Result<(), Error> {
        self.entry()?
            .set_secret(bytes)
            .map_err(|err| self.error(&err))
    }

    /// Loads the material. Returns `None` when nothing is stored.
    ///
    /// # Errors
    ///
    /// Fails when the credential store is unusable.
    pub fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        match self.entry()?.get_secret() {
            Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(err) => Err(self.error(&err)),
        }
    }

    /// Deletes the material. Deleting absent material succeeds.
    ///
    /// # Errors
    ///
    /// Fails when the credential store is unusable.
    pub fn delete(&self) -> Result<(), Error> {
        match self.entry()?.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(err) => Err(self.error(&err)),
        }
    }
}
