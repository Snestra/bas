//! Machine tokens and secret input, kept out of arguments, output, and debug formatting.

use std::env;
use std::fmt;
use std::io::{self, IsTerminal, Read};
use std::mem;

use ap_client::IdentityFingerprint;
use bitwarden::secrets_manager::AccessToken;
use zeroize::Zeroizing;

use crate::output::Error;
use crate::profile::{CredentialSource, Profile};
use crate::reference::ProfileName;

mod store;

/// Environment variable that supplies a machine token to `environment` profiles.
pub const ACCESS_TOKEN_VAR: &str = "BWS_ACCESS_TOKEN";

/// Pairing token variable read by the upstream Agent Access CLI.
pub const AGENT_ACCESS_TOKEN_VAR: &str = "AAC_TOKEN";

/// Bootstrap and pairing credentials that `bas` removes from every child environment.
pub const BOOTSTRAP_CREDENTIAL_VARS: &[&str] = &[ACCESS_TOKEN_VAR, AGENT_ACCESS_TOKEN_VAR];

/// Secret text whose memory is zeroed on drop and whose `Debug` output is redacted.
pub struct SecretText(Zeroizing<String>);

impl SecretText {
    pub fn new(text: String) -> Self {
        Self(Zeroizing::new(text))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn from_zeroizing(text: Zeroizing<String>) -> Self {
        Self(text)
    }

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
#[derive(Debug)]
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

    pub fn expose(&self) -> &str {
        self.0.expose()
    }
}

/// Loads the machine token from the profile's single configured source.
///
/// # Errors
///
/// Fails when that source has no usable token. Never consults another source.
pub fn load_token(profile: &Profile) -> Result<MachineToken, Error> {
    match profile.credential {
        CredentialSource::Environment => {
            let token = env::var(ACCESS_TOKEN_VAR).map_err(|_| {
                Error::new(format!(
                    "profile '{}' reads its token from {ACCESS_TOKEN_VAR}, which is not set",
                    profile.name
                ))
            })?;
            MachineToken::parse(SecretText::new(token))
        }
        CredentialSource::OsStore => {
            let token = store_entry(&profile.name)?
                .get_password()
                .map_err(|err| store_error(&profile.name, &err))?;
            MachineToken::parse(SecretText::new(token))
        }
    }
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
        keyring_core::Error::NoStorageAccess(_) => "is locked or denied access",
        keyring_core::Error::NoDefaultStore => "is not available on this system",
        _ => "failed",
    };
    Error::new(format!(
        "the OS credential store {reason} for profile '{profile}'; headless systems can use \
         --from-env instead"
    ))
}

/// Agent Access key material, kept only in the OS credential store.
///
/// Identity keys and session transport keys let a device act as a paired peer, so they
/// are never written to configuration files and have no plaintext fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
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
        let reason = match err {
            keyring_core::Error::NoStorageAccess(_) => "is locked or denied access",
            keyring_core::Error::NoDefaultStore => "is not available on this system",
            _ => "failed",
        };
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

/// Channel that supplies a secret value or token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputSource {
    Stdin,
    Clipboard,
}

/// Reads one secret from stdin or the clipboard.
///
/// The text must be UTF-8, because Secrets Manager stores text. Every byte is preserved,
/// including terminal line endings. Empty input is rejected. Machine-token parsing
/// handles token-specific line endings separately.
///
/// # Errors
///
/// Fails when stdin is a terminal, the input is not UTF-8 or is empty, or the clipboard
/// has no text.
pub fn read_secret(source: InputSource) -> Result<SecretText, Error> {
    let text = match source {
        InputSource::Stdin => read_stdin()?,
        InputSource::Clipboard => read_clipboard()?,
    };
    if text.is_empty() {
        return Err(Error::new("the secret input is empty"));
    }
    Ok(SecretText(text))
}

fn read_stdin() -> Result<Zeroizing<String>, Error> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return Err(Error::usage(
            "--stdin needs piped input; typing at a terminal would echo the secret",
        ));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    stdin
        .lock()
        .read_to_end(&mut bytes)
        .map_err(|_| Error::new("could not read the secret from stdin"))?;
    match String::from_utf8(mem::take(&mut *bytes)) {
        Ok(text) => Ok(Zeroizing::new(text)),
        Err(err) => {
            drop(Zeroizing::new(err.into_bytes()));
            Err(Error::new("the secret input is not valid UTF-8 text"))
        }
    }
}

fn read_clipboard() -> Result<Zeroizing<String>, Error> {
    let mut clipboard = arboard::Clipboard::new()
        .map_err(|_| Error::new("no clipboard is available here; use --stdin"))?;
    match clipboard.get_text() {
        Ok(text) => Ok(Zeroizing::new(text)),
        Err(arboard::Error::ContentNotAvailable) => {
            Err(Error::new("the clipboard does not contain text"))
        }
        Err(_) => Err(Error::new("could not read the clipboard; use --stdin")),
    }
}
