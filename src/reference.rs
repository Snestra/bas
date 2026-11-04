//! Validated profile names and `bas://<profile>/<secret-id>` references.
//!
//! Parse errors never repeat the rejected input, because a mistyped reference can be a
//! pasted secret value.

use std::fmt::{self, Display};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::output::Error;

/// Scheme prefix of every reference.
const SCHEME: &str = "bas://";

/// Longest accepted profile name, so names stay usable as credential-store account names.
const MAX_PROFILE_NAME: usize = 64;

/// Profile name: lowercase ASCII letters, digits, `-` and `_`, starting with a letter or digit.
///
/// Lowercase only, so names compare the same on case-insensitive file systems and stores.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProfileName(String);

impl ProfileName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ProfileName {
    type Err = Error;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        let mut bytes = name.bytes();
        let valid_first = bytes
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
        let valid_rest =
            bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
        if valid_first && valid_rest && name.len() <= MAX_PROFILE_NAME {
            Ok(Self(name.to_owned()))
        } else {
            Err(Error::usage(format!(
                "a profile name must be 1 to {MAX_PROFILE_NAME} lowercase letters, digits, '-' or \
                 '_', starting with a letter or digit"
            )))
        }
    }
}

impl Display for ProfileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for ProfileName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ProfileName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

/// Parses a secret ID in canonical hyphenated form, in either letter case.
///
/// # Errors
///
/// Returns a usage error that does not repeat the input.
pub fn parse_secret_id(raw: &str) -> Result<Uuid, Error> {
    Uuid::try_parse(raw)
        .ok()
        .filter(|id| raw.eq_ignore_ascii_case(&id.hyphenated().to_string()))
        .ok_or_else(|| Error::usage("a secret or project ID must be a hyphenated UUID"))
}

/// Reference to one secret in one configured profile.
///
/// The profile, not the reference, decides the endpoint and organization, so a reference
/// can never redirect authentication.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretRef {
    pub profile: ProfileName,
    pub id: Uuid,
}

impl FromStr for SecretRef {
    type Err = Error;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let invalid = || Error::usage("a reference must look like bas://<profile>/<secret-id>");
        let rest = raw.strip_prefix(SCHEME).ok_or_else(invalid)?;
        let (profile, id) = rest.split_once('/').ok_or_else(invalid)?;
        let profile = profile.parse().map_err(|_| invalid())?;
        let id = parse_secret_id(id).map_err(|_| invalid())?;
        Ok(Self { profile, id })
    }
}

impl Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{SCHEME}{}/{}", self.profile, self.id.hyphenated())
    }
}

impl Serialize for SecretRef {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Environment variable name: an ASCII letter or `_`, then ASCII letters, digits, or `_`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvName(String);

impl EnvName {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether two names select the same variable on this platform.
    ///
    /// Windows treats environment names case-insensitively.
    fn collides_with(&self, other: &Self) -> bool {
        if cfg!(windows) {
            self.0.eq_ignore_ascii_case(&other.0)
        } else {
            self.0 == other.0
        }
    }
}

impl FromStr for EnvName {
    type Err = Error;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        let mut bytes = name.bytes();
        let valid_first = bytes
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_');
        if valid_first && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            Ok(Self(name.to_owned()))
        } else {
            Err(Error::usage(
                "an environment name must be an ASCII letter or '_' followed by letters, digits, \
                 or '_'",
            ))
        }
    }
}

impl Display for EnvName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One `NAME=bas://<profile>/<secret-id>` environment binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub name: EnvName,
    pub reference: SecretRef,
}

impl FromStr for Binding {
    type Err = Error;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let (name, reference) = raw.split_once('=').ok_or_else(|| {
            Error::usage("a binding must look like NAME=bas://<profile>/<secret-id>")
        })?;
        Ok(Self {
            name: name.parse()?,
            reference: reference.parse()?,
        })
    }
}

impl Display for Binding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.name, self.reference)
    }
}

/// Parses bindings, labelling each error with its position but never its text.
///
/// # Errors
///
/// Fails on the first malformed binding or on two bindings for the same variable.
pub fn parse_bindings<'a>(
    raw: impl IntoIterator<Item = (String, &'a str)>,
) -> Result<Vec<Binding>, Error> {
    let mut bindings: Vec<Binding> = Vec::new();
    for (position, text) in raw {
        let binding: Binding = text
            .parse()
            .map_err(|err: Error| Error::usage(format!("{position}: {err}")))?;
        if bindings
            .iter()
            .any(|existing| existing.name.collides_with(&binding.name))
        {
            return Err(Error::usage(format!(
                "{position}: environment variable {} is bound more than once",
                binding.name
            )));
        }
        bindings.push(binding);
    }
    Ok(bindings)
}
