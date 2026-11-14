//! Owner-only TOML files beside the profile configuration that bas rewrites whole, such as
//! `grants.toml` and `helpers.toml`.
//!
//! A missing file reads as absent. An unreadable, malformed, or unprotected file is refused,
//! so it authorizes nothing and is never rewritten.

use std::fs;
use std::io;
use std::path::PathBuf;

use bas_core::profile;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::output::Error;

/// One such file and the words its messages use.
#[derive(Debug)]
pub struct PrivateToml {
    path: PathBuf,
    /// What the file is, such as "grant policy".
    name: &'static str,
    /// What a refused file means, such as "no grant applies".
    refusal: &'static str,
}

impl PrivateToml {
    /// The file `file_name` in the configuration directory.
    ///
    /// # Errors
    ///
    /// Fails when the configuration directory is unknown.
    pub fn new(file_name: &str, name: &'static str, refusal: &'static str) -> Result<Self, Error> {
        Ok(Self {
            path: profile::config_dir()?.join(file_name),
            name,
            refusal,
        })
    }

    /// Refuses the file because it `why`, such as "is malformed".
    pub fn unusable(&self, why: &str) -> Error {
        Error::new(format!(
            "{} {} {why}; {} and nothing is rewritten until it is fixed",
            self.name,
            self.path.display(),
            self.refusal
        ))
    }

    /// Reads the file, or `None` when it does not exist.
    ///
    /// # Errors
    ///
    /// Fails when the file is unreadable, not a regular file, accessible to other users,
    /// malformed, or when `version_of` reads a version other than `version` from it.
    pub fn load<T: DeserializeOwned>(
        &self,
        version: u32,
        version_of: impl Fn(&T) -> u32,
    ) -> Result<Option<T>, Error> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(self.unusable("is unreadable")),
        };
        if !metadata.is_file() {
            return Err(self.unusable("is not a regular file"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(self.unusable("is accessible to other users"));
            }
        }
        let text = fs::read_to_string(&self.path).map_err(|_| self.unusable("is unreadable"))?;
        let file: T = toml::from_str(&text).map_err(|_| self.unusable("is malformed"))?;
        if version_of(&file) != version {
            return Err(self.unusable("has an unsupported version"));
        }
        Ok(Some(file))
    }

    /// Replaces the file atomically and flushes it to disk before returning, so a reported
    /// change survives a crash.
    ///
    /// # Errors
    ///
    /// Fails if durable completion cannot be confirmed. The file may already have changed.
    pub fn save(&self, contents: &impl Serialize) -> Result<(), Error> {
        let failed = || {
            Error::new(format!(
                "could not confirm a durable update to {} {}; inspect it before retrying",
                self.name,
                self.path.display()
            ))
        };
        let dir = self.path.parent().ok_or_else(failed)?;
        profile::create_private_dir(dir).map_err(|_| failed())?;
        let text = toml::to_string(contents).map_err(|_| failed())?;
        profile::replace_private_file(&self.path, text.as_bytes()).map_err(|_| failed())
    }
}
