//! The credential-helper allowlist: references whose raw value `bas get` may print.
//!
//! Tools such as git credential helpers and `apiKeyHelper` run a command and read one
//! secret from its stdout. Only references that the operator added with `bas helper
//! allow`, after typing a code on the controlling terminal, can be read that way. Every
//! other reference stays masked.
//!
//! The list lives in `helpers.toml` beside the profile configuration, with owner-only
//! permissions, and changes under the same lock as grants and profiles. A missing file
//! means an empty list. An unreadable, malformed, or unprotected file allows nothing and is
//! never rewritten.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::PathBuf;

use bas_core::lock::ConfigLock;
use bas_core::profile;
use bas_core::reference::SecretRef;
use serde::{Deserialize, Serialize};

use crate::grant::Change;
use crate::output::Error;

const HELPER_FILE: &str = "helpers.toml";

/// Schema version of `helpers.toml`. Any other version allows nothing.
const VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperFile {
    version: u32,
    #[serde(default)]
    helpers: BTreeSet<String>,
}

/// The allowlisted references and the file they came from.
#[derive(Debug)]
pub struct Helpers {
    path: PathBuf,
    references: BTreeSet<SecretRef>,
}

impl Helpers {
    /// Reads the allowlist from disk.
    ///
    /// # Errors
    ///
    /// Fails when the file is unreadable, malformed, not a regular file, or accessible to
    /// other users. Callers then refuse instead of assuming any list.
    pub fn load() -> Result<Self, Error> {
        let path = profile::config_dir()?.join(HELPER_FILE);
        let unusable = |why: &str| {
            Error::new(format!(
                "helper allowlist {} {why}; no reference is allowed and nothing is rewritten \
                 until it is fixed",
                path.display()
            ))
        };
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(Self {
                    path,
                    references: BTreeSet::new(),
                });
            }
            Err(_) => return Err(unusable("is unreadable")),
        };
        if !metadata.is_file() {
            return Err(unusable("is not a regular file"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(unusable("is accessible to other users"));
            }
        }
        let text = fs::read_to_string(&path).map_err(|_| unusable("is unreadable"))?;
        let file: HelperFile = toml::from_str(&text).map_err(|_| unusable("is malformed"))?;
        if file.version != VERSION {
            return Err(unusable("has an unsupported version"));
        }
        let references = file
            .helpers
            .iter()
            .map(|raw| raw.parse::<SecretRef>())
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(|_| unusable("is malformed"))?;
        Ok(Self { path, references })
    }

    /// Allowlisted references in order.
    pub fn references(&self) -> impl Iterator<Item = &SecretRef> {
        self.references.iter()
    }

    /// Whether `bas get` may print the value of this reference.
    pub fn allows(&self, reference: &SecretRef) -> bool {
        self.references.contains(reference)
    }

    /// Adds a reference in memory. Returns whether it was new.
    pub fn insert(&mut self, reference: SecretRef) -> Change {
        if self.references.insert(reference) {
            Change::Applied
        } else {
            Change::AlreadyInPlace
        }
    }

    /// Removes a reference in memory. Returns whether it was listed.
    pub fn remove(&mut self, reference: &SecretRef) -> Change {
        if self.references.remove(reference) {
            Change::Applied
        } else {
            Change::AlreadyInPlace
        }
    }

    /// Replaces the file atomically and flushes it to disk before returning.
    ///
    /// # Errors
    ///
    /// Fails if durable completion cannot be confirmed. The file may already have changed.
    pub fn save(&self, _lock: &ConfigLock) -> Result<(), Error> {
        let failed = || {
            Error::new(format!(
                "could not confirm a durable update to helper allowlist {}; inspect it before \
                 retrying",
                self.path.display()
            ))
        };
        let dir = self.path.parent().ok_or_else(failed)?;
        profile::create_private_dir(dir).map_err(|_| failed())?;
        let text = toml::to_string(&HelperFile {
            version: VERSION,
            helpers: self.references.iter().map(ToString::to_string).collect(),
        })
        .map_err(|_| failed())?;
        profile::replace_private_file(&self.path, text.as_bytes()).map_err(|_| failed())
    }
}
