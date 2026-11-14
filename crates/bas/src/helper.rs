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

use bas_core::lock::ConfigLock;
use bas_core::reference::SecretRef;
use serde::{Deserialize, Serialize};

use crate::grant::Change;
use crate::output::Error;
use crate::private_toml::PrivateToml;

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
    file: PrivateToml,
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
        let file = PrivateToml::new(HELPER_FILE, "helper allowlist", "no reference is allowed")?;
        let references = file
            .load(VERSION, |helpers: &HelperFile| helpers.version)?
            .map_or_else(BTreeSet::new, |helpers| helpers.helpers)
            .iter()
            .map(|raw| raw.parse::<SecretRef>())
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(|_| file.unusable("is malformed"))?;
        Ok(Self { file, references })
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
        self.file.save(&HelperFile {
            version: VERSION,
            helpers: self.references.iter().map(ToString::to_string).collect(),
        })
    }
}
