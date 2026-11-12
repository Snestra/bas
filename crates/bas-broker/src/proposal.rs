//! The policy proposal, `policy.toml` in the bas configuration directory, which `bas policy
//! edit` and `bas tui` open in an editor before they send it to the broker. It holds
//! references and rules, never a value.

use std::path::{Path, PathBuf};
use std::process::Command;

use bas_core::profile::{config_dir, create_private_dir, replace_private_file};

use crate::Error;

/// The proposal's file name in the configuration directory.
const PROPOSAL_FILE: &str = "policy.toml";

/// The proposal file: `policy.toml` in `BAS_CONFIG_DIR`, or in the user configuration
/// directory.
///
/// # Errors
///
/// Fails when no configuration directory can be found.
pub fn path() -> Result<PathBuf, Error> {
    Ok(config_dir()?.join(PROPOSAL_FILE))
}

/// Replaces the proposal with `toml`, mode 0600, creating its directory when needed.
///
/// # Errors
///
/// Fails when the directory or the file cannot be written.
pub fn write(path: &Path, toml: &str) -> Result<(), Error> {
    if let Some(dir) = path.parent() {
        create_private_dir(dir)
            .map_err(|err| Error::new(format!("could not create {}: {err}", dir.display())))?;
    }
    replace_private_file(path, toml.as_bytes())
        .map_err(|err| Error::new(format!("could not write {}: {err}", path.display())))
}

/// Reads the proposal.
///
/// # Errors
///
/// Fails when the file cannot be read.
pub fn read(path: &Path) -> Result<String, Error> {
    std::fs::read_to_string(path)
        .map_err(|err| Error::new(format!("could not read {}: {err}", path.display())))
}

/// The command that opens `path` in `$VISUAL`, else `$EDITOR`, else `vi`. A shell splits
/// the setting, because it may hold arguments, such as `code --wait`.
#[must_use]
pub fn editor(path: &Path) -> Command {
    let editor = ["VISUAL", "EDITOR"]
        .iter()
        .filter_map(|name| std::env::var(name).ok())
        .find(|editor| !editor.trim().is_empty())
        .unwrap_or_else(|| "vi".to_owned());
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(format!("{editor} \"$1\""))
        .arg("sh")
        .arg(path);
    command
}
