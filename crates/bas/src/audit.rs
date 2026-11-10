//! Appends one JSON line per credential that `bas run` hands to a program.
//!
//! A line records the time, the variable name, where the value came from (a reference, or
//! the broker socket), the program, and the working directory. It never records a value.

use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use bas_core::reference::{EnvName, SecretRef};

use crate::output::Error;

/// Absolute directory that replaces the default state directory.
pub const STATE_DIR_VAR: &str = "BAS_STATE_DIR";
const LOG_FILE: &str = "audit.log";

/// Path of the audit log: `$BAS_STATE_DIR/audit.log`, or `audit.log` in a `bas` directory
/// inside the user state directory (the local data directory where there is none).
pub fn path() -> Result<PathBuf, Error> {
    let dir = match std::env::var_os(STATE_DIR_VAR) {
        Some(dir) => {
            let dir = PathBuf::from(dir);
            if !dir.is_absolute() {
                return Err(Error::usage(format!(
                    "{STATE_DIR_VAR} must be an absolute path"
                )));
            }
            dir
        }
        None => dirs::state_dir()
            .or_else(dirs::data_local_dir)
            .ok_or_else(|| Error::new("could not find a state directory for the audit log"))?
            .join("bas"),
    };
    Ok(dir.join(LOG_FILE))
}

/// Where `bas run` got the value of one variable.
pub enum Source<'a> {
    /// Read through a profile.
    Reference(&'a SecretRef),
    /// Handed out by the bas broker on this socket.
    Broker(&'a Path),
}

/// Appends one line per variable. The program must not start when this fails.
pub fn record(variables: &[(&EnvName, Source<'_>)], program: &OsStr) -> Result<(), Error> {
    let path = path()?;
    let failed = |_| {
        Error::new(format!(
            "not started: could not write the audit log {}",
            path.display()
        ))
    };
    let time = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let directory = std::env::current_dir()
        .map(|dir| dir.display().to_string())
        .unwrap_or_default();
    let mut lines = String::new();
    for (name, source) in variables {
        let mut line = serde_json::json!({
            "time": time,
            "name": name.as_str(),
            "program": program.to_string_lossy(),
            "directory": directory,
            "pid": std::process::id(),
        });
        match source {
            Source::Reference(reference) => {
                line["reference"] = reference.to_string().into();
                line["profile"] = reference.profile.as_str().into();
            }
            Source::Broker(socket) => {
                line["broker"] = socket.display().to_string().into();
            }
        }
        lines.push_str(&line.to_string());
        lines.push('\n');
    }
    if let Some(parent) = path.parent() {
        create_private_dir(parent).map_err(failed)?;
    }
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path).map_err(failed)?;
    file.write_all(lines.as_bytes()).map_err(failed)?;
    file.sync_data().map_err(failed)
}

fn create_private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}
