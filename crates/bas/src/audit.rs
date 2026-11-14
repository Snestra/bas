//! Appends one JSON line per credential that `bas run` hands to a program, and one per
//! value that `bas get` prints.
//!
//! A `bas run` line records the time, the variable name, where the value came from (a
//! reference, or the broker socket), the program, and the working directory. A `bas get`
//! line records the time, the reference, the parent process, and the working directory.
//! No line records a value.

use std::ffi::OsStr;
use std::fs::OpenOptions;
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
    let failed = |err| {
        Error::new(format!(
            "not started: could not write the audit log {}: {err}",
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
    append(&path, &lines).map_err(failed)
}

/// Appends one line for a value that `bas get` is about to print. The value must not be
/// printed when this fails.
pub fn record_get(reference: &SecretRef) -> Result<(), Error> {
    let path = path()?;
    let line = serde_json::json!({
        "time": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "command": "get",
        "reference": reference.to_string(),
        "profile": reference.profile.as_str(),
        "directory": std::env::current_dir()
            .map(|dir| dir.display().to_string())
            .unwrap_or_default(),
        "pid": std::process::id(),
    });
    let mut text = with_parent(line).to_string();
    text.push('\n');
    append(&path, &text).map_err(|err| {
        Error::new(format!(
            "not printed: could not write the audit log {}: {err}",
            path.display()
        ))
    })
}

/// Adds the parent's process ID and executable to an audit line.
#[cfg(unix)]
fn with_parent(mut line: serde_json::Value) -> serde_json::Value {
    let parent = std::os::unix::process::parent_id();
    line["parent_pid"] = parent.into();
    if let Some(program) = parent_program(parent) {
        line["parent"] = program.into();
    }
    line
}

/// Leaves the line unchanged where the standard library can't name the parent process.
#[cfg(not(unix))]
fn with_parent(line: serde_json::Value) -> serde_json::Value {
    line
}

/// Path of the parent's executable, read from /proc.
#[cfg(target_os = "linux")]
fn parent_program(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|path| path.display().to_string())
}

/// Path of the parent's executable, as `ps` reports it.
#[cfg(all(unix, not(target_os = "linux")))]
fn parent_program(pid: u32) -> Option<String> {
    let output = std::process::Command::new("/bin/ps")
        .args(["-o", "comm=", "-p", &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    let program = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (output.status.success() && !program.is_empty()).then_some(program)
}

/// Appends `lines` to the audit log with owner-only permissions and flushes them.
fn append(path: &Path, lines: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        bas_core::profile::create_private_dir(parent).map_err(|err| {
            if parent.is_dir() {
                std::io::Error::new(
                    err.kind(),
                    format!(
                        "{} must be a directory you own with no group or other permissions \
                         (chmod 700)",
                        parent.display()
                    ),
                )
            } else {
                err
            }
        })?;
    }
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(lines.as_bytes())?;
    file.sync_data()
}
