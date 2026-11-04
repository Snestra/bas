//! Resolves selected references and starts a child process with them in its environment.
//!
//! Direct profiles retrieve from Secrets Manager. Remote profiles request each ID from
//! their pinned listener. Neither falls back to the other.
//!
//! The argument vector reaches the program unchanged; no shell is involved. Bootstrap
//! credentials are removed from the child environment. Output redaction is not a sandbox,
//! and a child can print what it receives.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::process::Command;

use uuid::Uuid;

use crate::agent_access;
use crate::credential::{self, BOOTSTRAP_CREDENTIAL_VARS, SecretText};
use crate::output::Error;
use crate::profile::{Connection, Profiles};
use crate::reference::{Binding, ProfileName, SecretRef};
use crate::secrets::{self, Session};

/// Exit status when the program cannot be found, matching POSIX shells.
const EXIT_NOT_FOUND: u8 = 127;
/// Exit status when the program exists but cannot be started, matching POSIX shells.
const EXIT_CANNOT_START: u8 = 126;

/// Resolves every binding, then replaces this process with the program (Unix) or runs it and
/// exits with its status (Windows).
///
/// Returns only when the program could not be run, with the reason.
pub fn run(bindings: &[Binding], program: &OsStr, arguments: &[OsString]) -> Error {
    let environment = match resolve(bindings) {
        Ok(environment) => environment,
        Err(err) => return err,
    };
    let mut command = Command::new(program);
    command.args(arguments);
    for name in BOOTSTRAP_CREDENTIAL_VARS {
        command.env_remove(name);
    }
    for (binding, value) in bindings.iter().zip(&environment) {
        command.env(binding.name.as_str(), value.expose());
    }
    drop(environment);
    launch(command, program)
}

/// Retrieves each referenced secret once and returns values in binding order.
fn resolve(bindings: &[Binding]) -> Result<Vec<SecretText>, Error> {
    let profiles = Profiles::load()?;
    let mut wanted: BTreeMap<&ProfileName, Vec<Uuid>> = BTreeMap::new();
    for binding in bindings {
        let ids = wanted.entry(&binding.reference.profile).or_default();
        if !ids.contains(&binding.reference.id) {
            ids.push(binding.reference.id);
        }
    }
    let selected = wanted
        .iter()
        .map(|(name, ids)| {
            profiles
                .connection(name)
                .map(|connection| (connection, ids))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let mut retrieved: BTreeMap<SecretRef, SecretText> = BTreeMap::new();
    secrets::runtime()?.block_on(async {
        for (connection, ids) in &selected {
            match connection {
                Connection::Direct(profile) => {
                    let token = credential::load_token(profile)?;
                    let session = Session::open(profile, &token).await?;
                    for secret in session.get_many(ids).await? {
                        let reference = SecretRef {
                            profile: profile.name.clone(),
                            id: secret.id,
                        };
                        retrieved.insert(reference, secret.value);
                    }
                }
                Connection::Remote(remote) => {
                    for (id, value) in agent_access::fetch(remote, ids).await? {
                        let reference = SecretRef {
                            profile: remote.name.clone(),
                            id,
                        };
                        retrieved.insert(reference, value);
                    }
                }
            }
        }
        Ok::<(), Error>(())
    })?;
    let missing: Vec<String> = bindings
        .iter()
        .filter(|binding| !retrieved.contains_key(&binding.reference))
        .map(|binding| binding.reference.to_string())
        .collect();
    if !missing.is_empty() {
        return Err(Error::new(format!(
            "not started: no accessible secret for {}",
            missing.join(", ")
        )));
    }
    bindings
        .iter()
        .map(|binding| {
            let value = &retrieved[&binding.reference];
            if value.expose().contains('\0') {
                Err(Error::new(format!(
                    "not started: the value for {} contains a NUL character, which an \
                     environment variable cannot hold",
                    binding.name
                )))
            } else {
                Ok(SecretText::new(value.expose().to_owned()))
            }
        })
        .collect()
}

fn start_error(program: &OsStr, err: &io::Error) -> Error {
    let program = program.to_string_lossy();
    if err.kind() == io::ErrorKind::NotFound {
        Error::with_exit(
            format!("could not start '{program}': program not found"),
            EXIT_NOT_FOUND,
        )
    } else {
        Error::with_exit(
            format!("could not start '{program}': {}", err.kind()),
            EXIT_CANNOT_START,
        )
    }
}

/// Replaces this process, so the program's exit status and signal handling are its own.
#[cfg(unix)]
fn launch(mut command: Command, program: &OsStr) -> Error {
    use std::os::unix::process::CommandExt;
    let err = command.exec();
    start_error(program, &err)
}

/// Runs the program and exits with its status.
///
/// The console delivers Ctrl-C and Ctrl-Break to the child as well; registered handlers
/// keep `bas` alive until the child exits so its status is reported.
#[cfg(windows)]
fn launch(mut command: Command, program: &OsStr) -> Error {
    let runtime = match secrets::runtime() {
        Ok(runtime) => runtime,
        Err(err) => return err,
    };
    let _context = runtime.enter();
    let handlers = tokio::signal::windows::ctrl_c().and_then(|ctrl_c| {
        tokio::signal::windows::ctrl_break().map(|ctrl_break| (ctrl_c, ctrl_break))
    });
    let Ok(_handlers) = handlers else {
        return Error::new("could not install console control handlers");
    };
    match command.status() {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(err) => start_error(program, &err),
    }
}
