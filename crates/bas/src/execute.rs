//! Resolves selected references and starts a child process with them in its environment.
//!
//! Direct profiles retrieve from Secrets Manager. Remote profiles request each ID from
//! their pinned listener. Neither falls back to the other.
//!
//! The argument vector reaches the program unchanged; no shell is involved. Bootstrap
//! credentials are removed from the child environment. Injected values are masked in the
//! child's stdout and stderr, but masking isn't a sandbox: a child can still write a value to
//! a file, send it elsewhere, or print it in another encoding.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::thread;

use uuid::Uuid;

use crate::agent_access;
use crate::audit;
use crate::mask::Masker;
use crate::output::Error;
use bas_core::credential::{self, BOOTSTRAP_CREDENTIAL_VARS, SecretText};
use bas_core::profile::{Connection, Profiles};
use bas_core::reference::{Binding, ProfileName, SecretRef};
use bas_core::secrets::Session;

/// Exit status when the program cannot be found, matching POSIX shells.
const EXIT_NOT_FOUND: u8 = 127;
/// Exit status when the program exists but cannot be started, matching POSIX shells.
const EXIT_CANNOT_START: u8 = 126;

/// Resolves every binding, records one audit line per binding, then runs the program with
/// its output masked and exits with its status.
///
/// Returns only when the program could not be run, with the reason.
pub fn run(bindings: &[Binding], program: &OsStr, arguments: &[OsString]) -> Error {
    let environment = match resolve(bindings) {
        Ok(environment) => environment,
        Err(err) => return err,
    };
    let masker = match Masker::new(
        bindings
            .iter()
            .zip(&environment)
            .map(|(binding, value)| (binding.name.as_str(), value.expose())),
    ) {
        Ok(masker) => masker,
        Err(_) => return Error::new("not started: could not prepare output masking"),
    };
    if let Err(err) = audit::record(bindings, program) {
        return err;
    }
    let mut command = Command::new(program);
    command.args(arguments);
    for name in BOOTSTRAP_CREDENTIAL_VARS {
        command.env_remove(name);
    }
    for (binding, value) in bindings.iter().zip(&environment) {
        command.env(binding.name.as_str(), value.expose());
    }
    drop(environment);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    launch(command, program, masker)
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
        .collect::<Result<Vec<_>, bas_core::Error>>()?;
    let mut retrieved: BTreeMap<SecretRef, SecretText> = BTreeMap::new();
    crate::runtime()?.block_on(async {
        for (connection, ids) in &selected {
            match connection {
                Connection::Direct(profile) => {
                    let token = credential::load_token(profile)?;
                    let session = Session::open(profile, &token, crate::USER_AGENT).await?;
                    for secret in session.get_many(ids).await? {
                        let reference = SecretRef {
                            profile: profile.name.clone(),
                            id: secret.id(),
                        };
                        retrieved.insert(reference, secret.into_value());
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

/// Starts the program and copies its stdout and stderr through `masker` on two threads.
fn spawn_masked(
    command: &mut Command,
    program: &OsStr,
    masker: Masker,
) -> Result<(Child, Vec<thread::JoinHandle<()>>), Error> {
    let mut child = command.spawn().map_err(|err| start_error(program, &err))?;
    let masker = Arc::new(masker);
    let mut copiers = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        let masker = Arc::clone(&masker);
        copiers.push(thread::spawn(move || {
            let _ = masker.copy(stdout, io::stdout());
        }));
    }
    if let Some(stderr) = child.stderr.take() {
        copiers.push(thread::spawn(move || {
            let _ = masker.copy(stderr, io::stderr());
        }));
    }
    Ok((child, copiers))
}

/// Waits for the copy threads so no output is lost, then exits with `status`.
fn finish(status: ExitStatus, copiers: Vec<thread::JoinHandle<()>>) -> ! {
    for copier in copiers {
        let _ = copier.join();
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            std::process::exit(128 + signal);
        }
    }
    std::process::exit(status.code().unwrap_or(1))
}

/// Runs the program with masked output and forwards SIGINT, SIGTERM, SIGHUP, and SIGQUIT to
/// it, so `bas` exits only after the program does.
#[cfg(unix)]
fn launch(mut command: Command, program: &OsStr, masker: Masker) -> Error {
    use rustix::process::{Pid, Signal, kill_process};
    use tokio::signal::unix::{SignalKind, signal};

    let runtime = match crate::runtime() {
        Ok(runtime) => runtime,
        Err(err) => return err,
    };
    let _context = runtime.enter();
    let streams = (
        signal(SignalKind::interrupt()),
        signal(SignalKind::terminate()),
        signal(SignalKind::hangup()),
        signal(SignalKind::quit()),
    );
    let (Ok(mut int), Ok(mut term), Ok(mut hup), Ok(mut quit)) = streams else {
        return Error::new("not started: could not install signal handlers");
    };
    let (mut child, copiers) = match spawn_masked(&mut command, program, masker) {
        Ok(started) => started,
        Err(err) => return err,
    };
    let pid = Pid::from_child(&child);
    let status = runtime.block_on(async move {
        let mut waiter = tokio::task::spawn_blocking(move || child.wait());
        loop {
            let forward = tokio::select! {
                status = &mut waiter => return status,
                _ = int.recv() => Signal::INT,
                _ = term.recv() => Signal::TERM,
                _ = hup.recv() => Signal::HUP,
                _ = quit.recv() => Signal::QUIT,
            };
            let _ = kill_process(pid, forward);
        }
    });
    match status {
        Ok(Ok(status)) => finish(status, copiers),
        _ => Error::new("lost track of the program after it started"),
    }
}

/// Runs the program with masked output and exits with its status.
///
/// The console delivers Ctrl-C and Ctrl-Break to the child as well; registered handlers
/// keep `bas` alive until the child exits so its status is reported.
#[cfg(windows)]
fn launch(mut command: Command, program: &OsStr, masker: Masker) -> Error {
    let runtime = match crate::runtime() {
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
    let (mut child, copiers) = match spawn_masked(&mut command, program, masker) {
        Ok(started) => started,
        Err(err) => return err,
    };
    match child.wait() {
        Ok(status) => finish(status, copiers),
        Err(_) => Error::new("lost track of the program after it started"),
    }
}
