//! Resolves selected references and starts a child process with them in its environment.
//!
//! Direct profiles retrieve from Secrets Manager. Remote profiles request each ID from
//! their pinned listener. Neither falls back to the other. Names given with `--with` never
//! reach the program as values: the bas broker confirms they are proxy entries, and the
//! program gets the proxy settings instead.
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
use crate::audit::{self, Source};
use crate::mask::Masker;
use crate::output::Error;
use bas_core::credential::{self, BOOTSTRAP_CREDENTIAL_VARS, SecretText};
use bas_core::profile::{Connection, Profiles};
use bas_core::reference::{Binding, EnvName, ProfileName, SecretRef};
use bas_core::secrets::Session;

/// Exit status when the program cannot be found, matching POSIX shells.
const EXIT_NOT_FOUND: u8 = 127;
/// Exit status when the program exists but cannot be started, matching POSIX shells.
const EXIT_CANNOT_START: u8 = 126;

/// Resolves every binding, asks the broker to confirm every name in `brokered`, records
/// one audit line per name, then runs the program with its output masked and exits with
/// its status.
///
/// Returns only when the program could not be run, with the reason.
pub fn run(
    bindings: &[Binding],
    brokered: &[EnvName],
    program: &OsStr,
    arguments: &[OsString],
) -> Error {
    let environment: Vec<(&EnvName, SecretText)> = if bindings.is_empty() {
        Vec::new()
    } else {
        match resolve(bindings) {
            Ok(values) => bindings
                .iter()
                .map(|binding| &binding.name)
                .zip(values)
                .collect(),
            Err(err) => return err,
        }
    };
    let mut sources: Vec<(&EnvName, Source<'_>)> = bindings
        .iter()
        .map(|binding| (&binding.name, Source::Reference(&binding.reference)))
        .collect();
    let socket;
    let mut proxy_settings = Vec::new();
    if !brokered.is_empty() {
        socket = broker::socket();
        match broker::proxy_settings(&socket, brokered, program, arguments) {
            Ok(settings) => proxy_settings = settings,
            Err(err) => return err,
        }
        sources.extend(brokered.iter().map(|name| (name, Source::Broker(&socket))));
    }
    let masker = match Masker::new(
        environment
            .iter()
            .map(|(name, value)| (name.as_str(), value.expose())),
    ) {
        Ok(masker) => masker,
        Err(_) => return Error::new("not started: could not prepare output masking"),
    };
    if let Err(err) = audit::record(&sources, program) {
        return err;
    }
    let mut command = Command::new(program);
    command.args(arguments);
    for name in BOOTSTRAP_CREDENTIAL_VARS {
        command.env_remove(name);
    }
    for (name, value) in &proxy_settings {
        command.env(name, value);
    }
    for (name, value) in &environment {
        command.env(name.as_str(), value.expose());
    }
    drop(environment);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    launch(command, program, masker)
}

/// Proxy settings from the bas broker, which runs on Linux and macOS.
#[cfg(unix)]
mod broker {
    use std::ffi::{OsStr, OsString};
    use std::path::{Path, PathBuf};

    use bas_broker::client::{self, Client};
    use bas_broker::protocol::RunRequest;
    use bas_core::reference::EnvName;

    use crate::output::Error;

    /// Variables that point common HTTPS clients at the proxy and its certificate bundle.
    const PROXY_VARS: &[&str] = &["HTTPS_PROXY", "https_proxy"];
    const BUNDLE_VARS: &[&str] = &[
        "SSL_CERT_FILE",
        "CURL_CA_BUNDLE",
        "REQUESTS_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
        "GIT_SSL_CAINFO",
    ];

    /// The broker socket.
    pub fn socket() -> PathBuf {
        client::socket_path()
    }

    /// Asks the broker to confirm that every name is a proxy entry, and returns the
    /// variables that send the program's HTTPS through the proxy. No value is involved.
    pub fn proxy_settings(
        socket: &Path,
        names: &[EnvName],
        program: &OsStr,
        arguments: &[OsString],
    ) -> Result<Vec<(&'static str, String)>, Error> {
        let request = RunRequest {
            names: names.iter().map(|name| name.as_str().to_owned()).collect(),
            argv: std::iter::once(program)
                .chain(arguments.iter().map(OsString::as_os_str))
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect(),
            cwd: std::env::current_dir()
                .map(|dir| dir.display().to_string())
                .unwrap_or_default(),
        };
        let reply = crate::runtime()?
            .block_on(Client::new(socket).run(&request))
            .map_err(|err| Error::new(format!("not started: {err}")))?;
        let mut settings: Vec<(&'static str, String)> = PROXY_VARS
            .iter()
            .map(|name| (*name, reply.proxy.url.clone()))
            .collect();
        settings.extend(
            BUNDLE_VARS
                .iter()
                .map(|name| (*name, reply.proxy.ca_bundle.clone())),
        );
        Ok(settings)
    }
}

/// Stands in for the broker client where there is no broker.
#[cfg(not(unix))]
mod broker {
    use std::ffi::{OsStr, OsString};
    use std::path::{Path, PathBuf};

    use bas_core::reference::EnvName;

    use crate::output::Error;

    pub fn socket() -> PathBuf {
        PathBuf::new()
    }

    pub fn proxy_settings(
        _socket: &Path,
        _names: &[EnvName],
        _program: &OsStr,
        _arguments: &[OsString],
    ) -> Result<Vec<(&'static str, String)>, Error> {
        Err(Error::usage(
            "--with needs the bas broker, which runs only on Linux and macOS; use --env instead",
        ))
    }
}

/// Refuses a value that an environment variable cannot hold.
fn env_value(name: &EnvName, value: SecretText) -> Result<SecretText, Error> {
    if value.expose().contains('\0') {
        Err(Error::new(format!(
            "not started: the value for {name} contains a NUL character, which an \
             environment variable cannot hold"
        )))
    } else {
        Ok(value)
    }
}

/// Retrieves each referenced secret once and returns values in binding order.
fn resolve(bindings: &[Binding]) -> Result<Vec<SecretText>, Error> {
    let references: Vec<&SecretRef> = bindings.iter().map(|binding| &binding.reference).collect();
    let retrieved = retrieve(&references).map_err(Error::not_started)?;
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
            env_value(&binding.name, SecretText::new(value.expose().to_owned()))
        })
        .collect()
}

/// Retrieves one secret for `bas get`, through the same profiles, listener approvals, and
/// grants as `bas run`.
///
/// # Errors
///
/// Fails when the profile is not configured, retrieval fails or is denied, or no
/// accessible secret has this ID.
pub fn get(reference: &SecretRef) -> Result<SecretText, Error> {
    retrieve(&[reference])?
        .remove(reference)
        .ok_or_else(|| Error::new(format!("no accessible secret for {reference}")))
}

/// Retrieves each referenced secret once. Direct profiles read from Secrets Manager, and
/// remote profiles ask their paired listener. Secrets that are missing or denied without
/// an error are absent from the result.
fn retrieve(references: &[&SecretRef]) -> Result<BTreeMap<SecretRef, SecretText>, Error> {
    let profiles = Profiles::load()?;
    let mut wanted: BTreeMap<&ProfileName, Vec<Uuid>> = BTreeMap::new();
    for reference in references {
        let ids = wanted.entry(&reference.profile).or_default();
        if !ids.contains(&reference.id) {
            ids.push(reference.id);
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
    Ok(retrieved)
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
