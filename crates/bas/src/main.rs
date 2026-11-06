//! `bas` gives coding agents references to Bitwarden Secrets Manager secrets.

mod agent_access;
mod approval;
mod cli;
mod discover;
mod doctor;
mod execute;
mod grant;
mod input;
mod output;
mod save;
mod template;

use std::collections::BTreeSet;
use std::io::{self, Write};
use std::process::ExitCode;

use bas_core::credential::{self, MachineToken};
use bas_core::profile::{Connection, CredentialSource, Endpoints, Profile, Profiles, RelayUrl};
use bas_core::reference::{self, Binding, ProfileName, SecretRef, parse_secret_id};
use bas_core::secrets::Session;
use clap::Parser;
use clap::error::ErrorKind;

use std::ffi::OsString;

use crate::agent_access::{Listener, Pairing};
use crate::cli::{
    AuthCommand, Cli, Command, CreateArgs, DoctorArgs, EnvCommand, FindArgs, GrantAddArgs,
    GrantCommand, GrantListArgs, ListenArgs, LoginArgs, UpdateArgs,
};
use crate::grant::{Change, Grant, Policy};
use crate::input::InputSource;
use crate::output::{EXIT_USAGE, Error, FindReport, GrantReport, Receipt, Result, Status};
use crate::template::Overwrite;

/// User agent sent with every Secrets Manager request.
const USER_AGENT: &str = concat!("bas/", env!("CARGO_PKG_VERSION"));

/// Builds a current-thread async runtime for SDK calls.
///
/// # Errors
///
/// Fails when the operating system refuses the runtime's resources.
fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| Error::new("could not start the async runtime"))
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => return usage_error(&err),
    };
    match dispatch(cli.command) {
        Ok(code) => code,
        Err(err) => {
            output::write_error(&err.to_string());
            err.exit_code()
        }
    }
}

/// Prints clap errors whose text holds only argument names; replaces the others, which
/// can repeat a rejected value, with fixed guidance.
fn usage_error(err: &clap::Error) -> ExitCode {
    match err.kind() {
        ErrorKind::DisplayHelp
        | ErrorKind::DisplayVersion
        | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        | ErrorKind::MissingRequiredArgument
        | ErrorKind::MissingSubcommand
        | ErrorKind::ArgumentConflict => {
            // Nothing else can report a failed write of help text, so the result is dropped.
            drop(err.print());
            ExitCode::from(u8::try_from(err.exit_code()).unwrap_or(EXIT_USAGE))
        }
        _ => {
            output::write_error(
                "invalid arguments; rejected values are not repeated because they may be \
                 secrets. Run `bas --help` or `bas <command> --help`",
            );
            ExitCode::from(EXIT_USAGE)
        }
    }
}

fn dispatch(command: Command) -> Result<ExitCode> {
    match command {
        Command::Auth(AuthCommand::Login(args)) => login(args),
        Command::Auth(AuthCommand::Status(args)) => status(&args.profile.parse()?),
        Command::Auth(AuthCommand::Logout(args)) => logout(&args.profile.parse()?),
        Command::Auth(AuthCommand::List) => list_profiles(),
        Command::Find(args) => find(args),
        Command::Run(args) => {
            let bindings = cli_bindings(&args.bindings)?;
            run(&bindings, &args.command)
        }
        Command::Env(EnvCommand::Write(args)) => {
            let bindings = cli_bindings(&args.bindings)?;
            let overwrite = if args.force {
                Overwrite::Replace
            } else {
                Overwrite::Refuse
            };
            template::write(&args.file, &bindings, overwrite)?;
            writeln!(
                io::stdout().lock(),
                "wrote {} reference binding(s) to {}",
                bindings.len(),
                args.file.display()
            )
            .map_err(stdout_failed)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Env(EnvCommand::Run(args)) => run(&template::read(&args.file)?, &args.command),
        Command::Create(args) => create(args),
        Command::Update(args) => update(args),
        Command::Doctor(args) => doctor(args),
        Command::Listen(args) => listen(args),
        Command::Pair(args) => {
            let name: ProfileName = args.profile.parse()?;
            let relay: RelayUrl = args.relay.parse()?;
            agent_access::pair(name, relay)
        }
        Command::Grant(GrantCommand::Add(args)) => grant_add(args),
        Command::Grant(GrantCommand::List(args)) => grant_list(&args),
        Command::Grant(GrantCommand::Revoke(args)) => {
            let id = parse_secret_id(&args.grant)
                .map_err(|_| Error::usage("a grant ID is a hyphenated UUID"))?;
            let lock = grant::acquire_lock()?;
            let (grant, change) = grant::revoke(&lock, id)?;
            drop(lock);
            if change == Change::AlreadyInPlace {
                output::write_error(&format!("grant {id} was already revoked"));
            }
            print_grant(&grant)
        }
    }
}

fn grant_add(args: GrantAddArgs) -> Result<ExitCode> {
    let name: ProfileName = args.profile.parse()?;
    let device = grant::parse_device(&args.device)?;
    let secrets = args
        .secrets
        .iter()
        .map(|raw| parse_secret_id(raw))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let lock = grant::acquire_lock()?;
    let (grant, change) = grant::add(&lock, &name, device, secrets)?;
    drop(lock);
    if change == Change::AlreadyInPlace {
        output::write_error(&format!(
            "an identical active grant {} already exists",
            grant.id
        ));
    }
    print_grant(&grant)
}

fn grant_list(args: &GrantListArgs) -> Result<ExitCode> {
    let profile = args
        .profile
        .as_deref()
        .map(str::parse::<ProfileName>)
        .transpose()?;
    let policy = Policy::load()?;
    let grants: Vec<&Grant> = policy
        .grants()
        .iter()
        .filter(|grant| profile.as_ref().is_none_or(|name| grant.profile == *name))
        .collect();
    let mut out = io::stdout().lock();
    if args.json {
        output::write_json(&mut out, &GrantReport { grants: &grants })
    } else {
        output::write_grants(&mut out, &grants)
    }
    .map_err(stdout_failed)?;
    Ok(ExitCode::SUCCESS)
}

fn print_grant(grant: &Grant) -> Result<ExitCode> {
    output::write_json(&mut io::stdout().lock(), grant).map_err(stdout_failed)?;
    Ok(ExitCode::SUCCESS)
}

fn listen(args: ListenArgs) -> Result<ExitCode> {
    let name: ProfileName = args.profile.parse()?;
    let relay: RelayUrl = args.relay.parse()?;
    let scope = args
        .allow
        .iter()
        .map(|raw| parse_secret_id(raw))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let peer_name = args
        .peer_name
        .as_deref()
        .map(str::parse::<ProfileName>)
        .transpose()?;
    let profile = Profiles::load()?.get(&name)?;
    agent_access::listen(Listener {
        profile,
        relay,
        scope,
        pairing: args.pair.then_some(Pairing { peer_name }),
    })
}

fn input_source(clipboard: bool) -> InputSource {
    if clipboard {
        InputSource::Clipboard
    } else {
        InputSource::Stdin
    }
}

fn create(args: CreateArgs) -> Result<ExitCode> {
    let name: ProfileName = args.profile.parse()?;
    save::check_key(&args.key)?;
    let project = parse_secret_id(&args.project)?;
    let profile = Profiles::load()?.get(&name)?;
    let value = input::read_secret(input_source(args.clipboard))?;
    let receipt = save::create(&profile, &args.key, project, &value)?;
    print_receipt(&receipt)
}

fn update(args: UpdateArgs) -> Result<ExitCode> {
    let reference: SecretRef = args.reference.parse()?;
    let profile = Profiles::load()?.get(&reference.profile)?;
    let value = input::read_secret(input_source(args.clipboard))?;
    let receipt = save::update(&profile, &reference, &value)?;
    print_receipt(&receipt)
}

fn print_receipt(receipt: &Receipt) -> Result<ExitCode> {
    for duplicate in &receipt.duplicate_keys {
        output::write_error(&format!(
            "note: {duplicate} already used key '{}' before this create",
            receipt.key
        ));
    }
    output::write_json(&mut io::stdout().lock(), receipt).map_err(stdout_failed)?;
    Ok(receipt.outcome.exit_code())
}

fn cli_bindings(raw: &[String]) -> Result<Vec<Binding>> {
    let bindings = reference::parse_bindings(
        raw.iter()
            .enumerate()
            .map(|(index, text)| (format!("--env value {}", index + 1), text.as_str())),
    )?;
    Ok(bindings)
}

/// Returns only when the program could not be started.
fn run(bindings: &[Binding], command: &[OsString]) -> Result<ExitCode> {
    let (program, arguments) = command
        .split_first()
        .ok_or_else(|| Error::usage("give the program to run after --"))?;
    Err(execute::run(bindings, program, arguments))
}

fn stdout_failed(_: io::Error) -> Error {
    Error::new("could not write to standard output")
}

fn login(args: LoginArgs) -> Result<ExitCode> {
    let name: ProfileName = args.profile.parse()?;
    let organization = parse_secret_id(&args.organization)?;
    let endpoints = Endpoints::from_flags(&args.endpoint.into())?;
    let credential = if args.from_env {
        CredentialSource::Environment
    } else {
        CredentialSource::OsStore
    };
    let profile = Profile {
        name: name.clone(),
        organization,
        endpoints,
        credential,
    };
    login_target(&Profiles::load()?, &profile)?;
    let token = if args.stdin {
        MachineToken::parse(input::read_secret(InputSource::Stdin)?)?
    } else if args.clipboard {
        MachineToken::parse(input::read_secret(InputSource::Clipboard)?)?
    } else {
        credential::load_token(&profile)?
    };
    runtime()?.block_on(Session::open(&profile, &token, USER_AGENT))?;
    let lock = grant::acquire_lock()?;
    let mut profiles = Profiles::load()?;
    let previous = login_target(&profiles, &profile)?;
    if credential == CredentialSource::OsStore {
        credential::store_token(&name, &token)?;
    } else if previous.is_some_and(|previous| previous.credential == CredentialSource::OsStore) {
        credential::delete_token(&name)?;
    }
    drop(token);
    profiles.insert(profile.clone());
    profiles.save(&lock)?;
    drop(lock);
    writeln!(
        io::stdout().lock(),
        "authenticated profile '{name}' for organization {organization} at {}; token source: {}",
        profile.endpoints.api(),
        profile.credential
    )
    .map_err(stdout_failed)?;
    Ok(ExitCode::SUCCESS)
}

/// Returns the existing profile `profile` would replace, refusing a remote profile or a
/// change of organization or endpoint.
fn login_target(profiles: &Profiles, profile: &Profile) -> Result<Option<Profile>> {
    let name = &profile.name;
    if profiles.remote(name).is_some() {
        return Err(Error::new(format!(
            "profile '{name}' is a remote profile; run `bas auth logout {name}` first"
        )));
    }
    let previous = profiles.find(name);
    if let Some(previous) = &previous
        && (previous.organization != profile.organization
            || previous.endpoints != profile.endpoints)
    {
        return Err(Error::new(format!(
            "profile '{name}' is bound to another organization or endpoint; run `bas auth \
             logout {name}` first"
        )));
    }
    Ok(previous)
}

fn status(name: &ProfileName) -> Result<ExitCode> {
    let profile = Profiles::load()?.get(name)?;
    let token = credential::load_token(&profile)?;
    runtime()?.block_on(Session::open(&profile, &token, USER_AGENT))?;
    writeln!(
        io::stdout().lock(),
        "profile '{name}' authenticated to organization {} at {} using the {}",
        profile.organization,
        profile.endpoints.api(),
        profile.credential
    )
    .map_err(stdout_failed)?;
    Ok(ExitCode::SUCCESS)
}

fn logout(name: &ProfileName) -> Result<ExitCode> {
    let lock = grant::acquire_lock()?;
    let mut profiles = Profiles::load()?;
    match profiles.connection(name)? {
        Connection::Direct(profile) => {
            let revoked = grant::revoke_profile(&lock, name)?;
            if revoked > 0 {
                output::write_error(&format!("revoked {revoked} grant(s) of profile '{name}'"));
            }
            if profile.credential == CredentialSource::OsStore {
                credential::delete_token(name)?;
            }
            let peers = profiles.remove_listener(name);
            agent_access::forget_listener(name, &peers)?;
            profiles.remove(name);
        }
        Connection::Remote(_) => {
            agent_access::forget_remote(name)?;
            profiles.remove_remote(name);
        }
    }
    profiles.save(&lock)?;
    drop(lock);
    writeln!(io::stdout().lock(), "removed profile '{name}'").map_err(stdout_failed)?;
    Ok(ExitCode::SUCCESS)
}

fn list_profiles() -> Result<ExitCode> {
    let profiles = Profiles::load()?;
    let mut out = io::stdout().lock();
    for profile in profiles.iter() {
        writeln!(
            out,
            "{}  organization={}  api={}  identity={}  token={}",
            profile.name,
            profile.organization,
            profile.endpoints.api(),
            profile.endpoints.identity(),
            profile.credential
        )
        .map_err(stdout_failed)?;
    }
    for profile in profiles.iter() {
        for peer in profiles.listener_peers(&profile.name) {
            let label = peer
                .name
                .map(|name| format!("  name={name}"))
                .unwrap_or_default();
            writeln!(
                out,
                "{}  paired-device  device={}{label}",
                profile.name,
                peer.fingerprint.to_hex()
            )
            .map_err(stdout_failed)?;
        }
    }
    for remote in profiles.remotes() {
        writeln!(
            out,
            "{}  remote  relay={}  listener={}",
            remote.name,
            remote.relay,
            remote.listener.to_hex()
        )
        .map_err(stdout_failed)?;
    }
    Ok(ExitCode::SUCCESS)
}

fn find(args: FindArgs) -> Result<ExitCode> {
    let name: ProfileName = args.profile.parse()?;
    let project = args.project.as_deref().map(parse_secret_id).transpose()?;
    if args.queries.iter().any(|query| query.trim().is_empty()) {
        return Err(Error::usage("a query must not be empty"));
    }
    let profile = Profiles::load()?.get(&name)?;
    let token = credential::load_token(&profile)?;
    let identifiers = runtime()?.block_on(async {
        let session = Session::open(&profile, &token, USER_AGENT).await?;
        session.list_identifiers(project).await
    })?;
    drop(token);
    let found = discover::discover(&name, identifiers, &args.queries);
    let mut out = io::stdout().lock();
    if args.json {
        output::write_json(
            &mut out,
            &FindReport {
                matches: &found.matches,
                unmatched: &found.unmatched,
            },
        )
        .map_err(stdout_failed)?;
    } else {
        output::write_summaries(&mut out, &found.matches).map_err(stdout_failed)?;
        for query in &found.unmatched {
            output::write_error(&format!("no secret key matches '{query}'"));
        }
    }
    if found.unmatched.is_empty() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::FAILURE)
    }
}

fn doctor(args: DoctorArgs) -> Result<ExitCode> {
    let mut checks = doctor::offline();
    if let Some(name) = args.profile {
        let name: ProfileName = name.parse()?;
        let profile = Profiles::load()?.get(&name)?;
        checks.push(runtime()?.block_on(doctor::authenticated(&profile)));
    }
    output::write_checks(&mut io::stdout().lock(), &checks).map_err(stdout_failed)?;
    if checks.iter().any(|check| check.status == Status::Failed) {
        Ok(ExitCode::FAILURE)
    } else {
        Ok(ExitCode::SUCCESS)
    }
}
