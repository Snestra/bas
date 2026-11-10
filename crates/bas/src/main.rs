//! `bas` gives coding agents references to Bitwarden Secrets Manager secrets.

mod agent_access;
mod approval;
mod audit;
mod cli;
mod discover;
mod doctor;
mod execute;
mod grant;
mod input;
mod mask;
mod output;
mod save;
mod template;

use std::collections::BTreeSet;
use std::io::{self, Write};
use std::process::ExitCode;

use bas_core::Uuid;
use bas_core::credential::{self, MachineToken};
use bas_core::login::{self, DEFAULT_PROFILE, LoginRequest};
use bas_core::profile::{
    Connection, CredentialSource, EndpointFlags, Endpoints, Profiles, RelayUrl,
};
use bas_core::reference::{self, Binding, EnvName, ProfileName, SecretRef, parse_secret_id};
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
    #[cfg(target_os = "linux")]
    bas_broker::install_crypto_provider();
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
        Command::Auth(AuthCommand::Status(args)) => status(&profile_name(&args.profile)?),
        Command::Auth(AuthCommand::Logout(args)) => logout(&profile_name(&args.profile)?),
        Command::Auth(AuthCommand::List) => list_profiles(),
        Command::Find(args) => find(args),
        Command::Run(args) => {
            let bindings = cli_bindings(&args.bindings)?;
            let brokered = brokered_names(&args.with, &bindings)?;
            run(&bindings, &brokered, &args.command)
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
        Command::Env(EnvCommand::Run(args)) => {
            run(&template::read(&args.file)?, &[], &args.command)
        }
        Command::Create(args) => create(args),
        Command::Update(args) => update(args),
        Command::Doctor(args) => doctor(args),
        Command::Listen(args) => listen(args),
        Command::Pair(args) => {
            let name = profile_name(&args.profile)?;
            let relay: RelayUrl = args
                .relay
                .ok_or_else(|| {
                    Error::usage(
                        "missing --relay URL, the relay of a `bas listen` on another machine. \
                         To sign in with a machine account token instead, run: bas auth login",
                    )
                })?
                .parse()?;
            agent_access::pair(name, relay)
        }
        Command::Tui(args) => tui(args.profile.as_deref()),
        #[cfg(target_os = "linux")]
        Command::Broker(args) => {
            bas_broker::serve(&bas_broker::Options {
                socket: args.socket,
                config: args.config,
                policy: args.policy,
                state_dir: args.state_dir,
                ca_bundle: args.ca_bundle,
            })
            .map_err(|err| Error::new(err.to_string()))?;
            Ok(ExitCode::SUCCESS)
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
    let name = profile_name(&args.profile)?;
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
    let profile = args.profile.as_deref().map(profile_name).transpose()?;
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
    let name = profile_name(&args.profile)?;
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
    let name = profile_name(&args.profile)?;
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

/// Parses the `--with` names and refuses a variable given twice, in `--with` or `--env`.
fn brokered_names(raw: &[String], bindings: &[Binding]) -> Result<Vec<EnvName>> {
    let mut names: Vec<EnvName> = Vec::new();
    for (index, text) in raw.iter().enumerate() {
        let position = format!("--with value {}", index + 1);
        let name: EnvName = text
            .parse()
            .map_err(|err: bas_core::Error| Error::usage(format!("{position}: {err}")))?;
        let taken = names.iter().any(|other| other.as_str() == name.as_str())
            || bindings
                .iter()
                .any(|binding| binding.name.as_str() == name.as_str());
        if taken {
            return Err(Error::usage(format!(
                "{position}: environment variable {name} is bound more than once"
            )));
        }
        names.push(name);
    }
    Ok(names)
}

/// Returns only when the program could not be started.
fn run(bindings: &[Binding], brokered: &[EnvName], command: &[OsString]) -> Result<ExitCode> {
    let (program, arguments) = command
        .split_first()
        .ok_or_else(|| Error::usage("give the program to run after --"))?;
    Err(execute::run(bindings, brokered, program, arguments))
}

fn stdout_failed(_: io::Error) -> Error {
    Error::new("could not write to standard output")
}

/// Parses a profile name from the command line.
///
/// A hyphenated ID is a valid name, but people type a project or organization ID there by
/// mistake, so it is refused with the commands they most likely wanted. The rejected value
/// is never repeated.
fn profile_name(raw: &str) -> Result<ProfileName> {
    if Uuid::try_parse(raw).is_ok() {
        return Err(Error::usage(
            "that is an ID, not a profile name. A profile name is the name a profile got at \
             sign-in, such as default. To sign in with a machine account token, run: bas auth \
             login. To see your profiles, run: bas auth list",
        ));
    }
    Ok(raw.parse()?)
}

fn login(args: LoginArgs) -> Result<ExitCode> {
    let name = profile_name(&args.profile)?;
    let organization = args
        .organization
        .as_deref()
        .map(parse_secret_id)
        .transpose()?;
    let flags = EndpointFlags::from(args.endpoint);
    let endpoints = if flags == EndpointFlags::default() {
        None
    } else {
        Some(Endpoints::from_flags(&flags)?)
    };
    let credential = if args.from_env {
        CredentialSource::Environment
    } else {
        CredentialSource::OsStore
    };
    if !(args.stdin || args.clipboard || args.from_env || input::can_prompt()) {
        return Err(Error::usage(
            "no terminal to paste the token into; give it with --stdin, --clipboard, or \
             --from-env",
        ));
    }
    let request = LoginRequest {
        name: name.clone(),
        organization,
        endpoints,
        credential,
    };
    let previous = request.check(&Profiles::load()?)?;
    let token = if args.stdin {
        MachineToken::parse(input::read_secret(InputSource::Stdin)?)?
    } else if args.clipboard {
        MachineToken::parse(input::read_secret(InputSource::Clipboard)?)?
    } else if args.from_env {
        credential::load_environment_token(&name)?
    } else {
        MachineToken::parse(input::prompt_hidden(
            "Paste the machine account access token and press Enter (input is hidden): ",
        )?)?
    };
    let session = runtime()?.block_on(request.sign_in(previous.as_ref(), &token, USER_AGENT))?;
    let profile = session.profile();
    let lock = grant::acquire_lock()?;
    login::save(&lock, profile, &token)?;
    drop(lock);
    drop(token);
    writeln!(
        io::stdout().lock(),
        "authenticated profile '{name}' for organization {} at {}; token source: {}",
        profile.organization,
        profile.endpoints.api(),
        profile.credential
    )
    .map_err(stdout_failed)?;
    output::write_error(&format!(
        "next: run `bas tui --profile {name}` to browse your secrets, or `bas find --profile \
         {name}` to list references"
    ));
    Ok(ExitCode::SUCCESS)
}

/// Opens the terminal UI on a profile, or on its sign-in screen when the profile is new.
fn tui(requested: Option<&str>) -> Result<ExitCode> {
    let profiles = Profiles::load()?;
    let name = match requested {
        Some(raw) => profile_name(raw)?,
        None => default_tui_profile(&profiles)?,
    };
    let start = if profiles.is_configured(&name) {
        let profile = profiles.get(&name)?;
        let token = credential::load_token(&profile)?;
        bas_tui::Start::Open(Box::new(profile), token)
    } else {
        bas_tui::Start::SignIn(name)
    };
    bas_tui::run(start).map_err(|err| Error::new(format!("{err:#}")))?;
    Ok(ExitCode::SUCCESS)
}

/// The profile `bas tui` opens without --profile: `default`, else the only direct profile,
/// else a new `default` when no profile exists.
fn default_tui_profile(profiles: &Profiles) -> Result<ProfileName> {
    let default: ProfileName = DEFAULT_PROFILE.parse()?;
    let names: Vec<ProfileName> = profiles.iter().map(|profile| profile.name).collect();
    match names.as_slice() {
        _ if profiles.find(&default).is_some() => Ok(default),
        [only] => Ok(only.clone()),
        [] => Ok(default),
        several => {
            let listed: Vec<String> = several.iter().map(ToString::to_string).collect();
            Err(Error::usage(format!(
                "choose a profile: bas tui --profile NAME, where NAME is one of {}",
                listed.join(", ")
            )))
        }
    }
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
    let name = profile_name(&args.profile)?;
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
        let name = profile_name(&name)?;
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
