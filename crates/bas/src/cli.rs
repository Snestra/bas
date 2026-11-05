//! Command-line grammar for `bas`.
//!
//! Profile names, IDs, and references are taken as plain strings and parsed by `bas`, so a
//! rejected value is never echoed back. It might be a pasted secret.

use std::ffi::OsString;
use std::path::PathBuf;

use bas_core::profile::{EndpointFlags, Region};
use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};

/// Reference-based access to Bitwarden Secrets Manager for coding agents.
///
/// Commands print references, metadata, and receipts, never secret values.
#[derive(Debug, Parser)]
#[command(name = "bas", version, about, arg_required_else_help = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Connect, inspect, and remove profiles bound to an organization and endpoint.
    #[command(subcommand)]
    Auth(AuthCommand),
    /// Find secret references by key without retrieving values.
    Find(FindArgs),
    /// Run a program with referenced secrets in its environment.
    ///
    /// Every reference is resolved before the program starts; if any is missing or denied,
    /// the program does not start. References to a remote profile are requested one by one
    /// from its paired listener, and each needs approval there; a remote failure never falls
    /// back to a machine token. Arguments after -- reach the program unchanged, without a
    /// shell. BWS_ACCESS_TOKEN and AAC_TOKEN are removed from its environment. The program
    /// can still print what it receives.
    Run(RunArgs),
    /// Write or run reference-only environment templates.
    #[command(subcommand)]
    Env(EnvCommand),
    /// Create a secret from piped stdin or the clipboard and print a JSON receipt.
    ///
    /// Input bytes are preserved, including terminal line endings. The receipt outcome
    /// is verified (exit 0), written_unverified (exit 3), or unknown (exit
    /// 4). A refused write prints an error instead. Writes are never retried.
    Create(CreateArgs),
    /// Replace the value of an existing secret, keeping its key, note, and project.
    ///
    /// Input and receipts work as for create.
    Update(UpdateArgs),
    /// Report readiness. Offline unless --profile is given.
    Doctor(DoctorArgs),
    /// Serve paired remote devices through Agent Access until interrupted.
    ///
    /// A request is answered only when the device is paired and asks for one explicit
    /// secret ID listed with --allow. Then an active `bas grant` for that device, this
    /// profile and organization, and that secret delivers it without a prompt. Otherwise
    /// the operator must type the one-time code shown on this terminal for that request;
    /// without a terminal the request is denied. The value is retrieved from Secrets
    /// Manager only after that. Pairing, profile, and grant are checked again on disk
    /// before each reply is released. Domain and search requests are denied. Status lines
    /// go to stderr; values are never printed.
    Listen(ListenArgs),
    /// Pair this machine with a listener and save a remote profile.
    ///
    /// Asks on this terminal for the code that `bas listen --pair` shows, then for the
    /// handshake fingerprint shown on the listener. The profile stores no Secrets Manager
    /// token. Its bas://PROFILE/SECRET-ID references resolve only through that listener,
    /// one approved request at a time. Pairing grants no secret by itself.
    Pair(PairArgs),
    /// Create, list, and revoke standing grants for paired devices.
    ///
    /// A grant lets one paired device receive exact secret IDs from one listener profile
    /// and organization without a prompt, until revoked. It never widens the listener's
    /// --allow scope or pairs a device. Grants are stored in grants.toml in the bas
    /// configuration directory.
    #[command(subcommand)]
    Grant(GrantCommand),
}

#[derive(Debug, Subcommand)]
pub enum GrantCommand {
    /// Let one paired device receive exact secrets without a prompt, until revoked.
    ///
    /// The device must be paired with the listener of --profile, and the grant is bound
    /// to that profile's organization. Prints the grant as one JSON line:
    /// {"id","state","device","profile","organization","secrets"}. An identical active
    /// grant is printed instead of a duplicate.
    Add(GrantAddArgs),
    /// List grants, active and revoked.
    List(GrantListArgs),
    /// Revoke a grant and report only after the revocation is on disk.
    ///
    /// Waits while a listener commits a reply to its relay client, so once this succeeds
    /// no listener commits another reply under this grant, including on open connections.
    /// Already queued responses may arrive later and cannot be recalled. Prints the grant
    /// as one JSON line.
    Revoke(GrantRevokeArgs),
}

#[derive(Debug, Args)]
pub struct GrantAddArgs {
    /// Direct profile whose listener delivers the secrets.
    #[arg(long)]
    pub profile: String,
    /// Identity fingerprint of the paired device, as shown by `bas auth list`.
    #[arg(long, value_name = "FINGERPRINT")]
    pub device: String,
    /// Secret ID the device may receive. Repeat for more IDs.
    #[arg(long = "secret", value_name = "SECRET-ID", required = true)]
    pub secrets: Vec<String>,
}

#[derive(Debug, Args)]
pub struct GrantListArgs {
    /// Only grants of this listener profile.
    #[arg(long)]
    pub profile: Option<String>,
    /// Print {"grants":[...]} instead of text lines.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct GrantRevokeArgs {
    /// ID of the grant, as printed by `bas grant add` or `bas grant list`.
    pub grant: String,
}

#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    /// Authenticate a machine token and save the profile only after it succeeds.
    ///
    /// The token comes from piped stdin or the clipboard and is saved in the OS credential
    /// store, or the profile reads BWS_ACCESS_TOKEN at every use with --from-env. Never
    /// pass a token as an argument.
    Login(LoginArgs),
    /// Authenticate an existing profile and report its organization and endpoint.
    Status(ProfileArg),
    /// Delete a profile and its stored machine token.
    ///
    /// For a direct profile this also removes its paired devices and revokes its grants.
    Logout(ProfileArg),
    /// List configured profiles and paired devices without contacting a server.
    List,
}

#[derive(Debug, Args)]
pub struct ListenArgs {
    /// Direct profile whose Secrets Manager access the listener uses.
    #[arg(long)]
    pub profile: String,
    /// Agent Access relay: wss://HOST, or ws:// to a loopback address.
    #[arg(long, value_name = "URL")]
    pub relay: String,
    /// Secret ID remote devices may request. Repeat for more IDs.
    #[arg(long = "allow", value_name = "SECRET-ID", required = true)]
    pub allow: Vec<String>,
    /// Show a pairing code on this terminal and accept one new device.
    #[arg(long)]
    pub pair: bool,
    /// Label for the device paired with --pair.
    #[arg(long, value_name = "NAME", requires = "pair")]
    pub peer_name: Option<String>,
}

#[derive(Debug, Args)]
pub struct PairArgs {
    /// Name of the remote profile to create, used in bas://PROFILE/SECRET-ID references.
    pub profile: String,
    /// Agent Access relay the listener uses: wss://HOST, or ws:// to a loopback address.
    #[arg(long, value_name = "URL")]
    pub relay: String,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("token").required(true).args(["stdin", "clipboard", "from_env"])))]
pub struct LoginArgs {
    /// Profile name used in bas://PROFILE/SECRET-ID references.
    pub profile: String,
    /// Organization ID the machine token must belong to.
    #[arg(long, value_name = "UUID")]
    pub organization: String,
    #[command(flatten)]
    pub endpoint: EndpointArgs,
    /// Read the machine token from piped stdin and store it in the OS credential store.
    #[arg(long)]
    pub stdin: bool,
    /// Read the machine token from the clipboard and store it in the OS credential store.
    #[arg(long)]
    pub clipboard: bool,
    /// Store nothing; read BWS_ACCESS_TOKEN at every use (headless automation).
    #[arg(long)]
    pub from_env: bool,
}

#[derive(Debug, Args)]
pub struct EndpointArgs {
    /// Hosted Bitwarden region.
    #[arg(long, value_enum)]
    pub region: Option<RegionArg>,
    /// Self-hosted server base URL; uses URL/api and URL/identity.
    #[arg(long, value_name = "URL")]
    pub server_url: Option<String>,
    /// Explicit API URL, together with --identity-url.
    #[arg(long, value_name = "URL", requires = "identity_url")]
    pub api_url: Option<String>,
    /// Explicit identity URL, together with --api-url.
    #[arg(long, value_name = "URL", requires = "api_url")]
    pub identity_url: Option<String>,
}

/// Hosted Bitwarden region, as named on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RegionArg {
    /// bitwarden.com
    Us,
    /// bitwarden.eu
    Eu,
}

impl From<RegionArg> for Region {
    fn from(region: RegionArg) -> Self {
        match region {
            RegionArg::Us => Self::Us,
            RegionArg::Eu => Self::Eu,
        }
    }
}

impl From<EndpointArgs> for EndpointFlags {
    fn from(args: EndpointArgs) -> Self {
        Self {
            region: args.region.map(Region::from),
            server_url: args.server_url,
            api_url: args.api_url,
            identity_url: args.identity_url,
        }
    }
}

#[derive(Debug, Args)]
pub struct ProfileArg {
    /// Profile name.
    pub profile: String,
}

#[derive(Debug, Args)]
pub struct FindArgs {
    /// Case-insensitive key fragments. Each matching secret is listed once. No query lists all.
    pub queries: Vec<String>,
    /// Profile to search.
    #[arg(long)]
    pub profile: String,
    /// Restrict the search to one project ID.
    #[arg(long, value_name = "UUID")]
    pub project: Option<String>,
    /// Print {"matches":[...],"unmatched":[...]} instead of text lines.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Binding NAME=bas://PROFILE/SECRET-ID. Repeat for more variables.
    #[arg(long = "env", value_name = "NAME=REFERENCE", required = true)]
    pub bindings: Vec<String>,
    /// Program and arguments, after --.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub command: Vec<OsString>,
}

#[derive(Debug, Subcommand)]
pub enum EnvCommand {
    /// Write a template of NAME=bas://PROFILE/SECRET-ID lines. Values are never written.
    Write(EnvWriteArgs),
    /// Run a program with the bindings of a template, like `bas run`.
    ///
    /// Template lines are blank, # comments, or NAME=bas://PROFILE/SECRET-ID. Nothing is
    /// expanded or evaluated by a shell.
    Run(EnvRunArgs),
}

#[derive(Debug, Args)]
pub struct EnvWriteArgs {
    /// Template file to create.
    pub file: PathBuf,
    /// Binding NAME=bas://PROFILE/SECRET-ID. Repeat for more variables.
    #[arg(long = "env", value_name = "NAME=REFERENCE", required = true)]
    pub bindings: Vec<String>,
    /// Replace the file if it exists.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct EnvRunArgs {
    /// Template file to read.
    pub file: PathBuf,
    /// Program and arguments, after --.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub command: Vec<OsString>,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("input").required(true).args(["stdin", "clipboard"])))]
pub struct CreateArgs {
    /// Profile to write to.
    #[arg(long)]
    pub profile: String,
    /// Secret key (name).
    #[arg(long)]
    pub key: String,
    /// Project ID the secret belongs to.
    #[arg(long, value_name = "UUID")]
    pub project: String,
    /// Read the value from piped stdin.
    #[arg(long)]
    pub stdin: bool,
    /// Read the value from the clipboard.
    #[arg(long)]
    pub clipboard: bool,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("input").required(true).args(["stdin", "clipboard"])))]
pub struct UpdateArgs {
    /// Reference bas://PROFILE/SECRET-ID of the secret to update.
    pub reference: String,
    /// Read the new value from piped stdin.
    #[arg(long)]
    pub stdin: bool,
    /// Read the new value from the clipboard.
    #[arg(long)]
    pub clipboard: bool,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Also authenticate this profile and confirm its organization.
    #[arg(long)]
    pub profile: Option<String>,
}
