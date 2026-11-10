//! `bas add`, `bas rotate`, `bas policy edit`, `bas passkey add`, and `bas audit`: the
//! commands that talk to the bas broker or read its journal. Linux only.
//!
//! None of them ever handles a secret value. Values are typed on the phone's approval page.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use bas_broker::client::{self, Client, Outcome};
use bas_broker::protocol::{Accepted, AddSecret, ApprovalState, PolicyProposal, SecretEntry};
use bas_core::profile::{config_dir, create_private_dir, replace_private_file};
use bas_core::reference::EnvName;

use crate::cli::{AddArgs, AuditArgs};
use crate::output::{Error, Result};

/// The policy proposal in the configuration directory.
const PROPOSAL_FILE: &str = "policy.toml";
/// Unit whose journal entries `bas audit` reads by default.
const DEFAULT_UNIT: &str = "bas-broker.service";
/// Environment variable that names another broker unit, such as a development unit.
const UNIT_VAR: &str = "BAS_BROKER_UNIT";
/// How long each wait on the broker lasts before bas asks again.
const WAIT_SECONDS: u32 = 60;

fn client() -> Client {
    Client::new(&client::socket_path())
}

fn broker_error(err: bas_broker::Error) -> Error {
    Error::new(err.to_string())
}

fn say(text: &str) -> Result<()> {
    writeln!(io::stdout().lock(), "{text}").map_err(|_| Error::new("could not write to stdout"))
}

/// Prints the approval URL and waits until the phone answers or the request expires.
fn wait(client: &Client, accepted: &Accepted) -> Result<ApprovalState> {
    eprintln!(
        "Approve on your phone: {}\nWaiting for approval {} (it expires in 15 minutes)...",
        accepted.approval.url, accepted.approval.id
    );
    let runtime = crate::runtime()?;
    loop {
        let state = runtime
            .block_on(client.approval(&accepted.approval.id, WAIT_SECONDS))
            .map_err(broker_error)?;
        match state.state.as_str() {
            "pending" => {}
            "approved" => return Ok(state),
            "failed" => {
                return Err(Error::new(format!(
                    "the phone approved, but the broker could not apply the change: {}",
                    state.error.unwrap_or_default()
                )));
            }
            other => return Err(Error::new(format!("the request was {other}"))),
        }
    }
}

fn proposal_path() -> Result<PathBuf> {
    Ok(config_dir()?.join(PROPOSAL_FILE))
}

/// Writes the active policy to the proposal file.
fn sync_proposal(client: &Client, path: &Path) -> Result<()> {
    let active = crate::runtime()?
        .block_on(client.policy())
        .map_err(broker_error)?;
    if let Some(dir) = path.parent() {
        create_private_dir(dir)
            .map_err(|err| Error::new(format!("could not create {}: {err}", dir.display())))?;
    }
    replace_private_file(path, active.toml.as_bytes())
        .map_err(|err| Error::new(format!("could not write {}: {err}", path.display())))
}

/// `bas add NAME --host H --allow ...`.
pub fn add(args: AddArgs) -> Result<ExitCode> {
    args.name
        .parse::<EnvName>()
        .map_err(|_| Error::usage("NAME must be a valid environment variable name"))?;
    let request = AddSecret {
        name: args.name.clone(),
        entry: SecretEntry {
            reference: String::new(),
            delivery: "proxy".to_owned(),
            host: Some(args.host),
            header: Some(args.header),
            value: Some(args.value),
            allow: Some(args.allow),
        },
    };
    let client = client();
    let outcome = crate::runtime()?
        .block_on(client.add_secret(&request))
        .map_err(broker_error)?;
    let Outcome::Waiting(accepted) = outcome else {
        return Err(Error::new("the bas broker sent an unexpected reply"));
    };
    let state = wait(&client, &accepted)?;
    let reference = state
        .result
        .as_ref()
        .and_then(|result| result.get("reference"))
        .and_then(|reference| reference.as_str())
        .unwrap_or("an unknown reference");
    sync_proposal(&client, &proposal_path()?)?;
    say(&format!("added {} as {reference}", args.name))?;
    Ok(ExitCode::SUCCESS)
}

/// `bas rotate NAME`.
pub fn rotate(name: &str) -> Result<ExitCode> {
    let name_ok = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if !name_ok {
        return Err(Error::usage(
            "NAME must be a policy name, github, or tailscale",
        ));
    }
    let client = client();
    let outcome = crate::runtime()?
        .block_on(client.rotate(name))
        .map_err(broker_error)?;
    match outcome {
        Outcome::Done(_) => say(&format!(
            "dropped the cached {name} tokens; the next request mints new ones"
        ))?,
        Outcome::Waiting(accepted) => {
            wait(&client, &accepted)?;
            say(&format!("rotated {name}"))?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// `bas policy edit`.
pub fn policy_edit() -> Result<ExitCode> {
    let client = client();
    let path = proposal_path()?;
    if !path.exists() {
        sync_proposal(&client, &path)?;
    }
    let editor = std::env::var("VISUAL")
        .ok()
        .filter(|editor| !editor.trim().is_empty())
        .or_else(|| std::env::var("EDITOR").ok())
        .filter(|editor| !editor.trim().is_empty())
        .unwrap_or_else(|| "vi".to_owned());
    // The editor setting may hold arguments, such as "code --wait", so a shell splits it.
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!("{editor} \"$1\""))
        .arg("sh")
        .arg(&path)
        .status()
        .map_err(|err| Error::new(format!("could not start the editor: {err}")))?;
    if !status.success() {
        return Err(Error::new("the editor failed; nothing was sent"));
    }
    let toml = std::fs::read_to_string(&path)
        .map_err(|err| Error::new(format!("could not read {}: {err}", path.display())))?;
    let outcome = crate::runtime()?
        .block_on(client.propose_policy(&PolicyProposal { toml }))
        .map_err(|err| Error::new(format!("{}: {err}", path.display())))?;
    let accepted = match outcome {
        Outcome::Done(_) => {
            say("the proposal matches the active policy; nothing to approve")?;
            return Ok(ExitCode::SUCCESS);
        }
        Outcome::Waiting(accepted) => accepted,
    };
    if let Some(diff) = &accepted.diff {
        write!(io::stdout().lock(), "{diff}")
            .map_err(|_| Error::new("could not write to stdout"))?;
    }
    let state = wait(&client, &accepted)?;
    sync_proposal(&client, &path)?;
    let hash = state
        .result
        .as_ref()
        .and_then(|result| result.get("hash"))
        .and_then(|hash| hash.as_str())
        .unwrap_or_default()
        .to_owned();
    say(&format!("the active policy is now {hash}"))?;
    Ok(ExitCode::SUCCESS)
}

/// `bas passkey add`.
pub fn passkey_add() -> Result<ExitCode> {
    let client = client();
    let outcome = crate::runtime()?
        .block_on(client.add_passkey())
        .map_err(broker_error)?;
    let Outcome::Waiting(accepted) = outcome else {
        return Err(Error::new("the bas broker sent an unexpected reply"));
    };
    wait(&client, &accepted)?;
    say("approved; the approving phone shows the one-time enrollment link")?;
    Ok(ExitCode::SUCCESS)
}

/// `bas audit`.
pub fn audit(args: AuditArgs) -> Result<ExitCode> {
    let mut unit = args
        .unit
        .or_else(|| std::env::var(UNIT_VAR).ok().filter(|unit| !unit.is_empty()))
        .unwrap_or_else(|| DEFAULT_UNIT.to_owned());
    if !unit.contains('.') {
        unit.push_str(".service");
    }
    let mut command = Command::new("journalctl");
    command
        .arg(format!("_SYSTEMD_UNIT={unit}"))
        .arg("BAS_AUDIT=1")
        .args(["-o", "json", "--no-pager"]);
    if let Some(name) = &args.name {
        command.arg(format!("NAME={name}"));
    }
    if let Some(since) = &args.since {
        command.arg(format!("--since={}", since_arg(since)));
    }
    let output = command
        .output()
        .map_err(|err| Error::new(format!("could not run journalctl: {err}")))?;
    if !output.status.success() {
        return Err(Error::new(format!(
            "journalctl failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let mut stdout = io::stdout().lock();
    let mut count = 0usize;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let field = |key: &str| {
            entry
                .get(key)
                .and_then(|value| value.as_str())
                .unwrap_or("")
        };
        let time = field("__REALTIME_TIMESTAMP")
            .parse::<i64>()
            .ok()
            .and_then(chrono::DateTime::from_timestamp_micros)
            .map(|time| time.format("%Y-%m-%dT%H:%M:%SZ").to_string())
            .unwrap_or_default();
        let written = if args.json {
            let mut object = serde_json::Map::new();
            object.insert("time".to_owned(), time.into());
            if let Some(fields) = entry.as_object() {
                for (key, value) in fields {
                    let shown = !key.starts_with('_')
                        && !key.starts_with("SYSLOG")
                        && !matches!(
                            key.as_str(),
                            "PRIORITY" | "CODE_FILE" | "CODE_LINE" | "TARGET" | "BAS_AUDIT"
                        );
                    if shown && value.is_string() {
                        object.insert(key.to_lowercase(), value.clone());
                    }
                }
            }
            writeln!(stdout, "{}", serde_json::Value::Object(object))
        } else {
            writeln!(stdout, "{time}  {:<8} {}", field("EVENT"), field("MESSAGE"))
        };
        written.map_err(|_| Error::new("could not write to stdout"))?;
        count += 1;
    }
    if count == 0 {
        eprintln!("no audit entries for {unit}");
    }
    Ok(ExitCode::SUCCESS)
}

/// Turns a span such as `30m`, `1h`, or `2d` into journalctl's `-30m`. Anything else
/// passes through.
fn since_arg(since: &str) -> String {
    let digits = since.trim_end_matches(['s', 'm', 'h', 'd']);
    let unit_len = since.len() - digits.len();
    if unit_len == 1 && !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
        format!("-{since}")
    } else {
        since.to_owned()
    }
}
