//! Terminal output built from explicit, nonsecret fields.

use std::fmt::{self, Display};
use std::io::{self, Write};
use std::process::ExitCode;

use serde::Serialize;

use crate::grant::{Grant, State};
use crate::reference::SecretRef;

/// Exit status for a failure inside `bas` itself.
pub const EXIT_FAILURE: u8 = 1;
/// Exit status for unusable command-line arguments.
pub const EXIT_USAGE: u8 = 2;
/// Exit status for a write the service accepted but `bas` could not verify.
pub const EXIT_WRITTEN_UNVERIFIED: u8 = 3;
/// Exit status for a write whose server-side result is unknown.
pub const EXIT_UNKNOWN_OUTCOME: u8 = 4;

/// Application error whose message is built only from `bas` text and nonsecret identifiers.
///
/// No `From` conversions exist for upstream errors, so every upstream failure is mapped to
/// fixed wording at its call site and upstream bodies never reach the terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    message: String,
    exit: u8,
}

impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit: EXIT_FAILURE,
        }
    }

    pub fn usage(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit: EXIT_USAGE,
        }
    }

    pub fn with_exit(message: impl Into<String>, exit: u8) -> Self {
        Self {
            message: message.into(),
            exit,
        }
    }

    pub fn exit_code(&self) -> ExitCode {
        ExitCode::from(self.exit)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Outcome of one diagnostic line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The component works.
    Ready,
    /// Setup is absent.
    NotConfigured,
    /// The component was checked and does not work.
    Failed,
}

impl Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Self::Ready => "ready",
            Self::NotConfigured => "not configured",
            Self::Failed => "failed",
        })
    }
}

/// One labelled diagnostic with a fixed or SDK-provided nonsecret detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub status: Status,
    pub label: &'static str,
    pub detail: String,
}

/// Writes one aligned line per check.
///
/// # Errors
///
/// Returns an error when the writer fails.
pub fn write_checks(out: &mut impl Write, checks: &[Check]) -> io::Result<()> {
    let width = checks
        .iter()
        .map(|check| check.label.len())
        .max()
        .unwrap_or(0);
    for Check {
        status,
        label,
        detail,
    } in checks
    {
        writeln!(out, "{status:<14}  {label:<width$}  {detail}")?;
    }
    Ok(())
}

/// Safe discovery result: a reference plus metadata explicitly allowed for selection.
///
/// Values and notes are excluded because people put secrets in notes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecretSummary {
    pub reference: SecretRef,
    pub key: String,
    pub project_ids: Vec<uuid::Uuid>,
    /// Queries that matched this secret's key. Empty when no query was given.
    pub matched: Vec<String>,
    /// Another visible secret in the organization has the same key.
    pub duplicate_key: bool,
}

/// JSON document printed by `bas find --json`.
#[derive(Debug, Serialize)]
pub struct FindReport<'a> {
    pub matches: &'a [SecretSummary],
    pub unmatched: &'a [String],
}

/// Writes discovery results as aligned text lines.
///
/// # Errors
///
/// Returns an error when the writer fails.
pub fn write_summaries(out: &mut impl Write, summaries: &[SecretSummary]) -> io::Result<()> {
    for summary in summaries {
        let projects = summary
            .project_ids
            .iter()
            .map(uuid::Uuid::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let projects = if projects.is_empty() {
            "none".to_owned()
        } else {
            projects
        };
        let duplicate = if summary.duplicate_key {
            "  duplicate-key"
        } else {
            ""
        };
        writeln!(
            out,
            "{}  {}  project={projects}{duplicate}",
            summary.reference, summary.key
        )?;
    }
    Ok(())
}

/// Result of a create or update, as far as `bas` can establish it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The service accepted the write and a read-back matched every written field.
    Verified,
    /// The service accepted the write, but the read-back failed or differed.
    WrittenUnverified,
    /// The service may or may not have applied the write.
    Unknown,
}

impl Outcome {
    pub fn exit_code(self) -> ExitCode {
        ExitCode::from(match self {
            Self::Verified => 0,
            Self::WrittenUnverified => EXIT_WRITTEN_UNVERIFIED,
            Self::Unknown => EXIT_UNKNOWN_OUTCOME,
        })
    }
}

/// Write operation named in a receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Create,
    Update,
}

/// Safe write receipt printed as one JSON line. It never holds the value or note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Receipt {
    pub outcome: Outcome,
    pub operation: Operation,
    /// The affected secret. `None` only for a create whose result is unknown.
    pub reference: Option<SecretRef>,
    pub key: String,
    pub project_id: Option<uuid::Uuid>,
    /// Why the outcome is not `verified`.
    pub reason: Option<&'static str>,
    /// Other secrets that already used the key before a create. Feedback, not a guarantee.
    pub duplicate_keys: Vec<SecretRef>,
}

/// JSON document printed by `bas grant list --json`.
#[derive(Debug, Serialize)]
pub struct GrantReport<'a> {
    pub grants: &'a [&'a Grant],
}

/// Writes one aligned text line per grant.
///
/// # Errors
///
/// Returns an error when the writer fails.
pub fn write_grants(out: &mut impl Write, grants: &[&Grant]) -> io::Result<()> {
    for grant in grants {
        let state = match grant.state {
            State::Active => "active",
            State::Revoked => "revoked",
        };
        let secrets = grant
            .secrets
            .iter()
            .map(uuid::Uuid::to_string)
            .collect::<Vec<_>>()
            .join(",");
        writeln!(
            out,
            "{}  {state:<7}  profile={}  organization={}  device={}  secrets={secrets}",
            grant.id,
            grant.profile,
            grant.organization,
            grant.device.to_hex()
        )?;
    }
    Ok(())
}

/// Writes one value as a single JSON line.
///
/// # Errors
///
/// Returns an error when serialization or the writer fails.
pub fn write_json(out: &mut impl Write, value: &impl Serialize) -> io::Result<()> {
    serde_json::to_writer(&mut *out, value)?;
    writeln!(out)
}

/// Writes a short message to standard error.
///
/// Callers pass `bas` text. Upstream error bodies never reach this function.
pub fn write_error(message: &str) {
    // A failed write to stderr leaves nowhere else to report, so the result is dropped.
    drop(writeln!(io::stderr().lock(), "bas: {message}"));
}
