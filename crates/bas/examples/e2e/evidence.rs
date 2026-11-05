//! Incomplete manifest, sanitized records, and a deterministic summary.
//!
//! The run directory starts with `run.json` marked incomplete. `finish` derives the verdict
//! from the case records and marks the run complete only after every write succeeded.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use serde::Serialize;

use crate::runner::Termination;
use crate::{E2eError, SuiteOptions};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Pass,
    Fail,
    NotRun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseOutcome {
    Passed,
    Failed { assertion: &'static str },
    NotApplicable { reason: &'static str },
    NotRun { reason: &'static str },
}

/// One command that a case ran, before sanitizing.
pub struct CommandRecord {
    pub label: &'static str,
    /// Live output stays in memory for assertions and never reaches an evidence file.
    pub withhold_output: bool,
    pub program: PathBuf,
    pub args: Vec<std::ffi::OsString>,
    /// Names, never values, of the variables set in the child.
    pub environment_names: Vec<String>,
    pub termination: Termination,
    pub elapsed: Duration,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct Summary {
    pub source_revision: Option<String>,
    pub os: &'static str,
    pub arch: &'static str,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub not_applicable: usize,
    pub not_run: usize,
    pub suite: &'static str,
    pub verdict: Verdict,
}

#[derive(Serialize)]
struct Manifest<'a> {
    complete: bool,
    source_revision: Option<&'a str>,
    os: &'static str,
    arch: &'static str,
    executable_version: Option<&'a str>,
    suite: &'static str,
}

#[derive(Serialize)]
struct CaseLine {
    id: &'static str,
    outcome: CaseOutcome,
}

#[derive(Serialize)]
struct CommandLine<'a> {
    case: &'static str,
    label: &'static str,
    program: &'a str,
    args: Vec<String>,
    environment_names: &'a [String],
    termination: Termination,
    elapsed_ms: u128,
    stdout_file: String,
    stderr_file: String,
}

pub struct Evidence {
    root: PathBuf,
    suite: &'static str,
    source_revision: Option<String>,
    executable_version: Option<String>,
    redactions: Vec<(String, &'static str)>,
    outcomes: Vec<CaseOutcome>,
    commands_written: usize,
}

impl Evidence {
    /// Creates a new evidence directory with an incomplete manifest.
    ///
    /// # Errors
    ///
    /// Fails when `root` already exists or a write fails.
    pub fn create(
        root: PathBuf,
        options: &SuiteOptions,
        suite: &'static str,
    ) -> Result<Self, E2eError> {
        if let Some(parent) = root.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::create_dir(&root).map_err(|err| {
            E2eError::new(format!(
                "could not create evidence directory {}: {err}",
                root.display()
            ))
        })?;
        fs::create_dir(root.join("output"))?;
        let evidence = Self {
            root,
            suite,
            source_revision: options.source_revision.clone(),
            executable_version: None,
            redactions: Vec::new(),
            outcomes: Vec::new(),
            commands_written: 0,
        };
        evidence.write_manifest(false)?;
        Ok(evidence)
    }

    /// Replaces `text` with `placeholder` in everything that is written afterwards.
    pub fn redact(&mut self, text: &str, placeholder: &'static str) {
        self.redactions.push((text.to_owned(), placeholder));
    }

    pub fn set_executable_version(&mut self, version: String) -> Result<(), E2eError> {
        self.executable_version = Some(version);
        self.write_manifest(false)
    }

    pub fn record(
        &mut self,
        id: &'static str,
        outcome: CaseOutcome,
        commands: Vec<CommandRecord>,
    ) -> Result<(), E2eError> {
        for command in commands {
            self.commands_written += 1;
            let stem = format!("{:03}-{id}-{}", self.commands_written, command.label);
            let stdout_file = format!("output/{stem}.stdout");
            let stderr_file = format!("output/{stem}.stderr");
            let stdout_text = if command.withhold_output {
                "withheld\n".to_owned()
            } else {
                self.sanitize_bytes(&command.stdout)
            };
            let stderr_text = if command.withhold_output {
                "withheld\n".to_owned()
            } else {
                self.sanitize_bytes(&command.stderr)
            };
            fs::write(self.root.join(&stdout_file), stdout_text)?;
            fs::write(self.root.join(&stderr_file), stderr_text)?;
            let program = self.sanitize(&command.program.to_string_lossy());
            let line = CommandLine {
                case: id,
                label: command.label,
                program: &program,
                args: command
                    .args
                    .iter()
                    .map(|arg| self.sanitize(&arg.to_string_lossy()))
                    .collect(),
                environment_names: &command.environment_names,
                termination: command.termination,
                elapsed_ms: command.elapsed.as_millis(),
                stdout_file,
                stderr_file,
            };
            self.append("commands.jsonl", &line)?;
        }
        self.append("cases.jsonl", &CaseLine { id, outcome })?;
        self.outcomes.push(outcome);
        Ok(())
    }

    /// Writes `summary.json`, then marks the run complete.
    pub fn finish(self) -> Result<Summary, E2eError> {
        let count =
            |wanted: fn(&CaseOutcome) -> bool| self.outcomes.iter().filter(|o| wanted(o)).count();
        let failed = count(|o| matches!(o, CaseOutcome::Failed { .. }));
        let passed = count(|o| matches!(o, CaseOutcome::Passed));
        let not_applicable = count(|o| matches!(o, CaseOutcome::NotApplicable { .. }));
        let not_run = count(|o| matches!(o, CaseOutcome::NotRun { .. }));
        let total = self.outcomes.len();
        let verdict = if failed > 0 {
            Verdict::Fail
        } else if not_run > 0 {
            Verdict::NotRun
        } else if passed > 0 {
            Verdict::Pass
        } else {
            Verdict::Fail
        };
        let summary = Summary {
            source_revision: self.source_revision.clone(),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            total,
            passed,
            failed,
            not_applicable,
            not_run,
            suite: self.suite,
            verdict,
        };
        let mut text = serde_json::to_string_pretty(&summary)?;
        text.push('\n');
        fs::write(self.root.join("summary.json"), text)?;
        self.write_manifest(true)?;
        Ok(summary)
    }

    fn write_manifest(&self, complete: bool) -> Result<(), E2eError> {
        let manifest = Manifest {
            complete,
            source_revision: self.source_revision.as_deref(),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            executable_version: self.executable_version.as_deref(),
            suite: self.suite,
        };
        let mut text = serde_json::to_string_pretty(&manifest)?;
        text.push('\n');
        fs::write(self.root.join("run.json"), text)?;
        Ok(())
    }

    fn append(&self, name: &str, line: &impl Serialize) -> Result<(), E2eError> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.root.join(name))?;
        writeln!(file, "{}", serde_json::to_string(line)?)?;
        Ok(())
    }

    fn sanitize(&self, text: &str) -> String {
        self.redactions
            .iter()
            .fold(text.to_owned(), |text, (from, to)| {
                text.replace(from.as_str(), to)
            })
    }

    fn sanitize_bytes(&self, bytes: &[u8]) -> String {
        self.sanitize(&String::from_utf8_lossy(bytes))
    }
}
