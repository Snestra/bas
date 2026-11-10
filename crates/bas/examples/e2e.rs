//! Real-CLI end-to-end runner for `bas`.
//!
//! `offline` launches an existing `bas` executable through argument vectors, in an isolated
//! configuration directory, and writes sanitized evidence into a new directory. The hidden
//! `child` mode is the launch probe that the cases hand to `bas` as the program to run.
//! `live-direct` runs the same kind of cases against a real Secrets Manager account.
//!
//! ```sh
//! cargo run --locked --example e2e -- offline --bas /abs/path/to/bas --artifacts /abs/new/dir
//! cargo run --locked --example e2e -- live-direct --bas /abs/path/to/bas --artifacts /abs/new/dir
//! ```

#[path = "e2e/evidence.rs"]
mod evidence;
#[path = "e2e/live.rs"]
mod live;
#[path = "e2e/probe.rs"]
mod probe;
#[path = "e2e/runner.rs"]
mod runner;
#[path = "e2e/scenarios.rs"]
mod scenarios;

use std::fmt;
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use crate::evidence::{Evidence, Verdict};
use crate::runner::{Runner, Workspace};

/// Failure of the runner itself, as opposed to a failed case.
#[derive(Debug)]
pub struct E2eError(String);

impl E2eError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for E2eError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<io::Error> for E2eError {
    fn from(err: io::Error) -> Self {
        Self(format!("I/O error: {err}"))
    }
}

impl From<serde_json::Error> for E2eError {
    fn from(err: serde_json::Error) -> Self {
        Self(format!("JSON error: {err}"))
    }
}

#[derive(Debug, Parser)]
#[command(name = "e2e", about = "Real-CLI end-to-end checks for bas")]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Debug, Subcommand)]
enum Mode {
    /// Run the offline suite against an existing bas executable.
    Offline(SuiteOptions),
    /// Run the live suite against a dedicated Secrets Manager project.
    LiveDirect(SuiteOptions),
    #[command(hide = true)]
    Child(probe::ChildOptions),
}

#[derive(Debug, Args)]
pub struct SuiteOptions {
    /// Absolute path of the bas executable under test.
    #[arg(long)]
    pub bas: PathBuf,
    /// Absolute path of a new evidence directory. An existing path is refused.
    #[arg(long)]
    pub artifacts: PathBuf,
    /// Source revision recorded in the evidence.
    #[arg(long)]
    pub source_revision: Option<String>,
}

fn main() -> ExitCode {
    match Cli::parse().mode {
        Mode::Child(options) => probe::run(&options),
        Mode::Offline(options) => suite_exit(offline(&options)),
        Mode::LiveDirect(options) => suite_exit(live_direct(&options)),
    }
}

fn suite_exit(result: Result<Verdict, E2eError>) -> ExitCode {
    match result {
        Ok(Verdict::Pass) => ExitCode::SUCCESS,
        Ok(Verdict::Fail) => ExitCode::FAILURE,
        Ok(Verdict::NotRun) => ExitCode::from(3),
        Err(err) => {
            eprintln!("e2e: {err}");
            ExitCode::from(2)
        }
    }
}

/// Validates the shared options and builds a runner with its version recorded.
fn prepare(options: &SuiteOptions, suite: &'static str) -> Result<Runner, E2eError> {
    if !options.bas.is_absolute() || !options.bas.is_file() {
        return Err(E2eError::new("--bas must be an absolute path to a file"));
    }
    if !options.artifacts.is_absolute() {
        return Err(E2eError::new("--artifacts must be an absolute path"));
    }
    let child = std::env::current_exe()?;
    let mut evidence = Evidence::create(options.artifacts.clone(), options, suite)?;
    let workspace = Workspace::create()?;
    evidence.redact(&options.bas.to_string_lossy(), "<bas>");
    evidence.redact(&child.to_string_lossy(), "<probe>");
    evidence.redact(&workspace.root().to_string_lossy(), "<workspace>");
    evidence.redact(runner::CANARY, "<canary>");
    let mut runner = Runner::new(options.bas.clone(), child, workspace, evidence);
    runner.record_executable_version()?;
    Ok(runner)
}

fn offline(options: &SuiteOptions) -> Result<Verdict, E2eError> {
    let mut runner = prepare(options, "offline")?;
    for case in scenarios::CASES {
        let outcome = case.execute(&mut runner);
        runner.finish_case(case.id, outcome)?;
    }
    let summary = runner.finish()?;
    println!(
        "e2e offline: {} passed, {} failed, {} not applicable",
        summary.passed, summary.failed, summary.not_applicable
    );
    Ok(summary.verdict)
}

fn live_direct(options: &SuiteOptions) -> Result<Verdict, E2eError> {
    let mut runner = prepare(options, "live-direct")?;
    runner.set_deadline(live::LIVE_DEADLINE);
    runner.set_withhold_output(true);
    live::run(&mut runner)?;
    let summary = runner.finish()?;
    println!(
        "e2e live-direct: {} passed, {} failed, {} not run",
        summary.passed, summary.failed, summary.not_run
    );
    Ok(summary.verdict)
}
