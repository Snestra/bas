//! Hidden child protocol: the program that a refused `bas run` must never start.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;

#[derive(Debug, Args)]
pub struct ChildOptions {
    /// File created when this process actually starts.
    #[arg(long)]
    marker: PathBuf,
    /// Exit status to return after the marker is written.
    #[arg(long, default_value_t = 0)]
    exit_status: u8,
    /// Compare this environment variable with the exact bytes read from stdin, and fail
    /// when a bootstrap credential variable is present.
    #[arg(long)]
    expect_env: Option<String>,
}

/// Writes the launch marker, prints a fixed line, and exits with the requested status.
pub fn run(options: &ChildOptions) -> ExitCode {
    if let Some(name) = &options.expect_env
        && !expectation_matches(name)
    {
        return ExitCode::from(71);
    }
    let created = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&options.marker)
        .and_then(|mut file| file.write_all(b"launched\n"));
    if created.is_err() {
        return ExitCode::from(70);
    }
    println!("probe launched");
    ExitCode::from(options.exit_status)
}

/// Reads the expected bytes from stdin and compares them with the named variable.
/// Prints nothing, so a value can never leak through the probe.
fn expectation_matches(name: &str) -> bool {
    if std::env::var_os("BWS_ACCESS_TOKEN").is_some()
        || std::env::var_os("AAC_TOKEN").is_some()
        || std::env::var_os("BAS_E2E_ACCESS_TOKEN").is_some()
    {
        return false;
    }
    let mut expected = Vec::new();
    if std::io::stdin().lock().read_to_end(&mut expected).is_err() {
        return false;
    }
    std::env::var(name).is_ok_and(|value| value.as_bytes() == expected.as_slice())
}
