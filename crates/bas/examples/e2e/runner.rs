//! Sandbox, process lifecycle, limits, and observation.
//!
//! Children start from argument vectors, never through a shell. Each command gets an isolated
//! absolute `BAS_CONFIG_DIR` and has inherited product credentials removed.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::Serialize;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::E2eError;
use crate::evidence::{CaseOutcome, CommandRecord, Evidence, Summary};

const DEADLINE: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(10);
const OUTPUT_LIMIT: usize = 1 << 20;

/// Variables that carry product configuration or credentials and never reach a child.
const SCRUBBED: [&str; 7] = [
    "BWS_ACCESS_TOKEN",
    "AAC_TOKEN",
    "BAS_CONFIG_DIR",
    "BAS_E2E_ACCESS_TOKEN",
    "BAS_E2E_ORGANIZATION_ID",
    "BAS_E2E_PROJECT_ID",
    "BAS_E2E_REGION",
];

/// Synthetic value that cases feed into rejected input. It must never appear in `bas`
/// output, and it is replaced by a placeholder in every artifact.
pub const CANARY: &str = "bas-e2e-canary-6d0f3c2a91b7";

/// Temporary directory tree that this run creates and removes.
pub struct Workspace {
    root: PathBuf,
    config_dir: PathBuf,
}

impl Workspace {
    pub fn create() -> Result<Self, E2eError> {
        let root = std::env::temp_dir().join(format!("bas-e2e-{}", Uuid::new_v4().simple()));
        fs::create_dir(&root)?;
        let root = root.canonicalize()?;
        let config_dir = root.join("config");
        fs::create_dir(&config_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self { root, config_dir })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl Drop for Workspace {
    /// Best-effort removal on error paths. A normal run reports removal failure in
    /// [`Runner::finish`], which runs first.
    fn drop(&mut self) {
        drop(fs::remove_dir_all(&self.root));
    }
}

pub struct CommandSpec {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    /// `Some` sets a variable and `None` removes it from the child.
    pub environment: BTreeMap<OsString, Option<OsString>>,
    pub stdin: Option<Zeroizing<Vec<u8>>>,
}

/// Per-command changes to the default isolated invocation.
#[derive(Default)]
pub struct Invocation {
    stdin: Option<Zeroizing<Vec<u8>>>,
    config_dir: Option<OsString>,
    environment: Vec<(OsString, OsString)>,
}

impl Invocation {
    /// Pipes `bytes` to the child instead of an empty stdin.
    pub fn stdin(mut self, bytes: &[u8]) -> Self {
        self.stdin = Some(Zeroizing::new(bytes.to_vec()));
        self
    }

    /// Replaces the isolated `BAS_CONFIG_DIR` value.
    pub fn config_dir(mut self, dir: impl Into<OsString>) -> Self {
        self.config_dir = Some(dir.into());
        self
    }

    /// Sets one variable in the child.
    pub fn env(mut self, name: &str, value: &str) -> Self {
        self.environment.push((name.into(), value.into()));
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Termination {
    Exited(i32),
    Signaled,
    TimedOut,
    OutputLimitExceeded,
    /// The process could not be started or observed.
    CouldNotStart,
}

pub struct Observation {
    pub termination: Termination,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub elapsed: Duration,
}

impl Observation {
    pub fn exited_with(&self, status: i32) -> bool {
        self.termination == Termination::Exited(status)
    }

    pub fn stdout_contains(&self, needle: &str) -> bool {
        String::from_utf8_lossy(&self.stdout).contains(needle)
    }

    pub fn stderr_contains(&self, needle: &str) -> bool {
        String::from_utf8_lossy(&self.stderr).contains(needle)
    }

    pub fn stdout_is(&self, expected: &str) -> bool {
        self.stdout == expected.as_bytes()
    }

    pub fn stdout_is_empty(&self) -> bool {
        self.stdout.is_empty()
    }

    pub fn stderr_is_empty(&self) -> bool {
        self.stderr.is_empty()
    }
}

pub struct Runner {
    bas: PathBuf,
    child: PathBuf,
    workspace: Workspace,
    evidence: Evidence,
    pending: Vec<CommandRecord>,
    deadline: Duration,
    withhold_output: bool,
    protected: Vec<Vec<u8>>,
}

impl Runner {
    pub fn new(bas: PathBuf, child: PathBuf, workspace: Workspace, evidence: Evidence) -> Self {
        Self {
            bas,
            child,
            workspace,
            evidence,
            pending: Vec::new(),
            deadline: DEADLINE,
            withhold_output: false,
            protected: Vec::new(),
        }
    }

    /// Raises the per-command deadline, for live commands against a remote service.
    pub fn set_deadline(&mut self, deadline: Duration) {
        self.deadline = deadline;
    }

    /// Keeps command output out of evidence files. Observations still hold it in memory.
    pub fn set_withhold_output(&mut self, withhold: bool) {
        self.withhold_output = withhold;
    }

    /// Fails a passing case when a command prints `bytes`. Empty input is ignored.
    pub fn protect(&mut self, bytes: &[u8]) {
        if !bytes.is_empty() {
            self.protected.push(bytes.to_vec());
        }
    }

    /// Creates an empty directory for one case.
    pub fn scratch(&self, case_id: &str) -> Result<PathBuf, E2eError> {
        let path = self.workspace.root.join(case_id);
        fs::create_dir(&path)?;
        Ok(path)
    }

    /// Runs `bas` with `args`.
    pub fn bas<I, S>(&mut self, label: &'static str, args: I) -> Observation
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.bas_with(label, args, Invocation::default())
    }

    /// Runs `bas` with `args` and the changes in `invocation`.
    pub fn bas_with<I, S>(
        &mut self,
        label: &'static str,
        args: I,
        invocation: Invocation,
    ) -> Observation
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let program = self.bas.clone();
        self.run(label, program, args, invocation)
    }

    /// Runs the hidden probe directly, to prove that its marker works.
    pub fn probe<I, S>(&mut self, label: &'static str, args: I) -> Observation
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let program = self.child.clone();
        self.run(label, program, args, Invocation::default())
    }

    /// Path of the `bas` executable under test.
    pub fn bas_path(&self) -> &Path {
        &self.bas
    }

    /// Path of the probe executable, for use as a program inside `bas run`.
    pub fn probe_path(&self) -> &Path {
        &self.child
    }

    pub fn record_executable_version(&mut self) -> Result<(), E2eError> {
        let observation = self.bas("version", ["--version"]);
        self.pending.clear();
        if !observation.exited_with(0) {
            return Err(E2eError::new("bas --version did not exit 0"));
        }
        let version = String::from_utf8_lossy(&observation.stdout)
            .trim()
            .to_owned();
        self.evidence.set_executable_version(version)
    }

    pub fn finish_case(&mut self, id: &'static str, outcome: CaseOutcome) -> Result<(), E2eError> {
        let commands = std::mem::take(&mut self.pending);
        let echoed = commands.iter().any(|command| {
            contains(&command.stdout, CANARY.as_bytes())
                || contains(&command.stderr, CANARY.as_bytes())
        });
        let echoed_protected = commands.iter().any(|command| {
            self.protected.iter().any(|protected| {
                contains(&command.stdout, protected) || contains(&command.stderr, protected)
            })
        });
        let outcome = match outcome {
            CaseOutcome::Passed if echoed_protected => CaseOutcome::Failed {
                assertion: "output never echoes protected live values",
            },
            CaseOutcome::Passed if echoed => CaseOutcome::Failed {
                assertion: "output never echoes the synthetic canary",
            },
            other => other,
        };
        self.evidence.record(id, outcome, commands)
    }

    /// Removes the workspace, then derives the summary. A cleanup failure leaves the run
    /// incomplete.
    pub fn finish(self) -> Result<Summary, E2eError> {
        fs::remove_dir_all(&self.workspace.root)?;
        self.evidence.finish()
    }

    fn run<I, S>(
        &mut self,
        label: &'static str,
        program: PathBuf,
        args: I,
        invocation: Invocation,
    ) -> Observation
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut environment: BTreeMap<OsString, Option<OsString>> = SCRUBBED
            .iter()
            .map(|name| (OsString::from(name), None))
            .collect();
        let config_dir = invocation
            .config_dir
            .unwrap_or_else(|| self.workspace.config_dir.clone().into_os_string());
        environment.insert(OsString::from("BAS_CONFIG_DIR"), Some(config_dir));
        for (name, value) in invocation.environment {
            environment.insert(name, Some(value));
        }
        let spec = CommandSpec {
            program,
            args: args
                .into_iter()
                .map(|arg| arg.as_ref().to_owned())
                .collect(),
            environment,
            stdin: invocation.stdin,
        };
        let observation = execute(&spec, self.deadline);
        self.pending.push(CommandRecord {
            label,
            withhold_output: self.withhold_output,
            program: spec.program,
            args: spec.args,
            environment_names: spec
                .environment
                .iter()
                .filter(|(_, value)| value.is_some())
                .map(|(name, _)| name.to_string_lossy().into_owned())
                .collect(),
            termination: observation.termination,
            elapsed: observation.elapsed,
            stdout: observation.stdout.clone(),
            stderr: observation.stderr.clone(),
        });
        observation
    }
}

fn execute(spec: &CommandSpec, deadline: Duration) -> Observation {
    let started = Instant::now();
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .stdin(if spec.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in &spec.environment {
        match value {
            Some(value) => command.env(name, value),
            None => command.env_remove(name),
        };
    }
    let Ok(mut child) = command.spawn() else {
        return Observation {
            termination: Termination::CouldNotStart,
            stdout: Vec::new(),
            stderr: Vec::new(),
            elapsed: started.elapsed(),
        };
    };

    // The child may exit without reading its input, so a failed write is expected.
    let writer = spec.stdin.as_ref().and_then(|bytes| {
        let bytes = Zeroizing::new(bytes.to_vec());
        child.stdin.take().map(|mut pipe| {
            thread::spawn(move || {
                drop(pipe.write_all(&bytes));
            })
        })
    });

    let overflow = Arc::new(AtomicBool::new(false));
    let stdout = child
        .stdout
        .take()
        .map(|pipe| drain(pipe, Arc::clone(&overflow)));
    let stderr = child
        .stderr
        .take()
        .map(|pipe| drain(pipe, Arc::clone(&overflow)));

    let termination = wait(&mut child, &overflow, started, deadline);
    if let Some(writer) = writer {
        drop(writer.join());
    }
    let collect = |handle: Option<JoinHandle<Vec<u8>>>| {
        handle
            .and_then(|handle| handle.join().ok())
            .unwrap_or_default()
    };
    Observation {
        termination,
        stdout: collect(stdout),
        stderr: collect(stderr),
        elapsed: started.elapsed(),
    }
}

fn wait(
    child: &mut Child,
    overflow: &AtomicBool,
    started: Instant,
    deadline: Duration,
) -> Termination {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return status
                    .code()
                    .map_or(Termination::Signaled, Termination::Exited);
            }
            Ok(None) => {
                let stop = if overflow.load(Ordering::Relaxed) {
                    Some(Termination::OutputLimitExceeded)
                } else if started.elapsed() > deadline {
                    Some(Termination::TimedOut)
                } else {
                    None
                };
                if let Some(termination) = stop {
                    reap(child);
                    return termination;
                }
                thread::sleep(POLL);
            }
            Err(_) => {
                reap(child);
                return Termination::CouldNotStart;
            }
        }
    }
}

fn reap(child: &mut Child) {
    // The child may already have exited, in which case both calls report that and nothing is
    // left to clean up.
    drop(child.kill());
    drop(child.wait());
}

/// Reads a stream to the end, keeping at most [`OUTPUT_LIMIT`] bytes and flagging overflow.
fn drain(mut pipe: impl Read + Send + 'static, overflow: Arc<AtomicBool>) -> JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut kept = Vec::new();
        let mut buffer = [0_u8; 8192];
        while let Ok(read) = pipe.read(&mut buffer) {
            if read == 0 {
                break;
            }
            let room = OUTPUT_LIMIT.saturating_sub(kept.len());
            kept.extend_from_slice(&buffer[..read.min(room)]);
            if read > room {
                overflow.store(true, Ordering::Relaxed);
            }
        }
        kept
    })
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
