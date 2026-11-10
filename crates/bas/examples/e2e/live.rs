//! One ordered live scenario against a dedicated Secrets Manager project.
//!
//! Prerequisites come only from `BAS_E2E_*` variables. The token and the generated
//! values reach `bas` on stdin alone, every live command output stays in memory, and
//! dependent steps record `not_run` after a failure. Logout runs whenever login
//! succeeded, so a failed run still removes its unique profile.

use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::E2eError;
use crate::evidence::CaseOutcome;
use crate::runner::{Invocation, Runner};

/// Longest a live command may run. Offline commands keep their shorter deadline.
pub const LIVE_DEADLINE: Duration = Duration::from_secs(120);

const ENV_NAME: &str = "BAS_E2E_VALUE";
const TEMPLATE_HEADER: &str =
    "# bas reference template. Values are resolved only when `bas env run` starts a command.\n";

/// Validated inputs for a live run. The token never leaves this struct except on stdin.
struct Prerequisites {
    token: Zeroizing<Vec<u8>>,
    organization: String,
    project: String,
    region: &'static str,
}

enum PrerequisiteState {
    Ready(Prerequisites),
    Missing,
}

/// Reads the four `BAS_E2E_*` variables. A missing or empty value is `Missing`. A
/// malformed UUID or region is a runner error that names the variable, never its value.
fn prerequisites() -> Result<PrerequisiteState, E2eError> {
    let names = [
        "BAS_E2E_ACCESS_TOKEN",
        "BAS_E2E_ORGANIZATION_ID",
        "BAS_E2E_PROJECT_ID",
        "BAS_E2E_REGION",
    ];
    let mut values = Vec::new();
    for name in names {
        match std::env::var(name) {
            Ok(value) if !value.trim().is_empty() => values.push(value),
            Ok(_) => return Ok(PrerequisiteState::Missing),
            Err(std::env::VarError::NotPresent) => return Ok(PrerequisiteState::Missing),
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(E2eError::new(format!("{name} must be valid text")));
            }
        }
    }
    let [token, organization, project, region] = <[String; 4]>::try_from(values)
        .map_err(|_| E2eError::new("live prerequisites could not be read"))?;
    let mut normalized = Vec::new();
    for (name, value) in [
        ("BAS_E2E_ORGANIZATION_ID", &organization),
        ("BAS_E2E_PROJECT_ID", &project),
    ] {
        let id = Uuid::parse_str(value)
            .ok()
            .filter(|id| value.eq_ignore_ascii_case(&id.hyphenated().to_string()))
            .ok_or_else(|| E2eError::new(format!("{name} must be a hyphenated UUID")))?;
        normalized.push(id.hyphenated().to_string());
    }
    let [organization, project] = <[String; 2]>::try_from(normalized)
        .map_err(|_| E2eError::new("live prerequisites could not be read"))?;
    let region = match region.as_str() {
        "us" => "us",
        "eu" => "eu",
        _ => {
            return Err(E2eError::new("BAS_E2E_REGION must be 'us' or 'eu'"));
        }
    };
    Ok(PrerequisiteState::Ready(Prerequisites {
        token: Zeroizing::new(token.into_bytes()),
        organization,
        project,
        region,
    }))
}

#[derive(Deserialize)]
struct Receipt {
    outcome: String,
    operation: String,
    reference: Option<String>,
    key: String,
    project_id: Option<String>,
}

#[derive(Deserialize)]
struct FindReport {
    matches: Vec<FindMatch>,
    unmatched: Vec<String>,
}

#[derive(Deserialize)]
struct FindMatch {
    reference: String,
    key: String,
    project_ids: Vec<String>,
}

/// State shared by the ordered live steps. A step fills the fields later steps need.
pub struct LiveScenario {
    token: Zeroizing<Vec<u8>>,
    organization: String,
    project: String,
    region: &'static str,
    profile: String,
    key: String,
    reference: Option<String>,
    initial_value: Zeroizing<Vec<u8>>,
    updated_value: Zeroizing<Vec<u8>>,
    dir: PathBuf,
    login_succeeded: bool,
    logged_out: bool,
}

impl LiveScenario {
    fn new(prerequisites: Prerequisites) -> Self {
        Self {
            token: prerequisites.token,
            organization: prerequisites.organization,
            project: prerequisites.project,
            region: prerequisites.region,
            profile: format!("e2e-{}", Uuid::new_v4().simple()),
            key: format!("bas-e2e-{}", Uuid::new_v4().simple()),
            reference: None,
            initial_value: Zeroizing::new(
                format!("bas-e2e-initial-{}", Uuid::new_v4().simple()).into_bytes(),
            ),
            updated_value: Zeroizing::new(
                format!("bas-e2e-updated-{}", Uuid::new_v4().simple()).into_bytes(),
            ),
            dir: PathBuf::new(),
            login_succeeded: false,
            logged_out: false,
        }
    }

    /// Records one step. After a failure, dependent steps record `not_run` instead of
    /// running. Returns whether later dependent steps are blocked.
    fn step(
        &mut self,
        runner: &mut Runner,
        id: &'static str,
        blocked: bool,
        action: fn(&mut Self, &mut Runner) -> Result<(), &'static str>,
    ) -> Result<bool, E2eError> {
        if blocked {
            runner.finish_case(
                id,
                CaseOutcome::NotRun {
                    reason: "an earlier live step failed",
                },
            )?;
            return Ok(true);
        }
        let outcome = match action(self, runner) {
            Ok(()) => CaseOutcome::Passed,
            Err(assertion) => CaseOutcome::Failed { assertion },
        };
        let failed = matches!(outcome, CaseOutcome::Failed { .. });
        runner.finish_case(id, outcome)?;
        Ok(failed)
    }

    fn binding(&self) -> Result<String, &'static str> {
        let reference = self
            .reference
            .as_deref()
            .ok_or("a created secret reference is available")?;
        Ok(format!("{ENV_NAME}={reference}"))
    }

    fn template(&self) -> PathBuf {
        self.dir.join("secrets.env")
    }

    fn login(&mut self, runner: &mut Runner) -> Result<(), &'static str> {
        let observation = runner.bas_with(
            "login",
            [
                os("auth"),
                os("login"),
                os(&self.profile),
                os("--organization"),
                os(&self.organization),
                os("--region"),
                os(self.region),
                os("--stdin"),
            ],
            Invocation::default().stdin(&self.token),
        );
        self.login_succeeded = observation.exited_with(0);
        ensure(observation.exited_with(0), "live login exits 0")?;
        ensure(
            observation.stdout_contains(&self.profile),
            "live login names the new profile",
        )
    }

    fn auth_status(&mut self, runner: &mut Runner) -> Result<(), &'static str> {
        let observation = runner.bas("auth-status", [os("auth"), os("status"), os(&self.profile)]);
        ensure(observation.exited_with(0), "live auth status exits 0")?;
        ensure(
            observation.stdout_contains(&self.organization),
            "live auth status names the organization",
        )
    }

    fn doctor(&mut self, runner: &mut Runner) -> Result<(), &'static str> {
        let observation = runner.bas("doctor", [os("doctor"), os("--profile"), os(&self.profile)]);
        ensure(observation.exited_with(0), "live doctor --profile exits 0")?;
        ensure(
            observation.stdout_contains(&self.organization),
            "live doctor names the organization",
        )
    }

    fn create(&mut self, runner: &mut Runner) -> Result<(), &'static str> {
        let observation = runner.bas_with(
            "create",
            [
                os("create"),
                os("--profile"),
                os(&self.profile),
                os("--key"),
                os(&self.key),
                os("--project"),
                os(&self.project),
                os("--stdin"),
            ],
            Invocation::default().stdin(&self.initial_value),
        );
        ensure(observation.exited_with(0), "live create exits 0")?;
        let receipt = receipt(&observation.stdout)?;
        ensure(
            receipt.outcome == "verified" && receipt.operation == "create",
            "live create returns a verified create receipt",
        )?;
        ensure(
            receipt.key == self.key && receipt.project_id.as_deref() == Some(self.project.as_str()),
            "live create receipt names the key and project",
        )?;
        self.reference = Some(
            receipt
                .reference
                .ok_or("live create receipt names a reference")?,
        );
        Ok(())
    }

    fn find(&mut self, runner: &mut Runner) -> Result<(), &'static str> {
        let reference = self
            .reference
            .as_deref()
            .ok_or("a created secret reference is available")?;
        let observation = runner.bas(
            "find",
            [
                os("find"),
                os(&self.key),
                os("--profile"),
                os(&self.profile),
                os("--project"),
                os(&self.project),
                os("--json"),
            ],
        );
        ensure(observation.exited_with(0), "live find exits 0")?;
        let report: FindReport = serde_json::from_slice(&observation.stdout)
            .map_err(|_| "live find prints a JSON report")?;
        ensure(
            report.unmatched.is_empty() && report.matches.len() == 1,
            "live find matches the exact key once",
        )?;
        let found = report
            .matches
            .first()
            .ok_or("live find matches the exact key once")?;
        ensure(
            found.reference == reference && found.key == self.key,
            "live find returns the created reference and key",
        )?;
        ensure(
            found.project_ids.iter().any(|id| id == &self.project),
            "live find returns the dedicated project",
        )
    }

    /// Runs the probe through `bas run`. `expected` reaches the probe on stdin, where
    /// the probe compares it with the injected variable without printing either one.
    fn run_probe(
        &mut self,
        runner: &mut Runner,
        label: &'static str,
        marker_name: &str,
        expected: &[u8],
        exit_status: Option<u8>,
    ) -> Result<i32, &'static str> {
        let marker = self.dir.join(marker_name);
        let binding = self.binding()?;
        let mut args = vec![
            os("run"),
            os("--env"),
            os(&binding),
            os("--"),
            runner.probe_path().as_os_str().to_owned(),
            os("child"),
            os("--marker"),
            marker.clone().into_os_string(),
            os("--expect-env"),
            os(ENV_NAME),
        ];
        if let Some(status) = exit_status {
            args.push(os("--exit-status"));
            args.push(os(&status.to_string()));
        }
        let observation = runner.bas_with(label, args, Invocation::default().stdin(expected));
        ensure(
            marker.is_file(),
            "the probe writes its marker when launched",
        )?;
        match observation.termination {
            crate::runner::Termination::Exited(status) => Ok(status),
            _ => Err("the probe run exits with a status"),
        }
    }

    fn run_injection_exits_7(&mut self, runner: &mut Runner) -> Result<(), &'static str> {
        let expected = self.initial_value.clone();
        let status = self.run_probe(runner, "run", "run.marker", &expected, Some(7))?;
        ensure(status == 7, "live run propagates the program exit 7")
    }

    fn env_write(&mut self, runner: &mut Runner) -> Result<(), &'static str> {
        let binding = self.binding()?;
        let template = self.template();
        let observation = runner.bas(
            "env-write",
            [
                os("env"),
                os("write"),
                template.clone().into_os_string(),
                os("--env"),
                os(&binding),
            ],
        );
        ensure(observation.exited_with(0), "live env write exits 0")?;
        let expected = format!("{TEMPLATE_HEADER}{binding}\n");
        ensure(
            fs::read(&template).ok().as_deref() == Some(expected.as_bytes()),
            "the live template holds only the reference binding",
        )
    }

    fn env_run_injection(&mut self, runner: &mut Runner) -> Result<(), &'static str> {
        let marker = self.dir.join("env-run.marker");
        let expected = self.initial_value.clone();
        let observation = runner.bas_with(
            "env-run",
            [
                os("env"),
                os("run"),
                self.template().into_os_string(),
                os("--"),
                runner.probe_path().as_os_str().to_owned(),
                os("child"),
                os("--marker"),
                marker.clone().into_os_string(),
                os("--expect-env"),
                os(ENV_NAME),
            ],
            Invocation::default().stdin(&expected),
        );
        ensure(observation.exited_with(0), "live env run exits 0")?;
        ensure(
            marker.is_file(),
            "the probe writes its marker when launched",
        )
    }

    fn update(&mut self, runner: &mut Runner) -> Result<(), &'static str> {
        let reference = self
            .reference
            .as_deref()
            .ok_or("a created secret reference is available")?
            .to_owned();
        let observation = runner.bas_with(
            "update",
            [os("update"), os(&reference), os("--stdin")],
            Invocation::default().stdin(&self.updated_value),
        );
        ensure(observation.exited_with(0), "live update exits 0")?;
        let receipt = receipt(&observation.stdout)?;
        ensure(
            receipt.outcome == "verified" && receipt.operation == "update",
            "live update returns a verified update receipt",
        )?;
        ensure(
            receipt.reference.as_deref() == Some(reference.as_str()) && receipt.key == self.key,
            "live update receipt names the same reference and key",
        )
    }

    fn run_after_update(&mut self, runner: &mut Runner) -> Result<(), &'static str> {
        let expected = self.updated_value.clone();
        let status = self.run_probe(
            runner,
            "run-after-update",
            "updated.marker",
            &expected,
            None,
        )?;
        ensure(status == 0, "live run after update exits 0")
    }

    fn missing_program_exits_127(&mut self, runner: &mut Runner) -> Result<(), &'static str> {
        let binding = self.binding()?;
        let missing = self.dir.join("missing-program");
        let observation = runner.bas(
            "run-missing-program",
            [
                os("run"),
                os("--env"),
                os(&binding),
                os("--"),
                missing.into_os_string(),
            ],
        );
        ensure(
            observation.exited_with(127),
            "live run of a missing program exits 127 after resolution",
        )
    }

    fn logout(&mut self, runner: &mut Runner) -> Result<(), &'static str> {
        let observation = runner.bas("logout", [os("auth"), os("logout"), os(&self.profile)]);
        self.logged_out = observation.exited_with(0);
        ensure(observation.exited_with(0), "live logout exits 0")?;
        ensure(
            observation.stdout_contains(&self.profile),
            "live logout names the removed profile",
        )
    }

    fn post_logout_status(&mut self, runner: &mut Runner) -> Result<(), &'static str> {
        let observation = runner.bas(
            "auth-status-after-logout",
            [os("auth"), os("status"), os(&self.profile)],
        );
        ensure(
            observation.exited_with(1),
            "live auth status after logout exits 1",
        )
    }
}

fn ensure(ok: bool, assertion: &'static str) -> Result<(), &'static str> {
    if ok { Ok(()) } else { Err(assertion) }
}

fn os(text: &str) -> OsString {
    OsString::from(text)
}

fn receipt(stdout: &[u8]) -> Result<Receipt, &'static str> {
    serde_json::from_slice(stdout).map_err(|_| "the receipt parses as JSON")
}

/// Runs the live suite. Missing prerequisites record one `not_run` case and run no
/// `bas` service command.
pub fn run(runner: &mut Runner) -> Result<(), E2eError> {
    let prerequisites = match prerequisites()? {
        PrerequisiteState::Ready(prerequisites) => prerequisites,
        PrerequisiteState::Missing => {
            runner.finish_case(
                "live_prerequisites",
                CaseOutcome::NotRun {
                    reason: "live prerequisites are not set",
                },
            )?;
            return Ok(());
        }
    };
    let mut scenario = LiveScenario::new(prerequisites);
    runner.protect(&scenario.token);
    runner.protect(&scenario.initial_value);
    runner.protect(&scenario.updated_value);
    scenario.dir = runner.scratch("live_direct")?;
    runner.finish_case("live_prerequisites", CaseOutcome::Passed)?;

    // A failed evidence write stops the steps, but logout still runs, so the token never
    // stays in the OS credential store.
    let stepped = run_steps(&mut scenario, runner);

    // Logout is cleanup, not a dependent step. It runs whenever login succeeded, even
    // after a failure, and its own result decides the post-logout step.
    if scenario.login_succeeded {
        let outcome = match scenario.logout(runner) {
            Ok(()) => CaseOutcome::Passed,
            Err(assertion) => CaseOutcome::Failed { assertion },
        };
        runner.finish_case("live_logout", outcome)?;
    } else {
        runner.finish_case(
            "live_logout",
            CaseOutcome::NotRun {
                reason: "login did not succeed",
            },
        )?;
    }
    if scenario.logged_out {
        let outcome = match scenario.post_logout_status(runner) {
            Ok(()) => CaseOutcome::Passed,
            Err(assertion) => CaseOutcome::Failed { assertion },
        };
        runner.finish_case("live_post_logout_status", outcome)?;
    } else {
        runner.finish_case(
            "live_post_logout_status",
            CaseOutcome::NotRun {
                reason: "logout did not succeed",
            },
        )?;
    }
    stepped
}

/// Runs the dependent live steps in order.
fn run_steps(scenario: &mut LiveScenario, runner: &mut Runner) -> Result<(), E2eError> {
    let mut blocked = false;
    blocked = scenario.step(runner, "live_login", blocked, LiveScenario::login)?;
    blocked = scenario.step(
        runner,
        "live_auth_status",
        blocked,
        LiveScenario::auth_status,
    )?;
    blocked = scenario.step(runner, "live_doctor", blocked, LiveScenario::doctor)?;
    blocked = scenario.step(runner, "live_create", blocked, LiveScenario::create)?;
    blocked = scenario.step(runner, "live_find", blocked, LiveScenario::find)?;
    blocked = scenario.step(
        runner,
        "live_run_injection",
        blocked,
        LiveScenario::run_injection_exits_7,
    )?;
    blocked = scenario.step(runner, "live_env_write", blocked, LiveScenario::env_write)?;
    blocked = scenario.step(
        runner,
        "live_env_run",
        blocked,
        LiveScenario::env_run_injection,
    )?;
    blocked = scenario.step(runner, "live_update", blocked, LiveScenario::update)?;
    blocked = scenario.step(
        runner,
        "live_run_after_update",
        blocked,
        LiveScenario::run_after_update,
    )?;
    scenario.step(
        runner,
        "live_missing_program",
        blocked,
        LiveScenario::missing_program_exits_127,
    )?;
    Ok(())
}
