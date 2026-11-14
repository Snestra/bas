//! The single case registry and the public CLI behavior each case asserts.
//!
//! Every case runs the real `bas` executable offline and checks what a CLI user can see:
//! exit status, output, files, and whether the probe program started. The runner feeds the
//! synthetic canary into rejected input and fails any case whose output repeats it.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::evidence::CaseOutcome;
use crate::runner::{CANARY, Invocation, Observation, Runner};

/// Why a case stopped before it passed.
enum Stop {
    Failed(&'static str),
    NotApplicable(&'static str),
}

type Step = Result<(), Stop>;

pub struct Case {
    pub id: &'static str,
    run: fn(&mut Runner) -> Step,
}

impl Case {
    pub fn execute(&self, runner: &mut Runner) -> CaseOutcome {
        match (self.run)(runner) {
            Ok(()) => CaseOutcome::Passed,
            Err(Stop::Failed(assertion)) => CaseOutcome::Failed { assertion },
            Err(Stop::NotApplicable(reason)) => CaseOutcome::NotApplicable { reason },
        }
    }
}

macro_rules! cases {
    ($($name:ident),* $(,)?) => {
        pub const CASES: &[Case] = &[
            $(Case { id: stringify!($name), run: $name }),*
        ];
    };
}

cases![
    // Identity
    help_lists_commands,
    version_prints_name_and_version,
    bare_invocation_prints_usage_and_exits_2,
    doctor_reports_offline_readiness,
    doctor_hides_machine_token_value,
    doctor_unknown_profile_exits_1,
    // Empty local state
    auth_list_is_empty,
    grant_list_json_is_empty,
    grant_list_text_is_empty,
    // Bindings and launch refusal
    probe_writes_marker_when_launched,
    invalid_binding_does_not_launch,
    binding_without_equals_does_not_launch,
    invalid_env_name_does_not_launch,
    malformed_reference_does_not_launch,
    duplicate_binding_does_not_launch,
    missing_command_is_a_usage_error,
    unknown_profile_does_not_launch,
    env_write_invalid_binding_creates_no_file,
    // Sensitive input
    create_without_input_source_is_a_usage_error,
    create_with_two_input_sources_is_a_usage_error,
    create_invalid_keys_are_refused,
    create_invalid_project_is_not_echoed,
    create_unknown_profile_is_refused_before_input,
    update_invalid_reference_is_not_echoed,
    update_unknown_profile_is_refused_before_input,
    unknown_option_is_not_repeated,
    invalid_profile_name_is_not_echoed,
    // Templates
    env_write_writes_exact_bytes,
    template_overwrite_refused,
    env_write_force_replaces_the_file,
    env_run_missing_file_exits_1,
    env_run_plaintext_template_is_not_echoed,
    env_run_duplicate_template_is_refused,
    env_run_comments_only_template_is_refused,
    env_run_unknown_profile_does_not_launch,
    // Configuration
    relative_config_dir_is_refused,
    repository_local_config_dir_is_refused,
    non_private_config_dir_is_refused,
    // Platform differences
    windows_env_names_collide_case_insensitively,
    unix_env_names_are_case_sensitive,
    windows_executable_has_exe_suffix,
];

const REFERENCE: &str = "bas://demo/00000000-0000-4000-8000-000000000001";
const OTHER_REFERENCE: &str = "bas://other/00000000-0000-4000-8000-000000000001";
const SECRET_ID: &str = "00000000-0000-4000-8000-000000000001";
const EXIT_FAILURE: i32 = 1;
const EXIT_USAGE: i32 = 2;
const TEMPLATE_HEADER: &str =
    "# bas reference template. Values are resolved only when `bas env run` starts a command.\n";

// ---------------------------------------------------------------------------------------
// Helpers

fn ensure(ok: bool, assertion: &'static str) -> Step {
    if ok {
        Ok(())
    } else {
        Err(Stop::Failed(assertion))
    }
}

fn scratch(runner: &Runner, id: &str) -> Result<PathBuf, Stop> {
    runner
        .scratch(id)
        .map_err(|_| Stop::Failed("scratch directory is created"))
}

fn write_file(path: &Path, bytes: &[u8]) -> Step {
    fs::write(path, bytes).map_err(|_| Stop::Failed("fixture file is written"))
}

fn os(text: &str) -> OsString {
    OsString::from(text)
}

/// Runs `bas` and asserts its exit status and a fragment of stderr.
fn refuses(
    observation: &Observation,
    status: i32,
    fragment: &str,
    assertion: &'static str,
) -> Step {
    ensure(
        observation.exited_with(status) && observation.stderr_contains(fragment),
        assertion,
    )
}

/// `bas run` with `bindings` and the probe as the program. Asserts the refusal and that the
/// probe never wrote its launch marker.
fn refused_run(
    runner: &mut Runner,
    id: &'static str,
    bindings: &[&str],
    status: i32,
    fragment: &str,
) -> Step {
    let marker = scratch(runner, id)?.join("launched.marker");
    let mut args = vec![os("run")];
    for binding in bindings {
        args.push(os("--env"));
        args.push(os(binding));
    }
    args.push(os("--"));
    args.push(runner.probe_path().as_os_str().to_owned());
    args.push(os("child"));
    args.push(os("--marker"));
    args.push(marker.clone().into_os_string());
    let observation = runner.bas("run", args);
    refuses(
        &observation,
        status,
        fragment,
        "run is refused with the documented status and message",
    )?;
    ensure(!marker.exists(), "the child program is never launched")
}

/// `bas env run` on a template with `contents`. Asserts the refusal and no launch.
fn refused_env_run(
    runner: &mut Runner,
    id: &'static str,
    contents: &[u8],
    status: i32,
    fragment: &str,
) -> Step {
    let dir = scratch(runner, id)?;
    let template = dir.join("secrets.env");
    let marker = dir.join("launched.marker");
    write_file(&template, contents)?;
    let observation = runner.bas(
        "env-run",
        [
            os("env"),
            os("run"),
            template.into_os_string(),
            os("--"),
            runner.probe_path().as_os_str().to_owned(),
            os("child"),
            os("--marker"),
            marker.clone().into_os_string(),
        ],
    );
    refuses(
        &observation,
        status,
        fragment,
        "env run is refused with the documented status and message",
    )?;
    ensure(!marker.exists(), "the child program is never launched")
}

/// Runs `args` with the canary piped to stdin, as for a secret that must not be echoed.
fn with_piped_canary(runner: &mut Runner, label: &'static str, args: &[&str]) -> Observation {
    runner.bas_with(
        label,
        args.iter().map(|arg| os(arg)),
        Invocation::default().stdin(CANARY.as_bytes()),
    )
}

#[cfg(unix)]
fn create_dir_with_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn create_dir_with_mode(path: &Path, _mode: u32) -> io::Result<()> {
    fs::create_dir(path)
}

// ---------------------------------------------------------------------------------------
// Identity

fn help_lists_commands(runner: &mut Runner) -> Step {
    let observation = runner.bas("help", ["--help"]);
    ensure(observation.exited_with(0), "--help exits 0")?;
    let usage = if cfg!(windows) {
        "Usage: bas.exe <COMMAND>"
    } else {
        "Usage: bas <COMMAND>"
    };
    ensure(
        observation.stdout_contains(usage),
        "help prints the usage line",
    )?;
    for command in [
        "auth", "find", "run", "env", "create", "update", "doctor", "listen", "pair", "grant",
        "tui",
    ] {
        ensure(
            observation.stdout_contains(&format!("  {command} ")),
            "help lists every documented command",
        )?;
    }
    ensure(
        observation.stderr_is_empty(),
        "help prints nothing to stderr",
    )
}

fn version_prints_name_and_version(runner: &mut Runner) -> Step {
    let long = runner.bas("version-long", ["--version"]);
    let short = runner.bas("version-short", ["-V"]);
    ensure(
        long.exited_with(0) && short.exited_with(0),
        "--version and -V exit 0",
    )?;
    ensure(
        long.stdout.starts_with(b"bas ") && long.stdout.ends_with(b"\n"),
        "version prints 'bas <version>' on one line",
    )?;
    ensure(
        long.stdout.iter().filter(|byte| **byte == b'\n').count() == 1,
        "version prints exactly one line",
    )?;
    ensure(long.stdout == short.stdout, "-V matches --version")
}

fn bare_invocation_prints_usage_and_exits_2(runner: &mut Runner) -> Step {
    let observation = runner.bas("bare", std::iter::empty::<&str>());
    ensure(observation.exited_with(EXIT_USAGE), "bare bas exits 2")?;
    let usage = if cfg!(windows) {
        "Usage: bas.exe <COMMAND>"
    } else {
        "Usage: bas <COMMAND>"
    };
    ensure(observation.stderr_contains(usage), "bare bas prints usage")?;
    ensure(observation.stdout_is_empty(), "bare bas prints no stdout")
}

fn doctor_reports_offline_readiness(runner: &mut Runner) -> Step {
    let observation = runner.bas("doctor", ["doctor"]);
    ensure(observation.exited_with(0), "doctor exits 0 offline")?;
    for label in ["build", "profiles", "machine token"] {
        ensure(
            observation.stdout_contains(label),
            "doctor reports all three offline checks",
        )?;
    }
    ensure(
        observation.stdout_contains("none in"),
        "doctor reports no configured profiles",
    )?;
    ensure(
        observation.stdout_contains("is not set"),
        "doctor reports the unset machine token variable",
    )?;
    ensure(
        observation.stderr_is_empty(),
        "doctor prints nothing to stderr",
    )
}

fn doctor_hides_machine_token_value(runner: &mut Runner) -> Step {
    let observation = runner.bas_with(
        "doctor",
        ["doctor"],
        Invocation::default().env("BWS_ACCESS_TOKEN", CANARY),
    );
    ensure(
        observation.exited_with(0),
        "doctor exits 0 with the variable set",
    )?;
    ensure(
        observation.stdout_contains("is set; value hidden"),
        "doctor reports the variable as set and hidden",
    )
}

fn doctor_unknown_profile_exits_1(runner: &mut Runner) -> Step {
    let observation = runner.bas("doctor", ["doctor", "--profile", "nope"]);
    refuses(
        &observation,
        EXIT_FAILURE,
        "profile 'nope' is not configured",
        "doctor names the unknown profile and exits 1",
    )?;
    ensure(
        observation.stdout_is_empty(),
        "doctor prints no table before the profile check",
    )
}

// ---------------------------------------------------------------------------------------
// Empty local state

fn auth_list_is_empty(runner: &mut Runner) -> Step {
    let observation = runner.bas("auth-list", ["auth", "list"]);
    ensure(observation.exited_with(0), "auth list exits 0")?;
    ensure(
        observation.stdout_is_empty() && observation.stderr_is_empty(),
        "auth list prints nothing with no profiles",
    )
}

fn grant_list_json_is_empty(runner: &mut Runner) -> Step {
    let observation = runner.bas("grant-list", ["grant", "list", "--json"]);
    ensure(observation.exited_with(0), "grant list --json exits 0")?;
    ensure(
        observation.stdout_is("{\"grants\":[]}\n"),
        "grant list --json prints an empty grant array",
    )
}

fn grant_list_text_is_empty(runner: &mut Runner) -> Step {
    let observation = runner.bas("grant-list", ["grant", "list"]);
    ensure(observation.exited_with(0), "grant list exits 0")?;
    ensure(
        observation.stdout_is_empty() && observation.stderr_is_empty(),
        "grant list prints nothing with no grants",
    )
}

// ---------------------------------------------------------------------------------------
// Bindings and launch refusal

/// Control for every no-launch case: the probe writes its marker when it really starts.
fn probe_writes_marker_when_launched(runner: &mut Runner) -> Step {
    let marker = scratch(runner, "probe_writes_marker_when_launched")?.join("launched.marker");
    let observation = runner.probe(
        "probe",
        [os("child"), os("--marker"), marker.clone().into_os_string()],
    );
    ensure(observation.exited_with(0), "the probe exits 0")?;
    ensure(
        marker.is_file(),
        "the probe writes its marker when launched",
    )?;
    let again = runner.probe(
        "probe-again",
        [os("child"), os("--marker"), marker.into_os_string()],
    );
    ensure(
        again.exited_with(70),
        "the probe refuses to reuse an existing marker",
    )
}

/// A plaintext value in place of a reference exits 2 and never starts the program.
fn invalid_binding_does_not_launch(runner: &mut Runner) -> Step {
    const ID: &str = "invalid_binding_does_not_launch";

    let marker = scratch(runner, ID)?.join("launched.marker");

    // Control: the probe writes its marker when it really starts.
    let control = runner.probe(
        "probe-control",
        [os("child"), os("--marker"), marker.clone().into_os_string()],
    );
    ensure(
        control.exited_with(0) && marker.is_file(),
        "probe writes its marker when launched",
    )?;
    fs::remove_file(&marker).map_err(|_| Stop::Failed("control marker is removed"))?;

    let observation = runner.bas(
        "run",
        [
            os("run"),
            os("--env"),
            os("API_KEY=not-a-reference"),
            os("--"),
            runner.probe_path().as_os_str().to_owned(),
            os("child"),
            os("--marker"),
            marker.clone().into_os_string(),
        ],
    );
    ensure(
        observation.exited_with(EXIT_USAGE),
        "run with an invalid binding exits 2",
    )?;
    ensure(!marker.exists(), "the child program is never launched")
}

fn binding_without_equals_does_not_launch(runner: &mut Runner) -> Step {
    refused_run(
        runner,
        "binding_without_equals_does_not_launch",
        &["API_KEY"],
        EXIT_USAGE,
        "a binding must look like NAME=bas://<profile>/<secret-id>",
    )
}

fn invalid_env_name_does_not_launch(runner: &mut Runner) -> Step {
    refused_run(
        runner,
        "invalid_env_name_does_not_launch",
        &[&format!("1API_KEY={REFERENCE}")],
        EXIT_USAGE,
        "an environment name must be an ASCII letter or '_'",
    )
}

fn malformed_reference_does_not_launch(runner: &mut Runner) -> Step {
    refused_run(
        runner,
        "malformed_reference_does_not_launch",
        &[&format!("API_KEY=bas://demo/{CANARY}")],
        EXIT_USAGE,
        "a reference must look like bas://<profile>/<secret-id>",
    )
}

fn duplicate_binding_does_not_launch(runner: &mut Runner) -> Step {
    let binding = format!("API_KEY={REFERENCE}");
    refused_run(
        runner,
        "duplicate_binding_does_not_launch",
        &[&binding, &binding],
        EXIT_USAGE,
        "--env value 2: environment variable API_KEY is bound more than once",
    )
}

fn missing_command_is_a_usage_error(runner: &mut Runner) -> Step {
    let binding = format!("API_KEY={REFERENCE}");
    let without_separator = runner.bas("run-no-separator", ["run", "--env", binding.as_str()]);
    refuses(
        &without_separator,
        EXIT_USAGE,
        "<COMMAND>",
        "run without a program exits 2 and names the missing argument",
    )?;
    let empty_after_separator = runner.bas("run-empty", ["run", "--env", binding.as_str(), "--"]);
    refuses(
        &empty_after_separator,
        EXIT_USAGE,
        "<COMMAND>",
        "run with nothing after -- exits 2 and names the missing argument",
    )
}

fn unknown_profile_does_not_launch(runner: &mut Runner) -> Step {
    refused_run(
        runner,
        "unknown_profile_does_not_launch",
        &[&format!("API_KEY={REFERENCE}")],
        EXIT_FAILURE,
        "profile 'demo' is not configured",
    )
}

fn env_write_invalid_binding_creates_no_file(runner: &mut Runner) -> Step {
    let template = scratch(runner, "env_write_invalid_binding_creates_no_file")?.join("t.env");
    let observation = runner.bas(
        "env-write",
        [
            os("env"),
            os("write"),
            template.clone().into_os_string(),
            os("--env"),
            os(&format!("API_KEY={CANARY}")),
        ],
    );
    refuses(
        &observation,
        EXIT_USAGE,
        "a reference must look like bas://<profile>/<secret-id>",
        "env write with a plaintext value exits 2",
    )?;
    ensure(!template.exists(), "no template file is created")
}

// ---------------------------------------------------------------------------------------
// Sensitive input

fn create_without_input_source_is_a_usage_error(runner: &mut Runner) -> Step {
    let observation = runner.bas(
        "create",
        [
            "create",
            "--profile",
            "demo",
            "--key",
            "k",
            "--project",
            SECRET_ID,
        ],
    );
    refuses(
        &observation,
        EXIT_USAGE,
        "--stdin",
        "create without --stdin or --clipboard exits 2",
    )
}

fn create_with_two_input_sources_is_a_usage_error(runner: &mut Runner) -> Step {
    let observation = runner.bas(
        "create",
        [
            "create",
            "--profile",
            "demo",
            "--key",
            "k",
            "--project",
            SECRET_ID,
            "--stdin",
            "--clipboard",
        ],
    );
    refuses(
        &observation,
        EXIT_USAGE,
        "cannot be used with",
        "create with both input sources exits 2",
    )
}

fn create_invalid_keys_are_refused(runner: &mut Runner) -> Step {
    let leading_space = format!(" {CANARY}");
    let too_long = "k".repeat(501);
    for key in ["", leading_space.as_str(), too_long.as_str()] {
        let observation = with_piped_canary(
            runner,
            "create",
            &[
                "create",
                "--profile",
                "demo",
                "--key",
                key,
                "--project",
                SECRET_ID,
                "--stdin",
            ],
        );
        refuses(
            &observation,
            EXIT_USAGE,
            "a key must be 1 to 500 characters",
            "create refuses an invalid key with exit 2 before any profile lookup",
        )?;
    }
    Ok(())
}

fn create_invalid_project_is_not_echoed(runner: &mut Runner) -> Step {
    let observation = with_piped_canary(
        runner,
        "create",
        &[
            "create",
            "--profile",
            "demo",
            "--key",
            "k",
            "--project",
            CANARY,
            "--stdin",
        ],
    );
    refuses(
        &observation,
        EXIT_USAGE,
        "must be a hyphenated UUID",
        "create refuses a project that is not a UUID with exit 2",
    )
}

fn create_unknown_profile_is_refused_before_input(runner: &mut Runner) -> Step {
    let observation = with_piped_canary(
        runner,
        "create",
        &[
            "create",
            "--profile",
            "nope",
            "--key",
            "k",
            "--project",
            SECRET_ID,
            "--stdin",
        ],
    );
    refuses(
        &observation,
        EXIT_FAILURE,
        "profile 'nope' is not configured",
        "create with an unknown profile exits 1",
    )?;
    ensure(
        observation.stdout_is_empty(),
        "create prints no receipt for a refused write",
    )
}

fn update_invalid_reference_is_not_echoed(runner: &mut Runner) -> Step {
    let observation = with_piped_canary(runner, "update", &["update", CANARY, "--stdin"]);
    refuses(
        &observation,
        EXIT_USAGE,
        "a reference must look like bas://<profile>/<secret-id>",
        "update refuses an invalid reference with exit 2",
    )
}

fn update_unknown_profile_is_refused_before_input(runner: &mut Runner) -> Step {
    let reference = format!("bas://nope/{SECRET_ID}");
    let observation = with_piped_canary(runner, "update", &["update", &reference, "--stdin"]);
    refuses(
        &observation,
        EXIT_FAILURE,
        "profile 'nope' is not configured",
        "update with an unknown profile exits 1",
    )?;
    ensure(
        observation.stdout_is_empty(),
        "update prints no receipt for a refused write",
    )
}

fn unknown_option_is_not_repeated(runner: &mut Runner) -> Step {
    let option = format!("--{CANARY}");
    let observation = with_piped_canary(
        runner,
        "create",
        &[
            "create",
            "--profile",
            "demo",
            "--key",
            "k",
            "--project",
            SECRET_ID,
            "--stdin",
            &option,
        ],
    );
    refuses(
        &observation,
        EXIT_USAGE,
        "rejected values are not repeated",
        "an unknown option exits 2 with fixed guidance",
    )
}

fn invalid_profile_name_is_not_echoed(runner: &mut Runner) -> Step {
    // A space makes the name invalid while the canary stays intact.
    let name = format!("{CANARY} x");
    let observation = runner.bas("auth-status", ["auth", "status", name.as_str()]);
    refuses(
        &observation,
        EXIT_USAGE,
        "a profile name must be 1 to 64 lowercase letters",
        "an invalid profile name exits 2",
    )
}

// ---------------------------------------------------------------------------------------
// Templates

fn env_write_writes_exact_bytes(runner: &mut Runner) -> Step {
    let template = scratch(runner, "env_write_writes_exact_bytes")?.join("secrets.env");
    let observation = runner.bas(
        "env-write",
        [
            os("env"),
            os("write"),
            template.clone().into_os_string(),
            os("--env"),
            os(&format!("API_KEY={REFERENCE}")),
            os("--env"),
            os(&format!("DB_PASSWORD={OTHER_REFERENCE}")),
        ],
    );
    ensure(observation.exited_with(0), "env write exits 0")?;
    ensure(
        observation.stdout_contains("wrote 2 reference binding(s) to "),
        "env write reports the binding count",
    )?;
    let expected = format!("{TEMPLATE_HEADER}API_KEY={REFERENCE}\nDB_PASSWORD={OTHER_REFERENCE}\n");
    ensure(
        fs::read(&template).ok().as_deref() == Some(expected.as_bytes()),
        "the template holds the header and the bindings in order, and nothing else",
    )
}

/// `env write` without `--force` refuses to replace an existing file and leaves it untouched.
fn template_overwrite_refused(runner: &mut Runner) -> Step {
    const ID: &str = "template_overwrite_refused";
    const EXISTING: &[u8] = b"# pre-existing template\nKEEP=bas://demo/keep\n";

    let scratch = scratch(runner, ID)?;
    let template = scratch.join("secrets.env");
    write_file(&template, EXISTING)?;

    let observation = runner.bas(
        "env-write",
        [
            os("env"),
            os("write"),
            template.clone().into_os_string(),
            os("--env"),
            os(&format!("API_KEY={REFERENCE}")),
        ],
    );

    ensure(observation.exited_with(EXIT_FAILURE), "env write exits 1")?;
    ensure(
        observation.stderr_contains("already exists; pass --force to replace it"),
        "stderr names the refusal and --force",
    )?;
    ensure(
        fs::read(&template).ok().as_deref() == Some(EXISTING),
        "existing template bytes are unchanged",
    )?;
    ensure(
        fs::read_dir(&scratch).map(Iterator::count).ok() == Some(1),
        "no temporary file is left beside the template",
    )
}

fn env_write_force_replaces_the_file(runner: &mut Runner) -> Step {
    let dir = scratch(runner, "env_write_force_replaces_the_file")?;
    let template = dir.join("secrets.env");
    write_file(
        &template,
        b"# pre-existing template\nKEEP=bas://demo/keep\n",
    )?;
    let observation = runner.bas(
        "env-write-force",
        [
            os("env"),
            os("write"),
            template.clone().into_os_string(),
            os("--force"),
            os("--env"),
            os(&format!("API_KEY={REFERENCE}")),
        ],
    );
    ensure(observation.exited_with(0), "env write --force exits 0")?;
    let expected = format!("{TEMPLATE_HEADER}API_KEY={REFERENCE}\n");
    ensure(
        fs::read(&template).ok().as_deref() == Some(expected.as_bytes()),
        "--force replaces the file with exactly the new template",
    )?;
    ensure(
        fs::read_dir(&dir).map(Iterator::count).ok() == Some(1),
        "no temporary file is left beside the template",
    )
}

fn env_run_missing_file_exits_1(runner: &mut Runner) -> Step {
    let dir = scratch(runner, "env_run_missing_file_exits_1")?;
    let missing = dir.join("missing.env");
    let marker = dir.join("launched.marker");
    let observation = runner.bas(
        "env-run",
        [
            os("env"),
            os("run"),
            missing.into_os_string(),
            os("--"),
            runner.probe_path().as_os_str().to_owned(),
            os("child"),
            os("--marker"),
            marker.clone().into_os_string(),
        ],
    );
    refuses(
        &observation,
        EXIT_FAILURE,
        "could not read template",
        "env run with a missing file exits 1",
    )?;
    ensure(!marker.exists(), "the child program is never launched")
}

fn env_run_plaintext_template_is_not_echoed(runner: &mut Runner) -> Step {
    refused_env_run(
        runner,
        "env_run_plaintext_template_is_not_echoed",
        format!("API_KEY={CANARY}\n").as_bytes(),
        EXIT_USAGE,
        "template line 1: a reference must look like bas://<profile>/<secret-id>",
    )
}

fn env_run_duplicate_template_is_refused(runner: &mut Runner) -> Step {
    refused_env_run(
        runner,
        "env_run_duplicate_template_is_refused",
        format!("API_KEY={REFERENCE}\nAPI_KEY={OTHER_REFERENCE}\n").as_bytes(),
        EXIT_USAGE,
        "template line 2: environment variable API_KEY is bound more than once",
    )
}

fn env_run_comments_only_template_is_refused(runner: &mut Runner) -> Step {
    refused_env_run(
        runner,
        "env_run_comments_only_template_is_refused",
        b"# nothing but a comment\n\n",
        EXIT_USAGE,
        "the template has no bindings",
    )
}

fn env_run_unknown_profile_does_not_launch(runner: &mut Runner) -> Step {
    refused_env_run(
        runner,
        "env_run_unknown_profile_does_not_launch",
        format!("API_KEY={REFERENCE}\n").as_bytes(),
        EXIT_FAILURE,
        "profile 'demo' is not configured",
    )
}

// ---------------------------------------------------------------------------------------
// Configuration

/// Asks `auth list` and `doctor` to use `config_dir` and asserts both refuse it.
fn config_dir_refused(
    runner: &mut Runner,
    config_dir: &OsString,
    status: i32,
    fragment: &str,
) -> Step {
    let list = runner.bas_with(
        "auth-list",
        ["auth", "list"],
        Invocation::default().config_dir(config_dir),
    );
    refuses(
        &list,
        status,
        fragment,
        "auth list refuses the configuration directory",
    )?;
    ensure(list.stdout_is_empty(), "auth list prints nothing")?;
    let doctor = runner.bas_with(
        "doctor",
        ["doctor"],
        Invocation::default().config_dir(config_dir),
    );
    ensure(
        doctor.exited_with(EXIT_FAILURE),
        "doctor exits 1 when the profiles check fails",
    )?;
    ensure(
        doctor.stdout_contains("failed") && doctor.stdout_contains(fragment),
        "doctor reports the profiles check as failed with the same reason",
    )
}

fn relative_config_dir_is_refused(runner: &mut Runner) -> Step {
    config_dir_refused(
        runner,
        &os("relative/config"),
        EXIT_USAGE,
        "BAS_CONFIG_DIR must be an absolute path",
    )
}

fn repository_local_config_dir_is_refused(runner: &mut Runner) -> Step {
    let repository = scratch(runner, "repository_local_config_dir_is_refused")?;
    fs::create_dir(repository.join(".git"))
        .map_err(|_| Stop::Failed("repository marker is created"))?;
    config_dir_refused(
        runner,
        &repository.join("config").into_os_string(),
        EXIT_FAILURE,
        "profile configuration must live outside a repository",
    )
}

fn non_private_config_dir_is_refused(runner: &mut Runner) -> Step {
    if cfg!(not(unix)) {
        return Err(Stop::NotApplicable(
            "private directory modes are enforced on Unix only",
        ));
    }
    let open = scratch(runner, "non_private_config_dir_is_refused")?.join("config");
    create_dir_with_mode(&open, 0o755)
        .map_err(|_| Stop::Failed("non-private directory is created"))?;
    config_dir_refused(
        runner,
        &open.into_os_string(),
        EXIT_FAILURE,
        "must be a private directory accessible only to its owner",
    )
}

// ---------------------------------------------------------------------------------------
// Platform differences

fn windows_env_names_collide_case_insensitively(runner: &mut Runner) -> Step {
    if cfg!(not(windows)) {
        return Err(Stop::NotApplicable(
            "Windows treats environment names case-insensitively",
        ));
    }
    refused_run(
        runner,
        "windows_env_names_collide_case_insensitively",
        &[
            &format!("Api_Key={REFERENCE}"),
            &format!("API_KEY={REFERENCE}"),
        ],
        EXIT_USAGE,
        "environment variable API_KEY is bound more than once",
    )
}

fn unix_env_names_are_case_sensitive(runner: &mut Runner) -> Step {
    if cfg!(windows) {
        return Err(Stop::NotApplicable(
            "Windows treats environment names case-insensitively",
        ));
    }
    // Both names parse, so the run proceeds to profile resolution and fails there.
    refused_run(
        runner,
        "unix_env_names_are_case_sensitive",
        &[
            &format!("Api_Key={REFERENCE}"),
            &format!("API_KEY={REFERENCE}"),
        ],
        EXIT_FAILURE,
        "profile 'demo' is not configured",
    )
}

fn windows_executable_has_exe_suffix(runner: &mut Runner) -> Step {
    if cfg!(not(windows)) {
        return Err(Stop::NotApplicable(
            "only Windows executables carry the .exe suffix",
        ));
    }
    let has_exe = |path: &Path| {
        path.extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
    };
    ensure(
        has_exe(runner.bas_path()) && has_exe(runner.probe_path()),
        "the bas and probe executables end in .exe",
    )?;
    let observation = runner.bas("version", ["--version"]);
    ensure(
        observation.exited_with(0) && observation.stdout.starts_with(b"bas "),
        "the .exe path launches and reports its version",
    )
}
