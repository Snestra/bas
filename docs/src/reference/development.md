# Build and check bas

The repository builds one program, `bas`, from four crates. The checks below are the ones CI runs, and you can run them locally.

```text
crates/
├── bas/          the CLI and the end-to-end runner in examples/e2e
├── bas-core/     profiles, references, the credential store, Secrets Manager calls
├── bas-tui/      the terminal UI
└── bas-broker/   the broker, Linux and macOS
contrib/policy.toml.example    policy example for both platforms
contrib/linux/    unit, settings, shims, and ssh config for the broker
contrib/macos/    LaunchDaemons, settings, shim, and ssh config for the broker
docs/             this site, built with mdBook
```

## Local checks

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo doc --locked --no-deps
cargo build --locked --release --bin bas --example e2e
./target/release/examples/e2e offline --bas "$(pwd)/target/release/bas" --artifacts "$(pwd)/target/e2e/local"
```

The offline end-to-end run starts the built program through reference templates, refused launches, hidden input, configuration checks, and other behavior that needs no server. Each run needs a new artifact directory. The run writes a manifest, case records, the commands, and a summary that is the same on every run.

## Live checks

A live check needs a dedicated Secrets Manager project and a working OS credential store. Give the machine token to the runner through its environment only, never as an argument or in chat.

```sh
BAS_E2E_ACCESS_TOKEN=... \
BAS_E2E_ORGANIZATION_ID=<organization-id> \
BAS_E2E_PROJECT_ID=<project-id> \
BAS_E2E_REGION=us \
./target/release/examples/e2e live-direct --bas "$(pwd)/target/release/bas" --artifacts "$(pwd)/target/e2e/live-direct"
```

```text
e2e live-direct
  create a unique profile and a unique secret
  check login, find, run, update, exit codes, and logout
  remove the local profile
  keep the remote secret, because bas can't delete it
```

Use `eu` for an account in the EU region. The report keeps the reference to the remote secret, so you can delete the secret by hand. If a requirement is missing, the runner exits with code 3 and records `not_run`. The artifacts never include live command output.

## CI and releases

The `ci` workflow in `.github/workflows/ci.yml` runs on pull requests and on demand. It builds and checks `bas` on Linux, macOS, and Windows runners, and it checks Rust 1.89 on Linux. The `release` workflow runs the same checks on every `v*` tag and publishes the archives as a GitHub release. The `docs` workflow builds the site with mdBook and publishes it to GitHub Pages. No workflow receives live vault credentials.

```sh
cd docs
mise exec -- mdbook build    # writes docs/book
```
