<img src="assets/icon.svg" width="64" height="64" alt="">

# Bitwarden Agent Secrets

`bas` lets a coding agent find, use, and save secrets in Bitwarden Secrets Manager. The agent handles references of the form `bas://<profile>/<secret-id>` instead of secret values. When the agent asks `bas` to run a program, `bas` puts the matching values into the program's environment. The backend is Bitwarden Secrets Manager, and `bas` doesn't use Bitwarden Password Manager.

`bas` can reach Secrets Manager directly, or it can ask a trusted machine for each secret. With direct access, `bas` holds a machine account token and calls Secrets Manager itself. With Agent Access, a copy of `bas` on a remote machine holds no token, and it asks a listener on a trusted machine for each secret. Agent Access is an experimental Bitwarden protocol that sends credentials between paired machines through a relay server.

```mermaid
flowchart LR
    subgraph direct[Direct access]
        A1[Coding agent] -->|bas run| B1[bas with a machine account token]
    end
    subgraph remote[Agent Access]
        A2[Coding agent] -->|bas run| B2[bas on a remote machine]
        B2 -->|request for one secret ID| R[Relay]
        R --> L[bas listen on a trusted machine]
    end
    B1 --> SM[(Bitwarden Secrets Manager)]
    L --> SM
```

## Status

`bas` is at v0.3.0, and it isn't ready for production use. The current checks pass on Linux, macOS, and Windows with the D-Bus credential store. The checks include a build with Rust 1.89, the offline CLI checks, and checks of the extracted release executables. The compatibility check between the earlier zbus credential store and the D-Bus store also passed. The earlier checks of protected storage, pairing, grants, and the live service ran before the switch to the D-Bus store. The v0.1.0 release build passed the stable-toolchain checks on Linux, macOS, and Windows. The Rust 1.89 minimum-toolchain job runs on Linux only.

The `bas` source is MIT. `cargo deny check licenses` still fails, because `deny.toml` doesn't list any allowed licenses.

The `ci` workflow in `ci.yml` runs on demand, and the `release` workflow in `release.yml` runs it on every `v*` tag and publishes the archives as a GitHub release. No workflow receives live vault credentials.

## Install from a release

Each [GitHub release](https://github.com/Snestra/bas/releases) publishes `bas-<OS>-<ARCH>.tar.gz` archives built by the `release` workflow on Linux, macOS, and Windows runners. Download the archive for your platform, extract `bas` (or `bas.exe`), and put it on your `PATH`. The archive contains `bas` and this README. Run `bas tui` to manage a profile's secrets and projects in the terminal. When the profile doesn't exist yet, `bas tui` asks for the machine account access token and saves the profile the way `bas auth login` does.

## Build and install

You can build `bas` from a checkout with Rust 1.89 or newer and the native build tools for your platform. The Agent Access crates come from a pinned Git revision, so the first build needs access to the `bitwarden/agent-access` GitHub repository and to crates.io.

```sh
cargo build --locked --release
./target/release/bas --help
./target/release/bas --version
```

On Windows, the executable is `target\release\bas.exe`. Rust 1.89 is the minimum version because grants use the file locks in the standard library. Debug and release builds passed with Rust 1.89 on Linux ARM64, and a debug build passed with Rust 1.89 on Linux x86_64. The minimum toolchain checks on macOS and Windows haven't run yet.

You can run the executable from the build directory without installing it. Before you copy it onto your `PATH`, run `command -v bas` on Unix or `Get-Command bas` in PowerShell. Both commands show whether another program already uses the name `bas`.

```text
on(install bas)
  if command -v bas finds another program
    keep bas in its own directory
    call bas by its full path
    don't overwrite the other program or use a forced Cargo install
  else
    copy target/release/bas onto PATH
```

The CI workflow builds and checks `bas` on the native architecture of each runner. Treat an architecture as supported only after its build and executable checks pass.

## Set up direct access

Direct access starts with a Secrets Manager machine account that can read only the projects you need. A profile in `bas` ties the machine account token to one organization and one endpoint. `bas` saves the profile only after a successful sign-in with the token, organization, and endpoint.

The token is all you need. Run the command below in a terminal and paste the token when it asks. `bas` hides what you paste, learns the organization from Bitwarden's answer, and tries bitwarden.com, then bitwarden.eu. The profile is named `default` unless you give a name.

```sh
bas auth login
bas auth status default
```

The flags still work when you want to pin the answer: `bas auth login work --organization <organization-id> --region eu --clipboard`. `docs/first-run.md` explains what `bas` learns by itself and what each first-run message means.

```mermaid
sequenceDiagram
    participant You
    participant bas
    participant SM as Secrets Manager
    participant Store as OS credential store
    You->>bas: bas auth login, then paste the token
    bas->>SM: sign in with the token
    SM-->>bas: sign-in succeeds for the organization
    bas->>Store: save the token
    bas->>bas: save the profile in config.toml
```

`bas auth login --help` describes custom HTTPS endpoints and input from stdin. Never pass a token as an argument, and never paste a token into an agent transcript.

With a pasted, clipboard, or stdin token, `bas` saves the token in the credential store of the operating system. If the credential store isn't available, the login fails. `bas` never falls back to saving the token in plain text.

For direct use on a machine without a desktop session, supply `BWS_ACCESS_TOKEN` through the protected secret delivery you already use, and log in with `--from-env`. A profile created with `--from-env` reads only the environment variable, and it never falls back to another account.

`bas` keeps its configuration in a `bas` directory inside the user configuration directory. You can set `BAS_CONFIG_DIR` to an absolute path outside every Git repository instead. Keep the directory private, and make sure only trusted users can write to it.

```text
bas/                # or the path in BAS_CONFIG_DIR
├── config.toml     # profiles and paired device fingerprints
├── grants.toml     # grant policy
└── policy.lock     # orders changes to the grant policy
```

Machine tokens and Agent Access keys never go into the configuration directory.

## Find secrets and run a program with them

```sh
bas find --profile work API
bas find --profile work --project <project-id> --json
bas run --env "API_TOKEN=bas://work/<secret-id>" -- your-command
```

`bas find` returns secret IDs and metadata, and it never returns values or notes. Every binding has to resolve before the program starts. `bas` passes the arguments after `--` straight to the program, and it doesn't run them through a shell.

```mermaid
sequenceDiagram
    participant Agent as Coding agent
    participant bas
    participant SM as Secrets Manager
    participant Cmd as your-command
    Agent->>bas: bas run --env API_TOKEN=bas://work/SECRET_ID -- your-command
    bas->>SM: read each referenced secret
    SM-->>bas: secret values
    bas->>bas: remove BWS_ACCESS_TOKEN and AAC_TOKEN from the environment
    bas->>Cmd: start the program with API_TOKEN set
    Cmd-->>Agent: output and exit status
```

`bas` removes `BWS_ACCESS_TOKEN` and `AAC_TOKEN` from the environment of the program. It also replaces each injected value of 4 or more bytes with `[bas:NAME]` in the program's stdout and stderr, so a value doesn't reach an agent transcript by accident. Masking doesn't sandbox the program, because the program can still write a value to a file, send it over the network, or print it in another encoding. The program also inherits every other variable in your environment, so pick the command with care.

Before the program starts, `bas` appends one JSON line per binding to `audit.log`. The line holds the time, the variable name, the reference, the program name, the working directory, and the process ID, and it never holds a value. The log lives in `$BAS_STATE_DIR`, or in a `bas` directory inside the user state directory. If `bas` can't write the line, the program doesn't start.

```text
$ bas run --env "API_TOKEN=bas://work/<secret-id>" -- sh -c 'echo "$API_TOKEN"'
[bas:API_TOKEN]
```

### The bas broker (Linux)

On Linux, `bas broker` holds the credentials so that no program you run, and no agent, ever sees a raw value. It runs as a systemd service under its own user, holds the Secrets Manager machine token, and checks each caller's uid against `allow-uids` in `/etc/bas/broker.toml`. It writes one system journal entry with `BAS_AUDIT=1` for each credential it uses, each change, and each refusal. `BAS_BROKER_SOCKET` replaces the socket path `/run/bas/broker.sock`.

```text
bas broker
  /run/bas/broker.sock      HTTP and JSON API for the bas commands, peer uid checked
  127.0.0.1:3128            HTTPS proxy that adds credentials for policy hosts
  /run/bas/ssh-agent.sock   ssh-agent that signs with policy keys, peer uid checked
  127.0.0.1:793             approval pages, published to your phone with tailscale serve
```

The broker never hands a value to a program. Following the decision "send these keys through the proxy only", it refuses any policy entry with `delivery = "env"`. `bas run --with NAME` checks that `NAME` is a proxy entry, then sets `HTTPS_PROXY`, `https_proxy`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, and `GIT_SSL_CAINFO` in the program's environment. The proxy adds the credential to requests for the entry's host whose method and path match `allow`. Other hosts get a plain tunnel.

```text
$ bas run --with JINA_API_KEY -- sh -c 'env | grep -E "^(HTTPS_PROXY|SSL_CERT_FILE)="'
HTTPS_PROXY=http://127.0.0.1:3128
SSL_CERT_FILE=/run/bas/ca-bundle.pem
```

#### Policy

The active policy is `policy.toml` in the broker's state directory, `/var/lib/bas`. It changes only after a passkey on your phone approves the change. Your copy, `~/.config/bas/policy.toml`, is a proposal.

```toml
version = 1

[secret.JINA_API_KEY]
ref = "bas://home/<secret-id>"
delivery = "proxy"                       # the only delivery the broker accepts
host = "api.jina.ai"
header = "Authorization"
value = "Bearer {secret}"
allow = ["GET /v1/*", "POST /v1/*"]      # method and path globs; everything else is refused

[ssh.git_signing]
ref = "bas://home/<secret-id>"           # an ed25519 or rsa OpenSSH key without a passphrase
use = ["sign-git"]                       # sign-git, auth, or both

[github]
app_id = 123456
private_key = "bas://home/<secret-id>"  # the GitHub App's private key, PEM
[[github.repo]]
name = "OWNER/REPO"
installation_id = 7654321
permissions = { contents = "write", pull_requests = "write" }

[tailscale]
client_id = "bas://home/<secret-id>"
client_secret = "bas://home/<secret-id>"
scopes = ["devices:core:read"]
api_allow = ["GET /api/v2/tailnet/-/devices"]
```

| Command | What it does |
|---|---|
| `bas policy edit` | Opens the proposal in `$VISUAL` or `$EDITOR`, sends it, prints the diff and the approval URL, and waits. After the phone approves, bas rewrites the proposal from the active policy. A policy the broker can't load is refused with its line number. |
| `bas add NAME --host H --allow "GET /v1/*"` | Proposes a new proxy entry. `--header` defaults to `Authorization` and `--value` to `Bearer {secret}`. You type the value on the approval page, so it never passes through a terminal. After approval the broker creates the secret in the `project` of `broker.toml`, adds the entry, and bas prints the new reference. |
| `bas rotate NAME` | For a `[secret.NAME]` entry, you type the new value on the approval page. For `github` or `tailscale`, the broker drops its cached tokens at once. |
| `bas audit [--since 1h] [--name NAME]` | Prints the broker's journal entries. `--unit` or `BAS_BROKER_UNIT` names another unit, such as `bas-broker-dev`. Reading the system journal needs the `adm` or `systemd-journal` group. |
| `bas passkey add` | Asks an enrolled passkey to approve one more. The approving phone shows a one-time link, valid for 15 minutes. |

Each request that needs your phone waits up to 15 minutes. `GET /v1/approvals/ID?wait=60` on the socket reports `pending`, `approved`, `denied`, `expired`, or `failed`.

#### SSH and commit signing

The broker serves an ssh-agent with the `[ssh.NAME]` keys, which must be ed25519 or rsa keys without a passphrase. The agent refuses ECDSA keys, because their signing code isn't constant-time (RUSTSEC-2026-0387). A client can list keys and ask for signatures, and it can't add, remove, or export keys. A `sign-git` key signs only SSHSIG signatures in the `git` namespace, which is what `git commit -S` asks for. An `auth` key signs SSH logins.

```sh
export SSH_AUTH_SOCK=/run/bas/ssh-agent.sock
ssh-add -L
git config --global gpg.format ssh
git config --global user.signingkey "key::$(ssh-add -L | grep bas:git_signing)"
```

#### GitHub and Tailscale tokens

With `[github]`, the proxy adds a GitHub App installation token for one repository to requests for `api.github.com`, `uploads.github.com`, and `github.com`. The repository comes from the request path, or from the proxy user, as in `HTTPS_PROXY=http://gh:OWNER%2FREPO@127.0.0.1:3128`. It must be listed in `[[github.repo]]`. Tokens last an hour and are reused until five minutes before they expire. On `github.com` only git over HTTPS is allowed.

With `[tailscale]`, the proxy adds an OAuth access token to requests for `api.tailscale.com` whose method and path match `api_allow`.

Neither is in use yet, because the GitHub App and the Tailscale OAuth client don't exist. Until they do, the proxy fails each request with a message that names the cause, such as `bas broker: could not mint a GitHub token for OWNER/REPO: could not read the App's private key`. Without a `[github]` table, a request that claims a repository through the proxy user gets `403` with "the active policy has no [github] table".

#### Approve from your phone

The approval pages run on `127.0.0.1:793`, a port below 1024 that only the broker can take. Each page shows what was asked, the uid and pid the kernel reported, and for a policy change the diff. Approving runs a WebAuthn assertion with user verification required, against a challenge stored with that request only. An answer without a valid assertion gets `403`, and the request stays pending. Denying needs no passkey, because it grants nothing.

Following the decision "A passkey that lives only on your phone", the broker refuses a passkey that reports itself as synced to other devices, both when you enroll it and at each approval. The passkeys an iPhone keeps in iCloud Keychain, and those in Google Password Manager, report themselves as synced, so the broker refuses them.

`broker.toml` needs the approval origin and the project for `bas add`.

```toml
allow-uids = [1000]

[profile]
name = "home"
organization = "<organization-id>"
api-url = "https://api.bitwarden.com"
identity-url = "https://identity.bitwarden.com"
project = "<project-id>"

[approvals]
listen = "127.0.0.1:793"
origin = "https://bas.taildfc6b2.ts.net"
```

To enroll your phone's passkey, run these as root on the broker machine, with no agent running.

```sh
# 1. Publish the approval pages as the Tailscale Service svc:bas.
tailscale serve --service=svc:bas --https=443 127.0.0.1:793
tailscale serve status            # approve the Service host in the admin console if asked

# 2. Read the one-time enrollment link. The broker writes it while no passkey is enrolled.
cat /var/lib/bas/enroll-url
```

Open the link on your phone, name the passkey, and tap Create passkey. The page says "Enrolled", and the broker deletes `enroll-url`. Then approve a first change from the phone, as yourself.

```sh
bas policy edit                   # add a line "# approved from my phone", save, and quit
# open the printed URL on the phone and tap Approve with passkey
bas audit --since 10m             # shows the enroll, request, approve, and policy entries
```

To check that a forged answer is refused after enrollment, run `bas policy edit` with a change again, and use the approval ID it prints in place of `ID` below. The reply is `403` with "no valid assertion", and the last command still says `pending`.

```sh
O='Origin: https://bas.taildfc6b2.ts.net'
curl -s -X POST -H "$O" http://127.0.0.1:793/a/ID/begin > /dev/null
curl -s -X POST -H "$O" -H 'content-type: application/json' \
  -d '{"credential":{"id":"AA","rawId":"AA","type":"public-key","extensions":{},"response":{"authenticatorData":"AA","clientDataJSON":"AA","signature":"AA","userHandle":null}}}' \
  http://127.0.0.1:793/a/ID/finish
curl -s --unix-socket /run/bas/broker.sock http://localhost/v1/approvals/ID
```

#### Try the broker without installing it

A transient unit runs the broker as a throwaway user and leaves nothing behind. Put the binary, `broker.toml`, and a first `seed.toml` policy in `/dev/shm/basdev`, readable by every user.

```sh
CRED="$(systemd-creds --user --name=bws decrypt ~/.local/share/bas/bws.cred - \
  | sudo systemd-creds encrypt --name=bws - - | tr -d '\n')"
sudo systemd-run --unit=bas-broker-dev --collect -p Type=notify -p DynamicUser=yes \
  -p RuntimeDirectory=bas -p RuntimeDirectoryMode=0755 -p UMask=0077 \
  -p AmbientCapabilities=CAP_NET_BIND_SERVICE -p CapabilityBoundingSet=CAP_NET_BIND_SERVICE \
  -p NoNewPrivileges=yes -p "SetCredentialEncrypted=bws:$CRED" \
  -p "ExecStartPre=/bin/sh -c 'mkdir -p /run/bas/state && cp /dev/shm/basdev/seed.toml /run/bas/state/policy.toml'" \
  /dev/shm/basdev/bas broker --config /dev/shm/basdev/broker.toml --state-dir /run/bas/state
unset CRED
BAS_BROKER_UNIT=bas-broker-dev bas audit
sudo systemctl stop bas-broker-dev && rm -rf /dev/shm/basdev
```

### Reference templates

A reference template is a file of `NAME=bas://profile/id` bindings, and `bas env run` follows the same rules as `bas run`.

```sh
bas env write .env.refs --env "API_TOKEN=bas://work/<secret-id>"
bas env run .env.refs -- your-command
```

A template can hold bindings, comments, and blank lines. It can't hold plaintext values, shell commands, or substitutions. You need `--force` to replace an existing template. Before you commit a template, decide whether you want its reference metadata in version control.

## Create and update secrets

`bas` reads a new secret value from the clipboard or from piped UTF-8 stdin. It never accepts the value as an argument, and it refuses stdin from a terminal.

```sh
bas create --profile work --key API_TOKEN --project <project-id> --clipboard
bas update bas://work/<secret-id> --clipboard
```

`bas` keeps the input bytes as they are, including any line endings at the end. Machine token parsing handles line endings separately.

An update keeps the key, the note, and the project associations of the secret. The SDK replaces the whole secret without checking for concurrent changes, so an update can overwrite someone else's change. `bas` refuses an update when the SDK would rewrite an existing metadata value into a standard form.

A successful receipt holds metadata and a reference, and it never holds the value. `bas` reads the secret back from Secrets Manager before it reports a verified write. The warning about duplicate names doesn't guarantee that each name is unique.

```text
exit code of bas
  0          the command succeeded, or the write was read back and verified
  1          the command failed before a write, or the write was refused
  2          the usage or the input syntax was invalid
  3          the write was acknowledged but couldn't be verified
  4          the write outcome is unknown
  126, 127   the program couldn't be launched
  otherwise  the exit status of the launched program
```

Don't retry a create or an update automatically when the outcome is unclear. Check the metadata and the service state first. `bas` has no command for deleting a secret.

## Connect a remote machine through a listener

Agent Access is experimental, and both machines need a working credential store for identity keys and session keys. A machine token in the environment doesn't replace the credential store.

Choose and approve a relay before you expose a listener beyond local testing. Use `wss://` for a remote relay, because `bas` accepts plain `ws://` only for loopback addresses. The project doesn't deploy a relay.

On the trusted machine, run the listener.

```sh
bas listen --profile work --relay wss://<relay-host> --allow <secret-id> --pair --peer-name build-host
```

On the remote machine, pair with the listener and run the program.

```sh
bas pair remote --relay wss://<relay-host>
bas run --env "API_TOKEN=bas://remote/<secret-id>" -- your-command
```

Enter the pairing code through the terminal that controls the remote program. Compare the handshake fingerprints on both machines before you confirm. Keep pairing material out of logs and agent transcripts.

```mermaid
sequenceDiagram
    participant Remote as bas on the remote machine
    participant Relay
    participant Listener as bas listen on the trusted machine
    participant Operator
    Remote->>Relay: pair with the code
    Relay->>Listener: pairing handshake
    Note over Remote,Listener: compare fingerprints on both machines
    Remote->>Relay: request one secret ID
    Relay->>Listener: forward the request
    Listener->>Operator: show a fresh approval code
    Operator->>Listener: approve with the code
    Listener->>Relay: secret ID and value
    Relay-->>Remote: secret ID and value
```

Pairing lets a device ask for secrets, and it doesn't give the device access. By default, the operator on the trusted machine approves each exact request with a fresh code that the listener shows in its terminal. `bas` requests each reference separately, and one failed request stops the program from starting.

```text
on(request from a paired device)
  if the secret ID is outside --allow
    deny
  if the grant policy is malformed
    deny
  if an active grant covers the device, profile, and secret ID
    deliver
  else if the listener has a usable terminal
    ask the operator to approve with a fresh code
  else
    deny
```

The listener accepts only explicit secret IDs within its `--allow` list. A remote profile can't find, create, or update secrets, and a remote failure never falls back to a machine token. The listener puts the secret ID in the credential ID field of the Agent Access response and the value in the password field, and it leaves the other fields empty.

The pinned SDK doesn't save replay nonces across a restart, so each delivery has to pass the current authorization checks. A replay nonce is a one-time value that stops an old message from being accepted twice. When a session replacement handshake fails verification, the listener refuses the device and drops any queued replies for it. To recover, restart the listener or pair again, and don't weaken the check.

Paired tests confirmed the refusal during secret retrieval and after an approved reply was queued. The queued reply test used the GDB debugger to control thread scheduling in the unchanged binary. The replacement device received no credential response frame. In a control build with the outbound guard removed, the same test failed.

## Allow delivery without approval, and revoke it

A grant lets the listener deliver a secret without asking the operator. You create grants only on the trusted machine. Each grant ties one paired device fingerprint to a profile, an organization, and exact secret IDs. A grant stays active until you revoke it, and it can't widen the `--allow` list of the listener.

```sh
bas auth list
bas grant add --profile work --device <paired-fingerprint> --secret <secret-id>
bas grant list --profile work --json
bas grant revoke <grant-id>
```

`bas` reuses an identical active grant, and it keeps different overlapping grants separate. To remove access, revoke every grant that allows it. Without a grant, the operator has to approve each request. A malformed policy file makes the listener deny delivery.

The listener checks pairing, profile, and grant state again before it releases an approved reply. The listener holds the shared policy lock until the local relay client returns the send result. As a result, a successful revocation always waits for any delivery that has already started.

```mermaid
sequenceDiagram
    participant Listener as bas listen
    participant Lock as policy.lock
    participant Revoke as bas grant revoke
    participant Relay as local relay client
    Listener->>Lock: take the lock
    Listener->>Listener: check pairing, profile, and grant again
    Revoke->>Lock: wait for the lock
    Listener->>Relay: send the reply
    Relay-->>Listener: send accepted
    Listener->>Lock: release the lock
    Revoke->>Lock: take the lock and remove the grant
```

The listener withholds a reply that stays queued past its request deadline. It then denies the device until the listener restarts.

Paired tests confirmed revocation during secret retrieval. They also confirmed revocation while the revoke command waited on the policy lock before the relay handoff. The second test paused the unchanged listener with GDB and saw the revoke command waiting in the kernel. After the listener resumed, the test saw the delivery finish and then the revocation complete.

The send result confirms that the local relay client accepted the reply. It doesn't confirm arrival at the remote process. Replies queued before a revocation can still arrive after it. Revocation can't erase a value the remote machine already has.

`bas auth logout <profile>` removes the local credentials and pairing for the profile and revokes its local grants. It doesn't delete any secrets in Secrets Manager.

## Agent instructions and checks

The agent instructions are in [`skills/bitwarden-agent-secrets/SKILL.md`](skills/bitwarden-agent-secrets/SKILL.md). They show an agent how to find references, inject secrets, and write secrets without printing raw values.

The advisory check with `cargo-deny 0.20.2` passes with one exception for `RUSTSEC-2023-0071`, which applies to the RSA crate in the Bitwarden SDK. The exception covers only the advisory ID. The RSA finding stays open, because no patched RSA release exists. Moving the Linux credential store to D-Bus Secret Service removed the unmaintained `zbus_names`, `zvariant`, and `zvariant_derive` dependencies.

Run the local build and the offline CLI checks with the commands below.

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo doc --locked --no-deps
cargo build --locked --release --bin bas --example e2e
./target/release/examples/e2e offline --bas "$(pwd)/target/release/bas" --artifacts "$(pwd)/target/e2e/local"
```

The offline end-to-end (E2E) command runs the built executable through reference templates, refused launches, hidden sensitive input, configuration boundaries, and other offline CLI behavior. Each run needs a new artifact directory. The run writes a manifest, case records, the commands, and a summary that is the same on every run.

Earlier external CLI checks and live checks covered more behavior, but they ran before the switch to the D-Bus store.

- Grants
  - Exact grant scope
  - Delivery by grant after a restart
  - Revocation on a running listener
- Writes
  - Reading back a created secret
  - Updating a secret
- Delivery
  - Injection that keeps every byte of the value
  - Approval and denial
  - Protected token storage

Operation across machines and the remaining service failure cases haven't passed release checks yet.

Direct live testing needs a dedicated Secrets Manager project and a working native credential store. Supply the machine token only through the environment of the runner, and never as a command argument or in chat.

```sh
BAS_E2E_ACCESS_TOKEN=... \
BAS_E2E_ORGANIZATION_ID=<organization-id> \
BAS_E2E_PROJECT_ID=<project-id> \
BAS_E2E_REGION=us \
./target/release/examples/e2e live-direct --bas "$(pwd)/target/release/bas" --artifacts "$(pwd)/target/e2e/live-direct"
```

Use `eu` for an EU account.

```text
e2e live-direct
  create a unique profile and a unique secret
  check login, find, run, update, exit codes, and logout
  remove the local profile
  keep the remote secret, because bas can't delete it
```

The report and the Secrets Manager project keep the reference to the remote secret, so you can delete the secret by hand. If a prerequisite is missing, the runner exits with code 3 and records `not_run`. The artifacts never include live command output.
