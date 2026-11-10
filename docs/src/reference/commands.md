# Commands

The list below shows every `bas` command and its options. `bas <command> --help` prints the same options with longer descriptions. Commands marked Linux exist only in the Linux build.

```text
bas
├── auth      login, status, logout, list
├── find
├── run
├── env       write, run
├── create
├── update
├── doctor
├── tui
├── listen                       Agent Access
├── pair                         Agent Access
├── grant     add, list, revoke  Agent Access
├── broker                       Linux
├── add                          Linux
├── rotate                       Linux
├── policy    edit               Linux
├── audit                        Linux
└── passkey   add                Linux
```

No command prints a secret value. Commands print references, metadata, and receipts.

## Profiles

| Command | Options | What it does |
|---|---|---|
| `bas auth login [PROFILE]` | `--organization <UUID>`, `--region us\|eu`, `--server-url <URL>`, `--api-url <URL> --identity-url <URL>`, `--stdin`, `--clipboard`, `--from-env` | Signs in with a machine token and saves the profile only after the sign-in succeeds. `PROFILE` defaults to `default`. Without an input flag, it asks for the token in the terminal and hides it. |
| `bas auth status <PROFILE>` | | Signs in again and reports the organization and endpoint |
| `bas auth list` | | Lists profiles and paired devices without contacting a server |
| `bas auth logout <PROFILE>` | | Deletes a profile and its stored token. For a direct profile, it also removes its paired devices and revokes its grants. |
| `bas doctor` | `--profile <PROFILE>` | Reports readiness offline, or also signs in to the profile |
| `bas tui` | `--profile <PROFILE>` | Opens the terminal UI for secrets and projects, and signs in first when the profile doesn't exist |

## Secrets

| Command | Options | What it does |
|---|---|---|
| `bas find [QUERIES]...` | `--profile <PROFILE>` (required), `--project <UUID>`, `--json` | Lists references whose key contains a query, ignoring case |
| `bas run -- <COMMAND>...` | `--env <NAME=REFERENCE>` (repeat), `--with <NAME>` (repeat, Linux) | Runs a program with secrets in its environment, or with broker proxy settings |
| `bas env write <FILE>` | `--env <NAME=REFERENCE>` (repeat), `--force` | Writes a reference template |
| `bas env run <FILE> -- <COMMAND>...` | | Runs a program with the bindings of a template |
| `bas create` | `--profile <PROFILE>`, `--key <KEY>`, `--project <UUID>`, and `--stdin` or `--clipboard` | Creates a secret and prints a JSON receipt |
| `bas update <REFERENCE>` | `--stdin` or `--clipboard` | Replaces the value of a secret and keeps its key, note, and project |

## Agent Access

| Command | Options | What it does |
|---|---|---|
| `bas listen` | `--profile <PROFILE>`, `--relay <URL>`, `--allow <SECRET-ID>` (repeat), `--pair`, `--peer-name <NAME>` | Serves paired devices until interrupted |
| `bas pair <PROFILE>` | `--relay <URL>` (required) | Pairs with a listener and saves a remote profile |
| `bas grant add` | `--profile <PROFILE>`, `--device <FINGERPRINT>`, `--secret <SECRET-ID>` (repeat) | Lets a paired device receive exact secrets without a prompt |
| `bas grant list` | `--profile <PROFILE>`, `--json` | Lists active and revoked grants |
| `bas grant revoke <GRANT>` | | Revokes a grant and reports only after the revocation is on disk |

## Broker (Linux)

| Command | Options | What it does |
|---|---|---|
| `bas broker` | `--socket <PATH>`, `--ssh-agent-socket <PATH>`, `--config <PATH>`, `--state-dir <PATH>`, `--ca-bundle <PATH>` | Runs the broker, normally as `bas-broker.service` |
| `bas add <NAME>` | `--host <HOST>`, `--allow <METHOD PATH>` (repeat), `--header <HEADER>`, `--value <VALUE>` | Proposes a new proxy secret, whose value you type on the approval page |
| `bas rotate <NAME>` | | Replaces a stored value from the approval page, or drops minted `github` or `tailscale` tokens |
| `bas policy edit` | | Opens the policy proposal in an editor, sends it, and waits for the approval |
| `bas audit` | `--since <SINCE>`, `--name <NAME>`, `--unit <UNIT>`, `--json` | Prints the broker's audit entries from the system journal |
| `bas passkey add` | | Asks an enrolled passkey to approve enrolling one more |

The defaults of `bas broker` match the unit file.

```text
bas broker
  --socket            /run/bas/broker.sock
  --ssh-agent-socket  /run/bas/ssh-agent.sock
  --config            /etc/bas/broker.toml
  --state-dir         /var/lib/bas
  --ca-bundle         /run/bas/ca-bundle.pem
```

## Errors from the parser

When an argument is wrong, `bas` exits with code 2 and doesn't repeat the rejected value, because it may be a secret.

```text
$ bas run --with
bas: invalid arguments; rejected values are not repeated because they may be secrets. Run `bas --help` or `bas <command> --help`
```
