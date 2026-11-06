# First run with only an access token

This page is for a person who has one thing: the access token of a Bitwarden Secrets Manager machine account. It records what `bas` used to ask for on the first run, what `bas` can now learn by itself, and what every message before the first secret means.

The first run is now one command and one paste:

```sh
bas auth login      # paste the token, press Enter
bas tui             # or this alone: paste the token on its sign-in screen
```

## Two failed attempts that started this

Both attempts came from a person who had a token and a project ID, and both stopped at a usage error from bas 0.2.0:

```text
$ bas auth login c2851425-8eff-4431-9cae-b4e5011b2a6f
error: the following required arguments were not provided:
  --organization <UUID>
  <--stdin|--clipboard|--from-env>

$ bas pair c2851425-8eff-4431-9cae-b4e5011b2a6f
error: the following required arguments were not provided:
  --relay <URL>
```

The first attempt put a project ID where the profile name goes. The second picked `bas pair`, which connects to a listener on another machine and has nothing to do with a token. Neither error said so. A hyphenated UUID is also a valid profile name, so bas could not tell the mistake apart from a real name.

## What the token holds

`AccessToken::from_str` in bitwarden-core 3.0.0 (`src/auth/access_token.rs:47-84`) splits the token as `0.<access-token-id>.<client-secret>:<encryption-key>`. It holds a version, the access token ID, the client secret, and a 16-byte key. It names no organization, no region, and no server.

The organization comes from the server. `login_access_token` (`src/auth/login/access_token.rs:53`) posts the ID and secret to `<identity>/connect/token` (`src/auth/api/request/mod.rs:30-50`). It reads the `organization` claim from the returned JWT (`access_token.rs:72-77`, claim defined at `src/auth/jwt_token.rs:21-22`), and stores it in the login method (`access_token.rs:99-105`). `SecretsManagerClient::get_access_token_organization` (bitwarden-sm 3.0.0 `src/client.rs:50-52`) returns it through `SecretsManagerTokenHandler::get_access_token_organization` (bitwarden-auth 3.0.0 `src/token_management/secrets_manager_token_handler.rs:71-76`).

## What the identity servers answer for the writer token

I sent the writer token's client credentials to both hosted identity servers on 2026-11-06. The token was read from its file by a script and never printed. Only the status and the shape of each answer are recorded here.

| Server | HTTP status | Body shape |
|---|---|---|
| `https://identity.bitwarden.com/connect/token` | 200 | `{"access_token": str, "expires_in": int, "token_type": "Bearer", "scope": "api.secrets", "encrypted_payload": str}` |
| `https://identity.bitwarden.eu/connect/token` | 400 | `{"error": "invalid_client"}` |

The EU body lacks the `error_description` and `ErrorModel` fields that `IdentityTokenFailResponse` requires (`src/auth/api/response/identity_token_fail_response.rs:6-11`). So the SDK reports it as an API error with status 400 (`src/auth/api/response/identity_token_response.rs:35-42`). `bas` classifies that as a refusal (`crates/bas-core/src/secrets.rs:186`) and moves on to the next region (`secrets.rs:449`). A refused token is therefore safe to try against the next region, and a 200 answer settles the region.

## Each input bas asked for, and whether bas can learn it

| Input in bas 0.2.0 | Can bas learn it by itself? | Proof | What bas does now |
|---|---|---|---|
| Profile name (required positional) | Yes. Any name works, because the name exists only inside bas: references and the credential store key on it (`crates/bas-core/src/credential/store.rs:9-10`, `reference.rs` `ProfileName`). | The token holds no name (`access_token.rs:47-84`). | Defaults to `default` (`crates/bas-core/src/login.rs:17`, `crates/bas/src/cli.rs:197`). |
| `--organization` (required) | Yes. The identity server names it in the JWT's `organization` claim. | `access_token.rs:72-77`, `secrets_manager_token_handler.rs:71-76` | Optional. Without it bas takes the token's organization. With it bas still refuses a token of another organization (`secrets.rs` `check_organization`). |
| `--region`, `--server-url`, or `--api-url` with `--identity-url` (exactly one required) | For the two hosted regions, yes. The token names no server, but a wrong region refuses it with HTTP 400 and the right one answers 200 (table above). A self-hosted server cannot be guessed. | `access_token.rs:47-84`; the identity probe above | Optional. bas reuses the existing profile's endpoints, else tries bitwarden.com, then bitwarden.eu (`crates/bas-core/src/login.rs:62-66`, `profile.rs:41`). The success line names the API it used, so the region is never switched silently. |
| One of `--stdin`, `--clipboard`, `--from-env` (required) | Not the token itself. bas can ask for it. | clig.dev source `content/_index.md` at 697d6a2: prompt only when stdin is a TTY (lines 869-870), hide typed passwords (line 876), never read secrets from flags (lines 854-863). `gh auth login` asks "Paste your authentication token:" in a masked field (cli/cli eeb44bc `internal/prompter/huh_prompter.go:185-202`). | In a terminal with no input flag, bas asks and hides what you paste (`crates/bas/src/input.rs:73`). Without a terminal it says which flag to pass (`crates/bas/src/main.rs:315`). |
| Where to keep the token | Yes. The OS credential store was already the default. | `crates/bas/src/main.rs` `login` | Unchanged. `--from-env` still opts out. |

Prior art agrees on this split. `bws` takes the organization from the token and never asks for it, but it never tries a second region (sdk-sm `crates/bws/src/main.rs:115-121`). `gh auth login` defaults the host to github.com and prompts only on a terminal (cli/cli `pkg/cmd/auth/login/login.go:158-170`). 1Password's CLI needs no sign-in step for a service account token in `OP_SERVICE_ACCOUNT_TOKEN` (https://developer.1password.com/docs/cli/secrets-scripts, read through search results). clig.dev asks for a suggested next command in every error (`content/_index.md` lines 698-705) and for "did you mean" corrections (lines 463-475), which the tables below follow.

## Commands and keystrokes

These counts come from the VHS tapes in `tapes/first-run/`, recorded from an empty temporary `BAS_CONFIG_DIR` and a profile name with no credential-store entry. They count what the user types up to the line that proves success. A paste counts as one keystroke. Copying the token from the web vault happens first in every path, so it is not counted.

| Path | Before (0.2.0) | After |
|---|---|---|
| Sign in with `bas auth login` | 1 command, 107 keystrokes, plus finding the organization ID in the web vault | 1 command, 17 keystrokes |
| Sign in and see projects in the TUI | 2 commands, 141 keystrokes, plus finding the organization ID | 1 command, 10 keystrokes |

## Every message before the first secret

The first-run path is: `bas auth login` or `bas tui`, then `bas auth status`, `bas find`, or the TUI's project list. The table lists every message `bas` can print on that path, in the words it prints them. `NAME` stands for the profile name in the message.

### Usage errors from the command-line parser (exit 2)

| Message | What the user most likely meant | Exact command to type next |
|---|---|---|
| `bas` with no command prints the command list | To see what bas can do | `bas auth login` |
| `` bas: invalid arguments; rejected values are not repeated because they may be secrets. Run `bas --help` or `bas <command> --help` `` (unknown command, unknown flag, extra argument, or bad `--region` value) | A command or flag with a typo, or two profile names | `bas auth login --help` |
| `bas auth` with no subcommand prints the auth command list | To sign in | `bas auth login` |
| `error: the argument '--stdin' cannot be used with '--clipboard'` (any two of `--stdin`, `--clipboard`, `--from-env`) | One way to give the token | `bas auth login` and paste the token |
| `error: the following required arguments were not provided: --identity-url <URL>` (or `--api-url`) | A self-hosted server | `bas auth login --server-url https://your.server` |
| `error: the following required arguments were not provided: <PROFILE>` from `bas auth status` | The profile made by `bas auth login` | `bas auth status default` |
| `error: the following required arguments were not provided: --profile <PROFILE>` from `bas find` | The profile made by `bas auth login` | `bas find --profile default` |
| `error: the following required arguments were not provided: <PROFILE>` from `bas pair` | To sign in with a token | `bas auth login` |

### Errors from bas before it contacts the server

| Message | What the user most likely meant | Exact command to type next |
|---|---|---|
| `bas: that is an ID, not a profile name. A profile name is the name a profile got at sign-in, such as default. To sign in with a machine account token, run: bas auth login. To see your profiles, run: bas auth list` | A project or organization ID was typed where the profile name goes | `bas auth login` |
| `` bas: missing --relay URL, the relay of a `bas listen` on another machine. To sign in with a machine account token instead, run: bas auth login `` | To sign in with a token, not to pair | `bas auth login` |
| `bas: a profile name must be 1 to 64 lowercase letters, digits, '-' or '_', starting with a letter or digit` | A name with capitals or spaces | `bas auth login work` |
| `bas: a secret or project ID must be a hyphenated UUID` (from `--organization`) | A pasted organization ID with a typo | `bas auth login` (the organization is learned from the token) |
| `bas: choose exactly one endpoint: --region, --server-url, or both --api-url and --identity-url` | Two endpoint flags at once | `bas auth login` |
| `bas: an endpoint must be an https:// URL without credentials, query, or fragment` | An `http://` or decorated server URL | `bas auth login --server-url https://your.server` |
| `bas: an endpoint must be an absolute URL` | A host name without a scheme | `bas auth login --server-url https://your.server` |
| `bas: no terminal to paste the token into; give it with --stdin, --clipboard, or --from-env` | Sign-in from a script | `bas auth login --stdin < token-file` |
| `bas: --stdin needs piped input; typing at a terminal would echo the secret` | To paste the token | `bas auth login` |
| `bas: the secret input is empty` | Enter was pressed before the paste, or the pipe was empty | `bas auth login` and paste the token |
| `bas: the secret input is not valid UTF-8 text` | The wrong file was piped | `bas auth login` and paste the token |
| `bas: cancelled; nothing was saved` | Esc or Ctrl-C at the prompt | `bas auth login` |
| `bas: could not read the terminal` | A terminal that refuses raw mode; copy the token first | `bas auth login --clipboard` |
| `bas: the machine token is not in Secrets Manager access-token format` | Part of the token, or another secret, was pasted; copy the whole access token again | `bas auth login` |
| `bas: no clipboard is available here; use --stdin` | `--clipboard` over SSH or without a desktop | `bas auth login` |
| `bas: the clipboard does not contain text` | The token was not copied yet | `bas auth login` |
| `bas: could not read the clipboard; use --stdin` | A clipboard that refuses access | `bas auth login` |
| `bas: profile 'NAME' reads its token from BWS_ACCESS_TOKEN, which is not set` | `--from-env` in a shell without the variable | `bas auth login` |
| `` bas: profile 'NAME' is a remote profile; run `bas auth logout NAME` first `` | Reusing a paired profile's name for a token | `bas auth login other-name` |
| `` bas: profile 'NAME' is bound to another organization or endpoint; run `bas auth logout NAME` first `` | A token of another organization for an existing profile | `bas auth login other-name` |
| `bas: BAS_CONFIG_DIR must be an absolute path` | A relative path in the variable | `export BAS_CONFIG_DIR="$HOME/.config/bas"` |
| `bas: profile configuration must live outside a repository, but DIR is inside REPO; set BAS_CONFIG_DIR to another directory` | `BAS_CONFIG_DIR` inside a Git checkout | `export BAS_CONFIG_DIR="$HOME/.config/bas"` |
| `bas: the bas configuration directory must be a private directory accessible only to its owner` | A shared or group-readable directory | `chmod 700 "$BAS_CONFIG_DIR"` |
| `bas: no user configuration directory is available; set BAS_CONFIG_DIR` | A system without a home configuration directory | `export BAS_CONFIG_DIR=/absolute/private/dir` |
| `bas: profile configuration FILE is malformed` (also: `could not read profile configuration FILE`, `has a non-HTTPS endpoint`, `has a malformed remote or listener entry`) | A hand-edited `config.toml`; correct the file it names | `"$EDITOR" FILE` |
| `bas: waiting for another bas process that is changing grants or profiles, or delivering a secret` | Another bas run holds the lock; bas continues by itself when it ends | `pgrep -fl 'bas listen'` |
| `bas: could not lock the bas policy; grants and profiles were not changed` | An unwritable configuration directory | `ls -ld "$BAS_CONFIG_DIR"` |
| `bas: could not start the async runtime` | The system is out of resources | Retry `bas auth login` |

### Errors from the sign-in itself

| Message | What the user most likely meant | Exact command to type next |
|---|---|---|
| `bas: Secrets Manager refused the machine token for profile 'NAME' at https://identity.bitwarden.com and https://identity.bitwarden.eu; check that you copied the whole token, or pass --server-url for a self-hosted server` | A revoked, expired, or partly copied token, or a self-hosted server; copy a fresh token from the web vault | `bas auth login` |
| `bas: Secrets Manager refused the machine token for profile 'NAME'` (one endpoint given or stored) | The wrong region or server for this token | `bas auth login` without `--region` |
| `bas: could not reach the identity endpoint URL for profile 'NAME'` | No network, a proxy, or a mistyped server | `curl -sI URL` |
| `bas: authentication failed for profile 'NAME'` | An unusual server answer | `bas auth login` again |
| `bas: Secrets Manager did not authenticate profile 'NAME'` | The server answered without a session | `bas auth login` again |
| `bas: the machine token for profile 'NAME' names no organization` | A token that is not a machine account access token; create one for the machine account in the web vault | `bas auth login` |
| `bas: the machine token for profile 'NAME' belongs to organization ID, not the configured ID` | `--organization` with the wrong ID | `bas auth login` without `--organization` |
| `bas: the OS credential store is locked or denied access for profile 'NAME'; headless systems can use --from-env instead` | A locked keychain (macOS) | `security unlock-keychain` |
| `bas: the OS credential store is not available on this system for profile 'NAME'; headless systems can use --from-env instead` | A server without a keychain service; let your secret delivery set `BWS_ACCESS_TOKEN` in the environment | `bas auth login --from-env` |
| `bas: the OS credential store failed for profile 'NAME'; headless systems can use --from-env instead` | A keychain error | `bas auth login` again |
| `bas: could not write profile configuration FILE` | A full or read-only disk | `df -h "$BAS_CONFIG_DIR"` |
| `authenticated profile 'NAME' for organization ID at URL; token source: os credential store`, then `` bas: next: run `bas tui --profile NAME` to browse your secrets, or `bas find --profile NAME` to list references `` | Success | `bas tui --profile NAME` |

### After sign-in, before the first secret

| Message | What the user most likely meant | Exact command to type next |
|---|---|---|
| `` bas: profile 'NAME' is not configured; run `bas auth login NAME --help` or `bas pair NAME --help` `` | A profile that was never created, or a typo; `bas auth list` shows the names | `bas auth login NAME` |
| `` bas: no machine token is stored for profile 'NAME'; run `bas auth login NAME --help` `` | The credential-store entry was removed | `bas auth login NAME` |
| `` bas: profile 'NAME' is a remote profile; it only resolves references for `bas run` and `bas env run` through its paired listener `` | `bas find` or `bas tui` with a paired profile | `bas auth login` |
| `bas: choose a profile: bas tui --profile NAME, where NAME is one of A, B` | `bas tui` with several profiles and none named default | `bas tui --profile A` |
| `bas: bas tui needs an interactive terminal: …` | `bas tui` from a script or pipe; open a terminal | `bas tui` |
| `bas: profile 'NAME' is not authorized to list secret identifiers` | The machine account has no project access; grant it a project in the web vault | `bas find --profile NAME` |
| `bas: could not reach Secrets Manager at URL to list secret identifiers` | No network | `bas find --profile NAME` again |
| `bas: Secrets Manager refused to list secret identifiers for profile 'NAME' (HTTP STATUS)` | A server error | `bas auth status NAME` |
| `bas: could not list secret identifiers: the Secrets Manager response was unusable` | An unusual server answer | `bas auth status NAME` |
| `bas: no secret key matches 'QUERY'` | A key typed differently | `bas find --profile NAME` |
| TUI sign-in screen: `the machine token is not in Secrets Manager access-token format. Copy the whole access token and paste it again` | Part of the token was pasted; the field is cleared | Paste the whole token and press Enter (keys, not a command) |
| TUI sign-in screen: any sign-in error above, followed by `. Paste the token again` | As above; the screen stays open | Paste the token and press Enter (keys, not a command) |
| TUI: `could not connect to Secrets Manager: …` (the app closes) | A stored token that stopped working | `bas auth login NAME` |
| TUI: `Could not list projects: …` | The machine account has no project access; grant it a project in the web vault | `bas tui` |
