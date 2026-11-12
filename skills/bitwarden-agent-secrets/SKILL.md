---
name: bitwarden-agent-secrets
description: Use credentials from Bitwarden Secrets Manager through bas without printing values. Covers bas run --with on a bas broker host, bas:// references, bas find, bas create and update, and Agent Access remote profiles.
---

# Bitwarden Agent Secrets

Use `bas` for Bitwarden Secrets Manager. Don't use Bitwarden Password Manager, another account, or a raw export instead. `bas` isn't ready for production use.

## Check for a broker first

On a Linux host with the `bas` broker, use the credentials in its policy without asking for their raw values. Check for the broker with the command below.

```sh
test -S /run/bas/broker.sock && echo "broker host"
```

On a broker host, follow the rules below:

- Run a program that needs an API key with `bas run --with NAME -- command`. `NAME` is a `[secret.NAME]` entry of the policy, or `github` or `tailscale`. The program gets proxy settings, and the broker's proxy adds the credential to its HTTPS requests.
- `gh`, `git`, and `ssh` work without any token. Run `gh` inside a checkout whose `origin` is the GitHub repository. git commits are signed through the broker.
- If `bas run --with` says a name isn't in the policy, ask the person to add it. You may propose a change with `bas policy edit` or `bas add`, and the person approves it with a passkey. Never try to approve a request yourself.
- `bas audit --since 1h` shows what the broker did and why it refused a request.

```text
bas run --with JINA_API_KEY -- curl -s https://api.jina.ai/v1/embeddings -d @request.json
gh pr list
git push
```

## Safety

- Never ask for a token or a value in chat. Ask the person to set up a profile or a policy entry outside the transcript.
- Never put a token or a value in an argument, a log, shell history, a source file, or a reference template.
- Never run `env`, `printenv`, shell tracing, or a command that prints an injected value. `bas` isn't a sandbox.
- Never call an endpoint that echoes request headers through the proxy.
- Never approve a listener prompt, a fingerprint comparison, or a broker approval for the person.
- Don't retry an unclear write, and don't work around a refusal with another account.

## Direct access

Without a broker, find a reference and pass it to `bas run --env`.

```sh
bas auth list
bas find --profile work API --json
bas run --env "API_TOKEN=bas://work/<secret-id>" -- your-command
```

`bas find` returns references and metadata, never values. Treat an unmatched query as unresolved, and don't guess a secret ID. Every reference must resolve before the program starts. `bas run` removes `BWS_ACCESS_TOKEN` and `AAC_TOKEN` from the program's environment. It replaces each injected value of 4 or more bytes with `[bas:NAME]` in the program's output, and it writes one audit line per binding without the value. The program can still read the value, so choose a command that uses it without showing it.

`bas get bas://work/<secret-id>` prints one raw value for a credential helper, such as a `"!bas get ..."` key in a tool's config. It works only for a reference the person allowed with `bas helper allow`, which needs a code typed on their terminal. Never run `bas get` yourself to read a value, and never try to allow a reference for the person. If a tool needs `bas get` for a reference that isn't allowed, ask the person to run `bas helper allow`.

For repeated bindings, use `bas env write <file> --env NAME=bas://profile/id` and `bas env run <file> -- command`. A template holds references only.

## Save a value

Use `bas create --profile work --key <key> --project <project-id> --stdin` or `bas update bas://work/<secret-id> --stdin` with protected piped input only, or `--clipboard` when the person chooses it. Don't build the pipe from a value in a shell command.

| Exit code | Meaning | What to do |
|---|---|---|
| 0 | The write was read back and verified | Report the reference |
| 3 | Acknowledged, but not verified | Report it, and ask the person to check the web vault before another write |
| 4 | Outcome unknown | Same as 3 |
| 1 or 2 | Failed or invalid usage, nothing verified | Fix the cause |

There is no command that deletes a secret.

## Remote profiles

A remote profile resolves references through a paired listener on a trusted machine, one request at a time, and each request needs the operator's approval or a grant. A remote profile can't find, create, or update secrets, so ask the person for an explicit reference. Only the trusted operator may pair devices or create grants with `bas listen --pair` and `bas grant`.

If a credential store, a relay, or the broker is unavailable, report the exact error. Don't write a plain text fallback.
