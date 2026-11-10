---
name: bitwarden-agent-secrets
description: Find Bitwarden Secrets Manager references, inject them into a command, and create or update secrets through bas without printing values. Use for bas:// references and Agent Access remote profiles.
---

# Bitwarden Agent Secrets

Use `bas` for Secrets Manager. Do not substitute Bitwarden Password Manager, another account, or a raw secret export. `bas` is not ready for production use and still needs live-service, paired-delivery, and cross-platform verification.

## Safety

- Never ask for a token or value in chat. Use the host's private secret-input mechanism, or ask the person to configure a profile outside the agent transcript.
- Never put tokens or values in arguments, logs, shell history, source files, or reference templates.
- Never run `env`, `printenv`, shell tracing, or a child command that prints injected credentials. `bas` is not a sandbox; the child can disclose what it receives.
- Never approve a listener prompt or fingerprint comparison on the person's behalf. Pairing and grant creation are trusted-side actions, not permission to expand your own access.
- Do not retry ambiguous writes or work around denied requests with a broader account.

## Find a reference

Run `bas auth list` to inspect configured profiles. For a direct profile, use:

```sh
bas find --profile work API --json
```

Use an explicit project filter when appropriate. The result contains metadata and `bas://<profile>/<secret-id>` references, not values. Treat unmatched queries as unresolved; do not guess a secret ID. Remote profiles do not support discovery. Ask for an explicit reference when using a remote profile.

## Use a reference

```sh
bas run --env "API_TOKEN=bas://work/<secret-id>" -- your-command
```

Choose a command that consumes the variable without displaying it. All references must resolve before the child starts. Arguments after `--` are passed directly. `BWS_ACCESS_TOKEN` and `AAC_TOKEN` are removed, but other inherited variables remain available. `bas` replaces each injected value of 4 or more bytes with `[bas:NAME]` in the child's stdout and stderr. Masking isn't a sandbox, so still pick a command that doesn't write the value to a file or another encoding. Every run appends one audit line per binding, without values.

For repeatable bindings, use `bas env write <file> --env NAME=bas://profile/id`, then `bas env run <file> -- your-command`. Templates contain references only. Review whether their metadata can be committed.

Remote references use the same command syntax. Each request needs trusted-side approval or a matching exact grant. A failed remote request must not fall back to direct authentication.

## Save a value

Use `bas create --profile work --key <key> --project <project-id> --stdin` or `bas update bas://work/<secret-id> --stdin` only with protected piped input. Clipboard input is available with `--clipboard` when the person chooses it. Do not put the value into a shell command or argument to construct the pipe.

Secret input preserves trailing line endings. A value-only update preserves metadata through a full replacement, so it has no concurrent compare-and-swap guarantee.

Read the receipt without asking to print the value:

- Exit 0 means the write was read back and verified.
- Exit 3 means the server acknowledged the write but verification failed.
- Exit 4 means the write outcome is unknown.
- Exit 1 or 2 means failure or invalid usage, not a verified write.

For exit 3 or 4, report the reference and outcome and ask the person to inspect the service state before another write. Never claim a write failed merely because its verification failed. There is no secret deletion command.

## Access changes

Only the trusted operator should use `bas listen --pair`, confirm fingerprints, or create `bas grant` entries. A grant binds one paired device, profile, organization, and exact secret IDs until revoked. It cannot widen listener scope. Revocation stops future authorized deliveries but cannot recall values already received.

If credentials, a protected store, or a relay are unavailable, report the specific blocker. Do not write a plaintext fallback or claim an unrun workflow passed.
