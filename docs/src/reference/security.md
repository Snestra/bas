# Security notes

`bas` is at version 0.8.2 and isn't ready for production use. The notes below say what each part protects against and where its limits are.

## Direct access

With direct access, a program that `bas run` starts receives the values in its environment. Masking replaces each value of 4 or more bytes with `[bas:NAME]` in the program's stdout and stderr, which keeps a value out of an agent transcript by accident. Masking doesn't sandbox the program, because the program can write a value to a file, send it over the network, or print it in another encoding. Use a machine account that reads only the projects an agent needs.

## Credential helpers

`bas get` prints a raw value, so a program that runs it can read the value. It works only for a reference on the list in `helpers.toml`, and only `bas helper allow` adds to that list after you type a one-time code on the controlling terminal. A program that can't type on your terminal can't add a reference with `bas`. An agent that can write files as your user can still edit `helpers.toml`, as it can edit `grants.toml`, so keep agents out of the configuration directory when that matters. `bas get` refuses when stdout is a terminal, and it appends one line per read to `audit.log` with the reference and the parent process, never the value. A reference of a remote profile still needs approval or a grant on the listener.

On a broker host, the local list has no effect, because your user can edit it. There `bas get` reads only `[helper.NAME]` entries of the broker's policy, which change only after a passkey approval, and the broker records each read in its audit log.

## The broker

The broker keeps values away from your user only if your user has no way to root. [Lock down the host](../broker/lock-down.md) lists the steps. The table below lists attacks by an agent that runs as your user, what blocks each one, and what risk is left.

| Attack | Blocked by | Risk left |
|---|---|---|
| Become root with `sudo`, `docker`, or `lxd` | A sudo password, and no membership in `docker` or `lxd` | Capture of the sudo password through shell startup files, any other root path, kernel bugs |
| Decrypt the sealed token | The credential is sealed for the system and readable by root only | None without root |
| Read the broker's memory or environment | A separate user, `ProtectProc=invisible`, `LimitCORE=0`, no swap | None without root |
| Widen access by editing `policy.toml` | The broker uses only the approved copy and shows the diff on the approval page | You approve a diff without reading it |
| Approve its own request | WebAuthn with user verification on your device | A compromised phone, or a passkey synced to a machine where an agent runs |
| Show you a false approval page | The configured approval hostname, port 793 below 1024, and an HTTPS reverse proxy controlled only by administrators | A secret typed into a page on another origin |
| Read a token from `gh` or git | The proxy adds the token, and the program never receives it | None found |
| Send a credential to another host | Injection for exact policy hosts only, upstream TLS verified, inner `Host` equal to the `CONNECT` host, port 443 only | A policy host whose response repeats the request headers |
| Forge or delete audit entries | On Linux, journald sets `_SYSTEMD_UNIT`. On macOS, the audit file is root-owned with the append-only flag and unreadable to your user | Root |

The proxy and, on Linux, the approval pages listen on loopback addresses and don't check the caller's user ID. On macOS the approval pages listen on a socket only `_bas` and root can open, and no firewall rule guards the proxy port. On a machine with other local users, add a firewall rule that lets only your user and `bas` connect to ports 3128 and 793, for example an nftables rule that matches `meta skuid`.

The proxy doesn't inspect responses. A host that echoes request headers can return the credential to the program, so keep `allow` patterns narrow.

Pending approvals live in the broker's memory and expire after 15 minutes. A restart drops them. Each approval accepts only an assertion over a challenge issued for the same request, and the first valid assertion uses up every challenge of the request. A forged answer gets `403`, and the request stays pending.

```text
on(POST /a/ID/finish)
  if Origin isn't approvals.origin
    403
  if the assertion doesn't verify against a challenge issued for ID, with user verification
    403, and the request stays pending
  clear every challenge of ID
  apply the change and mark ID approved
```

```sh
curl -s -X POST -H 'Origin: https://bas.TAILNET.ts.net' http://127.0.0.1:793/a/ID/begin > /dev/null
curl -s -X POST -H 'Origin: https://bas.TAILNET.ts.net' -H 'content-type: application/json' \
  -d '{"credential":{"id":"AA","rawId":"AA","type":"public-key","extensions":{},"response":{"authenticatorData":"AA","clientDataJSON":"AA","signature":"AA","userHandle":null}}}' \
  http://127.0.0.1:793/a/ID/finish
curl -s --unix-socket /run/bas/broker.sock http://localhost/v1/approvals/ID
```

The second command gets `403` with "no valid assertion", and the third still reports `pending`. Replace `ID` with the approval ID that `bas policy edit` prints.

The ssh-agent refuses ECDSA keys, because their signing code in the library the broker uses isn't constant time (RUSTSEC-2026-0387).

## Agent Access

Pairing lets a device ask for secrets, and each request needs an approval code or a grant. A revocation waits for deliveries that have started, and it can't recall a value already delivered. [Grants](../remote/grants.md) explains the order.

## Dependencies

The advisory check with `cargo-deny` passes with the exceptions that `deny.toml` lists, each with its reason.

| Advisory | Where | Why it is ignored |
|---|---|---|
| `RUSTSEC-2023-0071` | The RSA crate in the Bitwarden SDK | No patched RSA release exists, so the finding stays open |
| `RUSTSEC-2026-0459` | Bundled SQLite in the Bitwarden SDK | `bas` opens no SQLite file |
| `RUSTSEC-2026-0387` | `crypto-bigint`, used for ECDSA by the ssh-agent library | The broker's ssh-agent refuses ECDSA keys |

`cargo deny check licenses` fails, because `deny.toml` doesn't list any allowed licenses yet. The `bas` source is under the MIT license.
