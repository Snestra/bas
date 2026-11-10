# Files and directories

`bas` keeps its settings in your configuration directory and its run log in your state directory. The broker adds root-owned files under `/etc` and `/usr/local`, and its own files under `/var/lib/bas` and `/run/bas`.

## Files of your user

```text
~/.config/bas/              BAS_CONFIG_DIR, mode 0700, outside every Git repository
├── config.toml             profiles and paired device fingerprints
├── grants.toml             grants for paired devices
├── policy.lock             orders changes to grants and profiles
└── policy.toml             broker policy proposal, on a broker host

~/.local/state/bas/         BAS_STATE_DIR
└── audit.log               one JSON line per bas run binding, never a value
```

The configuration directory and the state directory depend on the platform.

| Platform | Configuration directory | State directory |
|---|---|---|
| Linux | `~/.config/bas` | `~/.local/state/bas` |
| macOS | `~/Library/Application Support/bas` | `~/Library/Application Support/bas` |
| Windows | `%APPDATA%\bas` | `%LOCALAPPDATA%\bas` |

Machine tokens and Agent Access keys live in the OS credential store, never in the configuration or state directory.

## Files of the broker

| Path | Owner and mode | Holds |
|---|---|---|
| `/usr/local/bin/bas` | root, 0755 | The program, for the CLI and the broker |
| `/etc/systemd/system/bas-broker.service` | root, 0644 | The unit |
| `/etc/bas/broker.toml` | root, 0644 | Settings for this machine |
| `/etc/credstore.encrypted/bas-bws.cred` | root, 0600 | The sealed machine token |
| `/usr/local/lib/bas/shims/gh`, `ssh-keygen` | root, 0755 | Shims, which hold no secrets |
| `/etc/ssh/ssh_config.d/10-bas.conf` | root, 0644 | Points `ssh` at the broker's agent |
| `/etc/gitconfig` | root, 0644 | `gpg.ssh.program` for commit signing |
| `/var/lib/bas/policy.toml` | bas, 0600 | The active policy |
| `/var/lib/bas/passkeys.json` | bas, 0600 | Public keys of the enrolled passkeys |
| `/var/lib/bas/enroll-url` | bas, 0600 | The first enrollment link, while no passkey is enrolled |
| `/var/lib/bas/ca.key`, `ca.pem` | bas, 0600 and 0644 | The proxy's certificate authority |
| `/run/bas/broker.sock` | bas, 0666 | The socket API, caller uid checked |
| `/run/bas/ssh-agent.sock` | bas, 0666 | The ssh-agent, caller uid checked |
| `/run/bas/ca-bundle.pem` | bas, 0644 | The system roots plus the proxy's authority |

## broker.toml

`/etc/bas/broker.toml` holds the settings that belong to one machine and never sync. `contrib/linux/broker.toml.example` is a commented copy.

| Key | Required | Default | Meaning |
|---|---|---|---|
| `allow-uids` | yes | | User IDs that may use the socket API and the ssh-agent |
| `proxy` | no | `127.0.0.1:3128` | Address of the proxy, which must be a loopback address |
| `[profile]` `name` | yes | | Profile name used in policy references |
| `[profile]` `organization` | yes | | Organization ID of the machine token |
| `[profile]` `api-url`, `identity-url` | yes | | Secrets Manager endpoints |
| `[profile]` `project` | no | | Project where `bas add` creates secrets. Without it, `bas add` is refused. |
| `[approvals]` `listen` | no | `127.0.0.1:793` | Address of the approval pages, which must be a loopback address |
| `[approvals]` `origin` | yes | | HTTPS origin of the approval pages, with no path, such as `https://bas.TAILNET.ts.net` |
