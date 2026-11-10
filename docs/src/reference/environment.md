# Environment variables

`bas` reads a few environment variables, and `bas run --with` sets a few in the program it starts.

## Variables bas reads

| Variable | Read by | Meaning |
|---|---|---|
| `BAS_CONFIG_DIR` | every command | Absolute path of the configuration directory, outside every Git repository |
| `BAS_STATE_DIR` | `bas run`, `bas env run` | Absolute path of the directory for `audit.log` |
| `BWS_ACCESS_TOKEN` | profiles made with `--from-env` | The machine token, read at each use |
| `BAS_BROKER_SOCKET` | `bas run --with`, `add`, `rotate`, `policy`, `passkey` | Path of the broker socket, instead of `/run/bas/broker.sock` |
| `BAS_BROKER_UNIT` | `bas audit` | Broker unit to read, instead of `bas-broker.service` |
| `VISUAL`, `EDITOR` | `bas policy edit` | Editor for the proposal, `vi` when neither is set |
| `CREDENTIALS_DIRECTORY` | `bas broker` | Set by systemd. The broker reads the machine token from the file `bws` in the directory. |

## Variables bas run removes

`bas run` and `bas env run` remove `BWS_ACCESS_TOKEN` and `AAC_TOKEN` from the program's environment, so the program can't use the machine token or an Agent Access token of the caller. The program inherits every other variable.

```diff
 environment of bas run
-BWS_ACCESS_TOKEN=...
-AAC_TOKEN=...
 PATH=...
 HOME=...
+API_TOKEN=value              with --env API_TOKEN=bas://work/<secret-id>
```

## Variables bas run --with sets

`bas run --with` points the program's HTTPS clients at the broker's proxy and its certificate bundle.

```text
HTTPS_PROXY          http://127.0.0.1:3128
https_proxy          http://127.0.0.1:3128
SSL_CERT_FILE        /run/bas/ca-bundle.pem
CURL_CA_BUNDLE       /run/bas/ca-bundle.pem
REQUESTS_CA_BUNDLE   /run/bas/ca-bundle.pem
NODE_EXTRA_CA_CERTS  /run/bas/ca-bundle.pem
GIT_SSL_CAINFO       /run/bas/ca-bundle.pem
```

The `gh` shim sets `HTTPS_PROXY` with the repository in the proxy user, `SSL_CERT_FILE`, and `GH_TOKEN=bas-proxied`, which is a placeholder because `gh` refuses to run without a token. The `ssh-keygen` shim sets `SSH_AUTH_SOCK=/run/bas/ssh-agent.sock`.
