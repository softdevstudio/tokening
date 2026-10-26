# Tokening

Narrow permissions for AI agents.

Tokening sits between an agent and an API and issues grants for single actions: update this post, once, title and body only, within fifteen minutes. Every call is checked against its grant. Refusals include a machine code and a reason a person can read.

The real upstream credential must stay in Tokening, outside the agent environment. The admin listener must also be unreachable by agents. A grant cannot prevent bypass if the agent already has the real credential.

This is a development build, not a release. It runs as one Go binary with a SQLite database. MCP HTTP and REST forwarding, encrypted credentials, grant commands and audit export are implemented. The Docker WordPress demo runs with make demo. A read-only admin panel and offline visual replay are implemented. Release checks are still pending. The approved scope is in [the plan](docs/plan.md).

## Build and run

Build with Go 1.23 or newer:

```sh
make test
make build
bin/tokening check examples/wordpress.json
```

Create a private state directory and use different random secrets for the vault and the admin API:

```sh
umask 077
mkdir tokening-state
cd tokening-state
/path/to/tokening keygen > vault.key
/path/to/tokening keygen > admin.token
export TOKENING_ADMIN_TOKEN="$(cat admin.token)"
/path/to/tokening serve --policy /path/to/tokening.json --db tokening.db --key-file vault.key
```

The agent listener defaults to 127.0.0.1:8080 and the admin listener to 127.0.0.1:8081. The listeners speak HTTP. Keep them local or use private networking and a TLS reverse proxy. Save the vault key alongside secure backups, outside the database. See [running Tokening](docs/server.md) for listener options, policy reloads, the admin API and shutdown behavior.

## Issue a grant

The operator CLI talks to the admin port. It uses TOKENING_ADMIN_TOKEN and, optionally, TOKENING_ADMIN_URL. First declare a target and template in the policy. Then store the real credential in the vault and issue a narrower grant:

```sh
tokening target add demo-wp --cred-file wordpress-credential.json
tokening template list
tokening grant issue wp.edit-post-text \
  --bind id=2 --uses 1 --ttl 15m --to editor-bot \
  --by operator --reason "fix title"
```

Credential files contain JSON, such as {"username":"operator","password":"application-password"} for a basic-auth target. The upload reply never echoes the credential. Issuance returns JSON with grant metadata and its secret. Only that secret goes to the agent. Inspection and revocation never return it again:

```sh
tokening grant inspect g_ID
tokening grant revoke g_ID --by operator
tokening log --follow
tokening log --export > decisions.jsonl
```

The agent sends its grant in Authorization: Bearer to POST /mcp/{target}, /http/{target}/... or GET /grant. MCP tools/list is derived from the saved grant. Tool calls and REST calls consume a use in the same SQLite transaction as the authorization record, before forwarding. Upstream failures still spend the use. Neither the server nor the CLI retries writes automatically.

Run tokening doctor in the agent environment to look for common credential variable names. It reports names only, cannot find every credential source and cannot inspect another process.

## Read-only console

Open http://127.0.0.1:8081/admin/panel on the operator machine and enter the admin token and a grant ID. The panel shows grant state, expiry and recent decisions. The token stays in page memory. Export a verified demo JSON artifact with tokening replay --input replay.json --output replay.html for an offline visual replay.

## Docker demonstration

Run make demo with Docker Compose v2 and Python 3 installed. It creates a disposable WordPress stack, runs the deterministic seven-step agent script and checks the actual posts and audit records. The agent receives only grant secrets and cannot connect to WordPress or the admin port. No public site is used. The project volumes are removed after the run. See [the demo guide](demo/README.md) for diagnostics and replay artifacts.

## Reference

The [policy reference](docs/policy.md) covers templates and constraints. The [matcher](docs/matcher.md) is pure; the [consumer](docs/consumer.md) handles atomic use reservations. [Storage](docs/storage.md), [vault](docs/vault.md) and [grants](docs/grants.md) describe persistence and credential custody. [Audit](docs/audit.md) covers JSONL cursors and partial exports. The [REST gateway](docs/gateway.md) and [MCP adapter](docs/mcp.md) describe the forwarding boundaries and transport limits.

Licence: Apache 2.0.
