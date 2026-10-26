# Running Tokening

Tokening runs an agent listener and a separate admin listener in one process. Keep the real upstream credential, vault key and admin token outside the agent's environment. Agents get only grant secrets. Anyone who can reach an upstream with its real credential can bypass Tokening.

Build with make build. The binary is bin/tokening. Create a private working directory and save two different random secrets before starting the server:

```sh
umask 077
mkdir tokening-state
cd tokening-state
/path/to/tokening keygen > vault.key
/path/to/tokening keygen > admin.token
export TOKENING_ADMIN_TOKEN="$(cat admin.token)"
/path/to/tokening serve --policy /path/to/tokening.json --db tokening.db --key-file vault.key
```

keygen prints a random base64 key. Run it separately for the vault and the admin token. Keep vault.key available across restarts and backups; replacing it makes existing credentials unreadable. TOKENING_VAULT_KEY can supply the vault key instead of --key-file. Configuring both is an error. Neither key nor token is generated silently at startup.

The defaults are 127.0.0.1:8080 for agents and 127.0.0.1:8081 for operators. --agent and --admin change these addresses. Both ports bind before either serves traffic; a bind failure closes the other port. The listeners speak HTTP. Use a private network or a TLS reverse proxy for remote access, and keep the admin address unreachable by agents. --origins accepts comma-separated exact browser origins on the agent listener. The admin API rejects all Origin headers and does not enable CORS.

On Unix, SIGHUP reloads the policy file. A failed load or transaction leaves the old active templates in place. Successful reloads affect new issuance only; live grants retain their saved versions. A target ID cannot be redirected to a different upstream. Use a new ID. Windows operators restart the server to load a new policy. Interrupt or SIGTERM stops both listeners with a bounded drain before closing the store.

# Operator commands

The CLI uses the admin API. It never opens the database for grant commands or reads the vault key. Set TOKENING_ADMIN_TOKEN in the operator environment. TOKENING_ADMIN_URL defaults to http://127.0.0.1:8081 and can name another HTTP(S) origin. The client does not follow redirects, use environment proxies or retry requests. After an interrupted issuance response, inspect any returned grant ID before issuing another grant. A lost secret cannot be recovered.

Store a credential for a target already declared in the policy. The credential file is JSON: basic uses username and password, bearer uses value, and header uses name and value. The upload is validated, encrypted and acknowledged without echoing the credential. There is no credential read endpoint.

```sh
tokening target add demo-wp --cred-file wordpress-credential.json
tokening template list
tokening grant issue wp.edit-post-text \
  --bind id=2 --uses 1 --ttl 15m --to editor-bot \
  --by operator --reason "fix title"
```

Issuance prints a JSON object containing grant metadata and the secret. Save the secret only where the agent needs it. Inspection and revocation never return it:

```sh
tokening grant inspect g_ID
tokening grant revoke g_ID --by operator
tokening log --since 0
tokening log --follow --since 0
tokening log --export --grant g_ID > decisions.jsonl
```

--bind and --query-bind are repeatable name=JSON options. Numbers stay numbers; quote a string value as --bind 'slug="introduction"'. Repeated names are errors. --ttl is a Go duration such as 15m. Uses and TTL must fit the active template. Issuance needs --to and --reason; --by defaults to operator. The API records the supplied actor as operator metadata, not as a separately authenticated identity.

log returns up to 100 records after an exclusive ID cursor. --follow returns an SSE stream; events include record IDs and can be resumed with --since. --export writes a fixed-boundary JSONL snapshot. Its completion trailer is checked by the CLI; a missing marker or interrupted body returns an error. Keep only complete JSONL records and resume from the last complete ID after a failed export. Arguments and upstream response bodies are not part of the audit export.

Run tokening doctor inside the agent's environment. It reports common credential variable names, never values. It exits 1 when any listed credential variable is visible. It cannot inspect another process or discover every possible credential source. Operator shells are expected to contain their own admin credentials; do not hand that environment to the agent.

# Admin API

Every request needs Authorization: Bearer with the admin token. Tokens have 32 to 512 non-whitespace characters and should be generated randomly. Responses use no-store. JSON writes reject duplicate keys and unknown fields and are capped at 1 MiB. Credential values are limited to 64 KiB. There is no cookie authentication.

POST /admin/targets accepts name and credential. GET /admin/templates returns the active template map. POST /admin/grants accepts template, uses, ttl (a duration string), args, query, issued_to, reason and issued_by. It returns HTTP 201 with grant and secret after the transaction commits. GET /admin/grants/{id} returns state and bounded decision history. POST /admin/grants/{id}/revoke accepts actor.

GET /admin/decisions accepts since (exclusive nonnegative ID), grant (optional ID filter) and follow=true (optional SSE). GET /admin/decisions.jsonl accepts since and grant and reports a successful complete snapshot with the Tokening-Export-Complete: true HTTP trailer. Check this marker when calling the API directly. A stream that closes early is incomplete even if its initial status was 200.

Explain, the demo panel and the Docker WordPress demonstration are still pending. Stdio upstreams belong to the later MCP integration phase. This development build has not been released.
