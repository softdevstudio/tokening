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

# Stdio servers

An `mcp_stdio` target's command is started by the gateway for each allowed tool call, as the user running `tokening serve`, in the gateway's working directory. It does not inherit the gateway's environment. It gets PATH, HOME, USER, LOGNAME, SHELL, TMPDIR, TMP, TEMP, LANG, LC_ALL, LC_CTYPE and TZ when set, the Windows variables a process needs (SystemRoot, PATHEXT, ComSpec, USERPROFILE, APPDATA and the like), and the variables in the target's stored credential. The vault key, the admin token and every other TOKENING_ variable stay out.

A stdio credential file holds `{"env": {"NAME": "value"}}`. Names are upper case letters, digits and underscores, can't start with a digit, can't be one of the base names above and can't start with TOKENING_. Values can't contain NUL. `{"env": {}}` is valid, and a target with no stored credential runs with no extra variables.

Each call closes the server's stdin when it is done, waits up to two seconds for it to exit, then stops it and everything it started: on Unix its process group, on Windows a Job Object the server joins right after it starts. A process that deliberately leaves its group (setsid on Unix) or starts in the few milliseconds before the server joins its job on Windows can outlive the call. Calls have a 60-second deadline, start-up included, that holds even when a server stops reading. At most four servers per target run at once; further calls wait up to 30 seconds for a slot and then fail, spending their use like any failed forward. Messages from a server are limited to 1 MiB, the same limit as the HTTP adapter.

What the server can reach. It runs as the user running `tokening serve`, in the gateway's working directory, with that user's HOME. A filesystem server confined to one folder, as in the example, sees only that folder. A server with free-form paths, queries or shell commands can read whatever that user can, including vault.key, tokening.db, ~/.npmrc or other saved tokens. Grants narrow what the agent can ask the server for, not what the server process can do, so for servers like that, run Tokening as a separate operating system user whose files hold nothing else, keep the state directory out of any folder a server is given, and pin server versions (`@modelcontextprotocol/server-filesystem@2.1.0`, not a bare `npx -y` name) so an update can't change what runs. When a call fails, the gateway's log gets the cause and the end of the server's stderr. A server can print secrets there, so treat the log like the database.

# Connecting a stdio client

`tokening connect URL` relays a client that launches MCP servers as commands (Claude Desktop, many local agents) to the agent listener. URL is http(s)://host:port/mcp/target without credentials, query or fragment; plain http is accepted only for localhost and loopback addresses, since the grant would otherwise cross the network in clear. The grant secret comes from TOKENING_GRANT. Each line on stdin is one JSON-RPC message, posted with the grant as its bearer token; replies go to stdout one per line. A refusal from the gateway comes back as a JSON-RPC error whose message holds Tokening's code and reason. Notifications get no reply. The relay does not follow redirects or use environment proxies, and reports a gateway it can't reach on stderr and, for requests, as a JSON-RPC error. Messages are limited to 4 MiB; a longer line is dropped and answered with a JSON-RPC error whose id is null, because the relay can't read the id of a message it didn't read. Ctrl-C or the client closing stdin ends the relay.

# Admin API

Every request needs Authorization: Bearer with the admin token. Tokens have 32 to 512 non-whitespace characters and should be generated randomly. Responses use no-store. JSON writes reject duplicate keys and unknown fields and are capped at 1 MiB. Credential values are limited to 64 KiB. There is no cookie authentication.

POST /admin/targets accepts name and credential. GET /admin/templates returns the active template map. POST /admin/grants accepts template, uses, ttl (a duration string), args, query, issued_to, reason and issued_by. It returns HTTP 201 with grant and secret after the transaction commits. GET /admin/grants/{id} returns state and bounded decision history. POST /admin/grants/{id}/revoke accepts actor.

GET /admin/decisions accepts since (exclusive nonnegative ID), grant (optional ID filter) and follow=true (optional SSE). GET /admin/decisions.jsonl accepts since and grant and reports a successful complete snapshot with the Tokening-Export-Complete: true HTTP trailer. Check this marker when calling the API directly. A stream that closes early is incomplete even if its initial status was 200.

Explain remains a later-phase command. The Docker WordPress demo and read-only panel are implemented. Release archives and recorded results are described in docs/releases.md.

# Read-only panel and replay

Open http://127.0.0.1:8081/admin/panel on the operator machine. The HTML, CSS and JavaScript shell is public on the admin listener, but contains no grant or credential data. Enter the admin token and a grant ID to inspect that grant and poll its decisions. The page shows uses left, the expiry countdown and up to 200 recent records, including linked upstream outcomes. It cannot issue or revoke grants. The API still checks the admin bearer on every request.

The application keeps the token in page memory, clears the input after connecting and drops its reference on disconnect or page exit. It does not put the token in URLs, cookies, localStorage or sessionStorage. Browser extensions, saved passwords and a compromised operator browser remain outside that promise. Keep the admin listener outside the agent's network.

An optional --demo-replay /private/path/replay.json serves a verified schema-1 demo snapshot at authenticated GET /admin/demo. The panel shows its final WordPress post when the selected grant belongs to that snapshot. This is an operator-verified final snapshot, not a continuous upstream read. The server reads only this configured path; requests cannot choose a file. Missing or invalid snapshots return 503 without file contents. Unknown source fields are omitted by a typed projection.

Create a portable replay with tokening replay --input replay.json --output replay.html. The output file must be new. Use --input - or --output - for stdin or stdout. The exporter checks grant counters and completion links, keeps only its documented display fields, escapes JSON for HTML and embeds all CSS and JavaScript. The file works offline, has no credentials or external assets, and blocks network connections with a content security policy. It opens at step 0 and its controls (Play, Previous step, Next step) advance one actual audit record at a time, with a caption and the request the scripted agent sent. When the replay includes the posts recorded before the run, the post card follows the replay; the last step always shows the state verified after the run. Grant cards show each grant's lifetime from the recorded issue and expiry times, so reopening an old replay does not change its meaning. Add ?embed to the file's URL to hide its own header inside another page; it then posts only its height to the parent window so the frame can be sized.
