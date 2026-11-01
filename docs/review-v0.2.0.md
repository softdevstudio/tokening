# Review of v0.2.0: stdio MCP targets and tokening connect

Reviewed 2026-11-01 by a separate Claude agent that did not write the code, against 31148c2..2bc48c3, with its own adversarial tests (a server that stops reading, floods requests, holds pipes from a grandchild, floods stderr; id forms; partial lines). Fixes are in the commit after this review; each finding below is fixed, documented or left with a reason.

## Blocker

- The example policy `examples/claude-desktop/tokening.json` was never committed: `.gitignore` had an unanchored `tokening.json`. The rule is now `/tokening.json` and the file is in the repo; the release smoke check validates it.

## Should fix

1. The 60-second deadline did not hold while a write to the server was blocked (a server that stops reading, or floods requests that each need an answer). A deadline watcher now closes stdin and stops the server. Test: `TestDeadlineWhileWriting`; the reviewer's two repros return at the deadline.
2. No cap on concurrent servers: a grant with many uses could start that many at once. Now four per target; further calls wait up to 30 seconds, then fail.
3. Docs did not say what a server process can reach. docs/server.md now says it runs as the gateway's user with that user's files, and recommends a separate user, a state directory outside any served folder and pinned versions.
4. On Windows, npx servers (node under cmd.exe) were not stopped. The server now joins a kill-on-close Job Object; the grandchild test runs on Windows CI too. The milliseconds between start and joining the job are documented.
5. The example ran an unpinned `npx -y`. Pinned to `@modelcontextprotocol/server-filesystem@2.1.0`.
6. `tokening connect` ignored Ctrl-C. SIGINT keeps its default action now.

## Minor

- Plain http to a non-loopback gateway is refused by `tokening connect` (the grant would cross the network in clear).
- Server messages are limited to 1 MiB, the same as the HTTP adapter (was 4 MiB).
- A process that calls setsid leaves the group and can outlive a call: documented.
- Server stderr can reach the operator log: documented.
- An oversized line to the relay is answered with id null, because its id is unread: documented.
- Process group kill after the leader was reaped has a small PID reuse window; the group id is the leader's PID, and the kill happens right after it exits. Left as is.
- tools/list gives arguments no descriptions. Left for a later release.

## Fine as reviewed

The vault key, admin token, other TOKENING_ variables and loader variables never reach the server; Windows names are compared without case. Agent input never reaches argv. The agent only ever sees the fixed failure text. initialize, ping, tools/list and notifications never start a process, and a refused call never starts the server. mcp_http and mcp_stdio can't be confused. Duplicate keys, id forms, partial lines at end of input, non-object results, server requests and notifications, and a 50 MB stderr flood are handled. Against the real filesystem server, `read_text_file` with `path` bound restricts the agent to that one file.
