# v0.1.2 release review

Date: 2026-10-31. Reviewer: a second, separate pass by Claude over the full diff from v0.1.1 (742bf7b) to the release candidate, read after the implementation was finished and its CI was green. No separate review agent could be started from this session, so this is a fresh-eyes self-review, not an independent one. It is a source review and project release check, not an external security audit. ChatGPT/Codex or a later session may review it again; findings go in a new section below.

Scope: `internal/flight` (hash, JSONL, verifier, replay text), `internal/store/flight.go` and migration 004, the appends in grant issue and revoke, consume and upstream completion, the `tokening flight` commands, the release evidence parsing and smoke check, CI annotations and the docs.

Checked and found sound:

- Every append runs inside the transaction that makes the change, after SQLite's immediate write lock is taken, so a request and its decision cannot be split and two writers cannot link to the same entry. A failed append rolls back the decision and the use (tested).
- No credential, bearer secret, bearer hash or argument value reaches an entry. Requests carry argument names and the call digest already stored in decisions; grant entries carry binding names and a digest. Export tests search for the secret and an argument string.
- The hash covers seq, time, kind, agent, grant, body and prev with length prefixes, so fields cannot be shifted into each other. Bodies are hashed and exported byte for byte; the JSONL round trip is exact.
- Read-only open never creates a file or migrates, and a write through it fails (tested).
- After a tail deletion, appends continue past the AUTOINCREMENT counter, so the gap stays visible.

Findings and fixes:

1. Should fix. The replay printed agent, issuer and argument names as given. `issued_to` accepts any non-blank UTF-8, so a newline or terminal escape in a name could make a fake replay line. Names are now quoted when they hold spaces, quotes or non-printing characters, and other text is quoted when it holds control characters. Test added.
2. Note. `tokening flight` with no subcommand printed usage to standard output while exiting 2. It now goes to standard error, like other usage errors.
3. Docs. The flight reference said every request is recorded. MCP `initialize`, `tools/list`, `ping`, `GET /grant` and requests rejected before matching are not recorded, the same as the decisions table, and a result entry can be missing if the database fails after forwarding. The reference now says so.

Open notes, none blocking: there is no admin API route for flight export yet, so remote operators need file access to the database; a saved head protects only up to the point it was taken, which the docs state.

Results after the fixes are recorded by CI on the release candidate and copied into the release's test-results.json.
