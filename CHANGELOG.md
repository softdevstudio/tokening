# Tokening v0.1.4

A small fix release for `tokening flight verify`, from the flight recorder case studies. Grant checking, consumption, credentials, the log format and the database schema are unchanged. Logs written by v0.1.2 and v0.1.3 verify with v0.1.4.

- `flight verify --head ""` used to treat an empty head as no head, skip the check and exit 0. A script running `--head "$(tail -n 1 heads.txt)"` with an empty heads file passed without checking anything. A `--head` that is given must now be a valid SEQ:HASH: an empty, blank or malformed value is a usage error (exit 2) with a message saying so, checked before the database or file is opened.
- When the chain does not match a saved head, verify no longer prints "Entries 1 to N verify. Last good head" for entries a rebuild could have rewritten. It says the chain does not match the saved head, that the earlier entries link to each other but so would a rebuilt chain, and that entries after the last point matching a saved head cannot be trusted.
- A log shorter than a saved head, or than the database counter, is no longer described as "entries were removed from the end". A cut-off log and a chain rebuilt without some entries in the middle look the same from the evidence, so the message now reads "entries were removed, or the chain was rebuilt shorter".
- The MCP gateway reported version 0.1.1 in serverInfo, and to upstream servers in clientInfo, since v0.1.1. Both now report the real build version, which is written in one place (`internal/version`) and read by the binary, the gateway and the release workflow.

The review is in docs/review-v0.1.4.md. It is a project source review, not an external security audit.

Download the archive for your operating system and architecture, verify it against SHA256SUMS and read README.md inside it. Archive names have no version, so latest/download links keep working.

Licence: Apache 2.0. Third-party notices are included in every archive.

# Tokening v0.1.3

A bug-fix release for the flight recorder, after an independent review of the v0.1.2 code. Grant checking, consumption, credentials and the database schema are unchanged. Logs written by v0.1.2 verify with v0.1.3.

- `flight verify --file` and `flight replay --file` now accept only lines that are exactly what `flight export` writes. Before, a line with a repeated key, a key in other letter case or extra spaces still verified. A reader that takes the first of two repeated keys, or a plain text search, could then see a value that verify never checked.
- `flight replay --file` no longer says "Chain intact" when entries are missing from the file. It says how many are missing, since that can be a filtered export or a removal, and points to verifying the whole log.
- An agent could send a tool name or argument names that, once written as JSON, made one request entry longer than the 1 MiB line limit, so the export could not be verified or replayed from a file. The action and target are now cut to 256 bytes, and at most 100 argument names of up to 128 bytes are kept, with a count of the rest. The digest still covers the whole call.
- Replay now quotes tool names, paths and names that contain spaces of any kind, including no-break and wide spaces, so agent-chosen text cannot read as part of the replay sentence.
- docs/flight.md now says plainly that the argument and binding digests have no secret key, so short or guessable values can be found by trying candidates.

The review is in docs/review-v0.1.3.md. It is a project source review, not an external security audit.

Download the archive for your operating system and architecture, verify it against SHA256SUMS and read README.md inside it. Archive names have no version, so latest/download links keep working.

Licence: Apache 2.0. Third-party notices are included in every archive.

# Tokening v0.1.2

This release adds the flight recorder. Grant checking, consumption and credential handling are unchanged from v0.1.1.

Tokening already decided every call and kept an audit row for it. Now every grant issue and revocation, every request, every decision and every upstream result also goes into an append-only log where each entry carries the SHA-256 hash of the one before it. An edited, deleted, reordered or cut-off entry breaks the chain, and `tokening flight verify` names the first broken entry and why. The entries are written in the same SQLite transaction as the change they describe, so a crash leaves a log that verifies up to its last complete entry. Concurrent writers, in one process or several, cannot fork the chain.

New commands, all reading the database file without changing it:

- `tokening flight verify` checks the database log, or an exported file with `--file`. `--head SEQ:HASH` proves a head saved earlier is still in the chain. `--partial` accepts filtered exports.
- `tokening flight head` prints the last entry's seq and hash, to keep somewhere the database owner cannot rewrite.
- `tokening flight export` writes JSONL, filtered by `--agent`, `--grant`, `--since` and `--until`.
- `tokening flight replay` prints what an agent did, in order, and whether the chain is intact.

Entries hold argument names and a digest of each call. They never hold argument values, credentials, grant secrets or response bodies. A hash chain cannot stop someone who can rewrite the whole database file; a head saved outside it can show that it happened. See docs/flight.md for the entry format, the hash and these limits.

The database moves to schema 4 the first time v0.1.2 starts with it. History from before the upgrade stays in the decisions table and is not part of the chain. test-results.json now includes the measured flight recorder results from the tamper, concurrent-writer and kill-mid-write tests, and the archive smoke check verifies and replays a real flight log.

Download the archive for your operating system and architecture, verify it against SHA256SUMS and read README.md inside it. Archive names have no version, so latest/download links keep working. The limits listed for v0.1.0 still apply: the MCP agent profile is 2025-06-18, responses are buffered to 1 MiB, and stdio targets, OAuth server duties, rate limiting and vault key rotation are outside this release. The review recorded for this release is a project source review, not an external security audit.

Licence: Apache 2.0. Third-party notices are included in every archive.
