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
