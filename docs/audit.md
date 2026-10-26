# Audit records and JSONL export

Authorization decisions are stored with use consumption in the same transaction.
A call that is allowed reserves its use and writes an allowed decision before
forwarding. A refused call writes a refusal without consuming. Unknown tokens
have a null grant ID. Updates and deletes on the decisions table are refused by
SQLite triggers. Failed transactions leave neither a decrement nor a partial
authorization record.

The internal store now provides `ListDecisions(ctx, filter, limit)` and
`ExportDecisions(ctx, writer, filter)`. They are for the trusted admin side. The
admin HTTP routes, CLI export command and SSE transport use these methods.
The list method provides bounded pages for polling and the authenticated SSE stream.

A filter has an exclusive `AfterID` cursor and an optional `GrantID`. Zero starts
at the beginning; negative cursors are errors. Lists are ordered by ascending
record ID, with a default of 100 records and a maximum of 1000. Record IDs, rather
than timestamps, define cursor order, even if the system clock moves backwards.
An unknown grant filter returns an empty result.

Each exported line is a complete JSON object with `id`, `grant_id`, UTC `at`,
`agent`, `action`, `args_digest`, `outcome`, `code`, `reason`, `upstream_status`
and `latency_ms`, plus nullable `authorization_id` linking an upstream completion to its original authorization. The digest is lowercase SHA-256 hex. Nullable fields remain
JSON null. A method and path identify a REST action; an MCP action is its tool
name. The export selects audit columns only. It does not select bearer hashes,
secrets, credential ciphertext, bindings or upstream response bodies. Action
paths and readable reasons are still operational metadata, so exports belong on
the admin side.

An export captures the largest committed ID at its start as `ThroughID`. It
then reads at most 256 records per page, closes the query, and only then writes
the page to the caller. New decisions can continue to commit while a slow writer
receives the output. Their higher IDs belong to the next export. Append-only
records below the captured boundary remain stable across page reads.

The result reports the number of fully written records, the last fully written
ID and the captured upper ID. After a successful export, resume with
the greater of `LastID` and `ThroughID` as `AfterID`, keeping the same grant
filter. This advances past nonmatching records in a filtered export and keeps
a cursor ahead of the current log from moving backwards. On an error, do not advance to the
upper ID. The writer may have received a partial final line. Discard that
incomplete line before resuming after `LastID`, or discard and recreate the
partial export. Short writes without an error are detected as failures.

Cancellation is checked before each page and record write. It cannot interrupt
an arbitrary blocking `io.Writer` by itself; the transport must unblock its own
writer when the client disconnects. No database connection is held during a
writer call. Exporting does not mutate decisions, grant counters or credentials.

Authorization rows have null upstream status and latency. The [REST forwarder](gateway.md) now appends a linked completion record with outcome metadata; it does not modify the original authorization. Only one completion is allowed per authorization. A completed export is
not proof that an authorized upstream write succeeded. This is also an
append-only application log, not a tamper-evident system against someone who can
rewrite the database or remove its triggers.

Tests cover multiple pages, cursor/filter behavior, optional upstream metadata,
empty exports, cancellation, short writes and writer errors. A callback writer
creates a new decision through the same one-connection store to check that the
export releases its connection and keeps its initial upper boundary. Secrecy
tests check that a real issued bearer secret, its hash, a stored upstream
credential and body content are absent from exported output.
