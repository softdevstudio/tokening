# Spending a grant use

The store's `Consume(ctx, secret, call)` method is the authorization boundary for
forwarding. A caller may forward only when the returned decision is allowed and
the returned error is nil. Matching a grant in memory is not enough.

Consumption reserves a database connection and starts an immediate transaction.
SQLite takes the write lock before the grant is read. The bearer secret is hashed
with SHA-256 and looked up by hash; a grant ID alone cannot authorize a call.
The stored template version and bindings are loaded, then checked by the matcher.
The consumer samples server time after acquiring the lock and checks expiry
again after matching, just before decrementing.

The update requires a positive allowance, an expiry later than the current time
and no revocation. The same transaction writes the authorization decision. Both
writes must commit before the caller gets permission to forward. Refusals are
also recorded, with no counter change. Unknown secrets produce a refusal whose
audit row has a null grant ID. The row records a digest of the normalized call,
not the bearer secret or body/query argument content. REST actions record method and
path in the action column.

The template's `constraints_json` column contains `args`, `query` and
`additional_args`. Target, tool, method, path and maximum allowance are held in
other template columns. A grant's binding columns contain matcher binding
objects, for example `{"id":{"value":2}}`. The [grant issuer](grants.md) now writes these snapshots. The consumer does not issue grants.

A match refusal does not spend a use. An audit-insert failure rolls back the
decrement. Any commit error fails closed. SQLite can leave a transaction open
after a failed commit, so the consumer discards that reserved connection before
it can return to the pool. A caller must not retry automatically after an
uncertain commit: the use may already be durable.

If a process dies before commit, SQLite recovery discards the uncommitted
counter change and audit row together. If it dies after commit, the use stays
spent even if forwarding never started. Upstream failures also leave the use
spent. For a one-use grant this gives an at-most-once permission allowance; it does not guarantee
that the upstream operation happened.

Revocation and consumption serialize through the same database. A revocation
that commits first prevents the reservation. Once consumption commits, later
revocation cannot cancel that already authorized call; it blocks subsequent
reservations. The [REST gateway](gateway.md) now preserves this boundary when forwarding.
Adding a template version does not change the version referenced by a live grant.

Tests race two independent SQLite connections on each of 1,000 one-use grants,
checking one allowed decision and one exhausted refusal per grant. Crash tests
kill a child process after the real decrement and audit write, before commit,
and after a completed consumption commit. Other tests inject audit and commit
failures, check expiry after matching, and check queued revocation and expiry.
The JSONL test script records the race counts in `test/results/local/tests.jsonl`
and CI preserves that file as an artifact. Cached test results are disabled.

The REST handler and forwarder now have integration tests for saved policy versions and a real in-flight upstream request. MCP and running listeners are wired, with integration tests and the Docker demonstration.
