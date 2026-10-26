# Issuing and managing grants

The store now has internal Go methods for applying a policy, issuing a grant,
inspecting it and revoking it. The CLI grant commands use the separate admin
HTTP listener. These methods are only for the trusted admin side.

`ApplyPolicy(ctx, policy)` validates and snapshots the supplied policy, then
updates its active template set in one transaction. An unchanged template keeps
its version. A changed template gets a new version; historical versions remain
immutable. Removing a template stops new grants from using that name while its
existing grants keep their saved version. Reapplying a removed template can
activate its latest unchanged version again.

A target ID has a fixed kind, destination and credential reference. Changing
those properties under an existing ID is refused, so a policy reload cannot
silently redirect a live grant to a different upstream. Use a new target ID for
a different destination. Applying an unchanged target preserves its encrypted
credential. Targets and historical versions are retained when removed from the
current policy. New schema version 2 adds `active_templates`; databases from
schema 1 keep their data, but need a policy applied before issuing new grants.

`IssueGrant(ctx, request)` needs an active template name, a positive use count,
a positive TTL in whole milliseconds, argument/query bindings, an issuing actor,
a recipient label and a reason. Uses and TTL cannot exceed the template limits.
Metadata must be nonempty UTF-8; actor and recipient labels are limited to 256
bytes and the reason to 4096 bytes. Binding values must satisfy their scalar
constraints. Only fields declared for issue-time binding may be bound. Required
bindings, including hash rules, cannot be omitted.

A grant ID contains 16 random bytes. Its bearer secret contains 32 independent
random bytes, encoded as a `tkn_` string. The issuer stores only a SHA-256 hash of
that complete string. It returns the secret in the issuance reply after commit;
no inspection method can retrieve it later. Diagnostic formatting of the secret
is redacted, but issuance JSON intentionally includes it. Do not log that reply.
A commit error returns neither a grant nor a secret. Do not automatically retry
an uncertain issuance commit, since the row may already be durable.

Hash-bound string values are checked against their normal string constraints,
then converted to a SHA-256 digest before being passed to SQLite. Their supplied
plaintext is absent from the persisted binding and inspection response. Normal
scalar bindings are copied, so later changes to the request cannot alter them.
An issued grant does not prove the upstream tool or credential works; those are
separate operational checks.

`InspectGrant(ctx, id)` returns scope, saved template version, bindings, allowance
and expiry, with issuer/revocation metadata. It returns the total decision count
and up to the latest 100 decisions, newest first. Use [audit export](audit.md) for the full decision history. It does not select the bearer
hash, plaintext bearer secret or upstream credential. State is `issued` before
first use, `active` after a use when some remain, or `exhausted`. Revocation takes
precedence over expiry, and expiry over exhaustion in the displayed state.

`RevokeGrant(ctx, id, actor)` serializes with consumption and is idempotent.
Repeated revocation preserves the first actor and timestamp. If revocation wins
the transaction order, consumption is refused without decrement. If consumption
commits first, that call remains authorized and later calls are refused.

Tests exercise narrowing, invalid bindings, state changes, hidden secrets and
hash-bound plaintext, policy versions/removal and failed reload rollback. They
also test schema upgrades, REST grants, failed issuance commits, bounded audit
history and concurrent revocation versus consumption. The existing 1,000-run
single-use race and crash recovery tests still run through the same transaction
implementation.
