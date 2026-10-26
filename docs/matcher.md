# Permission matching

The internal matcher is a pure function: `Match(grant, call, now)`. It reads an
issued grant snapshot and a normalized call, and returns a decision. It does not
read credentials, talk to an upstream or change a counter. The database consumer
must atomically recheck state and spend a use before any call is forwarded.

A nil grant returns `grant_unknown`. Corrupt snapshots return an error; callers
must fail closed on that error. Revocation and expiry are checked first. Expiry
is exclusive: a grant is expired at its exact expiry time. Then the matcher checks
the target, action and arguments. Exhaustion is checked after scope, so an attempt
to edit a different post can still explain the wrong post after the legitimate
edit has spent the grant. Refusal ordering and argument names are deterministic.

Bindings live in the grant, alongside the saved template version. A binding is
an object with `value` containing a JSON scalar, or `sha256` containing a lowercase
hex digest. Required bindings must exist. Optional bindings may be absent, but
once bound they must be present in every call and match. Hash rules always need
an issued hash binding, including when the template says `bind: optional`.
Hash comparisons use decoded UTF-8 strings and constant-time digest comparison.
The matcher does not include supplied argument values or hashes in its reasons.

JSON scalar types are preserved: the string `"2"` differs from the number `2`.
JSON numbers compare exactly, so `1`, `1.0` and `1e0` are equivalent in JSON fields.
Integer rules accept any mathematically integral JSON number. To keep untrusted
exact arithmetic bounded, number tokens have at most 256 characters and exponents
between -1024 and 1024. Policy numeric bounds use the same representation and
retain their original precision. Unsupported numbers are refused.

String lengths count Unicode code points, while byte limits count UTF-8 bytes.
Regular expressions match the entire string, even with multiline flags.
Invalid UTF-8 and lone UTF-16 surrogate escapes are refused rather than silently
replaced. Declared fields must be non-null scalars. Unlisted fields are refused
unless `additional_args` explicitly allows them; allowed extra fields may contain
any valid JSON. Bound fields cannot be omitted to bypass their restriction.

REST calls have a decoded path without percent escapes, query text, backslashes,
control characters, repeated slashes or dot segments. Each path placeholder is
extracted and checked against its binding. Numeric and boolean path segments
must retain the exact spelling of the binding; a path bound to `2` does not allow
`2e0` or `2.0`, since a router could treat those strings as different resources.
A body field that repeats a path argument must agree with it. Query constraints
use a separate namespace, so a body field cannot satisfy a required query binding.

A future transport adapter must reject duplicate argument keys and repeated
query values before constructing a call. It must preserve scalar types and pass
the same normalized request to the matcher and forwarder. Raw JSON decoding,
upstream discovery and bearer-secret lookup are outside this package.

The `upstream_error` helper describes a call that was authorized and forwarded
but then failed. Its authorization flag remains true; its code records the
failure, and the use remains spent. It cannot refund or retry the operation.

The matcher is not connected to a listener yet. The next step is the atomic
SQLite consumer, including the parallel single-use test.
