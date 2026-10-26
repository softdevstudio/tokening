# Agent HTTP gateway

The internal `gateway.New(store, vault, options)` handler now serves REST requests
at `/http/{target}/...` and self-description at `GET /grant`. The running server
also serves the MCP handler and operator API. Both listeners bind to localhost
by default, with admin routes kept on a separate port. See [running Tokening](server.md).

Requests present exactly one `Authorization: Bearer <grant-secret>` header.
Query tokens, cookies and duplicate authorization headers are not accepted as
authentication. Known grants retain their saved permission version. A missing or
unknown bearer receives 401; scope, expiry, exhaustion and revocation refusals
receive 403. Malformed input is rejected before attempting forwarding. Missing
headers and malformed transport messages are not normalized permission calls;
unknown bearer attempts on a REST route record a route-level refusal.

`GET /grant` returns the holder's saved scope, argument rules and bindings,
remaining allowance, expiry and a readable description. It does not consume a
use, expose issuer/audit history, or return a credential or bearer hash. A holder
can also read terminal state, such as exhausted or revoked, to understand why the
grant can no longer forward calls.

REST request bodies are single UTF-8 JSON objects, limited to 1 MiB. Duplicate
keys, encoded request bodies and nesting beyond 64 levels are refused. Paths
must be plain, without percent escapes or repeated slashes; the matcher also
rejects traversal. Query parameters cannot repeat, shadow a path argument or
also appear in the body. `_method` overrides are refused. Numeric and boolean
query values use their declared scalar type; unspecified query rules are treated
as strings and remain subject to the template's additional-argument rule.

The same parsed object and query used by the matcher are re-encoded for the
upstream request. A successful consume transaction must commit before any
credential is decrypted or any upstream request is sent. A later failure never
refunds a use. Decryption, destination lookup or credential-format errors after
reservation return 502 with a generic reason and leave the use spent.

The target URL supplies a fixed HTTP(S) base path. Its query, fragment, embedded
credentials and percent-encoded base path are unsupported. The request path is
appended to that base. Agent headers cannot select another host or override the
method. Only `Accept` and standard conditional request headers are passed on;
body requests use `application/json`. Incoming authorization, cookies, proxy
headers and method-override headers are not forwarded.

Stored credentials are JSON objects encrypted by the vault. A `basic` credential
has `username` and `password`; `bearer` has `value`; `header` has `name` and `value`.
Unknown or duplicate fields, empty values and invalid header names/values fail
closed. Protocol/routing headers such as Host and Content-Length cannot be used
as credential headers. The forwarding code injects the real credential only
into its own upstream request and clears the decrypted byte buffer afterward.

The HTTP client does not follow redirects, use environment proxy settings, or
reuse connections. Bodies are non-replayable. These choices prevent automatic
transport retries from replaying an action. Dial/TLS/header timeouts are bounded,
and the full upstream operation has a 60-second timeout in this first handler.
A redirect response is returned to the agent without following its destination.

Response status and body bytes stream back unchanged. Response headers use an
allowlist: content metadata, ETag/Last-Modified, Location, Retry-After, range
metadata, Date, Vary and Expires. Cookies, authentication headers, arbitrary
custom headers and hop-by-hop headers do not pass through. Gateway responses
always use `Cache-Control: no-store`. This does not filter response bodies: an
upstream is trusted not to put its own credentials into its response content.

Origin headers are denied unless their exact origin is configured. An absent
Origin is allowed for native clients presenting a grant. This is origin
admission, not a browser CORS implementation. The admin server must not expose
its token or vault key to agents.

Consumption now returns a server-side audit receipt. Schema 3 adds nullable
`authorization_id` to audit rows with a unique completion link. After forwarding,
the handler appends a completion record containing HTTP status and elapsed
milliseconds. A completion cannot replace the authorization or refund its use.
The audit export includes the link, so two records for one forwarded call are
understood as authorization followed by completion, rather than two uses.
Result-recording failures are logged without credential or request-body content.
The handler tries to record an outcome even after a client disconnects, using a
separate five-second database context.

Revocation that commits before consumption blocks the request. Once a use has
committed and forwarding is in flight, later revocation does not cancel that
already authorized request. Tests exercise this boundary against a real local
HTTP upstream, along with policy reloads, malformed requests, credential
isolation, response header filtering, redirects, upstream failures and parallel
single-use calls. The 1,000-run database race and crash recovery tests still run.
