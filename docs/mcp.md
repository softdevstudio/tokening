# MCP gateway

The internal gateway handles POST /mcp/{target} for mcp_http targets. The running server and CLI are still being wired. The agent presents its grant in Authorization: Bearer. Upstream credentials and session IDs stay inside Tokening. Origin admission is shared with the REST endpoint.

This implementation uses the MCP 2025-06-18 Streamable HTTP transport profile. It returns JSON responses and does not open a server event stream for GET (405). POST clients must accept application/json and text/event-stream. An absent protocol header is accepted for older clients; explicit 2025-03-26 and 2025-06-18 headers are accepted. Initialization negotiates 2025-06-18. Other versions get HTTP 400.

The endpoint handles initialize, notifications/initialized, ping, tools/list and tools/call. Other methods and notifications are rejected. It advertises tools only, without list-change notifications. There are no agent sessions, resumable events, subscriptions, sampling or elicitation. Each request still needs the bearer token. The gateway accepts a single JSON-RPC object, never a batch, with a body limit of 1 MiB and duplicate-key checks. Tool-call parameters are name and arguments only; client metadata is not forwarded.

Tool discovery is local and does not spend uses or contact the upstream. The list contains only the grant's tool, with a conservative schema built from the saved template. GET /grant describes the exact bindings and limits. The matcher is authoritative. Discovery remains available after expiry, exhaustion or revocation so clients can explain the grant; it does not imply that another call is allowed.

A tool call is normalized, matched and consumed in SQLite before any upstream initialization or write. Refusals are MCP tool results with isError true and a text block containing the decision code, reason and grant ID. An upstream failure also returns a tool error. The use stays spent. A linked audit record captures the completion, including upstream tool errors.

Each authorized call opens a separate upstream MCP session: initialize, notifications/initialized, then tools/call. This prevents session state from being shared between grants or concurrent calls. The upstream must negotiate 2025-06-18. Its session ID is used privately and a bounded best-effort DELETE follows the call. A server that does not allow DELETE can return 405. No write is retried after a missing session or other failure.

Upstream responses may use JSON or SSE. This first adapter buffers up to 1 MiB, selects the response matching its private request ID, validates the envelope and returns its result with the agent's original request ID. SSE responses must finish within the shared 60-second HTTP timeout. Server requests are not serviced, and upstream notifications are not relayed. Large results, long-lived SSE streams and tools that need server-to-client requests need a later transport extension. Response result content is not filtered, so the upstream must not echo its own credential.

Credentials use the same encrypted basic, bearer or named-header format as REST. Incoming cookies, credentials, session IDs and arbitrary headers are never copied. Redirects, environment proxies and automatic request replay are disabled. This is a pre-issued local grant bearer profile, not an OAuth authorization server or a claim of the full MCP OAuth discovery flow.

Transport reference: https://modelcontextprotocol.io/specification/2025-06-18/basic/transports
