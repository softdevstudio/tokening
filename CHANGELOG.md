# Tokening v0.1.0

Tokening is a self-hosted permission gateway for AI agents. A grant can allow one edit to one WordPress post, bind its ID, limit the fields and expire after fifteen minutes. The real upstream credential stays in the encrypted vault, outside the agent environment. The admin listener must also stay outside the agent's network.

This first release includes REST forwarding and an MCP Streamable HTTP tool profile, saved permission versions, atomic SQLite use consumption, encrypted upstream credentials, an operator CLI, an append-only audit log and a read-only admin panel. Uses are spent before forwarding. Failed or redirected upstream requests do not restore them. Windows, Linux and macOS run the same Go program with CGO disabled.

The disposable Docker WordPress demo uses the official WordPress MCP Adapter. Its deterministic agent receives only narrow grant secrets. The operator checks the actual post state and audit records after the agent finishes. The downloadable demo replay is a self-contained HTML file that sends no network requests. test-results.json contains the measured failure-test results and native archive smoke reports from this release's CI runs.

Download the archive for your operating system and architecture, verify it against SHA256SUMS and read README.md inside it. Archive names have no version so latest/download links remain stable. The source checkout includes make demo; Docker Compose v2 and Python 3 are needed for that demonstration.

The MCP agent profile is 2025-06-18. Upstream initialization supports 2025-11-25 and 2025-06-18. Responses are buffered to 1 MiB, server-to-client requests are not serviced, and long-lived streams need a later transport extension. Stdio targets, OAuth server duties, rate limiting and vault key rotation are outside this release. See docs/mcp.md and docs/server.md for the exact boundaries. This review is a project release check, not an external security audit.

Licence: Apache 2.0. Third-party notices are included in every archive.
