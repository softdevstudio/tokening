# Tokening plan

Approved plan for Tokening, October 2026. Process rules (workflow, releases, site, guardrails) live in `AGENTS.md`. This file covers what to build.

## The claim v0.1 proves

An agent can edit one WordPress post through Tokening, and every attempt to go beyond that grant is refused with a reason a person can read. The real WordPress credential never reaches the agent.

## Positioning

MCP gateways that check tool calls against standing policies already exist (AWS Bedrock AgentCore Policy, Gravitee, TrueFoundry and others), including parameter-level rules. Tokening doesn't compete on "we inspect arguments." It differs in two ways:

- **Grants, not policies.** A grant is issued for one task, used up, and gone. Policies are standing rules.
- **Small and self-hosted.** One binary a solo developer runs in a minute. No platform to adopt.

Target user: a developer or small team running agents against their own WordPress, GitHub or SaaS accounts, who will never deploy an enterprise gateway.

Follow the MCP spec's direction on gateway authorization rather than inventing a separate transport.

## Concepts

- **Target.** An upstream: an MCP server (Streamable HTTP or stdio) or a REST base URL. Each target has a stored credential the agent never sees.
- **Template.** A named permission shape in the policy file: target, tool (or method + path), which arguments are bound at issue time, which are free and within what limits.
- **Grant.** One issued instance of a template with the blanks filled in: e.g. post 4812, 1 use, 15 minutes, issued to `editor-bot`, reason "fix typo in intro". Has an ID and a bearer secret. The secret is the only thing the agent holds.
- **Call.** A request from the agent carrying the grant secret. If it fits the grant, one use is consumed, the real credential is injected and the call is forwarded.
- **Decision.** Every call produces `allowed` or `refused`, a machine code and a readable reason. Every decision goes to the audit log.

Grant lifecycle: `issued` → `active` → `exhausted` | `expired` | `revoked`. A grant never comes back. New grants are cheap.

### Refusal codes (v0.1)

| Code | Example reason |
| --- | --- |
| `grant_unknown` | No grant matches this token. |
| `grant_expired` | Grant g_7Kq expired at 10:14, 3 minutes ago. |
| `grant_exhausted` | Grant g_7Kq allowed 1 use and it was used at 10:02. |
| `grant_revoked` | Grant g_7Kq was revoked by yk at 10:05. |
| `tool_not_allowed` | Grant allows wp_update_post; call asked for wp_delete_post. |
| `arg_mismatch` | Grant allows post 4812; call targeted post 4813. |
| `arg_not_allowed` | Grant allows fields title, content; call also set status. |
| `arg_limit` | content is 41 KB; grant allows up to 32 KB. |
| `upstream_error` | Call was allowed and forwarded; WordPress returned 500. The use is still consumed. |

## Architecture

One Go binary runs as a server, or as a CLI talking to that server's admin API. One SQLite file in WAL mode. No other services.

1. **Agent listener.** MCP Streamable HTTP at `/mcp/{target}`, REST passthrough at `/http/{target}/...`. Grant secret as bearer token.
2. **Admin listener.** Separate port, localhost by default. Admin token from config. Serves the admin API and the demo panel.
3. **Matcher.** Normalises a call (target, tool or method+path, args as JSON) and checks it against the grant. Pure function, no I/O, heavily tested.
4. **Consumer.** Check and decrement in one statement:

   ```sql
   UPDATE grants SET uses_left = uses_left - 1, last_used_at = ?
   WHERE id = ? AND uses_left > 0 AND expires_at > ? AND revoked_at IS NULL;
   ```

   One row changed: proceed. Zero: used up, expired or revoked. SQLite serialises writers, so two calls on a 1-use grant can't both win.
5. **Vault.** Upstream credentials encrypted at rest (NaCl secretbox or age), key from an env var or key file. Decrypted in memory only at forward time.
6. **Forwarder.** Injects the credential (header, basic auth, or env for stdio MCP servers) and sends the call. Response streams back unchanged. Response bodies are not stored.
7. **Audit log.** Append-only `decisions` table. Exportable as JSONL.

Consumption happens **before** forwarding. If the upstream fails, the use is spent, so a flaky upstream can't be used to replay a write. A per-template `refund_on_upstream_5xx` flag may relax this later.

Stdio MCP targets are spawned by Tokening as child processes, one per target, with the credential in their environment. The agent only talks HTTP to Tokening.

### Schema (v0.1)

| Table | Key columns |
| --- | --- |
| `targets` | id, kind (mcp_http, mcp_stdio, http), url_or_cmd, cred_ciphertext, created_at |
| `templates` | id, target_id, tool, constraints_json, max_ttl_s, max_uses, version |
| `grants` | id, secret_hash, template_id, bound_args_json, uses_left, expires_at, issued_to, reason, issued_by, revoked_at, created_at |
| `decisions` | id, grant_id, at, agent, tool, args_digest, outcome, code, reason, upstream_status, latency_ms |

Grant secrets stored as SHA-256 hashes only, shown once at issue. Templates load from the policy file at startup and on SIGHUP; the database keeps versioned copies so old grants stay explainable after a policy edit.

## Policy file

`tokening.json`, in the operator's own config repo. Declares targets and templates. Grants are never in the file.

```json
{
  "targets": {
    "briefly-wp": {
      "kind": "mcp_http",
      "url": "https://example.com/wp-json/mcp/v1",
      "credential": { "type": "basic", "ref": "vault:briefly-wp" }
    }
  },
  "templates": {
    "wp.edit-post-text": {
      "target": "briefly-wp",
      "tool": "wp_update_post",
      "args": {
        "id":      { "bind": "required" },
        "title":   { "type": "string", "max_len": 200 },
        "content": { "type": "string", "max_bytes": 32768 }
      },
      "additional_args": "refuse",
      "max_uses": 3,
      "max_ttl": "30m"
    },
    "wp.read-post": {
      "target": "briefly-wp",
      "tool": "wp_get_post",
      "args": { "id": { "bind": "required" } },
      "max_uses": 20,
      "max_ttl": "1h"
    }
  }
}
```

Constraint vocabulary (v0.1, kept small):

| Constraint | Applies to | Meaning |
| --- | --- | --- |
| `bind: required` | any | Fixed at issue time; call must match exactly |
| `bind: optional` | any | May be fixed at issue time; otherwise any value of the right type |
| `type` | any | string, integer, number, boolean |
| `enum` | string, number | One of a listed set |
| `max_len` / `max_bytes` | string | Characters / UTF-8 bytes |
| `min` / `max` | number | Numeric range |
| `pattern` | string | RE2 regex, anchored |
| `sha256` | string | Value must hash to this, bound at issue time |
| `additional_args` | template | `refuse` (default) or `allow` |

REST templates use `method` and `path` (with `{id}` placeholders bound like args) instead of `tool`, with the same constraints on JSON body fields and query parameters.

Issuing narrows, never widens:

```
tokening grant issue wp.edit-post-text \
  --bind id=4812 --uses 1 --ttl 15m \
  --to editor-bot --reason "fix typo in intro"

grant  g_7Kq3mX   uses 1   expires 10:14
secret tkn_9f2a...   (shown once)
```

Nested args, arrays and cross-field rules wait for v0.3. If needed sooner, the escape hatch is a Cedar expression on the template evaluated with `cedar-go`, not a home-made language.

## CLI and API

The CLI is a thin client of the admin API.

| CLI | Admin API | Does |
| --- | --- | --- |
| `tokening serve` | n/a | Start both listeners |
| `tokening check tokening.json` | n/a | Validate the policy file; warn on unbounded strings and `additional_args: allow` |
| `tokening target add <name> --cred-file <f>` | `POST /admin/targets` | Store an encrypted credential |
| `tokening template list` | `GET /admin/templates` | Loaded templates |
| `tokening grant issue <template> ...` | `POST /admin/grants` | Issue a grant, print the secret once |
| `tokening grant inspect <id>` | `GET /admin/grants/{id}` | State, uses left, expiry, decisions |
| `tokening grant revoke <id>` | `POST /admin/grants/{id}/revoke` | Revoke now |
| `tokening log --follow` | `GET /admin/decisions?since=` (SSE) | Live decision stream |
| `tokening log --export` | `GET /admin/decisions.jsonl` | Audit export |
| `tokening explain <grant> <call.json>` | `POST /admin/explain` | Dry-run a call, no consumption |
| `tokening doctor` | n/a | Warn if common credential env vars are visible to agents |

Agent-facing:

- `POST /mcp/{target}`. `tools/list` returns only tools the grant allows. `tools/call` is matched, consumed, forwarded.
- `ANY /http/{target}/{path...}` for REST targets.
- `GET /grant` returns what the presented grant allows, in plain English and JSON.

Refusals come back as MCP tool errors (`isError: true`) or HTTP 403 with `{code, reason, grant}`.

## Security model

Defends against: a prompt-injected agent calling a destructive tool; an agent looping on a write; a leaked agent log or environment (it holds only a narrow, short-lived, probably spent grant secret); two parallel runs spending a 1-use grant.

Assumes: the real credential exists only in Tokening's vault (the README must say this on its first screen); operators write sensible templates; the admin port isn't reachable by agents.

Non-goals for v0.x: content safety; identity federation, SSO, OAuth server duties; making a third-party API key narrower anywhere except through the gateway; response filtering; high availability.

Hardening before v1.0: constant-time secret comparison, rate limits per grant and per agent, request size cap, fuzz tests on the matcher, vault key rotation, external review of matcher and consumer.

## The demo

Thirty seconds, ending on four log lines: one allowed, three refused, each with its reason. Runs identically in CI, as a live local run (one command) and as a static replay on the site.

Setup: throwaway WordPress in Docker (`demo/docker-compose.yml`) seeded with three posts and the WordPress MCP adapter plugin; Tokening with target `demo-wp` and template `wp.edit-post-text`; a scripted MCP client agent so the run is deterministic (an optional mode lets a real model drive it).

Script:

1. Operator issues a grant: edit post 2, 1 use, 15 minutes, title and content only.
2. Agent calls `tools/list`. Only `wp_update_post` comes back.
3. Agent updates post 2's title. **Allowed.**
4. Same call again. **Refused:** grant allowed 1 use and it was used.
5. Agent targets post 3. **Refused:** grant allows post 2.
6. Agent calls `wp_delete_post`. **Refused:** tool not in grant.
7. Two parallel calls on a new 1-use grant. One allowed, one refused, every time.

Panel (admin port, also exported as a static replay): grant card with uses left and expiry timer; live decision log with full reason text; the post as it currently reads.

Live public demo, if wanted later: a Cloudflare Worker with a fake WordPress endpoint, the matcher compiled to WebAssembly, and a Durable Object holding grant state. Free tier, no hosted WordPress.

## Milestones

Each release ships when its gate passes. No calendar dates.

- **v0.1, the demo works.** Matcher, consumer, vault, MCP Streamable HTTP proxy, REST passthrough, CLI, admin API, `wp.edit-post-text` and `wp.read-post` templates, Docker demo, decision log panel.
  Gate: the seven-step demo passes in CI on every commit, including 1,000 runs of the parallel race with exactly one winner each time.
- **v0.2, real MCP servers.** Stdio targets, `tools/list` filtering, grant request flow (agent asks, operator approves from CLI or panel), JSONL export, `tokening explain`.
  Gate: Claude Desktop and one other MCP client complete the demo through Tokening with no client changes.
- **v0.3, template library.** WordPress, GitHub (comment on one issue, open one PR on one repo), Stripe (one refund under an amount), Slack (one message to one channel). Nested args, arrays, optional Cedar expressions.
  Gate: each template has explain-based tests for at least one allowed and three refused calls.
- **v1.0, safe to depend on.** Hardening checklist, external review, stable policy schema with migration notes, Go library package for embedding the matcher.
  Gate: review findings closed; no breaking schema change for 60 days of releases.

## Risks

| Risk | Mitigation |
| --- | --- |
| Big platforms move down-market | Stay small and self-hosted; win on setup time and readable refusals |
| Agents bypass the gateway | README leads with credential custody; `tokening doctor` |
| MCP gateway auth spec settles differently | Keep the transport layer thin; follow the spec |
| Loose templates | `tokening check` warns on unbounded args |
| Per-task grants feel like friction | Templates plus the v0.2 grant request flow |

## Later: hosted version (not before v0.3 has real users)

Human approval of grants (headline paid feature), managed gateways, shared audit history, team-owned templates. Pricing shape to test: free for one gateway and 1,000 decisions a month, paid per gateway plus volume.
