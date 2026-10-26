# TODO

Current state, next tasks, and the session log. Both assistants read this at the start of a session and update it before stopping. See `AGENTS.md` for the rules.

## Status

Repo set up with instructions only. No code yet. Next phase: **v0.1, the demo works** (see `docs/plan.md`).

## Open questions for the owner

- [ ] Aim v0.1 at Web Summit (Lisbon, November 9 to 12, 2026), or let it ship when it's ready?
- [ ] Should the public demo also run against one of his real WordPress sites, or stay Docker-only?
- [x] Site repo exists: https://github.com/photozeitgeist/tokening.net (confirmed by the owner 2026-10-26)

## v0.1 tasks

Work top to bottom unless a task is blocked. Tick when done and pushed.

### Foundation
- [ ] `go.mod` (`github.com/softdevstudio/tokening`), `cmd/tokening/main.go`, `version` constant `0.1.0`
- [ ] `NOTICE` and `THIRD_PARTY_LICENSES.md` (LICENSE is in place)
- [ ] `.gitignore`, `Makefile` or `justfile` with `test`, `build`, `demo`
- [ ] CI workflow: `go vet`, `gofmt` check, `go test ./...` on Linux and macOS, every push to main

### Core
- [ ] Policy file loader and validator (`tokening check`), constraint vocabulary from the plan
- [ ] SQLite store (pure-Go driver), schema migrations, WAL mode
- [ ] Matcher: pure function, every constraint and refusal code, table-driven tests
- [ ] Consumer: atomic check-and-decrement, race test (1,000 runs, one winner)
- [ ] Vault: encrypt/decrypt credentials, key from env or file
- [ ] Grant issue / inspect / revoke, secret shown once, stored hashed
- [ ] Audit log: one row per decision, JSONL export

### Gateway
- [ ] Agent listener: MCP Streamable HTTP at `/mcp/{target}` (tools/list filtering, tools/call)
- [ ] REST passthrough at `/http/{target}/...`
- [ ] `GET /grant` self-description
- [ ] Forwarder with credential injection
- [ ] Admin listener and admin API; CLI as its client

### Demo
- [ ] `demo/docker-compose.yml`: WordPress, MCP adapter plugin, seeded posts, Tokening
- [ ] Scripted agent (deterministic) running the seven-step script
- [ ] Decision log panel on the admin port; static replay export
- [ ] Demo runs in CI

### Release
- [ ] Release workflow (triggered by green CI on a new version, builds Linux/macOS/Windows, smoke tests, tags, publishes with SHA256SUMS; versionless archive names)
- [ ] Failure tests recorded to `test/results/` by script
- [ ] Independent review, fixes, fresh recording
- [ ] README as manual and explainer (credential custody on the first screen)
- [ ] Ship v0.1.0

### Site (tokening.net)
- [ ] Set up from the standard Hugo Launch template (content and config only)
- [ ] Pages: About (incl. the name), Contact, Quick start, Download, Reference
- [ ] Posts: launch, agent permissions explainer, how it was tested, the name
- [ ] Demo replay on the home page; footer "A SoftDevStudio.com project"
- [ ] Add Tokening to softdevstudio.com

## Session log

Newest first. One entry per session: date, who, what changed, what's next, blockers.

- **2026-10-26, Claude.** Created the repo's instruction set: `AGENTS.md` (shared rules for Claude and ChatGPT/Codex), `CLAUDE.md` (pointer), `docs/plan.md` (approved plan), this `TODO.md`, `README.md` stub, Apache 2.0 `LICENSE`. No code yet. Next: Foundation tasks above.
