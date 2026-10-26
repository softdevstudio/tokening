# TODO

Current state, next tasks, and the session log. Both assistants read this at the start of a session and update it before stopping. See `AGENTS.md` for the rules.

## Status

Foundation added: Go command scaffold, license notices, build targets and Linux/macOS CI. Gateway and policy implementation are next. Current phase: **v0.1, the demo works** (see `docs/plan.md`).

## Open questions for the owner

- [x] Web Summit: no. v0.1 ships when its gate passes, no deadline (owner, 2026-10-26)
- [x] Public demo stays Docker-only, never against a real site (owner, 2026-10-26)
- [x] Site repo exists: https://github.com/photozeitgeist/tokening.net (confirmed by the owner 2026-10-26)

## v0.1 tasks

Work top to bottom unless a task is blocked. Tick when done and pushed.

### Foundation
- [x] `go.mod` (`github.com/softdevstudio/tokening`), `cmd/tokening/main.go`, `version` constant `0.1.0`
- [x] `NOTICE` and `THIRD_PARTY_LICENSES.md` (LICENSE is in place)
- [x] `.gitignore`, `Makefile` or `justfile` with `test`, `build`, `demo`
- [x] CI workflow: `go vet`, `gofmt` check, `go test ./...` on Linux and macOS, every push to main

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

- **2026-10-26, ChatGPT.** Pulled main and read AGENTS.md, TODO.md and docs/plan.md in order. Added the Go module and version/help command, notices, ignore rules, build/test/demo targets and Linux/macOS CI with retained diagnostics. No release published. Local Go validation is blocked because this environment has no Go toolchain; CI is the validation route. Next: policy loader and validator. The demo target explicitly fails until the Docker demo exists.

- **2026-10-26, Claude.** Created the repo's instruction set: `AGENTS.md` (shared rules for Claude and ChatGPT/Codex), `CLAUDE.md` (pointer), `docs/plan.md` (approved plan), this `TODO.md`, `README.md` stub, Apache 2.0 `LICENSE`. No code yet. Next: Foundation tasks above.
