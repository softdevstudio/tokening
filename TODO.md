# TODO

Current state, next tasks, and the session log. Both assistants read this at the start of a session and update it before stopping. See `AGENTS.md` for the rules.

## Status

Foundation added: Go command scaffold, license notices, build targets and Linux/macOS CI. Policy loading and validation are implemented. SQLite storage, WAL mode and atomic schema migrations are implemented. The pure permission matcher is implemented. Atomic consumption and the 1,000-run race test are implemented. The credential vault is next. Current phase: **v0.1, the demo works** (see `docs/plan.md`).

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
- [x] Policy file loader and validator (`tokening check`), constraint vocabulary from the plan
- [x] SQLite store (pure-Go driver), schema migrations, WAL mode
- [x] Matcher: pure function, every constraint and refusal code, table-driven tests
- [x] Consumer: atomic check-and-decrement, race test (1,000 runs, one winner)
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

- **2026-10-26, ChatGPT.** Pulled main and read AGENTS.md, TODO.md and docs/plan.md. Implemented bearer-hash lookup, saved-template matching and atomic use consumption with authorization audit records in one immediate transaction. Added a 1,000-run race through independent database connections with exactly one winner per run, real process-kill recovery before and after commit, audit/commit failure rollback, expiry rechecks, queued state changes, saved-version tests and REST snapshot coverage. An injected COMMIT failure showed SQLite could leave an open transaction; fixed this by discarding the reserved connection on commit errors, with a regression test proving rollback and subsequent usability. Local CGO-free format/vet/tests/build and the storage race detector passed. Disabled cached test results in the JSONL recording script. Updated consumer documentation, including the forwarding boundary and remaining gateway integration tests. Next: credential vault, then grant/admin APIs and audit export. No release published.

- **2026-10-26, ChatGPT.** Pulled main and read AGENTS.md, TODO.md and docs/plan.md. Implemented the pure matcher for grant lifecycle, MCP target/tool scope, scalar constraints, exact bindings, SHA-256 bindings and REST path/query scope. Added deterministic readable decisions and the upstream-failure decision helper, with tests for every planned code. Refactored policy validation for saved template snapshots and replaced floating-point numeric bounds with bounded exact JSON numbers, because rounding could incorrectly admit a value above its limit. Tested Unicode limits and malformed strings, large-number boundaries, hash corruption, path traversal/alias attempts, refusal ordering and input immutability. Local CGO-free format/vet/tests/build passed; recorded tests through the existing JSONL script. Updated the matcher and policy references. Next: atomic SQLite consumer and the 1,000-run single-use race test. No release published.

- **2026-10-26, ChatGPT.** Pulled main and read AGENTS.md, TODO.md and docs/plan.md. Added the pure-Go SQLite store, WAL with FULL synchronization, per-connection foreign keys and busy timeout, atomic versioned migrations and private database file permissions. Added the target/template/grant/decision schema, immutable template versions and append-only audit triggers. Tests cover reopening, constraints, failed-migration rollback, future-schema refusal and concurrent initialization. Local CGO-free format/vet/tests/build passed, as did the storage race test and repeated concurrent-open test. Pinned SQLite and its runtime dependencies, included license notices and documented storage. CI now tests with CGO disabled on Linux and macOS. Next: matcher. No release published.

- **2026-10-26, ChatGPT.** Pulled main and read AGENTS.md, TODO.md and docs/plan.md. Implemented policy loading and `tokening check`, the planned constraint vocabulary, target and template validation, deterministic warnings, WordPress example and policy reference. Added malformed-policy and CLI tests, JSONL test recording and CI artifact retention. Installed a scratch Go toolchain; local format, vet, tests, build and example check passed. Confirmed the foundation CI passed on Linux and macOS. Next: SQLite store and migrations. No release published.

- **2026-10-26, ChatGPT.** Pulled main and read AGENTS.md, TODO.md and docs/plan.md in order. Added the Go module and version/help command, notices, ignore rules, build/test/demo targets and Linux/macOS CI with retained diagnostics. No release published. Local Go validation is blocked because this environment has no Go toolchain; CI is the validation route. Next: policy loader and validator. The demo target explicitly fails until the Docker demo exists.

- **2026-10-26, Claude.** Created the repo's instruction set: `AGENTS.md` (shared rules for Claude and ChatGPT/Codex), `CLAUDE.md` (pointer), `docs/plan.md` (approved plan), this `TODO.md`, `README.md` stub, Apache 2.0 `LICENSE`. No code yet. Next: Foundation tasks above.
