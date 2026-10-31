# CLAUDE.md

All project instructions live in `AGENTS.md`, shared with ChatGPT/Codex. Read it first and follow it.

Where to start a session:

1. `git pull --rebase origin main`
2. Read `AGENTS.md`, then `TODO.md` (current state, next tasks, session log), then `docs/plan.md` as needed.
3. Work the next unticked task in `TODO.md`.
4. Before stopping, add a session log entry at the top of the log in `TODO.md` and push.

Don't put project rules in this file. If a rule changes, change it in `AGENTS.md` so both assistants see it.

## Flight recorder (v0.1.2): done

Shipped 2026-10-31 as v0.1.2 (release run 41189145735, CI run 41188972690, tag on 8c81d74). An append-only, hash-chained log of every grant issue and revocation, MCP tool call or REST call, decision and upstream result, written in the same SQLite transaction as the change (table `flight`, schema 4). Commands: `tokening flight verify | export | replay | head`, reading the database read-only. Reference: `docs/flight.md`. Chain logic: `internal/flight`; appends and reads: `internal/store/flight.go`.

**Status.** Measured in the release's test-results.json on Linux, macOS and all five native release platforms: 208 of 208 tamper cases caught (every edit, deletion, adjacent swap and truncation of a 42-entry log, plus truncations with the counter reset, caught with a saved head); 800 entries from 8 connections and 400 from 4 processes, chain intact, every request next to its decision; 20 of 20 kill-mid-write rounds verified. The archive smoke check runs `flight verify` and `flight replay`. The review was a second pass by Claude (`docs/review-v0.1.2.md`), since no separate agent could be started; a review by ChatGPT/Codex is welcome. Site post: https://tokening.net/tokening-0.1.2-adds-a-flight-recorder-for-ai-agent-actions/

**Next.** Optional admin API route for flight export (remote operators currently need file access to the database); the three v0.1.2 wording/test follow-ups in `TODO.md`; then the plan's v0.2 milestone, agreed with the owner first. CI prints the consumer-race and flight summaries as notice annotations, because job log and artifact hosts are blocked from cloud sessions.

## In progress: independent review of flight recorder

Started 2026-10-31 by Claude (independent reviewer, did not write the v0.1.2 code). Scope: `internal/flight`, `internal/store/flight.go`, `cmd/tokening/flight.go`, every place the gateway writes flight entries (grant issue/revoke, MCP and REST calls, decisions, upstream results), `docs/flight.md`, the release workflow's flight checks.

What gets checked: canonical encoding of hashed fields (boundaries, unicode, numbers, ordering); actions that skip logging (error paths, early returns, panics, denied, revoked or expired grants, upstream timeouts); transaction boundaries; races between reading the previous hash and inserting; verify accepting a forged chain (head, `--partial`, sequence gaps, AUTOINCREMENT); secrets in arg names, errors or upstream results; export filters; control characters in replay/export; large or malformed input.

Method: a failing test first for each suspected bug, then the fix. Database tests run only in CI (proxy.golang.org and modernc.org are unreachable from cloud sessions); results are read from check-run annotations.

Resume: read the latest commits on main and the findings list in `docs/review-v0.1.3.md` (created as findings are confirmed).
