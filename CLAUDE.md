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

**Status.** Measured in the release's test-results.json on Linux, macOS and all five native release platforms: 208 of 208 tamper cases caught (every edit, deletion, adjacent swap and truncation of a 42-entry log, plus truncations with the counter reset, caught with a saved head); 800 entries from 8 connections and 400 from 4 processes, chain intact, every request next to its decision; 20 of 20 kill-mid-write rounds verified. The archive smoke check runs `flight verify` and `flight replay`. The review was a second pass by Claude (`docs/review-v0.1.2.md`), since no separate agent could be started; a review by ChatGPT/Codex is welcome. Site post: https://tokening.net/tokening-adds-a-flight-recorder-for-ai-agent-actions/

**Next.** Optional admin API route for flight export (remote operators currently need file access to the database); the three v0.1.2 wording/test follow-ups in `TODO.md`; then the plan's v0.2 milestone, agreed with the owner first. CI prints the consumer-race and flight summaries as notice annotations, because job log and artifact hosts are blocked from cloud sessions.

## Independent review of the flight recorder: done (v0.1.3)

Done 2026-10-31 by Claude in a session that did not write the v0.1.2 code. Full findings: `docs/review-v0.1.3.md`. Shipped as v0.1.3 (CI run 41190710547, release run 41190855180, tag on 3cb8a3c); latest/download links, SHA256SUMS and the downloaded Linux binary checked; site updated (badge, Download, Reference, evidence file).

Fixed, each with a test that failed first: verify and replay accepted non-canonical JSONL lines (duplicate or case-variant keys, spaces), so other readers could see values verify never checked; `replay --file` said "Chain intact" for a file with entries cut out; agent-chosen tool and argument names could make a request entry longer than the 1 MiB line limit, so exports stopped verifying from a file (now bounded: 256-byte action and target, at most 100 names of 128 bytes, with counts); replay left tool names with spaces or Unicode spaces unquoted.

Still open (owner's call or v0.2): requests rejected before matching (such as `_method` overrides) are not recorded anywhere; a database row with a malformed hash makes verify fail closed without naming the entry. CI now prints failing test output as error annotations.

Decided: `args_digest` and `bindings_digest` stay plain SHA-256, as documented in docs/flight.md (owner, 2026-10-31). No keyed (HMAC) digests.

## Flight recorder case studies: done

Done 2026-10-31 by Claude. Script and recorded runs: `test/results/case-studies/flight/` (`sh run.sh` downloads the latest release, checks SHA256SUMS and reruns everything locally: the released binary in front of a stub MCP CMS on 127.0.0.1, no Docker, no real site). Recorded on v0.1.3: a 20-entry session (single-use publish grant, a scoped edit, a revoked grant, an unknown token); verify caught an edited entry, a deletion and a truncation; a full rebuild verified as intact on its own and was caught by the saved head; a filtered export verified with `--partial` and an edited copy was caught; the full export held no grant secret, upstream key or argument value; all 20 hashes recomputed from the format in docs/flight.md matched. Site posts (tag "case studies"): https://tokening.net/replaying-an-ai-agent-publish-session-with-the-tokening-flight-recorder/, https://tokening.net/when-someone-edits-the-audit-log-behind-an-ai-agent/, https://tokening.net/exporting-one-ai-agent-session-for-a-reviewer-to-check/; tag "use cases": https://tokening.net/flight-recorder-recipes-for-audits-and-incident-reviews/. The flight recorder post is now titled "Tokening Adds a Flight Recorder for AI Agent Actions" (no version in titles, owner rule) at https://tokening.net/tokening-adds-a-flight-recorder-for-ai-agent-actions/.

Found during case studies (not fixed): `flight verify --head ""` treats an empty head as no head and exits 0 without checking it, so a script reading an empty heads file fails open (should be a usage error, exit 2); after a saved-head mismatch verify still prints "Entries 1 to N verify. Last good head: N" for entries that were rewritten, and a shorter rebuilt chain is described as "entries were removed from the end" when they were removed from the middle.

## In progress: 0.1.4 fixes

Started 2026-10-31 by Claude (owner request). A small fix release from the case study follow-ups. Plan, in order:

1. `flight verify --head ""` (or any malformed head) is a usage error, exit 2, with a clear message, checked before the database or file is opened. Failing test first.
2. Wording after a saved-head mismatch: say the chain does not match the saved head and that entries after the last point matching it cannot be trusted, instead of "Entries 1 to N verify. Last good head". A shorter chain than the saved head (or than SQLite's counter) is described neutrally, without saying entries were removed from the end. Tests for the new messages.
3. MCP serverInfo (and the upstream clientInfo) report the real build version from one place, `internal/version`, which the release script reads. Test that serverInfo matches it.
4. Version 0.1.4, CHANGELOG, review record, release-readiness.json; the release workflow publishes after green CI. Then check the release files, SHA256SUMS, latest/download and the downloaded binary once.
5. Rerun the case studies on 0.1.4 and update the site (badge, Download, posts quoting the changed messages).

Status: plan pushed.
