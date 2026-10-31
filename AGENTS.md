# AGENTS.md

Instructions for any AI assistant working on this repo. Claude and ChatGPT/Codex both work here, sometimes alternating. This file is the single source of truth for how the project runs. `CLAUDE.md` only points here.

Read this file, then `TODO.md`, then `docs/plan.md`, before doing anything.

## What Tokening is

A permission gateway for AI agents. It sits between an agent and an API and issues grants for single actions: update this post, once, title and body only, within fifteen minutes. The agent never sees the real credential. Every call is checked against its grant, and every refusal comes with a reason a person can read.

- Language: Go. One binary, `tokening`. State in SQLite.
- Licence: Apache 2.0.
- Code repo: `github.com/softdevstudio/tokening` (this repo). Go module path: `github.com/softdevstudio/tokening`.
- Site: tokening.net, repo `github.com/photozeitgeist/tokening.net`.
- Full plan: `docs/plan.md`.

## The owner's role, and yours

This project runs on the owner's "low maintenance workflow": it should run practically without his participation.

His part is only: the go-ahead, the language choice, creating repos and granting push access. You do everything else: code, tests, docs, CI, releases, site and upkeep.

- Never ask him to publish a release, tag a version, click through GitHub settings for routine work, or run commands for you.
- Do ask him before anything that changes the plan's direction, scope or public positioning. Agree the next phase with him before writing it into `TODO.md` as committed work.
- When you need something only he can do (a new repo, a secret, a permission), say exactly what and why in one message.

## Working with two assistants

Claude and ChatGPT/Codex push to the same repo. To keep that safe:

1. **Pull before you start.** `git pull --rebase origin main` before any work. The other assistant may have pushed since you last looked.
2. **Read `TODO.md` first.** It holds the current state, the next tasks and the session log. Pick up from there.
3. **Small commits, pushed often.** One logical change per commit, with a clear message. Don't sit on unpushed work.
4. **Don't rewrite the other assistant's work** without a reason you can state. If you think something is wrong, fix it in a separate commit and say why in the log.
5. **Log every session.** Before you stop, add an entry at the top of the session log in `TODO.md`: date, who (Claude or ChatGPT), what changed, what's next, anything blocked. Tick off finished tasks.
6. **Branch:** `main` is the default and only long-lived branch. Never make a side branch the default.

## Guardrails against work loops

These exist because past projects lost hours to retry loops. Follow them strictly.

1. **Read the real error before any fix or rerun.** Never rerun a failed CI or release job blind. If the log API returns nothing, try other routes (`gh run view --log-failed`, the job logs endpoint following its redirect, annotations, artifacts). If none work, add a step that prints the failing command's output as annotations, then rerun once.
2. **At most two fix-and-retry rounds on one failure.** A rerun without a known cause counts as a round. After two, stop and report what's known and the options.
3. **15-minute time box.** If a problem has no known cause after 15 minutes of your own diagnosis (waiting on a running build doesn't count), stop and report. Handing it to the other assistant is a valid option.
4. **Report early.** A blocked release or failing CI gets reported, not quietly retried.
5. **Don't wait silently.** While CI or a release runs, work on the next thing and say so.
6. **Keep failures readable.** CI and release steps must keep their diagnostics: failing output in annotations, logs kept as artifacts.

## Repo conventions

- `LICENSE` (Apache 2.0), `NOTICE`, `THIRD_PARTY_LICENSES.md` (update it whenever a dependency is added).
- `README.md` is the manual and the plain-language explainer. Reference docs are Markdown in `docs/`.
- No Word or PDF documents, no zips in the repo.
- Prefer the Go standard library. Every dependency needs a reason. SQLite via a pure-Go driver (`modernc.org/sqlite`) so builds stay CGO-free and cross-compile cleanly.
- `go vet` and `gofmt` clean. Tests with `go test ./...`.

## Testing

- Unit tests for every matcher rule and every refusal code.
- Failure tests aimed at the main promise, single use under concurrency:
  - parallel race on a 1-use grant, 1,000 runs, exactly one winner each time
  - process killed mid-consume
  - policy reload while grants are live
  - grant revoked during an in-flight call
- A script records test results to `test/results/`. Every number published on the site comes from there, never typed by hand.
- Before calling a release done, an independent review (a separate agent or the other assistant) reads the change. Fix what it finds, then record results again.
- CI runs on every push to main, on Linux and macOS.

## Releases (automated, owner never involved)

1. Raise the version in the code on main (a `version` constant).
2. When CI finishes green on that commit, the release workflow (triggered by the finished CI run) sees a version with no tag yet.
3. It builds Linux, macOS and Windows binaries, smoke-tests them, then tags `vX.Y.Z` and creates the release "Tokening vX.Y.Z" (not a pre-release) with binaries, `SHA256SUMS` and notes.
4. Archive names carry no version, so `releases/latest/download/...` links on the site stay valid.
5. The workflow runs on the repo's own `GITHUB_TOKEN`, because cloud assistant sessions can't create tags or releases themselves.
6. After it runs, check the release files and links, download a binary and run it.

Nothing goes public unless every build passes. A manually published release or a hand-run rebuild of an existing tag must still work.

## Site (tokening.net)

- Repo `photozeitgeist/tokening.net`. The owner's standard Hugo Launch template, copied unchanged: change content and config values only, never layouts, theme or CSS. No `public/` folder committed. No added `_index.md` files.
- Pages: About (including what the name "Tokening" means and how it connects to the project), Contact (info@tokening.net), Quick start, Download, Reference.
- Launch posts: the launch announcement, a plain-language explainer of agent permissions, how it was tested, and a post about the name.
- The demo replay goes on the home page.
- Footer line: "A SoftDevStudio.com project", linking to softdevstudio.com.
- Images drawn by you into `static/images/`. Never reuse content from the owner's other projects.

Hugo post rules (the owner's standing rules):

- Frontmatter fields: `title`, `date`, `draft`, `tags` only, plus `featured_image` when a post has a lead image.
- `title` always in double quotes, normal title casing, no characters that could break a template.
- `date` is date only, e.g. `date: 2026-10-26`. `draft: false`.
- Never repeat the title in the body, in any form.
- A lead image goes in `featured_image` and also inline after the second or third paragraph, never at the top. Image URLs always https.
- No citation markers or source attributions in post text.

## Writing style for everything public (README, docs, site, release notes)

Write like a person, not a brochure.

- Plain words: need, get, about, many. Not require, obtain, approximately, numerous.
- Mix sentence lengths. Short ones are fine.
- No em dashes. Use commas, full stops or parentheses.
- Avoid canned moves: "it's not X, it's Y", "not only... but also", lists of three for rhythm, opening hooks, closing summaries.
- No hype adjectives. Say what it does and show the numbers from `test/results/`.

## Out of scope until the owner says otherwise

- The hosted version (managed gateways, approvals service, billing).
- Content safety checks on what agents write.
- OAuth server or SSO features.
- High availability.

## Flight recorder (v0.1.2): done

Shipped 2026-10-31 as v0.1.2 (release run 41189145735, CI run 41188972690, tag on 8c81d74). An append-only, hash-chained log of every grant issue and revocation, MCP tool call or REST call, decision and upstream result, written in the same SQLite transaction as the change (table `flight`, schema 4). Commands: `tokening flight verify | export | replay | head`, reading the database read-only. Reference: `docs/flight.md`. Chain logic: `internal/flight`; appends and reads: `internal/store/flight.go`.

**Status.** Measured in the release's test-results.json on Linux, macOS and all five native release platforms: 208 of 208 tamper cases caught (every edit, deletion, adjacent swap and truncation of a 42-entry log, plus truncations with the counter reset, caught with a saved head); 800 entries from 8 connections and 400 from 4 processes, chain intact, every request next to its decision; 20 of 20 kill-mid-write rounds verified. The archive smoke check runs `flight verify` and `flight replay`. The review was a second pass by Claude (`docs/review-v0.1.2.md`), since no separate agent could be started; a review by ChatGPT/Codex is welcome. Site post: https://tokening.net/tokening-0.1.2-adds-a-flight-recorder-for-ai-agent-actions/

**Next.** Optional admin API route for flight export (remote operators currently need file access to the database); the three v0.1.2 wording/test follow-ups in `TODO.md`; then the plan's v0.2 milestone, agreed with the owner first. CI prints the consumer-race and flight summaries as notice annotations, because job log and artifact hosts are blocked from cloud sessions.

## Independent review of the flight recorder: done (v0.1.3)

Done 2026-10-31 by Claude in a session that did not write the v0.1.2 code. Full findings: `docs/review-v0.1.3.md`. Shipped as v0.1.3 (CI run 41190710547, release run 41190855180, tag on 3cb8a3c); latest/download links, SHA256SUMS and the downloaded Linux binary checked; site updated (badge, Download, Reference, evidence file).

Fixed, each with a test that failed first: verify and replay accepted non-canonical JSONL lines (duplicate or case-variant keys, spaces), so other readers could see values verify never checked; `replay --file` said "Chain intact" for a file with entries cut out; agent-chosen tool and argument names could make a request entry longer than the 1 MiB line limit, so exports stopped verifying from a file (now bounded: 256-byte action and target, at most 100 names of 128 bytes, with counts); replay left tool names with spaces or Unicode spaces unquoted.

Still open (owner's call or v0.2): `args_digest` and `bindings_digest` are unkeyed SHA-256, so guessable values (post IDs) can be found by trying candidates (now stated in docs/flight.md; an HMAC with a stored key would fix it); requests rejected before matching (such as `_method` overrides) are not recorded anywhere; a database row with a malformed hash makes verify fail closed without naming the entry. CI now prints failing test output as error annotations.

## In progress: flight recorder case studies

Started 2026-10-31 by Claude. Owner asked for case studies and use examples of the flight recorder, built from real runs. Rules: only new files in this repo (no recorder code changes); runs are local only (released binary from releases/latest plus a local stub upstream, or the Docker demo), never a real WordPress site or third-party service.

Plan:

1. [ ] `test/results/case-studies/flight/run.sh`: downloads the latest release binary, starts a local stub upstream and `tokening serve`, runs each scenario and writes its commands and output to files in that folder. Rerun with `sh test/results/case-studies/flight/run.sh`.
2. [ ] Scenarios: single-use publish grant with replay; a row edited and a row deleted in SQLite, caught by verify; a saved head catching a full chain rebuild; an export of one agent's actions for a reviewer; the use-example recipes (head on a schedule, verify in CI, export by agent and time, replay after an incident, what the log never stores).
3. [ ] Site (photozeitgeist/tokening.net): two or three "case studies" posts and one "use cases" post, numbers copied only from the recorded files; linked from the 0.1.2 flight recorder post.
4. [ ] Done entry here and in `TODO.md`.

Any real bug found goes under "Found during case studies" below, not fixed here.
