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

## In progress: flight recorder (v0.1.2)

Owner request, 2026-10-31. This section is the hand-off: Claude, ChatGPT/Codex or a fresh session must be able to continue from it alone. It is kept identical in `CLAUDE.md` and `AGENTS.md`. When v0.1.2 ships, replace it with a normal done/status/next entry.

**What and why.** An append-only, tamper-evident log of every action that passes through the gateway: the grant (issue, revoke), the request, the decision and the upstream result. Each entry is hash-chained to the one before, so an edit, deletion, reorder or truncation is detectable. Tokening grants the permission; the recorder proves what was done with it. v0.1 is already released (v0.1.1), so this ships as v0.1.2. The plan's v0.2 milestone (stdio targets, grant requests, explain) is unchanged.

**Design decisions.**

- Storage: new SQLite table `flight` (migration 004), written in the same transaction as the grant change or decision it records. A crash therefore loses nothing that committed and leaves no half entry. Concurrent writers (goroutines or several processes on one database) are serialized by SQLite's immediate write lock, and each append reads the previous hash inside that lock, so the chain cannot fork. UPDATE and DELETE triggers refuse changes, as on `decisions`.
- Entry fields: `seq` (1, 2, 3 ... no gaps), `at` (UTC, milliseconds), `kind` (`grant`, `request`, `decision`, `result`), `agent`, `grant`, `body` (compact JSON), `prev`, `hash`. No credentials, bearer secrets, bearer hashes or argument plaintext ever enter an entry; requests carry argument names and the same SHA-256 call digest the `decisions` table uses.
- Hash: SHA-256 over a length-prefixed binary encoding: the domain string `tokening-flight-v1`, seq (uint64 big-endian), at in ms (int64 big-endian), then kind, agent, grant and body each as uint32 length + bytes, then the previous entry's 32-byte hash (32 zero bytes for seq 1). Exported as lowercase hex.
- Body per kind: grant `{event: issued|revoked, ...}`; request `{target, action, args_digest, args}` (names only); decision `{decision_id, outcome, code, reason, uses_left}`; result `{decision_id, authorization_id, code, upstream_status, latency_ms}`.
- Limits, stated in the docs: a chain alone cannot stop someone with write access to the database from rewriting the whole chain from the first changed entry onward. `tokening flight head` prints the latest seq and hash so the operator can keep it somewhere else; `verify --head SEQ:HASH` then proves the saved point is still in the chain, which also catches deleted tail entries. History from before the upgrade stays in `decisions` only.
- Commands, all reading the database file directly (read-only), so they work with or without a running server: `tokening flight verify [--db F | --file F.jsonl] [--head SEQ:HASH] [--partial]`, `tokening flight export [--db F] [--agent A] [--grant G] [--since T] [--until T] [--output F]` (JSONL), `tokening flight replay [same filters]` (readable timeline in order), `tokening flight head [--db F]`. Verify prints the first broken entry and why, and exits 1. A file whose last line is cut off verifies up to the last complete entry and reports the cut-off line (exit 1). `--partial` accepts filtered exports: every entry's own hash is checked, and links are checked where seq numbers are consecutive.
- Chain logic lives in `internal/flight` (no database or network imports) so it is tested on its own; `internal/store/flight.go` does the appends and reads.

**Steps** (tick and push with the code as each finishes):

- [x] 1. `internal/flight`: entry type, hash, JSONL encode/decode, verifier, replay formatting, with unit tests (edit, delete, reorder, truncate, torn last line, bad head, partial exports)
- [x] 2. Store: migration 004, append on grant issue/revoke, consume (request + decision) and upstream completion; read, filter and export; tests incl. concurrent writers on separate connections and a process killed mid-write
- [x] 3. CLI `tokening flight verify|export|replay|head`, tests
- [x] 4. Recorded results: a `{"flight_recorder": ...}` summary line from the tests, parsed by `scripts/release.py` into `test-results.json`; new required tests listed there
- [x] 5. Docs: `docs/flight.md`, README section, storage/audit docs, CHANGELOG for v0.1.2
- [ ] 6. Independent review (separate agent or a fresh second pass), fixes, results recorded again; `docs/review-v0.1.2.md`
- [ ] 7. Version 0.1.2 and approved `release-readiness.json` digest; watch CI and the release; check assets, SHA256SUMS, latest/download links and run a downloaded binary
- [ ] 8. Site: one post on tokening.net plus Quick start, Download and Reference updates; check the Pages deploy once

**Resume here.** Step 6 review is written (`docs/review-v0.1.2.md`) and its fixes are pushed; once that CI run is green, tick step 6 and do step 7: set the version constant to 0.1.2 and `release-readiness.json` to version 0.1.2, approved, with `python3 scripts/release.py digest` as `source_sha256` and the current main SHA as `base_commit`, in one commit. Local note: this sandbox cannot reach proxy.golang.org or modernc.org, so database tests run in CI; `internal/flight` tests run anywhere.
