# CLAUDE.md

All project instructions live in `AGENTS.md`, shared with ChatGPT/Codex. Read it first and follow it.

Where to start a session:

1. `git pull --rebase origin main`
2. Read `AGENTS.md`, then `TODO.md` (current state, next tasks, session log), then `docs/plan.md` as needed.
3. Work the next unticked task in `TODO.md`.
4. Before stopping, add a session log entry at the top of the log in `TODO.md` and push.

Don't put project rules in this file. If a rule changes, change it in `AGENTS.md` so both assistants see it.

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
- [ ] 3. CLI `tokening flight verify|export|replay|head`, tests
- [ ] 4. Recorded results: a `{"flight_recorder": ...}` summary line from the tests, parsed by `scripts/release.py` into `test-results.json`; new required tests listed there
- [ ] 5. Docs: `docs/flight.md`, README section, storage/audit docs, CHANGELOG for v0.1.2
- [ ] 6. Independent review (separate agent or a fresh second pass), fixes, results recorded again; `docs/review-v0.1.2.md`
- [ ] 7. Version 0.1.2 and approved `release-readiness.json` digest; watch CI and the release; check assets, SHA256SUMS, latest/download links and run a downloaded binary
- [ ] 8. Site: one post on tokening.net plus Quick start, Download and Reference updates; check the Pages deploy once

**Resume here.** Steps 3 (CLI, `cmd/tokening/flight.go`) and 4 (`scripts/release.py` parses the flight summary; CI prints both summaries as notice annotations, since job log and artifact hosts are blocked from cloud sessions) are pushed; confirm CI is green, then tick them. Step 5 (docs) is next. Local note: this sandbox cannot reach proxy.golang.org or modernc.org, so database tests run in CI; `internal/flight` tests run anywhere.
