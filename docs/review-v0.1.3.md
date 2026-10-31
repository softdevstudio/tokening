# v0.1.3 review: independent review of the flight recorder

Date: 2026-10-31. Reviewer: Claude, in a separate session that did not write the v0.1.2 code, asked to look for real bugs and not to rely on the earlier self-review (`docs/review-v0.1.2.md`). It is a source review with tests, not an external security audit. The fixes below were written by the same reviewer, so a further read by ChatGPT/Codex is welcome; findings go in a new section at the end.

Scope: `internal/flight`, `internal/store/flight.go` and migration 004, the appends in grant issue and revoke, consume and upstream completion, the REST and MCP gateway paths that lead to them, `cmd/tokening/flight.go`, `docs/flight.md`, and the flight checks in `scripts/release.py` and the workflows.

Method: each suspected bug got a failing test first. Database tests cannot run in cloud sessions (proxy.golang.org and modernc.org are blocked), so the failing tests were pushed in 13610ef and their output read from CI annotations. CI now prints the output of any failing test as an error annotation for that reason. All four suspected bugs failed as expected on Linux and macOS before the fix.

## Confirmed bugs, fixed

1. Medium. `verify --file` accepted lines that were not what `export` writes. Go's JSON decoder takes the last of two repeated keys, matches keys without regard to case and ignores spaces, so a line such as `{"agent":"mallory","seq":1,...,"agent":"editor-bot",...}` verified. A reader that keeps the first key, or a plain text search, sees a value that verify never checked, and this works even for entries covered by a saved head. `UnmarshalLine` now re-encodes the entry and refuses any line that differs from the exact export bytes. Test: `TestNonCanonicalLinesAreRefused` (plus `TestCanonicalLineWithLineSeparators` for U+2028 and HTML characters).
2. Medium. `replay --file` checks a file as a partial export, then ended with "Chain intact through entry N" even when entries had been cut out of the middle of the file. It now says how many entries are missing and that this can be a filter or a removal. Test: `TestFlightReplayFileWithGapsIsNotCalledIntact`.
3. Low to medium. Any caller, even one with an unknown token, could make the export unverifiable from a file. The MCP tool name and argument names come from the agent and were written in full. Characters such as U+2028 take 3 bytes in the request and 6 once JSON-escaped, so a 1 MiB request produced a request entry over the 1 MiB line limit, and `verify --file` and `replay --file` stopped with "line is longer than 1 MiB". The action and target are now cut to 256 bytes and at most 100 argument and 100 query names of up to 128 bytes are kept, with `args_omitted` and `query_omitted` counting the rest. The digest still covers the whole call. Test: `TestFlightOversizedAgentInputStillExportsVerifiably`, `TestBoundNamesAndClip`.
4. Low. Replay printed the agent-chosen tool name unquoted when it held ordinary spaces, so a tool named `wp_get_post on demo-wp with no arguments (digest 000000000000); refused` read as part of the sentence. Names were also left bare when they held no-break or wide spaces. Tool names and paths are now bare only in their usual form (a plain tool name, or `METHOD /path`); names with any kind of space are quoted. Tests: `TestFormatEntryQuotesActionsWithSpaces`, `TestFormatEntryQuotesUnicodeSpaces`.

## Looked at and found sound

- Hash input: fixed-width seq and time, 32-bit length before kind, agent, grant and body, then prev, under a domain string. No two different entries hash the same input, and unicode in names is hashed as stored (invalid UTF-8 is replaced before the append).
- Bodies are hashed byte for byte and checked to be compact JSON objects; the encoder writes them unchanged (`SetEscapeHTML(false)`, raw bytes), so exports round-trip, including U+2028.
- Every append runs in the caller's write transaction, opened with `_txlock=immediate`, so reading the last hash and inserting cannot interleave across connections or processes. A failed append rolls back the use and the decision row. Read-only opens never write.
- Logging coverage: refusals for unknown, revoked, expired and exhausted grants, wrong tool, transport or target all go through `Consume` and get a request and decision entry. Upstream results are written from a deferred call with a context that outlives the client, so a failed connection, a timeout or a panic in forwarding still records the result. Early refusals for malformed or encoded requests are not recorded, which the docs say.
- Verifier: sequence gaps, reorders, repeats, a non-zero prev on entry 1, a log not starting at 1 and a head with another hash are all caught and named. `--partial` is refused for the database. The database check compares the AUTOINCREMENT counter with the last entry, read in an order that cannot give a false alarm during appends.
- Refusal reasons quote and shorten agent strings to 64 characters and never repeat string values. Numbers can appear, as documented.
- Replay quotes control characters, so a name cannot start a fake line or send terminal escapes.
- Export writes to a temporary file and renames it, never overwriting.

## Open, not fixed

- Digests have no secret key. `args_digest` and `bindings_digest` are plain SHA-256, so a short or guessable value such as a post ID can be found by trying candidates. This is the same digest the decisions table has stored since v0.1.0. A keyed digest (for example HMAC with a key kept next to the vault key) would close it but changes how an operator proves a call matches; that is a design choice for the owner. docs/flight.md now states the limit.
- A database row whose hash or prev is not 32 bytes (only possible with check constraints switched off) makes `verify` stop with "invalid flight entry in database" and exit 1 instead of naming the entry. It fails closed.
- Requests rejected before matching (for example a `_method` override or a field in both body and query) are not recorded in the decisions table or the flight log. Documented; worth reconsidering for v0.2.
- `replay --file` reads up to 1 GiB into memory. It is a local command on a file the operator picks.
- A hash chain without a saved head cannot stop someone who can rewrite the whole file or database. Documented.
