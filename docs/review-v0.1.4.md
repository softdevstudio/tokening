# Review: v0.1.4 flight verify fixes

Reviewed 2026-10-31 by Claude, as a second pass over its own change. No separate agent could be started from this session; a review by ChatGPT/Codex is welcome. This is a project source review, not an external security audit.

Scope: the three follow-ups found during the flight recorder case studies (`test/results/case-studies/flight/`). Base commit f561395.

## What changed

1. `tokening flight verify --head ""` read an empty value as "no head", skipped the check and exited 0. `cmd/tokening/flight.go` now notes whether `--head` was given at all (`flag.Visit`), refuses an empty or blank value with exit 2 and a message that names the likely cause (an empty heads file), and parses any given head before the database or file is opened. Malformed heads with a missing database used to exit 1 from the open; they now exit 2 like the rest. Test: `TestFlightVerifyRefusesEmptyOrMalformedHead`.
2. After a saved-head mismatch, `printReport` printed "Entries 1 to N verify. Last good head: N". Those entries link to each other, but a rebuilt chain does too, so the head confirms none of them. `flight.Report` gains `HeadMismatch` (set when the entry at the head's seq has another hash, or the log ends before the head) and `Shortened` (set by the new `Verifier.Shorter` when SQLite's counter is ahead of the last entry). The CLI now says the chain does not match the saved head and that entries after the last point matching a saved head cannot be trusted. A shorter log is described as "entries were removed, or the chain was rebuilt shorter" instead of "removed from the end", because the evidence cannot tell a cut-off log from a chain rebuilt without entries in the middle. When both the counter and a saved head show a shorter log, both flags are set and the head wording wins. Tests: `TestHeadMismatchIsMarked`, `TestShorterThanCounterIsNeutral`, `TestFlightVerifyHeadMismatchWording`, the updated 208-case tamper test in `internal/store`.
3. MCP `serverInfo` and the upstream `clientInfo` hard-coded "0.1.1". The version now lives only in `internal/version` (`const Version`). The binary, both MCP messages and `scripts/release.py` read it there. A local variable named `version` in the MCP handler was renamed `wireVersion` so it cannot shadow the package. Tests: `TestMCPReportsBuildVersion`, `TestVersionCommandUsesBuildVersion`, the updated release guard test.

## Checked

- Ordinary breaks without a head (edits, deletions, reorders, cut-off lines) print exactly what they did before, including "Entries 1 to N verify. Last good head", which is accurate there: nothing suggests those entries were rewritten.
- A head outside a partial export ("not in this export") is not marked as a mismatch; that case is about a filtered file, not a rewrite.
- `--head` exists only for `verify`, so `headSet` is never true for other subcommands and `head` is never dereferenced as nil.
- The JSON shape of `Report` only gains two `omitempty` fields.
- The log format, hashing, schema and grant handling are untouched.

## Not changed

- The "Broken at entry K: entry K has a different hash from the saved head: the log was rewritten from entry K or earlier" line stays; it was already accurate.
- Still open from v0.1.3: requests rejected before matching are not recorded; a database row with a malformed hash fails closed without naming the entry.

Approved for release as v0.1.4.
