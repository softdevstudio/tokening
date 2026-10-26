# v0.1.0 independent release review

Date: 2026-10-26. Reviewer: the separate release_review agent, working independently of the implementing agent. Scope: matcher, consumer, persistence, vault, REST/MCP forwarding, admin boundary, replay export and release automation. This is a source review and project release check, not an external security audit.

The reviewer found no authorization bypass, credential-custody defect or single-use transaction blocker. The review preserved the documented v0.1 boundaries, including buffered MCP responses, unsupported server-to-client methods and deferred stdio targets.

Three transport findings were closed. Unknown-token MCP tool calls now keep their refusal audit record and return HTTP 401 with WWW-Authenticate. Failed upstream initialization and initialized notifications retain their actual HTTP status in the linked completion record. The SSE reader accepts CR, LF, CRLF and one initial UTF-8 BOM. Regression tests cover these cases; the reviewer also reran independent overlay reproductions against the fixes.

Release automation findings were closed before approval. Draft or partial releases can resume only at the reviewed source commit. Remote tags are checked again before uploading or publishing. An explicit publish-job status condition prevents a deliberately skipped manual-check ancestor from suppressing automatic publication. The evidence guard requires the complete 1,000-run race and at least two callers. The test serializes actual SQL counters and an executed-run counter. Relative README links are present in every archive. Rebuilding an older tag does not move the latest pointer backwards.

The release candidate is bound to the tracked source digest in release-readiness.json. Application source, tests, scripts, workflows, examples, notices and manuals are covered. This review document, the readiness record and TODO.md are excluded to avoid a self-reference. Every native build and extracted-archive smoke test must still pass before publication. The release's test-results.json records the fresh CI evidence and the review digest.

The first native workflow run exposed module-download diagnostics mixed into the structured test log. Native test recording now preserves stdout as JSONL and stderr in a separate log. A regression test simulates download output while checking that the required evidence remains parseable. The independent reviewer checked this correction before the release digest was refreshed.

The native Windows run also found a test fixture using a question mark in a filesystem name. Windows rejects that character before SQLite is opened. The fixture retains the question-mark case on Unix and uses the valid space/hash/percent filename on Windows, preserving URI escaping coverage on both systems. No production path validation was relaxed.

The next native run passed four targets but caught concurrent initializers contending while switching SQLite to WAL on Intel macOS. Startup now retries only typed SQLITE_BUSY/SQLITE_LOCKED errors, including extended codes, within a caller-aware five-second limit. A real held-read-lock regression checks recovery and cancellation. The independent reviewer found no blocker in this correction; transaction and grant-consumption behavior are unchanged.
