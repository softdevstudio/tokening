# v0.1.1 independent release review

Date: 2026-10-26. Reviewer: a separate review agent, working independently of the implementing agent. Scope: the diff from v0.1.0 (fb5b425) to the release candidate, covering refusal wording in the matcher, the grant self-description, the replay projection and page, the Docker demo recording, the browser check, docs and version. This is a source review and project release check, not an external security audit.

First pass: changes requested. No authorization decision changed and no reason leaked a string value, hash or secret, but CI was red on the browser check. Should-fix and notes: missing tests for the new reason rules and replay projection; caller-supplied names quoted only when they held spaces or quotes; "Allowed: ." when a group had no rules; a confusing message for an MCP call to a REST grant; unsorted replay argument keys.

Fixes: the browser check's own error was surfaced through a single CI annotation. It showed the replay header 11px past a 390px screen once the wordmark read tokening.net; the header now wraps. An earlier failure was the injection check expecting the final title at step 0. Tests were added for reason values, name cutting and escaping, and replay step projection. quoteShort now keeps plain identifiers bare and quotes everything else with strconv.QuoteToGraphic. The edge-case wordings were fixed and argument keys are sorted. The embedded replay reports the height of its content.

Second pass: approved. CI run 40381297127 passed on Linux, macOS, the Docker WordPress demo and the browser checks. Decisions are unchanged; the new branches only choose wording. The embed message carries a number only. The live console's behaviour is unchanged.

Open notes for v0.1.2, none blocking: a call with the right method but an unsafe path reads "call used PATCH", which looks odd; the "no query rules" wording is not reached by its test, which needs a REST grant; the replay step test does not cover the 8-argument cap or sort order.
