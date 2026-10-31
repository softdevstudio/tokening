# Flight recorder

Tokening grants a permission. The flight recorder keeps a record of what was done with it, in a form where changes show.

Every grant change and every call that passes through the gateway adds entries to an append-only log in the Tokening database: the grant being issued or revoked, each request an agent sends, the decision on that request, and the upstream result of an allowed call. Each entry carries the SHA-256 hash of the entry before it. Change one entry, delete one, move one or cut entries off the end, and `tokening flight verify` says which entry is broken and why.

The recorder needs no setup. A database created or upgraded by Tokening v0.1.2 records from that moment on. History from before the upgrade stays in the decisions table and is not part of the chain.

## What gets recorded

| Kind | When | Body |
| --- | --- | --- |
| `grant` | A grant is issued | `event: "issued"`, template and version, target, action, uses, expiry, who issued it and why, the names of bound arguments and a SHA-256 digest of the bindings |
| `grant` | A grant is revoked (first time only) | `event: "revoked"`, who revoked it |
| `request` | Any call reaches the gateway, including unknown tokens | target, action (MCP tool, or method and path), argument names, query names and the SHA-256 digest of the call. The action and target are cut to 256 bytes and at most 100 argument names (and 100 query names) of up to 128 bytes each are kept; `args_omitted` and `query_omitted` count the rest. The digest covers the whole call |
| `decision` | Straight after its request | `decision_id` (the row in the decisions table), outcome, code, the readable reason, and uses left after the decision |
| `result` | An allowed call finishes | `decision_id`, `authorization_id`, code, upstream HTTP status (or null when no answer came back) and latency |

Every entry also has `seq`, `at` (UTC, milliseconds), `kind`, `agent` (the grant's `issued_to`, empty for unknown tokens), `grant` (empty for unknown tokens), `prev` and `hash`.

A request here means an MCP `tools/call` or a REST call, the same calls that get a row in the decisions table. MCP `initialize`, `tools/list`, `ping` and `GET /grant` read the grant without spending anything and are not recorded. Neither are requests turned away before matching because they are malformed, too large or encoded. If the database fails after an allowed call was forwarded, the result entry can be missing; the decision entry stands and the server logs the failure.

Entries never hold credentials, bearer secrets, bearer hashes or argument values. A request lists argument names only. The digest is the same one the decisions table stores, so an operator who still has the original call can show that it matches. The digests are plain SHA-256 with no secret key, so a value that is short or easy to guess, such as a post ID, can be found by trying candidates. Treat an export like the decisions table and share it with people who may know which posts or records an agent touched. Reasons follow the refusal rules: numbers can appear, string values never do. The grant's `reason` text is the operator's own note from `grant issue`.

## How entries are chained

Entry `n` stores `hash(n)` and `prev`, which must equal `hash(n-1)`. Entry 1 has 32 zero bytes as `prev`. The hash is SHA-256 over this byte sequence:

1. the ASCII string `tokening-flight-v1`
2. `seq` as an unsigned 64-bit big-endian integer
3. `at` in Unix milliseconds as a signed 64-bit big-endian integer
4. `kind`, `agent`, `grant` and `body`, each as a 32-bit big-endian byte length followed by the bytes
5. the 32 bytes of `prev`

`body` is hashed exactly as stored: compact JSON, written once and never re-encoded. Anyone can recompute the chain from an export with a few lines of code in any language.

## Crashes and concurrent writers

Entries are written inside the same SQLite transaction as the change they describe. An allowed call's use, its decision row and its request and decision entries commit together or not at all. If the process dies mid-write, the transaction rolls back and the log ends at its last complete entry, which still verifies. If an entry cannot be written, the whole transaction fails: the agent gets a storage error, no use is spent and nothing is forwarded.

Every write transaction takes SQLite's write lock before it reads anything. The append reads the previous hash and inserts the next entry while holding that lock, so two writers, in one process or in several processes sharing the database file, can never both link to the same entry. A request and its decision are always next to each other.

## Commands

The flight commands open the database file read-only. They never create a file, change the schema or take the write lock, so they are safe to run next to a running server. `--db` defaults to `tokening.db` in the current directory.

```sh
tokening flight verify --db tokening.db
tokening flight head --db tokening.db
tokening flight replay --db tokening.db --agent editor-bot
tokening flight export --db tokening.db --grant g_ID --output g_ID.jsonl
tokening flight verify --file g_ID.jsonl --partial
```

`verify` checks the whole chain in the database, or a JSONL file with `--file` (`-` reads standard input). It exits 0 when the log is intact and 1 when it is not, and prints the first broken entry, the reason, and the last entry that still verifies:

```
Broken at entry 5: entry 4 is missing between entries 3 and 5.
Entries 1 to 3 verify. Last good head: 3:9c1e...
```

Each line of a file must be exactly what `export` writes, byte for byte. A line with an extra space, a repeated or renamed key or a different escape is refused, even when its hash still matches, because other JSON readers might show a different value from the one verify checked. A file whose last line was cut off by an interrupted write verifies up to its last complete entry and names the cut line. A filtered export skips entries on purpose, so it fails a normal check; `--partial` accepts it, checks every entry's own hash, and checks links wherever seq numbers are consecutive. Files whose lines are longer than 1 MiB are refused.

`head` prints the last entry as `SEQ:HASH`. Save it somewhere the database's owner cannot rewrite: a ticket, a commit, a message to a colleague, a printout. Later, `verify --head SEQ:HASH` proves that entry is still in the chain with the same hash.

A `--head` that is given must be a valid `SEQ:HASH`. An empty or malformed value is a usage error (exit 2), checked before the database or file is opened, so a script passing the last line of an empty heads file fails instead of skipping the check. Before 0.1.4 an empty `--head ""` was read as no head and verify exited 0.

When the chain does not match the saved head, verify says so and does not call the earlier entries good. They still link to each other, but a chain rebuilt from scratch does too:

```
Broken at entry 20: entry 20 has a different hash from the saved head: the log was rewritten from entry 20 or earlier.
The chain does not match the saved head.
Entries 1 to 19 link to each other, but so would a rebuilt chain. Entries after the last point that matches a saved head cannot be trusted; check an earlier saved head to find that point.
```

A log that ends before the saved head reads "the saved head is entry 20 but the log ends at entry 18: entries were removed, or the chain was rebuilt shorter". From the database alone, a cut-off log and a chain rebuilt without some entries in the middle look the same, so verify does not say where the entries went.

`replay` prints the matching entries in order as a readable timeline, then whether the chain is intact. It checks the full chain first, so a broken log is flagged even when the filter shows only one agent. With `--file`, entries missing from the file can be a filter or a removal, so the last line says how many are missing instead of calling the chain intact. Names, tool names and paths that hold spaces, quotes or control characters are printed quoted:

```
#12  2026-10-31T10:02:03.120Z  grant     g_1a2b issued to editor-bot by operator: wp.edit-post-text on wp_update_post, 1 use, expires 2026-10-31T10:17:03.120Z, bound id, reason "fix title"
#13  2026-10-31T10:02:05.410Z  request   g_1a2b editor-bot asked for wp_update_post on demo-wp with arguments id, title (digest 3f2a91c07d4e)
#14  2026-10-31T10:02:05.410Z  decision  g_1a2b allowed: Call fits this grant. One use was consumed before forwarding. 0 uses left.
#15  2026-10-31T10:02:05.494Z  result    g_1a2b upstream answered HTTP 200 in 84 ms
Chain intact through entry 15.
```

`export` writes JSONL, one entry per line, to standard output or to a new file with `--output`. A file export is written to a temporary file and renamed when complete, and an existing file is never overwritten. `export` and `replay` filter with `--agent`, `--grant`, `--since` (inclusive) and `--until` (exclusive). Times are RFC 3339, such as `2026-10-31T10:00:00Z`, or a UTC date such as `2026-10-31`. `replay --file` reads an export instead of the database.

An exported line:

```json
{"seq":14,"at":"2026-10-31T10:02:05.410Z","kind":"decision","agent":"editor-bot","grant":"g_1a2b","body":{"decision_id":7,"outcome":"allowed","code":"allowed","reason":"Call fits this grant. One use was consumed before forwarding.","uses_left":0},"prev":"5d0c...","hash":"9c1e..."}
```

## What it proves, and what it does not

The chain shows that nothing was edited, removed or reordered since the entries were written, as far as the entries themselves go. SQLite triggers also refuse updates and deletes during normal operation.

The table uses SQLite's AUTOINCREMENT counter, which remembers the largest seq ever assigned. A log that ends before that counter has lost entries, and `verify` reports it as "entries were removed, or the chain was rebuilt shorter", since the counter alone cannot show where they went. Any later append continues after the counter, so the gap stays in the chain.

A hash chain cannot stop someone who can write to the database file from rebuilding the whole chain from the first changed entry onward, and resetting the counter as well. A saved head catches that: the rebuilt chain will not contain the saved hash. Save a head at the points that matter to you, such as the end of each working day, after a sensitive grant, or before handing the database to someone else. A head proves everything up to it. Entries written after the last saved head are protected only by the chain and the counter.

The recorder is evidence of what passed through Tokening. It does not show what an agent did by other routes, and it does not record response bodies or argument values.

## Tests

`internal/flight` tests every single-field edit of every entry, every deletion, adjacent swaps with and without renumbering, truncation with a saved head, cut-off last lines, malformed lines and partial exports. `internal/store` builds a real 42-entry log through the grant, consume, completion and revoke paths, then edits, deletes, swaps and truncates it directly in SQLite with the triggers dropped. Each case must be caught at the right entry. Other store tests run eight connections and four separate processes appending at once, then check that the chain is whole and every request sits next to its decision. A writer process is killed at random moments twenty times; after each kill the log must verify, and every committed decision must have its two entries. The measured summary is printed as a `{"flight_recorder": ...}` line and copied into each release's `test-results.json`.
