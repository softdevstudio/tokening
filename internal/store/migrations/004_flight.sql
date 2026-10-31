-- Flight recorder: one hash-chained entry per grant change, request, decision
-- and upstream result, written in the same transaction as the change itself.
-- AUTOINCREMENT keeps the largest seq ever assigned in sqlite_sequence, so
-- entries removed from the end leave a visible gap for the next append and a
-- counter that verify compares with the last entry.
CREATE TABLE flight (
    seq INTEGER PRIMARY KEY AUTOINCREMENT CHECK (seq > 0),
    at INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('grant', 'request', 'decision', 'result')),
    agent TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    body TEXT NOT NULL CHECK (json_valid(body) AND json_type(body) = 'object'),
    prev BLOB NOT NULL CHECK (length(prev) = 32),
    hash BLOB NOT NULL UNIQUE CHECK (length(hash) = 32)
) STRICT;

CREATE INDEX flight_grant ON flight(grant_id, seq);
CREATE INDEX flight_agent ON flight(agent, seq);
CREATE INDEX flight_at ON flight(at, seq);

CREATE TRIGGER flight_no_update BEFORE UPDATE ON flight
BEGIN SELECT RAISE(ABORT, 'flight entries are append-only'); END;
CREATE TRIGGER flight_no_delete BEFORE DELETE ON flight
BEGIN SELECT RAISE(ABORT, 'flight entries are append-only'); END;
