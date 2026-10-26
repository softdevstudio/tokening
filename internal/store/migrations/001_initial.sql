CREATE TABLE targets (
    id TEXT PRIMARY KEY NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('http', 'mcp_http', 'mcp_stdio')),
    url_or_cmd TEXT NOT NULL,
    credential_type TEXT NOT NULL CHECK (credential_type IN ('basic', 'bearer', 'header', 'env')),
    credential_ref TEXT NOT NULL,
    cred_ciphertext BLOB,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE templates (
    id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    target_id TEXT NOT NULL REFERENCES targets(id),
    tool TEXT NOT NULL DEFAULT '',
    method TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    constraints_json TEXT NOT NULL CHECK (json_valid(constraints_json) AND json_type(constraints_json) = 'object'),
    max_ttl_s INTEGER NOT NULL CHECK (max_ttl_s > 0),
    max_uses INTEGER NOT NULL CHECK (max_uses > 0),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (id, version)
) STRICT;

CREATE TABLE grants (
    id TEXT PRIMARY KEY NOT NULL,
    secret_hash BLOB NOT NULL UNIQUE CHECK (length(secret_hash) = 32),
    template_id TEXT NOT NULL,
    template_version INTEGER NOT NULL,
    bound_args_json TEXT NOT NULL CHECK (json_valid(bound_args_json) AND json_type(bound_args_json) = 'object'),
    bound_query_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(bound_query_json) AND json_type(bound_query_json) = 'object'),
    initial_uses INTEGER NOT NULL CHECK (initial_uses > 0),
    uses_left INTEGER NOT NULL CHECK (uses_left >= 0 AND uses_left <= initial_uses),
    expires_at INTEGER NOT NULL,
    issued_to TEXT NOT NULL,
    reason TEXT NOT NULL,
    issued_by TEXT NOT NULL,
    revoked_at INTEGER,
    revoked_by TEXT,
    last_used_at INTEGER,
    created_at INTEGER NOT NULL,
    CHECK (expires_at > created_at),
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL)),
    FOREIGN KEY (template_id, template_version) REFERENCES templates(id, version)
) STRICT;

CREATE TABLE decisions (
    id INTEGER PRIMARY KEY,
    grant_id TEXT REFERENCES grants(id),
    at INTEGER NOT NULL,
    agent TEXT NOT NULL,
    tool TEXT NOT NULL,
    args_digest BLOB NOT NULL CHECK (length(args_digest) = 32),
    outcome TEXT NOT NULL CHECK (outcome IN ('allowed', 'refused')),
    code TEXT NOT NULL CHECK (code IN (
        'allowed', 'grant_unknown', 'grant_expired', 'grant_exhausted',
        'grant_revoked', 'tool_not_allowed', 'arg_mismatch',
        'arg_not_allowed', 'arg_limit', 'upstream_error'
    )),
    reason TEXT NOT NULL,
    upstream_status INTEGER CHECK (upstream_status BETWEEN 100 AND 599),
    latency_ms INTEGER CHECK (latency_ms >= 0)
) STRICT;

CREATE INDEX decisions_grant_at ON decisions(grant_id, at, id);
CREATE INDEX decisions_at ON decisions(at, id);
CREATE INDEX grants_expires_at ON grants(expires_at);

CREATE TRIGGER templates_no_update BEFORE UPDATE ON templates
BEGIN SELECT RAISE(ABORT, 'template versions are immutable'); END;
CREATE TRIGGER templates_no_delete BEFORE DELETE ON templates
BEGIN SELECT RAISE(ABORT, 'template versions are immutable'); END;
CREATE TRIGGER decisions_no_update BEFORE UPDATE ON decisions
BEGIN SELECT RAISE(ABORT, 'decisions are append-only'); END;
CREATE TRIGGER decisions_no_delete BEFORE DELETE ON decisions
BEGIN SELECT RAISE(ABORT, 'decisions are append-only'); END;
