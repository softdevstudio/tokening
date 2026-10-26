-- Historical template versions stay immutable. This separate set controls
-- which version may issue new grants after a policy reload.
CREATE TABLE active_templates (
    id TEXT PRIMARY KEY NOT NULL,
    version INTEGER NOT NULL,
    FOREIGN KEY (id, version) REFERENCES templates(id, version)
) STRICT;
