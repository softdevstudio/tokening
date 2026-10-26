-- Completion records append to the audit log without modifying authorization.
ALTER TABLE decisions ADD COLUMN authorization_id INTEGER REFERENCES decisions(id);
CREATE UNIQUE INDEX decisions_one_completion ON decisions(authorization_id)
WHERE authorization_id IS NOT NULL;
