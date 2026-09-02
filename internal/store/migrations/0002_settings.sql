-- Schema version 2: a small key/value table for control-plane state that has no better
-- home — the bootstrap admin token hash, the configured control-plane domain, and the
-- like. Deliberately not a dumping ground: anything with structure gets its own table.

CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at BIGINT NOT NULL
);
