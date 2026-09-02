-- Schema version 1: nodes and join tokens.
--
-- One schema serves both backends. Two conventions make that possible without
-- per-dialect files:
--
--   * Timestamps are BIGINT unix nanoseconds, not a date type. SQLite has no native
--     timestamp and Postgres has several; storing an integer means one Go scan path, one
--     comparison semantics, and no timezone ambiguity in a dump. NULL means "never".
--   * Binary values are base64 TEXT rather than BLOB/BYTEA, which differ in name and in
--     driver handling. The only binary value here is a public key, so the encoding cost
--     is irrelevant and the portability is free.
--
-- SQLite resolves BIGINT and DOUBLE PRECISION by type affinity, so the declarations below
-- are accepted verbatim by both engines.

CREATE TABLE nodes (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL UNIQUE,
    status           TEXT NOT NULL,
    arch             TEXT NOT NULL DEFAULT '',
    version          TEXT NOT NULL DEFAULT '',
    protocol         BIGINT NOT NULL DEFAULT 0,
    agent_pubkey     TEXT NOT NULL DEFAULT '',
    applied_revision TEXT NOT NULL DEFAULT '',
    zone             TEXT NOT NULL DEFAULT '',
    private_addr     TEXT NOT NULL DEFAULT '',
    public_addr      TEXT NOT NULL DEFAULT '',
    cpu_cores        DOUBLE PRECISION NOT NULL DEFAULT 0,
    memory_bytes     BIGINT NOT NULL DEFAULT 0,
    disk_bytes       BIGINT NOT NULL DEFAULT 0,
    enrolled_at      BIGINT,
    last_seen_at     BIGINT,
    created_at       BIGINT NOT NULL,
    updated_at       BIGINT NOT NULL
);

CREATE INDEX idx_nodes_status ON nodes (status);
CREATE INDEX idx_nodes_zone ON nodes (zone);

CREATE TABLE join_tokens (
    id           TEXT PRIMARY KEY,
    hash         TEXT NOT NULL UNIQUE,
    node_hint    TEXT NOT NULL DEFAULT '',
    created_by   TEXT NOT NULL DEFAULT '',
    created_at   BIGINT NOT NULL,
    expires_at   BIGINT NOT NULL,
    used_at      BIGINT,
    used_by_node TEXT NOT NULL DEFAULT '',
    revoked_at   BIGINT
);

CREATE INDEX idx_join_tokens_expires ON join_tokens (expires_at);
