package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type sqlStore struct {
	db      *sql.DB
	dialect Dialect
}

func (s *sqlStore) Dialect() Dialect { return s.dialect }
func (s *sqlStore) Close() error     { return s.db.Close() }
func (s *sqlStore) DB() *sql.DB      { return s.db }

func (s *sqlStore) Migrate(ctx context.Context) error { return migrate(ctx, s.db, s.dialect) }
func (s *sqlStore) Nodes() NodeRepo                   { return &nodeRepo{s} }
func (s *sqlStore) JoinTokens() JoinTokenRepo         { return &tokenRepo{s} }
func (s *sqlStore) Settings() SettingsRepo            { return &settingsRepo{s} }

func (s *sqlStore) q(query string) string { return rebind(s.dialect, query) }

// nullable time helpers. Timestamps are stored as unix nanoseconds with NULL meaning
// "never", so a zero time.Time and an absent value stay distinguishable.

func toNano(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UnixNano()
}

func toNanoPtr(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UnixNano()
}

func fromNano(n sql.NullInt64) time.Time {
	if !n.Valid {
		return time.Time{}
	}
	return time.Unix(0, n.Int64).UTC()
}

func fromNanoPtr(n sql.NullInt64) *time.Time {
	if !n.Valid {
		return nil
	}
	t := time.Unix(0, n.Int64).UTC()
	return &t
}

// isUniqueViolation recognises a duplicate-key error from either engine.
//
// Both drivers report it, in their own words and with their own error types. Matching on
// the message is unlovely, but the alternative — importing each driver's error package
// into the shared path — couples this file to both drivers and defeats the point.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint") || // sqlite, postgres
		strings.Contains(msg, "duplicate key") // postgres
}

// ---------------------------------------------------------------- nodes

type nodeRepo struct{ s *sqlStore }

const nodeColumns = `id, name, status, arch, version, protocol, agent_pubkey, applied_revision,
	zone, private_addr, public_addr, cpu_cores, memory_bytes, disk_bytes,
	enrolled_at, last_seen_at, created_at, updated_at`

func scanNode(sc interface{ Scan(...any) error }) (Node, error) {
	var n Node
	var enrolled, lastSeen sql.NullInt64
	var created, updated int64
	err := sc.Scan(&n.ID, &n.Name, &n.Status, &n.Arch, &n.Version, &n.Protocol, &n.AgentPubkey,
		&n.AppliedRevision, &n.Zone, &n.PrivateAddr, &n.PublicAddr, &n.CPUCores, &n.MemoryBytes,
		&n.DiskBytes, &enrolled, &lastSeen, &created, &updated)
	if err != nil {
		return Node{}, err
	}
	n.EnrolledAt = fromNano(enrolled)
	n.LastSeenAt = fromNano(lastSeen)
	n.CreatedAt = time.Unix(0, created).UTC()
	n.UpdatedAt = time.Unix(0, updated).UTC()
	return n, nil
}

func (r *nodeRepo) Create(ctx context.Context, n Node) error {
	if n.ID == "" || n.Name == "" {
		return errors.New("store: node requires an id and a name")
	}
	if n.CreatedAt.IsZero() {
		n.CreatedAt = time.Now().UTC()
	}
	n.UpdatedAt = n.CreatedAt
	_, err := r.s.db.ExecContext(ctx, r.s.q(`INSERT INTO nodes (`+nodeColumns+`)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`),
		n.ID, n.Name, string(n.Status), n.Arch, n.Version, n.Protocol, n.AgentPubkey,
		n.AppliedRevision, n.Zone, n.PrivateAddr, n.PublicAddr, n.CPUCores, n.MemoryBytes,
		n.DiskBytes, toNano(n.EnrolledAt), toNano(n.LastSeenAt),
		n.CreatedAt.UnixNano(), n.UpdatedAt.UnixNano())
	if isUniqueViolation(err) {
		return fmt.Errorf("%w: node %q already exists", ErrConflict, n.Name)
	}
	if err != nil {
		return fmt.Errorf("store: create node: %w", err)
	}
	return nil
}

func (r *nodeRepo) Get(ctx context.Context, id string) (Node, error) {
	row := r.s.db.QueryRowContext(ctx, r.s.q(`SELECT `+nodeColumns+` FROM nodes WHERE id = ?`), id)
	n, err := scanNode(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, fmt.Errorf("%w: node %s", ErrNotFound, id)
	}
	if err != nil {
		return Node{}, fmt.Errorf("store: get node: %w", err)
	}
	return n, nil
}

func (r *nodeRepo) GetByName(ctx context.Context, name string) (Node, error) {
	row := r.s.db.QueryRowContext(ctx, r.s.q(`SELECT `+nodeColumns+` FROM nodes WHERE name = ?`), name)
	n, err := scanNode(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, fmt.Errorf("%w: node %q", ErrNotFound, name)
	}
	if err != nil {
		return Node{}, fmt.Errorf("store: get node by name: %w", err)
	}
	return n, nil
}

func (r *nodeRepo) List(ctx context.Context) ([]Node, error) {
	rows, err := r.s.db.QueryContext(ctx, `SELECT `+nodeColumns+` FROM nodes ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: list nodes: %w", err)
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan node: %w", err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// Enroll is idempotent: an agent whose connection dropped mid-enrollment retries, and
// must be accepted rather than refused for having already partly succeeded.
func (r *nodeRepo) Enroll(ctx context.Context, id string, in EnrollInput, now time.Time) error {
	res, err := r.s.db.ExecContext(ctx, r.s.q(`UPDATE nodes SET
		status = ?, arch = ?, version = ?, protocol = ?, agent_pubkey = ?,
		zone = ?, private_addr = ?, public_addr = ?,
		cpu_cores = ?, memory_bytes = ?, disk_bytes = ?,
		enrolled_at = COALESCE(enrolled_at, ?), last_seen_at = ?, updated_at = ?
		WHERE id = ? AND status <> ?`),
		string(NodeActive), in.Arch, in.Version, in.Protocol, in.AgentPubkey,
		in.Zone, in.PrivateAddr, in.PublicAddr,
		in.CPUCores, in.MemoryBytes, in.DiskBytes,
		now.UnixNano(), now.UnixNano(), now.UnixNano(),
		id, string(NodeRemoved))
	if err != nil {
		return fmt.Errorf("store: enroll node: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: enroll node: %w", err)
	}
	if n == 0 {
		// Either the node does not exist or it has been removed. Both mean the same
		// thing to a caller holding a certificate: you are not part of this fleet.
		return fmt.Errorf("%w: node %s is not enrollable", ErrNotFound, id)
	}
	return nil
}

func (r *nodeRepo) Heartbeat(ctx context.Context, id, appliedRevision string, now time.Time) error {
	_, err := r.s.db.ExecContext(ctx, r.s.q(`UPDATE nodes
		SET last_seen_at = ?, applied_revision = ?, updated_at = ?,
		    status = CASE WHEN status = ? THEN ? ELSE status END
		WHERE id = ?`),
		now.UnixNano(), appliedRevision, now.UnixNano(),
		string(NodeUnreachable), string(NodeActive), id)
	if err != nil {
		return fmt.Errorf("store: heartbeat: %w", err)
	}
	return nil
}

func (r *nodeRepo) SetStatus(ctx context.Context, id string, status NodeStatus, now time.Time) error {
	_, err := r.s.db.ExecContext(ctx,
		r.s.q(`UPDATE nodes SET status = ?, updated_at = ? WHERE id = ?`),
		string(status), now.UnixNano(), id)
	if err != nil {
		return fmt.Errorf("store: set node status: %w", err)
	}
	return nil
}

func (r *nodeRepo) IsAuthorized(ctx context.Context, id string) error {
	var status string
	row := r.s.db.QueryRowContext(ctx, r.s.q(`SELECT status FROM nodes WHERE id = ?`), id)
	if err := row.Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: node %s", ErrNotFound, id)
		}
		return fmt.Errorf("store: authorize node: %w", err)
	}
	if NodeStatus(status) == NodeRemoved {
		return fmt.Errorf("node %s has been removed from the fleet", id)
	}
	return nil
}

// ---------------------------------------------------------------- join tokens

type tokenRepo struct{ s *sqlStore }

const tokenColumns = `id, hash, node_hint, created_by, created_at, expires_at, used_at, used_by_node, revoked_at`

func scanToken(sc interface{ Scan(...any) error }) (JoinTokenRecord, error) {
	var t JoinTokenRecord
	var created, expires int64
	var used, revoked sql.NullInt64
	if err := sc.Scan(&t.ID, &t.Hash, &t.NodeHint, &t.CreatedBy, &created, &expires,
		&used, &t.UsedByNode, &revoked); err != nil {
		return JoinTokenRecord{}, err
	}
	t.CreatedAt = time.Unix(0, created).UTC()
	t.ExpiresAt = time.Unix(0, expires).UTC()
	t.UsedAt = fromNanoPtr(used)
	t.RevokedAt = fromNanoPtr(revoked)
	return t, nil
}

func (r *tokenRepo) Create(ctx context.Context, t JoinTokenRecord) error {
	_, err := r.s.db.ExecContext(ctx, r.s.q(`INSERT INTO join_tokens (`+tokenColumns+`)
		VALUES (?,?,?,?,?,?,?,?,?)`),
		t.ID, t.Hash, t.NodeHint, t.CreatedBy, t.CreatedAt.UnixNano(), t.ExpiresAt.UnixNano(),
		toNanoPtr(t.UsedAt), t.UsedByNode, toNanoPtr(t.RevokedAt))
	if isUniqueViolation(err) {
		return fmt.Errorf("%w: join token already exists", ErrConflict)
	}
	if err != nil {
		return fmt.Errorf("store: create join token: %w", err)
	}
	return nil
}

func (r *tokenRepo) ListActive(ctx context.Context, now time.Time) ([]JoinTokenRecord, error) {
	rows, err := r.s.db.QueryContext(ctx, r.s.q(`SELECT `+tokenColumns+` FROM join_tokens
		WHERE used_at IS NULL AND revoked_at IS NULL AND expires_at > ?
		ORDER BY created_at`), now.UnixNano())
	if err != nil {
		return nil, fmt.Errorf("store: list join tokens: %w", err)
	}
	defer rows.Close()
	var out []JoinTokenRecord
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan join token: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Consume marks a token used in a single conditional UPDATE.
//
// Doing this as read-then-write would leave a window in which two agents presenting the
// same token both see it unused. The WHERE clause is the mutual exclusion: exactly one
// caller can observe a row change, and everyone else gets ErrConflict.
func (r *tokenRepo) Consume(ctx context.Context, hash, nodeID string, now time.Time) (JoinTokenRecord, error) {
	res, err := r.s.db.ExecContext(ctx, r.s.q(`UPDATE join_tokens
		SET used_at = ?, used_by_node = ?
		WHERE hash = ? AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?`),
		now.UnixNano(), nodeID, hash, now.UnixNano())
	if err != nil {
		return JoinTokenRecord{}, fmt.Errorf("store: consume join token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return JoinTokenRecord{}, fmt.Errorf("store: consume join token: %w", err)
	}
	if n == 0 {
		return JoinTokenRecord{}, fmt.Errorf("%w: token is unknown, already used, revoked, or expired", ErrConflict)
	}
	row := r.s.db.QueryRowContext(ctx, r.s.q(`SELECT `+tokenColumns+` FROM join_tokens WHERE hash = ?`), hash)
	t, err := scanToken(row)
	if err != nil {
		return JoinTokenRecord{}, fmt.Errorf("store: reload consumed token: %w", err)
	}
	return t, nil
}

func (r *tokenRepo) Revoke(ctx context.Context, id string, now time.Time) error {
	_, err := r.s.db.ExecContext(ctx,
		r.s.q(`UPDATE join_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`),
		now.UnixNano(), id)
	if err != nil {
		return fmt.Errorf("store: revoke join token: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------- settings

type settingsRepo struct{ s *sqlStore }

func (r *settingsRepo) Get(ctx context.Context, key string) (string, error) {
	var v string
	row := r.s.db.QueryRowContext(ctx, r.s.q(`SELECT value FROM settings WHERE key = ?`), key)
	if err := row.Scan(&v); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("%w: setting %q", ErrNotFound, key)
		}
		return "", fmt.Errorf("store: get setting: %w", err)
	}
	return v, nil
}

// Set is an upsert. The ON CONFLICT form is spelled identically by SQLite and Postgres,
// which is why this needs no dialect branch.
func (r *settingsRepo) Set(ctx context.Context, key, value string, now time.Time) error {
	_, err := r.s.db.ExecContext(ctx, r.s.q(`INSERT INTO settings (key, value, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`),
		key, value, now.UnixNano())
	if err != nil {
		return fmt.Errorf("store: set setting: %w", err)
	}
	return nil
}
