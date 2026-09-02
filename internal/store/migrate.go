package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

type migration struct {
	version int
	name    string
	sql     string
}

func loadMigrations() ([]migration, error) {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("store: read migrations: %w", err)
	}
	var out []migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		// 0001_init.sql -> version 1, name "init"
		base := strings.TrimSuffix(e.Name(), ".sql")
		numStr, name, ok := strings.Cut(base, "_")
		if !ok {
			return nil, fmt.Errorf("store: migration %q is not named <version>_<name>.sql", e.Name())
		}
		version, err := strconv.Atoi(numStr)
		if err != nil {
			return nil, fmt.Errorf("store: migration %q has a non-numeric version: %w", e.Name(), err)
		}
		body, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("store: read %s: %w", e.Name(), err)
		}
		out = append(out, migration{version: version, name: name, sql: string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })

	for i, m := range out {
		if m.version != i+1 {
			return nil, fmt.Errorf("store: migration versions must be contiguous from 1; found %d at position %d", m.version, i+1)
		}
	}
	return out, nil
}

// migrate applies every migration newer than the recorded version, each in its own
// transaction, holding a lock so two control planes starting at once cannot both apply.
//
// Migrations are forward-only. Rolling a binary back across a migration boundary requires
// the pre-migration backup, which is why expand/contract matters: the release that stops
// writing a column is never the release that drops it (§23.4).
func migrate(ctx context.Context, db *sql.DB, d Dialect) error {
	migrations, err := loadMigrations()
	if err != nil {
		return err
	}

	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    BIGINT PRIMARY KEY,
		name       TEXT NOT NULL,
		applied_at BIGINT NOT NULL
	)`); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}

	unlock, err := lockForMigration(ctx, db, d)
	if err != nil {
		return err
	}
	defer unlock()

	var current int
	row := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`)
	if err := row.Scan(&current); err != nil {
		return fmt.Errorf("store: read schema version: %w", err)
	}

	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("store: begin migration %d: %w", m.version, err)
		}
		if _, err := tx.ExecContext(ctx, m.sql); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: migration %d (%s) failed: %w", m.version, m.name, err)
		}
		if _, err := tx.ExecContext(ctx,
			rebind(d, `INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`),
			m.version, m.name, time.Now().UnixNano()); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: record migration %d: %w", m.version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store: commit migration %d: %w", m.version, err)
		}
	}
	return nil
}

// lockForMigration serialises concurrent starts.
//
// Postgres has advisory locks, which is the right tool. SQLite is a single file with a
// single writer, so the transaction in migrate() is already the mutual exclusion — there
// is nothing to take, and pretending otherwise would add a failure mode without adding
// safety.
func lockForMigration(ctx context.Context, db *sql.DB, d Dialect) (func(), error) {
	if d != Postgres {
		return func() {}, nil
	}
	const lockID = 0x5645_5354 // "VEST"
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: acquire connection for migration lock: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, lockID); err != nil {
		conn.Close()
		return nil, fmt.Errorf("store: take migration lock: %w", err)
	}
	return func() {
		// Best effort: if unlocking fails the session is ending anyway, and Postgres
		// releases advisory locks when the connection closes.
		conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, lockID)
		conn.Close()
	}, nil
}

// rebind converts `?` placeholders to the dialect's form.
//
// This is the entire dialect difference in the query layer. Keeping it to one function,
// applied at the edge, is what stops "supports two backends" from meaning "two sets of
// SQL that drift apart".
func rebind(d Dialect, query string) string {
	if d != Postgres {
		return query
	}
	var b strings.Builder
	n := 0
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(query[i])
	}
	return b.String()
}
