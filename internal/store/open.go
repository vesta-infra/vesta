package store

import (
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// Open returns a Store for the given DSN.
//
// The DSN decides the backend, so callers configure one string rather than a string plus
// a flag that can disagree with it:
//
//	postgres://user:pass@host:5432/vesta   external or bundled Postgres (§2.5)
//	sqlite:///var/lib/vesta/vesta.db       file-backed SQLite
//	sqlite://:memory:                      tests
func Open(dsn string) (Store, error) {
	switch {
	case strings.HasPrefix(dsn, "postgres://"), strings.HasPrefix(dsn, "postgresql://"):
		return openPostgres(dsn)
	case strings.HasPrefix(dsn, "sqlite://"):
		return openSQLite(strings.TrimPrefix(dsn, "sqlite://"))
	default:
		return nil, fmt.Errorf("store: unrecognised DSN %q: expected a postgres:// or sqlite:// URL", redactDSN(dsn))
	}
}

func openPostgres(dsn string) (Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open postgres: %w", err)
	}
	// The control plane is not a high-concurrency workload, and an unbounded pool against
	// a bundled single-container Postgres is a way to exhaust its connection limit rather
	// than to go faster.
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(4)
	return &sqlStore{db: db, dialect: Postgres}, nil
}

func openSQLite(path string) (Store, error) {
	// WAL for concurrent readers alongside the writer, foreign keys on, and a busy
	// timeout so a concurrent writer waits instead of immediately returning SQLITE_BUSY.
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open sqlite: %w", err)
	}
	// SQLite permits exactly one writer. Allowing the pool to open several connections
	// converts what would be an in-process wait into SQLITE_BUSY errors surfacing to
	// callers, so the pool is capped at one and the queueing happens here.
	db.SetMaxOpenConns(1)
	return &sqlStore{db: db, dialect: SQLite}, nil
}

// redactDSN removes credentials before a DSN reaches an error message or a log.
func redactDSN(dsn string) string {
	at := strings.LastIndex(dsn, "@")
	scheme := strings.Index(dsn, "://")
	if at < 0 || scheme < 0 || at < scheme {
		return dsn
	}
	return dsn[:scheme+3] + "***@" + dsn[at+1:]
}
