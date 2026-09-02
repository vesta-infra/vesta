package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// Every test below runs against every configured backend.
//
// SQLite always runs. Postgres runs when VESTA_TEST_POSTGRES is set, and CI must set it —
// §2.5 commits to exercising both on every commit, and a suite that only ever runs
// against the convenient one is how the other quietly stops working. When it is unset the
// suite says so rather than passing silently, so a green local run is not mistaken for
// full coverage.
func eachBackend(t *testing.T, fn func(t *testing.T, s Store)) {
	t.Helper()

	backends := []struct {
		name string
		dsn  string
	}{{"sqlite", "sqlite://:memory:"}}

	if dsn := os.Getenv("VESTA_TEST_POSTGRES"); dsn != "" {
		backends = append(backends, struct{ name, dsn string }{"postgres", dsn})
	} else {
		t.Log("VESTA_TEST_POSTGRES is unset: Postgres coverage skipped (CI must set it)")
	}

	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			s, err := Open(b.dsn)
			if err != nil {
				t.Fatalf("Open(%s): %v", b.name, err)
			}
			t.Cleanup(func() { s.Close() })

			ctx := context.Background()
			if b.name == "postgres" {
				// Each run starts from a clean schema so ordering between tests cannot
				// matter. SQLite gets this for free by being in-memory per connection.
				//
				// The whole schema is dropped rather than a list of tables: a list has to
				// be updated by every future migration, and forgetting leaves a stale
				// table behind while schema_migrations is reset — which presents as
				// "relation already exists" on a migration that is perfectly correct.
				if _, err := s.(*sqlStore).db.ExecContext(ctx,
					"DROP SCHEMA public CASCADE; CREATE SCHEMA public"); err != nil {
					t.Fatalf("reset schema: %v", err)
				}
			}
			if err := s.Migrate(ctx); err != nil {
				t.Fatalf("Migrate(%s): %v", b.name, err)
			}
			fn(t, s)
		})
	}
}

func now() time.Time { return time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC) }

func TestMigrateIsIdempotent(t *testing.T) {
	eachBackend(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		// Migrate runs on every control-plane start, so running it against an
		// already-current schema must be a no-op rather than an error.
		for i := 0; i < 3; i++ {
			if err := s.Migrate(ctx); err != nil {
				t.Fatalf("re-running Migrate failed on attempt %d: %v", i+2, err)
			}
		}
	})
}

func TestNodeLifecycle(t *testing.T) {
	eachBackend(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		n := Node{ID: "n1", Name: "hetzner-1", Status: NodePending, CreatedAt: now()}
		if err := s.Nodes().Create(ctx, n); err != nil {
			t.Fatalf("Create: %v", err)
		}

		// A name is the operator's handle for a machine; two nodes sharing one would make
		// every subsequent instruction ambiguous.
		dup := Node{ID: "n2", Name: "hetzner-1", Status: NodePending, CreatedAt: now()}
		if err := s.Nodes().Create(ctx, dup); !errors.Is(err, ErrConflict) {
			t.Fatalf("duplicate node name should conflict, got %v", err)
		}

		got, err := s.Nodes().Get(ctx, "n1")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Name != "hetzner-1" || got.Status != NodePending {
			t.Fatalf("unexpected node %+v", got)
		}
		if !got.CreatedAt.Equal(now()) {
			t.Fatalf("timestamp did not round-trip: got %v want %v", got.CreatedAt, now())
		}

		if _, err := s.Nodes().Get(ctx, "missing"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}

		in := EnrollInput{
			Arch: "linux/arm64", Version: "0.1.0", Protocol: 1,
			AgentPubkey: "cHVia2V5", Zone: "hel1", PrivateAddr: "10.0.0.4",
			CPUCores: 4, MemoryBytes: 8 << 30,
		}
		if err := s.Nodes().Enroll(ctx, "n1", in, now()); err != nil {
			t.Fatalf("Enroll: %v", err)
		}
		got, _ = s.Nodes().Get(ctx, "n1")
		if got.Status != NodeActive || got.Zone != "hel1" || got.CPUCores != 4 {
			t.Fatalf("enrollment did not record identity: %+v", got)
		}
		enrolledFirst := got.EnrolledAt

		// An agent whose connection dropped mid-enrollment retries. That must succeed,
		// and must not rewrite when the node originally joined.
		later := now().Add(time.Hour)
		if err := s.Nodes().Enroll(ctx, "n1", in, later); err != nil {
			t.Fatalf("re-enrollment must be idempotent: %v", err)
		}
		got, _ = s.Nodes().Get(ctx, "n1")
		if !got.EnrolledAt.Equal(enrolledFirst) {
			t.Fatalf("re-enrollment moved enrolled_at from %v to %v", enrolledFirst, got.EnrolledAt)
		}
	})
}

func TestRemovedNodeIsUnauthorizedAndCannotReEnroll(t *testing.T) {
	eachBackend(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		if err := s.Nodes().Create(ctx, Node{ID: "n1", Name: "a", Status: NodeActive, CreatedAt: now()}); err != nil {
			t.Fatal(err)
		}
		if err := s.Nodes().IsAuthorized(ctx, "n1"); err != nil {
			t.Fatalf("an active node should be authorized: %v", err)
		}

		if err := s.Nodes().SetStatus(ctx, "n1", NodeRemoved, now()); err != nil {
			t.Fatal(err)
		}
		// This backs the TLS handshake check: removal takes effect on the next
		// connection, not at certificate expiry.
		if err := s.Nodes().IsAuthorized(ctx, "n1"); err == nil {
			t.Fatal("a removed node is still authorized")
		}
		// And a removed node must not be able to re-enroll its way back in.
		if err := s.Nodes().Enroll(ctx, "n1", EnrollInput{}, now()); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a removed node re-enrolled, got %v", err)
		}
		if err := s.Nodes().IsAuthorized(ctx, "unknown"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("an unknown node should be ErrNotFound, got %v", err)
		}
	})
}

func TestHeartbeatRecoversAnUnreachableNode(t *testing.T) {
	eachBackend(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		s.Nodes().Create(ctx, Node{ID: "n1", Name: "a", Status: NodeActive, CreatedAt: now()})
		s.Nodes().SetStatus(ctx, "n1", NodeUnreachable, now())

		if err := s.Nodes().Heartbeat(ctx, "n1", "rev-abc", now().Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		got, _ := s.Nodes().Get(ctx, "n1")
		if got.Status != NodeActive {
			t.Fatalf("a node that reported in is still %s", got.Status)
		}
		if got.AppliedRevision != "rev-abc" {
			t.Fatalf("applied revision not recorded: %q", got.AppliedRevision)
		}

		// A heartbeat must never resurrect a removed node: it is a liveness signal, not
		// an authorization decision.
		s.Nodes().SetStatus(ctx, "n1", NodeRemoved, now())
		s.Nodes().Heartbeat(ctx, "n1", "rev-def", now().Add(2*time.Minute))
		got, _ = s.Nodes().Get(ctx, "n1")
		if got.Status != NodeRemoved {
			t.Fatalf("a heartbeat resurrected a removed node to %s", got.Status)
		}
	})
}

func TestJoinTokenIsConsumedExactlyOnce(t *testing.T) {
	eachBackend(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		rec := JoinTokenRecord{
			ID: "t1", Hash: "hash-1", NodeHint: "hetzner-2", CreatedBy: "admin",
			CreatedAt: now(), ExpiresAt: now().Add(time.Hour),
		}
		if err := s.JoinTokens().Create(ctx, rec); err != nil {
			t.Fatalf("Create: %v", err)
		}

		active, err := s.JoinTokens().ListActive(ctx, now())
		if err != nil || len(active) != 1 {
			t.Fatalf("expected one active token, got %d (%v)", len(active), err)
		}

		got, err := s.JoinTokens().Consume(ctx, "hash-1", "n1", now())
		if err != nil {
			t.Fatalf("Consume: %v", err)
		}
		if got.UsedByNode != "n1" || got.UsedAt == nil {
			t.Fatalf("consumption not recorded: %+v", got)
		}

		// Single-use has to hold on the second attempt, not merely be documented.
		if _, err := s.JoinTokens().Consume(ctx, "hash-1", "n2", now()); !errors.Is(err, ErrConflict) {
			t.Fatalf("a token was consumed twice, got %v", err)
		}
		if active, _ := s.JoinTokens().ListActive(ctx, now()); len(active) != 0 {
			t.Fatalf("a consumed token is still listed active")
		}
	})
}

func TestJoinTokenRejectsExpiredAndRevoked(t *testing.T) {
	eachBackend(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		s.JoinTokens().Create(ctx, JoinTokenRecord{
			ID: "expired", Hash: "h-exp", CreatedAt: now(), ExpiresAt: now().Add(time.Minute),
		})
		s.JoinTokens().Create(ctx, JoinTokenRecord{
			ID: "revoked", Hash: "h-rev", CreatedAt: now(), ExpiresAt: now().Add(time.Hour),
		})
		if err := s.JoinTokens().Revoke(ctx, "revoked", now()); err != nil {
			t.Fatal(err)
		}

		if _, err := s.JoinTokens().Consume(ctx, "h-exp", "n1", now().Add(time.Hour)); !errors.Is(err, ErrConflict) {
			t.Fatalf("an expired token was accepted, got %v", err)
		}
		if _, err := s.JoinTokens().Consume(ctx, "h-rev", "n1", now()); !errors.Is(err, ErrConflict) {
			t.Fatalf("a revoked token was accepted, got %v", err)
		}
		if _, err := s.JoinTokens().Consume(ctx, "h-unknown", "n1", now()); !errors.Is(err, ErrConflict) {
			t.Fatalf("an unknown token was accepted, got %v", err)
		}
	})
}

// The property that matters under load: two agents presenting the same token at the same
// moment must not both enroll. A read-then-write implementation passes the sequential
// test above and fails this one.
func TestJoinTokenConsumeIsAtomicUnderConcurrency(t *testing.T) {
	eachBackend(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		s.JoinTokens().Create(ctx, JoinTokenRecord{
			ID: "t1", Hash: "race", CreatedAt: now(), ExpiresAt: now().Add(time.Hour),
		})

		const racers = 8
		var (
			wg        sync.WaitGroup
			mu        sync.Mutex
			succeeded int
		)
		start := make(chan struct{})
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				if _, err := s.JoinTokens().Consume(ctx, "race", fmt.Sprintf("n%d", i), now()); err == nil {
					mu.Lock()
					succeeded++
					mu.Unlock()
				}
			}(i)
		}
		close(start)
		wg.Wait()

		if succeeded != 1 {
			t.Fatalf("%d of %d concurrent claims succeeded; a join token must be usable exactly once", succeeded, racers)
		}
	})
}

func TestRedactDSNRemovesCredentials(t *testing.T) {
	// A DSN reaches error messages and logs. The password must not travel with it.
	got := redactDSN("postgres://vesta:hunter2@db.internal:5432/vesta")
	if got != "postgres://***@db.internal:5432/vesta" {
		t.Fatalf("credentials survived redaction: %s", got)
	}
	if got := redactDSN("sqlite:///var/lib/vesta/vesta.db"); got != "sqlite:///var/lib/vesta/vesta.db" {
		t.Fatalf("a credential-free DSN was mangled: %s", got)
	}
}

func TestRebindOnlyRewritesForPostgres(t *testing.T) {
	const q = `SELECT a FROM t WHERE b = ? AND c = ?`
	if got := rebind(SQLite, q); got != q {
		t.Fatalf("sqlite query was rewritten: %s", got)
	}
	want := `SELECT a FROM t WHERE b = $1 AND c = $2`
	if got := rebind(Postgres, q); got != want {
		t.Fatalf("postgres rebind wrong:\n got %s\nwant %s", got, want)
	}
}

func TestMigrationsAreContiguous(t *testing.T) {
	// A gap means a file was deleted or misnamed, and a schema that skips a version is a
	// schema nobody can reason about afterwards.
	ms, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if len(ms) == 0 {
		t.Fatal("no migrations found: the embed directive is not matching")
	}
	for i, m := range ms {
		if m.version != i+1 {
			t.Fatalf("migration %d is version %d; versions must run 1..n without gaps", i, m.version)
		}
	}
}
