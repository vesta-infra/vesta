// Package store is the control plane's persistence layer.
//
// It exists as an interface with two implementations because the default install bundles
// Postgres while SQLite remains fully supported (ARCHITECTURE §2.5). Nothing above this
// package knows which backend is behind it: handlers, services and the scheduler take a
// Store, and dialect-specific SQL never leaves this directory.
//
// Supporting two backends means the less-used one rots unless that is actively prevented.
// It is prevented by running the same suite against both on every commit — see
// store_test.go — not by discipline.
package store

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("store: not found")
	ErrConflict = errors.New("store: conflicts with an existing record")
)

// Dialect names a backend. It is exposed because a few operational paths (migration,
// backup guidance) legitimately differ; query construction does not.
type Dialect string

const (
	SQLite   Dialect = "sqlite"
	Postgres Dialect = "postgres"
)

// NodeStatus tracks a node through enrollment and removal. A node is never silently
// deleted: removal is a status, so its history and its certificate's revocation remain
// answerable after the fact.
type NodeStatus string

const (
	NodePending     NodeStatus = "pending"     // token minted, agent has not yet enrolled
	NodeActive      NodeStatus = "active"      //
	NodeUnreachable NodeStatus = "unreachable" // missed heartbeats; workloads keep running
	NodeDraining    NodeStatus = "draining"    //
	NodeRemoved     NodeStatus = "removed"     // certificate no longer authorized
)

// Node is a machine in the fleet.
//
// Addresses are plural on purpose: peer selection uses the private address within a zone
// and the public one across zones (§10.6), and a node that has only one is a normal case
// rather than an error.
type Node struct {
	ID       string
	Name     string
	Status   NodeStatus
	Arch     string
	Version  string
	Protocol uint32

	// AgentPubkey is the node's ephemeral X25519 public key, base64. It changes on every
	// agent restart, which is what makes captured sealed bundles useless afterwards
	// (§11.2).
	AgentPubkey string

	AppliedRevision string

	Zone        string
	PrivateAddr string
	PublicAddr  string

	CPUCores    float64
	MemoryBytes int64
	DiskBytes   int64

	EnrolledAt time.Time
	LastSeenAt time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// Reachable reports whether the node should be sent Specs and counted for placement.
func (n Node) Reachable() bool {
	return n.Status == NodeActive || n.Status == NodeDraining
}

// Store is the whole persistence surface. It is deliberately narrow: every method here is
// one the control plane actually needs, and adding one is a decision rather than a
// convenience.
type Store interface {
	Dialect() Dialect
	Close() error

	// Migrate brings the schema to the latest version. Safe to call on every start; it
	// takes a lock so two control planes cannot race (§23.4).
	Migrate(ctx context.Context) error

	Nodes() NodeRepo
	JoinTokens() JoinTokenRepo
	Settings() SettingsRepo
}

// SettingsRepo holds small pieces of control-plane state that have no structured home.
type SettingsRepo interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string, now time.Time) error
}

type NodeRepo interface {
	Create(ctx context.Context, n Node) error
	Get(ctx context.Context, id string) (Node, error)
	GetByName(ctx context.Context, name string) (Node, error)
	List(ctx context.Context) ([]Node, error)

	// Enroll records a successful join: the node becomes active and its reported
	// identity is stored. It is idempotent, because an agent that reconnects after a
	// network failure mid-enrollment must not be refused.
	Enroll(ctx context.Context, id string, in EnrollInput, now time.Time) error

	Heartbeat(ctx context.Context, id string, appliedRevision string, now time.Time) error
	SetStatus(ctx context.Context, id string, status NodeStatus, now time.Time) error

	// IsAuthorized backs the TLS handshake check (ca.NodeAuthorizer), so a removed node
	// loses access at its next connection rather than at certificate expiry.
	IsAuthorized(ctx context.Context, id string) error
}

type EnrollInput struct {
	Arch        string
	Version     string
	Protocol    uint32
	AgentPubkey string
	Zone        string
	PrivateAddr string
	PublicAddr  string
	CPUCores    float64
	MemoryBytes int64
	DiskBytes   int64
}

type JoinTokenRepo interface {
	Create(ctx context.Context, t JoinTokenRecord) error
	ListActive(ctx context.Context, now time.Time) ([]JoinTokenRecord, error)

	// Consume marks a token used, atomically. It returns ErrConflict if the token was
	// already consumed, which is what makes single-use single-use under concurrency
	// rather than only under sequential access.
	Consume(ctx context.Context, hash string, nodeID string, now time.Time) (JoinTokenRecord, error)

	Revoke(ctx context.Context, id string, now time.Time) error
}

// JoinTokenRecord mirrors ca.JoinToken, holding only the hash. The secret is shown once,
// at mint time, and is not recoverable from here.
type JoinTokenRecord struct {
	ID         string
	Hash       string
	NodeHint   string
	CreatedBy  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	UsedAt     *time.Time
	UsedByNode string
	RevokedAt  *time.Time
}
