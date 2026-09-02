package ca

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DefaultJoinTTL bounds how long a printed join command stays usable. An hour is enough
// to paste it into a terminal and long enough to survive being written down; it is not
// long enough for a token left in a chat log to be useful a week later.
const DefaultJoinTTL = time.Hour

var (
	ErrTokenUnknown = errors.New("ca: join token is not recognised")
	ErrTokenUsed    = errors.New("ca: join token has already been used")
	ErrTokenExpired = errors.New("ca: join token has expired")
	ErrTokenRevoked = errors.New("ca: join token was revoked")
)

// JoinToken is the record the control plane keeps. The secret itself is never stored:
// only its SHA-256, the same treatment API tokens get (§17.3). A leaked database
// therefore yields no usable join token.
type JoinToken struct {
	ID        string
	Hash      string // hex SHA-256 of the secret
	NodeHint  string // the name the operator intends this node to have
	CreatedBy string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
	RevokedAt *time.Time
}

// NewJoinToken mints a token, returning the secret exactly once. The caller shows it to
// the operator and stores only the record; there is no path that recovers the secret
// afterwards, by design.
func NewJoinToken(nodeHint, createdBy string, ttl time.Duration, now time.Time) (secret string, rec JoinToken, err error) {
	if ttl <= 0 {
		ttl = DefaultJoinTTL
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", JoinToken{}, fmt.Errorf("ca: generate join token: %w", err)
	}
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return "", JoinToken{}, fmt.Errorf("ca: generate token id: %w", err)
	}
	secret = base64.RawURLEncoding.EncodeToString(raw)
	rec = JoinToken{
		ID:        hex.EncodeToString(idBytes),
		Hash:      hashToken(secret),
		NodeHint:  nodeHint,
		CreatedBy: createdBy,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}
	return secret, rec, nil
}

func hashToken(secret string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(secret)))
	return hex.EncodeToString(sum[:])
}

// Verify checks a presented secret against a stored record.
//
// The comparison is constant-time. That matters less here than for a long-lived
// credential — a join token is single-use and short-lived — but writing the timing-safe
// version costs nothing and removes the need for anyone to reason about whether it
// mattered.
func (t JoinToken) Verify(secret string, now time.Time) error {
	if subtle.ConstantTimeCompare([]byte(hashToken(secret)), []byte(t.Hash)) != 1 {
		return ErrTokenUnknown
	}
	if t.RevokedAt != nil {
		return ErrTokenRevoked
	}
	if t.UsedAt != nil {
		return ErrTokenUsed
	}
	if !now.Before(t.ExpiresAt) {
		return ErrTokenExpired
	}
	return nil
}

// FindAndVerify locates the record matching a presented secret and validates it.
//
// Lookup is by hash rather than by an identifier the caller supplies, so a client cannot
// choose which record it is checked against — it either presents a secret that hashes to
// a stored value or it does not.
func FindAndVerify(records []JoinToken, secret string, now time.Time) (JoinToken, error) {
	want := hashToken(secret)
	for _, r := range records {
		if subtle.ConstantTimeCompare([]byte(r.Hash), []byte(want)) == 1 {
			return r, r.Verify(secret, now)
		}
	}
	return JoinToken{}, ErrTokenUnknown
}

// HashToken exposes the storage form of a join-token secret, so the enrollment path can
// look a token up without the secret ever being written down.
func HashToken(secret string) string { return hashToken(secret) }
