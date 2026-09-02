// Package api is the control plane's HTTP surface.
//
// M0 scope: minting join tokens and listing the fleet, which is what `vesta server add`
// needs. Authentication is a single bootstrap token; the real identity model — OIDC,
// roles, scoped tokens, service accounts — lands in M4.5 (ARCHITECTURE §17), and this
// package is deliberately shaped so that arrives as a middleware change rather than a
// rewrite of every handler.
package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"getvesta.sh/internal/ca"
	"getvesta.sh/internal/store"
	"getvesta.sh/internal/stream"
)

// SettingBootstrapToken is where the hash of the bootstrap admin token lives. Only the
// hash: the secret is printed once at first run and is not recoverable afterwards.
const SettingBootstrapToken = "bootstrap_token_hash"

type Server struct {
	store     store.Store
	authority *ca.CA
	log       *slog.Logger
	clock     func() time.Time

	// endpoint is what an agent should dial, and fingerprint is what it should expect to
	// find there. Both go into the join command.
	endpoint    string
	fingerprint string
}

func NewServer(st store.Store, authority *ca.CA, endpoint string, log *slog.Logger, clock func() time.Time) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	if clock == nil {
		clock = time.Now
	}
	fp, err := stream.Fingerprint(authority.CertPEM())
	if err != nil {
		return nil, err
	}
	return &Server{
		store: st, authority: authority, log: log, clock: clock,
		endpoint: endpoint, fingerprint: fp,
	}, nil
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /v1/servers", s.auth(s.addServer))
	mux.Handle("GET /v1/servers", s.auth(s.listServers))
	mux.Handle("DELETE /v1/servers/{id}", s.auth(s.removeServer))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n"))
	})
	return mux
}

// EnsureBootstrapToken returns the existing token hash, or mints a token on first run and
// returns the secret exactly once.
//
// This is the setup token from §2.2: printed to the console where only someone with shell
// access sees it, rather than a first-visitor-wins setup page. The difference matters —
// an unattended install must not be claimable by whoever reaches it over the network.
func EnsureBootstrapToken(ctx context.Context, st store.Store, now time.Time) (secret string, err error) {
	if _, err := st.Settings().Get(ctx, SettingBootstrapToken); err == nil {
		return "", nil // already initialised; nothing to print
	} else if !errors.Is(err, store.ErrNotFound) {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("api: generate bootstrap token: %w", err)
	}
	secret = base64.RawURLEncoding.EncodeToString(raw)
	if err := st.Settings().Set(ctx, SettingBootstrapToken, hashToken(secret), now); err != nil {
		return "", err
	}
	return secret, nil
}

func hashToken(secret string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(secret)))
	return hex.EncodeToString(sum[:])
}

func (s *Server) auth(next func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presented := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if presented == "" {
			writeErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		want, err := s.store.Settings().Get(r.Context(), SettingBootstrapToken)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "authentication is not configured")
			return
		}
		if subtle.ConstantTimeCompare([]byte(hashToken(presented)), []byte(want)) != 1 {
			writeErr(w, http.StatusUnauthorized, "invalid token")
			return
		}
		next(w, r)
	})
}

type addServerRequest struct {
	Name string `json:"name"`
}

// AddServerResponse is what `vesta server add` prints. The token appears here once and is
// never retrievable again.
type AddServerResponse struct {
	Token         string `json:"token"`
	Endpoint      string `json:"endpoint"`
	CAFingerprint string `json:"caFingerprint"`
	ExpiresAt     string `json:"expiresAt"`
	Command       string `json:"command"`
}

func (s *Server) addServer(w http.ResponseWriter, r *http.Request) {
	var req addServerRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	if req.Name == "" {
		writeErr(w, http.StatusBadRequest, "a server name is required")
		return
	}

	now := s.clock()
	secret, rec, err := ca.NewJoinToken(req.Name, "bootstrap", ca.DefaultJoinTTL, now)
	if err != nil {
		s.log.Error("minting join token", "error", err)
		writeErr(w, http.StatusInternalServerError, "could not mint a join token")
		return
	}
	err = s.store.JoinTokens().Create(r.Context(), store.JoinTokenRecord{
		ID: rec.ID, Hash: rec.Hash, NodeHint: rec.NodeHint,
		CreatedBy: rec.CreatedBy, CreatedAt: rec.CreatedAt, ExpiresAt: rec.ExpiresAt,
	})
	if err != nil {
		s.log.Error("storing join token", "error", err)
		writeErr(w, http.StatusInternalServerError, "could not record the join token")
		return
	}

	resp := AddServerResponse{
		Token:         secret,
		Endpoint:      s.endpoint,
		CAFingerprint: s.fingerprint,
		ExpiresAt:     rec.ExpiresAt.Format(time.RFC3339),
		// The direct invocation, not a curl-to-install.sh: the installer lands in M7
		// (§2.2), and printing a command that fetches a script which does not exist yet
		// would be a worse experience than printing one that works.
		Command: fmt.Sprintf(
			"vesta-agent --endpoint %s --token %s --ca-fingerprint %s --name %s",
			s.endpoint, secret, s.fingerprint, req.Name),
	}
	s.log.Info("join token minted", "name", req.Name, "expires", resp.ExpiresAt)
	writeJSON(w, http.StatusCreated, resp)
}

type serverView struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Status          string `json:"status"`
	Arch            string `json:"arch,omitempty"`
	Version         string `json:"version,omitempty"`
	Zone            string `json:"zone,omitempty"`
	AppliedRevision string `json:"appliedRevision,omitempty"`
	LastSeen        string `json:"lastSeen,omitempty"`
}

func (s *Server) listServers(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.store.Nodes().List(r.Context())
	if err != nil {
		s.log.Error("listing nodes", "error", err)
		writeErr(w, http.StatusInternalServerError, "could not list servers")
		return
	}
	out := make([]serverView, 0, len(nodes))
	for _, n := range nodes {
		v := serverView{
			ID: n.ID, Name: n.Name, Status: string(n.Status), Arch: n.Arch,
			Version: n.Version, Zone: n.Zone, AppliedRevision: n.AppliedRevision,
		}
		if !n.LastSeenAt.IsZero() {
			v.LastSeen = n.LastSeenAt.Format(time.RFC3339)
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"servers": out})
}

// removeServer marks a node removed rather than deleting it, so its history stays
// answerable — and its certificate stops working at the next handshake (§22).
func (s *Server) removeServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.store.Nodes().Get(r.Context(), id); err != nil {
		writeErr(w, http.StatusNotFound, "no such server")
		return
	}
	if err := s.store.Nodes().SetStatus(r.Context(), id, store.NodeRemoved, s.clock()); err != nil {
		s.log.Error("removing node", "error", err)
		writeErr(w, http.StatusInternalServerError, "could not remove the server")
		return
	}
	s.log.Info("node removed from the fleet", "node", id)
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
