package stream

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"getvesta.sh/internal/ca"
	"getvesta.sh/internal/store"
	"getvesta.sh/internal/stream/frozenpb"
	"getvesta.sh/internal/stream/nodepb"
)

// Anchored to the real clock, fixed for the run. The fingerprint check at first contact
// verifies the chain with x509's real notion of "now" — as production must — so a fixture
// dated in the future would fail validity rather than test what it means to test.
var testNow = time.Now().UTC().Add(-time.Minute)

func fixedNow() time.Time { return testNow }

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// harness stands up a control plane: a CA, a store, an enrollment endpoint over TLS, and
// a gRPC agent endpoint requiring mutual TLS.
type harness struct {
	authority *ca.CA
	store     store.Store
	server    *Server
	httpSrv   *httptest.Server
	grpcAddr  string
	caFP      string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	authority, err := ca.New("vesta-test", fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open("sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}

	srv := NewServer(st, quietLogger(), fixedNow)

	// The control plane's own server certificate, issued by its own CA.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	certPEM, err := authority.IssueNode("control-plane", pub, time.Hour, fixedNow(),
		[]string{"localhost", "127.0.0.1"}, x509.ExtKeyUsageServerAuth)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	serverPair, err := tls.X509KeyPair(certPEM,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}

	// Enrollment: TLS, but no client certificate — the node does not have one yet.
	mux := http.NewServeMux()
	mux.Handle(EnrollPath, EnrollHandler(authority, st, fixedNow))
	// The chain includes the CA so an enrolling agent, which has nothing on disk to
	// anchor to yet, can verify against the fingerprint it was given.
	chain, err := ServerChain(serverPair, authority)
	if err != nil {
		t.Fatal(err)
	}
	httpSrv := httptest.NewUnstartedServer(mux)
	httpSrv.TLS = &tls.Config{Certificates: []tls.Certificate{chain}, MinVersion: tls.VersionTLS13}
	httpSrv.StartTLS()
	t.Cleanup(httpSrv.Close)

	// Agent endpoint: mutual TLS, with the authorizer consulted at handshake.
	grpcTLS := authority.ServerTLS(serverPair, srv.Authorizer())
	grpcTLS.Time = func() time.Time { return fixedNow().Add(time.Minute) }
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(grpcTLS)))
	nodepb.RegisterNodeServer(gs, srv)
	go gs.Serve(ln)
	t.Cleanup(gs.Stop)

	fp, err := Fingerprint(authority.CertPEM())
	if err != nil {
		t.Fatal(err)
	}

	return &harness{
		authority: authority, store: st, server: srv,
		httpSrv: httpSrv, grpcAddr: ln.Addr().String(), caFP: fp,
	}
}

// mintToken creates a join token the way `vesta server add` will.
func (h *harness) mintToken(t *testing.T, hint string) string {
	t.Helper()
	secret, rec, err := ca.NewJoinToken(hint, "admin@example.com", 0, fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	err = h.store.JoinTokens().Create(context.Background(), store.JoinTokenRecord{
		ID: rec.ID, Hash: rec.Hash, NodeHint: rec.NodeHint, CreatedBy: rec.CreatedBy,
		CreatedAt: rec.CreatedAt, ExpiresAt: rec.ExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return secret
}

func (h *harness) bundle(token string) JoinBundle {
	return JoinBundle{Endpoint: h.httpSrv.URL, Token: token, CAFingerprint: h.caFP}
}

// The M0 acceptance criterion, in miniature: one join token, and a node that enrolls,
// connects over mutual TLS, and appears in the fleet.
func TestEnrollThenConnect(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	token := h.mintToken(t, "hetzner-1")

	resp, nodeKey, err := EnrollClient(ctx, h.bundle(token),
		EnrollRequest{Name: "hetzner-1", Arch: "linux/arm64", Version: "0.1.0", Protocol: 1},
		h.httpSrv.Client())
	if err != nil {
		t.Fatalf("EnrollClient: %v", err)
	}
	if !strings.HasPrefix(resp.NodeID, "n_") {
		t.Fatalf("unexpected node id %q", resp.NodeID)
	}

	node, err := h.store.Nodes().Get(ctx, resp.NodeID)
	if err != nil {
		t.Fatalf("the enrolled node is not in the store: %v", err)
	}
	if node.Status != store.NodeActive || node.Name != "hetzner-1" {
		t.Fatalf("unexpected node state: %+v", node)
	}

	// Now hold a control stream with the issued identity.
	keyDER, _ := x509.MarshalPKCS8PrivateKey(nodeKey)
	pair, err := tls.X509KeyPair(resp.CertPEM,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatalf("the issued certificate does not match the key kept on the node: %v", err)
	}
	clientTLS, err := ca.ClientTLSFromPEM(resp.CAPEM, pair, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	clientTLS.Time = func() time.Time { return fixedNow().Add(time.Minute) }

	client := NewClient(ClientConfig{
		NodeID: resp.NodeID, Endpoint: h.grpcAddr, TLS: clientTLS,
		Log: quietLogger(), Heartbeat: 50 * time.Millisecond,
		AppliedRevision: func() string { return "rev-1" },
	})

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go client.Run(runCtx, nil)

	waitFor(t, 5*time.Second, func() bool {
		for _, id := range h.server.Connected() {
			if id == resp.NodeID {
				return true
			}
		}
		return false
	}, "node never appeared as connected")

	// The heartbeat must carry convergence progress back, which is how a stalled node is
	// distinguished from a disconnected one.
	waitFor(t, 5*time.Second, func() bool {
		n, err := h.store.Nodes().Get(ctx, resp.NodeID)
		return err == nil && n.AppliedRevision == "rev-1"
	}, "applied revision never reached the control plane")
}

func TestJoinTokenCannotBeUsedTwice(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	token := h.mintToken(t, "hetzner-1")

	if _, _, err := EnrollClient(ctx, h.bundle(token),
		EnrollRequest{Name: "first", Protocol: 1}, h.httpSrv.Client()); err != nil {
		t.Fatalf("first enrollment failed: %v", err)
	}
	_, _, err := EnrollClient(ctx, h.bundle(token),
		EnrollRequest{Name: "second", Protocol: 1}, h.httpSrv.Client())
	if err == nil {
		t.Fatal("a join token enrolled two nodes")
	}
	// The rejection must not say why. "expired" versus "already used" versus "unknown"
	// tells someone probing tokens which guesses were closer.
	if !strings.Contains(err.Error(), "enrollment refused") {
		t.Fatalf("rejection leaked a reason: %v", err)
	}
}

func TestEnrollmentRejectsUnknownToken(t *testing.T) {
	h := newHarness(t)
	_, _, err := EnrollClient(context.Background(),
		h.bundle("not-a-real-token"),
		EnrollRequest{Name: "intruder", Protocol: 1}, h.httpSrv.Client())
	if err == nil {
		t.Fatal("enrollment succeeded without a valid token")
	}
}

// Without fingerprint pinning, anyone who can intercept the single enrollment request
// could enroll the node into a control plane of their choosing.
func TestEnrollmentRefusesAWrongCAFingerprint(t *testing.T) {
	h := newHarness(t)
	token := h.mintToken(t, "hetzner-1")
	b := h.bundle(token)
	b.CAFingerprint = strings.Repeat("00", 32)

	// A plain client, so the pinning path in EnrollClient is the only verification.
	_, _, err := EnrollClient(context.Background(), b,
		EnrollRequest{Name: "hetzner-1", Protocol: 1}, &http.Client{Timeout: 5 * time.Second})
	if err == nil {
		t.Fatal("enrolled against a control plane whose CA did not match the pinned fingerprint")
	}
}

// Identity is taken from the verified certificate, so a Hello claiming to be another node
// is refused rather than believed.
func TestHelloCannotClaimAnotherNodesIdentity(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	token := h.mintToken(t, "hetzner-1")
	resp, nodeKey, err := EnrollClient(ctx, h.bundle(token),
		EnrollRequest{Name: "hetzner-1", Protocol: 1}, h.httpSrv.Client())
	if err != nil {
		t.Fatal(err)
	}

	keyDER, _ := x509.MarshalPKCS8PrivateKey(nodeKey)
	pair, _ := tls.X509KeyPair(resp.CertPEM,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	clientTLS, _ := ca.ClientTLSFromPEM(resp.CAPEM, pair, "localhost")
	clientTLS.Time = func() time.Time { return fixedNow().Add(time.Minute) }

	conn, err := grpc.NewClient(h.grpcAddr, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	sc, err := nodepb.NewNodeClient(conn).Control(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Claim a different node's id than the certificate carries.
	sc.Send(&nodepb.NodeMessage{Msg: &nodepb.NodeMessage_Hello{
		Hello: &frozenpb.Hello{NodeId: "n_someone_else", Protocol: 1, Version: "0.1.0"},
	}})
	if _, err := sc.Recv(); err == nil {
		t.Fatal("the control plane accepted a Hello claiming another node's identity")
	}
}

func waitFor(t *testing.T, limit time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(msg)
}
