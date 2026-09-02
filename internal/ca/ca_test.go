package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newCA(t *testing.T) (*CA, time.Time) {
	t.Helper()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	c, err := New("vesta-test", now)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, now
}

func issue(t *testing.T, c *CA, nodeID string, ttl time.Duration, now time.Time) (tls.Certificate, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := c.IssueNode(nodeID, pub, ttl, now, nil, x509.ExtKeyUsageClientAuth)
	if err != nil {
		t.Fatalf("IssueNode: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return pair, priv
}

func TestSaveLoadRoundTrip(t *testing.T) {
	c, now := newCA(t)
	dir := t.TempDir()
	if err := c.Save(dir); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// The root key must never be group- or world-readable.
	info, err := os.Stat(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("ca.key permissions are %o, want 0600", perm)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// A certificate issued by the reloaded authority must verify against the original,
	// or a control-plane restart would invalidate every node.
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	certPEM, err := loaded.IssueNode("node-1", pub, time.Hour, now, nil, x509.ExtKeyUsageClientAuth)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       c.Pool(),
		CurrentTime: now.Add(time.Minute),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("certificate from reloaded CA does not verify: %v", err)
	}
}

func TestNodeIdentityComesFromURISANNotCommonName(t *testing.T) {
	c, now := newCA(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	certPEM, err := c.IssueNode("node-alpha", pub, time.Hour, now, nil, x509.ExtKeyUsageClientAuth)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	id, err := NodeIDFromCert(cert)
	if err != nil {
		t.Fatalf("NodeIDFromCert: %v", err)
	}
	if id != "node-alpha" {
		t.Fatalf("got node id %q, want node-alpha", id)
	}

	// A certificate with a CommonName but no Vesta URI SAN must not be accepted as an
	// identity: CN is free-form and any CA-signed cert could carry a misleading one.
	if _, err := NodeIDFromCert(&x509.Certificate{Subject: cert.Subject}); err == nil {
		t.Fatal("a certificate with only a CommonName was accepted as a node identity")
	}
}

func TestExpiredCertificateIsRejected(t *testing.T) {
	c, now := newCA(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	certPEM, _ := c.IssueNode("node-1", pub, time.Hour, now, nil, x509.ExtKeyUsageClientAuth)
	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	_, err := cert.Verify(x509.VerifyOptions{
		Roots:       c.Pool(),
		CurrentTime: now.Add(2 * time.Hour), // past NotAfter
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err == nil {
		t.Fatal("an expired certificate verified; short TTLs would bound nothing")
	}
}

func TestIssueRejectsEmptyNodeID(t *testing.T) {
	c, now := newCA(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := c.IssueNode("", pub, time.Hour, now, nil, x509.ExtKeyUsageClientAuth); err == nil {
		t.Fatal("issued a certificate with no node identity")
	}
}

// The end-to-end property: a real TLS handshake, with the control plane requiring and
// verifying a client certificate and then consulting the authorizer.
func TestMutualTLSHandshakeAndRevocation(t *testing.T) {
	c, now := newCA(t)
	serverPair, _ := func() (tls.Certificate, ed25519.PrivateKey) {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		certPEM, err := c.IssueNode("control-plane", pub, time.Hour, now, []string{"localhost"}, x509.ExtKeyUsageServerAuth)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, _ := x509.MarshalPKCS8PrivateKey(priv)
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return pair, priv
	}()

	agentPair, _ := issue(t, c, "node-1", time.Hour, now)

	revoked := map[string]bool{}
	authorize := func(nodeID string) error {
		if revoked[nodeID] {
			return errors.New("node has been removed from the fleet")
		}
		return nil
	}

	serve := func() net.Listener {
		cfg := c.ServerTLS(serverPair, authorize)
		cfg.Time = func() time.Time { return now.Add(time.Minute) }
		ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer conn.Close()
					if err := conn.(*tls.Conn).Handshake(); err != nil {
						return
					}
					io.WriteString(conn, "ok")
				}()
			}
		}()
		return ln
	}

	ln := serve()
	defer ln.Close()

	dial := func() error {
		cfg := c.ClientTLS(agentPair, "localhost")
		cfg.Time = func() time.Time { return now.Add(time.Minute) }
		conn, err := tls.Dial("tcp", ln.Addr().String(), cfg)
		if err != nil {
			return err
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 2)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return err
		}
		return nil
	}

	if err := dial(); err != nil {
		t.Fatalf("an authorized node could not connect: %v", err)
	}

	// Revoking is immediate on the next connection — no CRL, no waiting for expiry.
	revoked["node-1"] = true
	if err := dial(); err == nil {
		t.Fatal("a revoked node still connected; removal must take effect at the next handshake")
	}
}

// A certificate signed by a different authority must not be accepted, which is what stops
// anyone who can reach the port from asserting a node identity.
func TestForeignCAIsRejected(t *testing.T) {
	c, now := newCA(t)
	other, _ := New("someone-else", now)
	foreignPair, _ := issue(t, other, "node-1", time.Hour, now)

	cfg := c.ServerTLS(tls.Certificate{}, nil)
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatal("client certificates must be required and verified")
	}
	block, _ := pem.Decode(pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: foreignPair.Certificate[0],
	}))
	cert, _ := x509.ParseCertificate(block.Bytes)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       c.Pool(),
		CurrentTime: now.Add(time.Minute),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err == nil {
		t.Fatal("a certificate from a foreign CA verified against ours")
	}
}

func TestJoinTokenIsSingleUseAndExpiring(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	secret, rec, err := NewJoinToken("node-1", "admin@example.com", 0, now)
	if err != nil {
		t.Fatal(err)
	}
	if secret == "" {
		t.Fatal("no secret returned")
	}
	// The secret itself is never stored, so a leaked database yields nothing usable.
	if strings.Contains(rec.Hash, secret) || rec.Hash == secret {
		t.Fatal("the token record contains the secret")
	}

	if err := rec.Verify(secret, now); err != nil {
		t.Fatalf("a fresh token failed to verify: %v", err)
	}
	if err := rec.Verify("some-other-token", now); !errors.Is(err, ErrTokenUnknown) {
		t.Fatalf("a wrong secret should be unrecognised, got %v", err)
	}

	used := now.Add(time.Minute)
	rec.UsedAt = &used
	if err := rec.Verify(secret, now.Add(2*time.Minute)); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("a used token must not be reusable, got %v", err)
	}

	rec.UsedAt = nil
	if err := rec.Verify(secret, now.Add(2*time.Hour)); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("an expired token must be refused, got %v", err)
	}

	rec.RevokedAt = &used
	if err := rec.Verify(secret, now); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("a revoked token must be refused, got %v", err)
	}
}

func TestFindAndVerifyLooksUpByHash(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	secretA, recA, _ := NewJoinToken("node-a", "admin", 0, now)
	_, recB, _ := NewJoinToken("node-b", "admin", 0, now)

	got, err := FindAndVerify([]JoinToken{recB, recA}, secretA, now)
	if err != nil {
		t.Fatalf("FindAndVerify: %v", err)
	}
	if got.NodeHint != "node-a" {
		t.Fatalf("matched the wrong record: %s", got.NodeHint)
	}
	if _, err := FindAndVerify([]JoinToken{recA, recB}, "not-a-token", now); !errors.Is(err, ErrTokenUnknown) {
		t.Fatalf("an unknown secret should not match any record, got %v", err)
	}
}

// First run reaches the control plane at the host's IP before any domain exists (§2.4).
// An address placed in DNSNames does not satisfy verification, so it must become an IP
// SAN — this is the certificate that makes bootstrap possible at all.
func TestIssuedCertificateVerifiesForAnIPAddress(t *testing.T) {
	c, now := newCA(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	certPEM, err := c.IssueNode("control-plane", pub, time.Hour, now,
		[]string{"vesta.example.com", "127.0.0.1"}, x509.ExtKeyUsageServerAuth)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	for _, host := range []string{"vesta.example.com", "127.0.0.1"} {
		if _, err := cert.Verify(x509.VerifyOptions{
			Roots:       c.Pool(),
			CurrentTime: now.Add(time.Minute),
			DNSName:     host,
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			t.Fatalf("certificate does not verify for %s: %v", host, err)
		}
	}
}
