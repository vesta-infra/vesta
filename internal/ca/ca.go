// Package ca is the control plane's internal certificate authority.
//
// It exists because Vesta stores no SSH keys and holds no standing access to any node
// (PLAN §1.4). A node authenticates with a short-lived certificate it obtained by
// presenting a single-use join token, and renews it over the connection it already holds.
// Nothing here grants a shell, and nothing issued here outlives a revocation by more than
// its remaining validity.
//
// The node's private key is generated on the node and never transmitted. The CA sees a
// public key and a token, and returns a certificate.
//
// See ARCHITECTURE.md §2.2 and §22.
package ca

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// NodeCertTTL is deliberately short. A certificate is a standing credential for as
	// long as it is valid, so the window in which a revoked or stolen one still works is
	// bounded by this rather than by anyone noticing.
	NodeCertTTL = 24 * time.Hour

	// RenewAt is the fraction of its life at which a node should renew. Renewing at two
	// thirds leaves a full third as slack for a control plane that is briefly
	// unreachable, so an outage does not become an expiry.
	RenewAt = 2.0 / 3.0

	caTTL = 10 * 365 * 24 * time.Hour

	// URI SAN scheme. The node identity lives in a URI SAN rather than only in the CN,
	// because CN is deprecated for identity and a DNS SAN would imply the name resolves.
	uriScheme = "vesta"
)

// CA holds the root key. It never leaves the control-plane process, and on disk the key
// is 0600 alongside the KEK — anything that can read one can read the other, so they sit
// at the same trust tier rather than pretending to differ.
type CA struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
	der  []byte
}

// New creates a fresh authority. Called once, at control-plane first run.
func New(commonName string, now time.Time) (*CA, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca: generate key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Vesta"}},
		NotBefore:             now.Add(-time.Minute), // tolerate small clock skew at first run
		NotAfter:              now.Add(caTTL),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true, // issues leaves only; no intermediates
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("ca: self-sign: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("ca: parse own certificate: %w", err)
	}
	return &CA{cert: cert, key: priv, der: der}, nil
}

// Save writes the authority to dir: ca.crt world-readable, ca.key 0600.
func (c *CA) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("ca: create %s: %w", dir, err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), certPEM, 0o644); err != nil {
		return fmt.Errorf("ca: write ca.crt: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(c.key)
	if err != nil {
		return fmt.Errorf("ca: marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	// 0600 before any content is written: creating it readable and tightening afterwards
	// leaves a window, however brief, in which the root key is world-readable.
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), keyPEM, 0o600); err != nil {
		return fmt.Errorf("ca: write ca.key: %w", err)
	}
	return nil
}

// Load reads an authority previously saved to dir.
func Load(dir string) (*CA, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("ca: read ca.crt: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		return nil, fmt.Errorf("ca: read ca.key: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("ca: ca.crt is not a PEM certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse ca.crt: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("ca: ca.key is not PEM")
	}
	anyKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse ca.key: %w", err)
	}
	key, ok := anyKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ca: expected an ed25519 key, got %T", anyKey)
	}
	return &CA{cert: cert, key: key, der: certBlock.Bytes}, nil
}

// CertPEM returns the authority certificate, which agents pin.
func (c *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})
}

// Pool returns a x509 pool trusting only this authority.
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// LeafOptions describes a certificate to issue.
//
// IPAddresses is not decoration: first-run reaches the control plane at the host's IP
// before any domain exists (§2.4), and an IP in DNSNames does not satisfy verification —
// it must be an IP SAN. Omitting it makes bootstrap impossible in exactly the case
// bootstrap exists for.
type LeafOptions struct {
	NodeID      string
	TTL         time.Duration
	DNSNames    []string
	IPAddresses []net.IP
	Usage       x509.ExtKeyUsage
}

// IssueLeaf signs a certificate for pub.
//
// The public key comes from the holder, which generated the pair locally; the private
// half is never transmitted and never held here.
func (c *CA) IssueLeaf(pub crypto.PublicKey, opt LeafOptions, now time.Time) ([]byte, error) {
	if opt.NodeID == "" {
		return nil, errors.New("ca: refusing to issue a certificate with an empty node id")
	}
	if opt.TTL <= 0 {
		opt.TTL = NodeCertTTL
	}
	if opt.Usage == 0 {
		opt.Usage = x509.ExtKeyUsageClientAuth
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	uri, err := nodeURI(opt.NodeID)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: opt.NodeID, Organization: []string{"Vesta"}},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(opt.TTL),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{opt.Usage},
		URIs:         []*url.URL{uri},
		DNSNames:     opt.DNSNames,
		IPAddresses:  opt.IPAddresses,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, pub, c.key)
	if err != nil {
		return nil, fmt.Errorf("ca: sign for %s: %w", opt.NodeID, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// IssueNode signs a client certificate binding nodeID to pub — the common case.
func (c *CA) IssueNode(nodeID string, pub crypto.PublicKey, ttl time.Duration, now time.Time, dnsNames []string, usage x509.ExtKeyUsage) ([]byte, error) {
	var ips []net.IP
	var names []string
	// Callers naturally pass "127.0.0.1" alongside hostnames; putting an address in
	// DNSNames silently produces a certificate that fails to verify for it, so they are
	// sorted here rather than becoming a puzzle at handshake time.
	for _, n := range dnsNames {
		if ip := net.ParseIP(n); ip != nil {
			ips = append(ips, ip)
			continue
		}
		names = append(names, n)
	}
	return c.IssueLeaf(pub, LeafOptions{
		NodeID: nodeID, TTL: ttl, DNSNames: names, IPAddresses: ips, Usage: usage,
	}, now)
}

// NodeIDFromCert extracts the identity a peer certificate asserts.
//
// It reads the URI SAN, not the CommonName: CN is free-form legacy and a certificate
// could carry a misleading one, whereas the URI SAN is what this CA puts there and what
// verification is anchored to.
func NodeIDFromCert(cert *x509.Certificate) (string, error) {
	for _, u := range cert.URIs {
		if u.Scheme == uriScheme && u.Host == "node" {
			id := strings.TrimPrefix(u.Path, "/")
			if id == "" {
				return "", errors.New("ca: certificate carries an empty node id")
			}
			return id, nil
		}
	}
	return "", errors.New("ca: certificate carries no vesta node identity")
}

func nodeURI(nodeID string) (*url.URL, error) {
	u, err := url.Parse(fmt.Sprintf("%s://node/%s", uriScheme, url.PathEscape(nodeID)))
	if err != nil {
		return nil, fmt.Errorf("ca: node id %q is not representable: %w", nodeID, err)
	}
	return u, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("ca: serial: %w", err)
	}
	return serial, nil
}
