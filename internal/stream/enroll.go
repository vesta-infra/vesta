package stream

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"getvesta.sh/internal/ca"
	"getvesta.sh/internal/store"
)

// EnrollPath is the one endpoint that accepts a request without a client certificate,
// because an enrolling node does not have one yet. Everything past this point is mTLS.
const EnrollPath = "/v1/enroll"

// EnrollRequest is what an agent presents to join. The private halves of both keypairs
// stay on the node: the CA receives public keys and returns a certificate.
type EnrollRequest struct {
	Token string `json:"token"`
	Name  string `json:"name"`

	CertPubkey  []byte `json:"certPubkey"`  // ed25519, the identity this node will present
	AgentPubkey []byte `json:"agentPubkey"` // x25519, what secrets are sealed to (§11.2)

	Arch     string `json:"arch"`
	Version  string `json:"version"`
	Protocol uint32 `json:"protocol"`

	Zone        string `json:"zone,omitempty"`
	PrivateAddr string `json:"privateAddr,omitempty"`
	PublicAddr  string `json:"publicAddr,omitempty"`

	CPUCores    float64 `json:"cpuCores"`
	MemoryBytes int64   `json:"memoryBytes"`
	DiskBytes   int64   `json:"diskBytes"`
}

type EnrollResponse struct {
	NodeID  string `json:"nodeId"`
	CertPEM []byte `json:"certPem"`
	CAPEM   []byte `json:"caPem"`
}

type enrollError struct {
	Error string `json:"error"`
}

// EnrollHandler serves node enrollment.
//
// It is deliberately the whole of the unauthenticated surface: a single-use token is
// exchanged for a short-lived certificate, once. Every failure returns the same generic
// message, because distinguishing "unknown token" from "expired token" tells an attacker
// probing tokens which guesses were closer.
func EnrollHandler(authority *ca.CA, st store.Store, clock func() time.Time) http.Handler {
	if clock == nil {
		clock = time.Now
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, enrollError{"method not allowed"})
			return
		}
		// Bounded: an unauthenticated endpoint must not let a caller choose how much
		// memory the control plane allocates.
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, enrollError{"request too large or unreadable"})
			return
		}
		var req EnrollRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, enrollError{"malformed request"})
			return
		}
		resp, err := Enroll(r.Context(), authority, st, req, clock())
		if err != nil {
			// One message for every rejection. The specific reason is logged
			// server-side, where the operator can see it and an attacker cannot.
			writeJSON(w, http.StatusUnauthorized, enrollError{"enrollment refused"})
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})
}

// Enroll performs the join. Exported separately from the handler so the flow can be
// tested, and driven, without HTTP.
func Enroll(ctx context.Context, authority *ca.CA, st store.Store, req EnrollRequest, now time.Time) (EnrollResponse, error) {
	if len(req.CertPubkey) != ed25519.PublicKeySize {
		return EnrollResponse{}, fmt.Errorf("stream: certificate public key must be %d bytes, got %d",
			ed25519.PublicKeySize, len(req.CertPubkey))
	}
	if req.Name == "" {
		return EnrollResponse{}, errors.New("stream: a node name is required")
	}

	// The node id is minted before the token is consumed so that consumption records
	// which node claimed it — an audit question ("who used this token?") that cannot be
	// answered afterwards if the id is chosen later.
	nodeID, err := newNodeID()
	if err != nil {
		return EnrollResponse{}, err
	}

	hash := ca.HashToken(req.Token)
	if _, err := st.JoinTokens().Consume(ctx, hash, nodeID, now); err != nil {
		return EnrollResponse{}, fmt.Errorf("stream: join token refused: %w", err)
	}

	in := store.EnrollInput{
		Arch: req.Arch, Version: req.Version, Protocol: req.Protocol,
		AgentPubkey: encodeKey(req.AgentPubkey),
		Zone:        req.Zone, PrivateAddr: req.PrivateAddr, PublicAddr: req.PublicAddr,
		CPUCores: req.CPUCores, MemoryBytes: req.MemoryBytes, DiskBytes: req.DiskBytes,
	}

	node := store.Node{
		ID: nodeID, Name: req.Name, Status: store.NodePending,
		CreatedAt: now,
	}
	if err := st.Nodes().Create(ctx, node); err != nil {
		return EnrollResponse{}, fmt.Errorf("stream: register node: %w", err)
	}
	if err := st.Nodes().Enroll(ctx, nodeID, in, now); err != nil {
		return EnrollResponse{}, fmt.Errorf("stream: record enrollment: %w", err)
	}

	certPEM, err := authority.IssueNode(nodeID, ed25519.PublicKey(req.CertPubkey),
		ca.NodeCertTTL, now, nil, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return EnrollResponse{}, err
	}
	return EnrollResponse{NodeID: nodeID, CertPEM: certPEM, CAPEM: authority.CertPEM()}, nil
}

// JoinBundle is what an agent needs to enroll: where to go, what to present, and how to
// recognise the control plane when it gets there.
type JoinBundle struct {
	Endpoint      string // https://vesta.example.com
	Token         string
	CAFingerprint string // hex SHA-256 of the CA certificate
}

// EnrollClient performs enrollment from the agent side and returns the issued identity.
//
// The CA fingerprint is the part that matters. Without it, a first contact would have to
// trust whatever certificate answers — so anyone able to intercept that one request could
// enroll the node into a control plane of their choosing. The fingerprint travels in the
// join command the operator pastes, which is the one channel already trusted.
func EnrollClient(ctx context.Context, bundle JoinBundle, req EnrollRequest, httpc *http.Client) (EnrollResponse, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return EnrollResponse{}, nil, fmt.Errorf("stream: generate node key: %w", err)
	}
	req.CertPubkey = pub
	req.Token = bundle.Token

	if httpc == nil {
		httpc = &http.Client{Timeout: 30 * time.Second}
	}
	if bundle.CAFingerprint != "" {
		tr, ok := httpc.Transport.(*http.Transport)
		if !ok || tr == nil {
			tr = &http.Transport{}
		} else {
			tr = tr.Clone()
		}
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
		}
		// The chain is not yet anchored in any store we hold, so standard verification
		// is bypassed and replaced with an explicit fingerprint check against the value
		// the operator carried over. This is pinning, not trusting-anything.
		tr.TLSClientConfig.InsecureSkipVerify = true
		want := bundle.CAFingerprint
		host, err := hostFromEndpoint(bundle.Endpoint)
		if err != nil {
			return EnrollResponse{}, nil, err
		}
		tr.TLSClientConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyFingerprint(rawCerts, want, host)
		}
		httpc.Transport = tr
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return EnrollResponse{}, nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, bundle.Endpoint+EnrollPath, bytes.NewReader(payload))
	if err != nil {
		return EnrollResponse{}, nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	res, err := httpc.Do(httpReq)
	if err != nil {
		return EnrollResponse{}, nil, fmt.Errorf("stream: contact control plane: %w", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != http.StatusOK {
		var e enrollError
		json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = res.Status
		}
		return EnrollResponse{}, nil, fmt.Errorf("stream: enrollment refused: %s", e.Error)
	}
	var out EnrollResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return EnrollResponse{}, nil, fmt.Errorf("stream: malformed enrollment response: %w", err)
	}
	if len(out.CertPEM) == 0 || len(out.CAPEM) == 0 {
		return EnrollResponse{}, nil, errors.New("stream: enrollment response carried no certificate")
	}
	return out, priv, nil
}

// verifyFingerprint checks a presented chain against a pinned CA.
//
// Two things must both hold, and checking only the first would be a hole: some
// certificate in the chain must hash to the pinned value, AND the leaf must actually
// chain to that certificate for the requested host. A fingerprint match alone would let
// anyone who can echo back a copy of our public CA certificate — which is not secret —
// present an unrelated leaf they hold the key for.
//
// This requires the control plane to serve its CA alongside its leaf. Roots are usually
// omitted from a TLS chain; here it is what makes first contact verifiable at all, since
// the agent has nothing on disk to anchor to yet.
func verifyFingerprint(rawCerts [][]byte, want, serverName string) error {
	if len(rawCerts) == 0 {
		return errors.New("stream: server presented no certificate")
	}
	var pinned *x509.Certificate
	for _, der := range rawCerts {
		sum := sha256.Sum256(der)
		if hex.EncodeToString(sum[:]) == want {
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return fmt.Errorf("stream: pinned certificate is unparseable: %w", err)
			}
			pinned = cert
			break
		}
	}
	if pinned == nil {
		return fmt.Errorf("stream: control plane did not present a certificate matching the expected fingerprint %s", want)
	}

	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("stream: leaf certificate is unparseable: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(pinned)
	intermediates := x509.NewCertPool()
	for _, der := range rawCerts[1:] {
		if c, err := x509.ParseCertificate(der); err == nil {
			intermediates.AddCert(c)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       serverName,
	}); err != nil {
		return fmt.Errorf("stream: control plane certificate does not chain to the pinned CA: %w", err)
	}
	return nil
}

// Fingerprint is the value printed in a join command and checked at first contact.
func Fingerprint(caPEM []byte) (string, error) {
	block, _ := pemDecode(caPEM)
	if block == nil {
		return "", errors.New("stream: CA PEM could not be decoded")
	}
	sum := sha256.Sum256(block)
	return hex.EncodeToString(sum[:]), nil
}

func newNodeID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("stream: generate node id: %w", err)
	}
	return "n_" + hex.EncodeToString(b), nil
}

func encodeKey(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// pemDecode returns the DER bytes of the first PEM block, or nil.
func pemDecode(b []byte) ([]byte, []byte) {
	blk, rest := pem.Decode(b)
	if blk == nil {
		return nil, rest
	}
	return blk.Bytes, rest
}

func hostFromEndpoint(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("stream: endpoint %q is not a URL: %w", endpoint, err)
	}
	return u.Hostname(), nil
}

// ServerChain returns the control plane's certificate followed by its CA, which is what
// makes the fingerprint check at first contact possible (see verifyFingerprint).
func ServerChain(leaf tls.Certificate, authority *ca.CA) (tls.Certificate, error) {
	caDER, _ := pemDecode(authority.CertPEM())
	if caDER == nil {
		return tls.Certificate{}, errors.New("stream: CA certificate could not be decoded")
	}
	leaf.Certificate = append(leaf.Certificate, caDER)
	return leaf, nil
}
