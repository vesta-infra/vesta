package ca

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// NodeAuthorizer decides whether a node whose certificate is otherwise valid is still
// allowed in. This is how revocation works here: rather than CRLs or OCSP, the control
// plane consults its own list of active nodes at handshake time, so a removed node loses
// access on its next connection rather than at its certificate's expiry.
type NodeAuthorizer func(nodeID string) error

var ErrNodeNotAuthorized = errors.New("ca: node is not authorized")

// ServerTLS builds the control plane's TLS config for the agent endpoint.
//
// Client certificates are required and verified against this authority, and then the node
// identity is checked against the authorizer. Both steps matter: the first proves the
// peer holds a key this CA signed, the second proves that node is still one we accept.
func (c *CA) ServerTLS(cert tls.Certificate, authorize NodeAuthorizer) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    c.Pool(),
		MinVersion:   tls.VersionTLS13,
		VerifyPeerCertificate: func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
			// chains is non-empty here because ClientAuth is RequireAndVerify: the
			// standard verification has already succeeded by the time this runs.
			if len(chains) == 0 || len(chains[0]) == 0 {
				return errors.New("ca: no verified chain presented")
			}
			nodeID, err := NodeIDFromCert(chains[0][0])
			if err != nil {
				return err
			}
			if authorize == nil {
				return nil
			}
			if err := authorize(nodeID); err != nil {
				return fmt.Errorf("%w: %s: %v", ErrNodeNotAuthorized, nodeID, err)
			}
			return nil
		},
	}
}

// ClientTLS builds an agent's TLS config for dialling the control plane.
func (c *CA) ClientTLS(cert tls.Certificate, serverName string) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      c.Pool(),
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}
}

// ClientTLSFromPEM is the agent-side equivalent for a process that holds only the CA
// certificate on disk, not the authority itself.
func ClientTLSFromPEM(caPEM []byte, cert tls.Certificate, serverName string) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("ca: no certificate found in the provided CA PEM")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
