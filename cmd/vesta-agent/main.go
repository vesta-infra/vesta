// Command vesta-agent runs on every app server. It dials the control plane — never the
// other way round — enrolling on first start and then holding a control stream.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"getvesta.sh/internal/ca"
	"getvesta.sh/internal/stream"
	"getvesta.sh/internal/stream/nodepb"
	"getvesta.sh/internal/version"
)

// identity is what the agent persists after enrolling. The private key sits beside it at
// 0600 and never leaves this machine.
type identity struct {
	NodeID   string `json:"nodeId"`
	Endpoint string `json:"endpoint"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "vesta-agent: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		dataDir  = flag.String("data-dir", env("VESTA_DATA_DIR", "/var/lib/vesta"), "state directory")
		endpoint = flag.String("endpoint", env("VESTA_ENDPOINT", ""), "control plane host:port for agents")
		token    = flag.String("token", env("VESTA_TOKEN", ""), "single-use join token (first start only)")
		fp       = flag.String("ca-fingerprint", env("VESTA_CA_FINGERPRINT", ""), "expected control-plane CA fingerprint")
		name     = flag.String("name", env("VESTA_NAME", ""), "name for this node (default: hostname)")
		zone     = flag.String("zone", env("VESTA_ZONE", ""), "network zone; peers sharing one talk privately (§10.6)")
		showVer  = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println(version.String("vesta-agent"))
		return nil
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	log.Info(version.String("vesta-agent"))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	if *name == "" {
		*name, _ = os.Hostname()
	}

	id, pair, caPEM, err := loadIdentity(*dataDir)
	if errors.Is(err, os.ErrNotExist) {
		if *token == "" || *endpoint == "" {
			return errors.New("not enrolled: pass --token and --endpoint, or run the join command from `vesta server add`")
		}
		id, pair, caPEM, err = enroll(ctx, *dataDir, *endpoint, *token, *fp, *name, *zone, log)
	}
	if err != nil {
		return err
	}
	if *endpoint == "" {
		*endpoint = id.Endpoint
	}

	host, _, splitErr := net.SplitHostPort(*endpoint)
	if splitErr != nil {
		host = *endpoint
	}
	tlsCfg, err := ca.ClientTLSFromPEM(caPEM, pair, host)
	if err != nil {
		return err
	}

	client := stream.NewClient(stream.ClientConfig{
		NodeID: id.NodeID, Endpoint: *endpoint, TLS: tlsCfg, Log: log,
		// M1 replaces this with the reconciler's actual applied revision.
		AppliedRevision: func() string { return "" },
	})

	log.Info("starting", "node", id.NodeID, "endpoint", *endpoint)
	err = client.Run(ctx, func(msg *nodepb.ServerMessage) error {
		switch msg.Msg.(type) {
		case *nodepb.ServerMessage_Apply:
			// M1: hand the Spec to the reconciler. Acknowledging receipt without acting
			// would be worse than not implementing it, so it is logged as unhandled.
			log.Warn("received a Spec but the reconciler is not implemented yet")
		case *nodepb.ServerMessage_Command:
			log.Warn("received a command but command handling is not implemented yet")
		}
		return nil
	})
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func enroll(ctx context.Context, dataDir, endpoint, token, fingerprint, name, zone string, log *slog.Logger) (identity, tls.Certificate, []byte, error) {
	log.Info("enrolling", "endpoint", endpoint, "name", name)

	// Enrollment speaks HTTPS on the port above the agent endpoint (see vestad).
	enrollURL, err := enrollEndpoint(endpoint)
	if err != nil {
		return identity{}, tls.Certificate{}, nil, err
	}

	resp, key, err := stream.EnrollClient(ctx,
		stream.JoinBundle{Endpoint: enrollURL, Token: token, CAFingerprint: fingerprint},
		stream.EnrollRequest{
			Name: name, Arch: runtime.GOOS + "/" + runtime.GOARCH,
			Version: version.Version, Protocol: version.ProtocolVersion,
			Zone: zone, CPUCores: float64(runtime.NumCPU()),
		}, nil)
	if err != nil {
		return identity{}, tls.Certificate{}, nil, err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return identity{}, tls.Certificate{}, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// 0600 at creation, not tightened afterwards: the window matters.
	if err := os.WriteFile(filepath.Join(dataDir, "agent.key"), keyPEM, 0o600); err != nil {
		return identity{}, tls.Certificate{}, nil, err
	}
	if err := os.WriteFile(filepath.Join(dataDir, "agent.crt"), resp.CertPEM, 0o644); err != nil {
		return identity{}, tls.Certificate{}, nil, err
	}
	if err := os.WriteFile(filepath.Join(dataDir, "ca.crt"), resp.CAPEM, 0o644); err != nil {
		return identity{}, tls.Certificate{}, nil, err
	}
	id := identity{NodeID: resp.NodeID, Endpoint: endpoint}
	idJSON, _ := json.MarshalIndent(id, "", "  ")
	if err := os.WriteFile(filepath.Join(dataDir, "node.json"), idJSON, 0o644); err != nil {
		return identity{}, tls.Certificate{}, nil, err
	}

	pair, err := tls.X509KeyPair(resp.CertPEM, keyPEM)
	if err != nil {
		return identity{}, tls.Certificate{}, nil, err
	}
	log.Info("enrolled", "node", resp.NodeID)
	return id, pair, resp.CAPEM, nil
}

func loadIdentity(dataDir string) (identity, tls.Certificate, []byte, error) {
	raw, err := os.ReadFile(filepath.Join(dataDir, "node.json"))
	if err != nil {
		return identity{}, tls.Certificate{}, nil, err
	}
	var id identity
	if err := json.Unmarshal(raw, &id); err != nil {
		return identity{}, tls.Certificate{}, nil, fmt.Errorf("node.json is malformed: %w", err)
	}
	certPEM, err := os.ReadFile(filepath.Join(dataDir, "agent.crt"))
	if err != nil {
		return identity{}, tls.Certificate{}, nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dataDir, "agent.key"))
	if err != nil {
		return identity{}, tls.Certificate{}, nil, err
	}
	caPEM, err := os.ReadFile(filepath.Join(dataDir, "ca.crt"))
	if err != nil {
		return identity{}, tls.Certificate{}, nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return identity{}, tls.Certificate{}, nil, fmt.Errorf("stored certificate and key do not match: %w", err)
	}
	return id, pair, caPEM, nil
}

func enrollEndpoint(agentEndpoint string) (string, error) {
	host, port, err := net.SplitHostPort(agentEndpoint)
	if err != nil {
		return "", fmt.Errorf("endpoint %q must be host:port: %w", agentEndpoint, err)
	}
	p := 8443
	fmt.Sscanf(port, "%d", &p)
	return "https://" + net.JoinHostPort(host, fmt.Sprint(p+1)), nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
