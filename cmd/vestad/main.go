// Command vestad is the control plane: API, scheduler, store, and the endpoint agents
// dial. It never opens a connection to a node.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"getvesta.sh/internal/api"
	"getvesta.sh/internal/ca"
	"getvesta.sh/internal/store"
	"getvesta.sh/internal/stream"
	"getvesta.sh/internal/stream/nodepb"
	"getvesta.sh/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "vestad: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		dataDir   = flag.String("data-dir", env("VESTA_DATA_DIR", "/var/lib/vesta"), "state directory")
		dsn       = flag.String("database", env("VESTA_DATABASE", ""), "database DSN (default: sqlite in the data directory)")
		httpAddr  = flag.String("http-addr", env("VESTA_HTTP_ADDR", "127.0.0.1:8080"), "API listener; fronted by vesta-proxy (§2.4)")
		agentAddr = flag.String("agent-addr", env("VESTA_AGENT_ADDR", ":8443"), "agent gRPC listener, mutual TLS")
		advertise = flag.String("advertise", env("VESTA_ADVERTISE", ""), "endpoint agents should dial (default: derived from agent-addr)")
		showVer   = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println(version.String("vestad"))
		return nil
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	log.Info(version.String("vestad"))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}

	if *dsn == "" {
		*dsn = "sqlite://" + filepath.Join(*dataDir, "vesta.db")
	}
	st, err := store.Open(*dsn)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	log.Info("store ready", "dialect", st.Dialect())

	authority, err := loadOrCreateCA(filepath.Join(*dataDir, "ca"), log)
	if err != nil {
		return err
	}

	// The setup token is printed to the console, not exposed on a first-visitor-wins
	// page, so an unattended install cannot be claimed over the network (§2.2).
	if secret, err := api.EnsureBootstrapToken(ctx, st, time.Now()); err != nil {
		return err
	} else if secret != "" {
		fmt.Fprintf(os.Stderr, "\n  Vesta is initialised. Your setup token:\n\n    %s\n\n"+
			"  It is shown once. Use it with:  vesta --endpoint http://%s --token <token> server add <name>\n\n",
			secret, *httpAddr)
	}

	if *advertise == "" {
		*advertise = deriveAdvertise(*agentAddr)
	}

	nodeSrv := stream.NewServer(st, log, time.Now)
	apiSrv, err := api.NewServer(st, authority, *advertise, log, time.Now)
	if err != nil {
		return err
	}

	// The control plane's own certificate, from its own CA, valid for the addresses an
	// agent might use to reach it. Served with the CA appended so a first-contact agent
	// can verify against the fingerprint it was given (§stream.ServerChain).
	serverPair, err := issueServerCert(authority, hostCandidates())
	if err != nil {
		return err
	}
	chain, err := stream.ServerChain(serverPair, authority)
	if err != nil {
		return err
	}

	// Agent endpoint: mutual TLS, with node authorization consulted at handshake so a
	// removed node loses access on its next connection rather than at cert expiry.
	grpcTLS := authority.ServerTLS(chain, nodeSrv.Authorizer())
	agentLn, err := net.Listen("tcp", *agentAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *agentAddr, err)
	}
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(grpcTLS)))
	nodepb.RegisterNodeServer(gs, nodeSrv)

	// Enrollment shares the agent endpoint's TLS material but requires no client
	// certificate, because a joining node does not have one yet.
	enrollMux := http.NewServeMux()
	enrollMux.Handle(stream.EnrollPath, stream.EnrollHandler(authority, st, time.Now))
	enrollTLS := &tls.Config{Certificates: []tls.Certificate{chain}, MinVersion: tls.VersionTLS13}
	enrollLn, err := tls.Listen("tcp", enrollAddr(*agentAddr), enrollTLS)
	if err != nil {
		return fmt.Errorf("listen for enrollment: %w", err)
	}
	enrollSrv := &http.Server{Handler: enrollMux, ReadHeaderTimeout: 10 * time.Second}

	apiHTTP := &http.Server{Addr: *httpAddr, Handler: apiSrv.Routes(), ReadHeaderTimeout: 10 * time.Second}

	errc := make(chan error, 3)
	go func() { errc <- serveNamed("agent gRPC", gs.Serve(agentLn)) }()
	go func() { errc <- serveNamed("enrollment", enrollSrv.Serve(enrollLn)) }()
	go func() { errc <- serveNamed("api", apiHTTP.ListenAndServe()) }()

	log.Info("listening",
		"api", *httpAddr, "agents", agentLn.Addr().String(),
		"enrollment", enrollLn.Addr().String(), "advertise", *advertise)

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errc:
		if err != nil {
			return err
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	apiHTTP.Shutdown(shutdownCtx)
	enrollSrv.Shutdown(shutdownCtx)
	gs.GracefulStop()
	return nil
}

func serveNamed(what string, err error) error {
	if err == nil || errors.Is(err, http.ErrServerClosed) || errors.Is(err, grpc.ErrServerStopped) {
		return nil
	}
	return fmt.Errorf("%s listener: %w", what, err)
}

// loadOrCreateCA is idempotent: a restart reuses the authority, because regenerating it
// would invalidate every certificate in the fleet at once.
func loadOrCreateCA(dir string, log *slog.Logger) (*ca.CA, error) {
	authority, err := ca.Load(dir)
	if err == nil {
		return authority, nil
	}
	if !errors.Is(err, os.ErrNotExist) && !os.IsNotExist(errors.Unwrap(err)) {
		// A malformed CA is not something to paper over by minting a new one: that would
		// silently orphan the fleet.
		if _, statErr := os.Stat(filepath.Join(dir, "ca.crt")); statErr == nil {
			return nil, fmt.Errorf("load certificate authority from %s: %w", dir, err)
		}
	}
	authority, err = ca.New("vesta", time.Now())
	if err != nil {
		return nil, err
	}
	if err := authority.Save(dir); err != nil {
		return nil, err
	}
	log.Info("created certificate authority", "dir", dir)
	return authority, nil
}

func issueServerCert(authority *ca.CA, hosts []string) (tls.Certificate, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM, err := authority.IssueNode("control-plane", pub, 90*24*time.Hour, time.Now(),
		hosts, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

// hostCandidates lists every name and address an agent might use to reach this control
// plane. Addresses matter as much as names: first contact happens before a domain is
// configured (§2.4), and a certificate without the IP would fail exactly then.
func hostCandidates() []string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	if h, err := os.Hostname(); err == nil && h != "" {
		hosts = append(hosts, h)
	}
	if extra := os.Getenv("VESTA_TLS_HOSTS"); extra != "" {
		for _, h := range strings.Split(extra, ",") {
			if h = strings.TrimSpace(h); h != "" {
				hosts = append(hosts, h)
			}
		}
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return hosts
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			hosts = append(hosts, ipnet.IP.String())
		}
	}
	return hosts
}

// enrollAddr puts enrollment one port above the agent endpoint. They share TLS material
// but differ in whether a client certificate is required, which is a listener-level
// property rather than something that can vary per route.
func enrollAddr(agentAddr string) string {
	host, port, err := net.SplitHostPort(agentAddr)
	if err != nil {
		return ":8444"
	}
	p := 8444
	fmt.Sscanf(port, "%d", &p)
	return net.JoinHostPort(host, fmt.Sprint(p+1))
}

func deriveAdvertise(agentAddr string) string {
	_, port, err := net.SplitHostPort(agentAddr)
	if err != nil {
		port = "8443"
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
