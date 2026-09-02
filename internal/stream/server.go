package stream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"getvesta.sh/internal/ca"
	"getvesta.sh/internal/store"
	"getvesta.sh/internal/stream/frozenpb"
	"getvesta.sh/internal/stream/nodepb"
	"getvesta.sh/internal/version"
)

// Server implements the Node service. It holds one live session per connected agent and
// is the only place that turns a peer certificate into an authenticated node identity.
type Server struct {
	nodepb.UnimplementedNodeServer

	store store.Store
	log   *slog.Logger
	clock func() time.Time

	mu       sync.RWMutex
	sessions map[string]*session
}

type session struct {
	nodeID string
	send   chan *nodepb.ServerMessage
}

func NewServer(st store.Store, log *slog.Logger, clock func() time.Time) *Server {
	if log == nil {
		log = slog.Default()
	}
	if clock == nil {
		clock = time.Now
	}
	return &Server{store: st, log: log, clock: clock, sessions: map[string]*session{}}
}

// Authorizer adapts the store to the CA's handshake check, so a node removed from the
// fleet loses access at its next connection rather than at certificate expiry (§22).
func (s *Server) Authorizer() ca.NodeAuthorizer {
	return func(nodeID string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.store.Nodes().IsAuthorized(ctx, nodeID)
	}
}

// Control is the long-lived bidirectional stream. The agent dials it; the control plane
// never initiates a connection to a node.
func (s *Server) Control(srv nodepb.Node_ControlServer) error {
	ctx := srv.Context()

	// Identity comes from the verified client certificate, never from anything the peer
	// says about itself. A Hello claiming another node's id is therefore not a
	// vulnerability, only a mistake we can report.
	certNodeID, err := nodeIDFromContext(ctx)
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}

	first, err := srv.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil {
		return status.Error(codes.InvalidArgument, "first message on the control stream must be Hello")
	}
	if hello.NodeId != "" && hello.NodeId != certNodeID {
		return status.Errorf(codes.PermissionDenied,
			"hello claims node %q but the certificate identifies %q", hello.NodeId, certNodeID)
	}

	ack := &frozenpb.HelloAck{
		ServerProtocol:       version.ProtocolVersion,
		MinSupportedProtocol: version.MinPeerProtocol,
		Accepted:             hello.Protocol >= version.MinPeerProtocol,
	}
	if !ack.Accepted {
		// Deliberately not a disconnect. An out-of-contract agent stays connected, is
		// marked outdated, and is offered an update — refusing it would strand exactly
		// the nodes that most need reaching (§23.3).
		ack.Message = fmt.Sprintf(
			"agent speaks protocol %d; this control plane requires at least %d. An update will be offered.",
			hello.Protocol, version.MinPeerProtocol)
		ack.UpdateOffered = true
	}

	sess := &session{nodeID: certNodeID, send: make(chan *nodepb.ServerMessage, 32)}
	s.addSession(sess)
	defer s.removeSession(sess)

	if err := srv.Send(&nodepb.ServerMessage{
		Msg: &nodepb.ServerMessage_HelloAck{HelloAck: ack},
	}); err != nil {
		return err
	}

	s.log.Info("agent connected",
		"node", certNodeID, "version", hello.Version, "protocol", hello.Protocol,
		"arch", hello.Arch, "accepted", ack.Accepted)

	if err := s.store.Nodes().Heartbeat(ctx, certNodeID, hello.AppliedRevision, s.clock()); err != nil {
		s.log.Warn("recording connection", "node", certNodeID, "error", err)
	}

	// Outbound pump. Sends are serialised through one goroutine because gRPC streams
	// permit only one concurrent Send.
	errc := make(chan error, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				errc <- ctx.Err()
				return
			case msg := <-sess.send:
				if err := srv.Send(msg); err != nil {
					errc <- err
					return
				}
			}
		}
	}()

	for {
		msg, err := srv.Recv()
		if errors.Is(err, io.EOF) {
			s.log.Info("agent disconnected", "node", certNodeID)
			return nil
		}
		if err != nil {
			return err
		}
		if err := s.handle(ctx, certNodeID, msg, sess); err != nil {
			return err
		}
		select {
		case err := <-errc:
			return err
		default:
		}
	}
}

func (s *Server) handle(ctx context.Context, nodeID string, msg *nodepb.NodeMessage, sess *session) error {
	switch m := msg.Msg.(type) {
	case *nodepb.NodeMessage_Ping:
		s.trySend(sess, &nodepb.ServerMessage{
			Msg: &nodepb.ServerMessage_Pong{Pong: &nodepb.Pong{UnixNano: s.clock().UnixNano()}},
		})
	case *nodepb.NodeMessage_Status:
		if err := s.store.Nodes().Heartbeat(ctx, nodeID, m.Status.AppliedRevision, s.clock()); err != nil {
			s.log.Warn("heartbeat", "node", nodeID, "error", err)
		}
		// A node whose clock is far from ours will apply Specs in an order we did not
		// intend, so the skew is surfaced rather than silently corrected (§21).
		if skew := m.Status.ClockOffsetMs; skew > 5000 || skew < -5000 {
			s.log.Warn("node clock skew", "node", nodeID, "offset_ms", skew)
		}
	case *nodepb.NodeMessage_Event:
		s.log.Info("node event",
			"node", nodeID, "kind", m.Event.Kind, "subject", m.Event.Subject, "message", m.Event.Message)
	case *nodepb.NodeMessage_Hello:
		return status.Error(codes.InvalidArgument, "duplicate Hello on an established stream")
	}
	return nil
}

// trySend never blocks. A slow or wedged agent must not be able to stall the control
// plane's own goroutines; dropping a message it cannot keep up with is recoverable
// because the next Spec is a full state transfer, not a delta.
func (s *Server) trySend(sess *session, msg *nodepb.ServerMessage) {
	select {
	case sess.send <- msg:
	default:
		s.log.Warn("dropping message to a slow agent", "node", sess.nodeID)
	}
}

// SendTo delivers a message to one connected node, reporting whether it is connected.
func (s *Server) SendTo(nodeID string, msg *nodepb.ServerMessage) error {
	s.mu.RLock()
	sess, ok := s.sessions[nodeID]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("stream: node %s is not connected", nodeID)
	}
	s.trySend(sess, msg)
	return nil
}

// Connected lists the nodes currently holding a control stream.
func (s *Server) Connected() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.sessions))
	for id := range s.sessions {
		out = append(out, id)
	}
	return out
}

func (s *Server) addSession(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A reconnecting agent replaces its previous session. The old one is already dead or
	// about to be; keeping both would mean messages going to a stream nobody reads.
	s.sessions[sess.nodeID] = sess
}

func (s *Server) removeSession(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.sessions[sess.nodeID]; ok && cur == sess {
		delete(s.sessions, sess.nodeID)
	}
}

// nodeIDFromContext reads the identity from the verified client certificate.
//
// This is the only source of a caller's identity on the control stream. Anything the peer
// asserts in a message is a claim; the certificate is proof, and it was already verified
// against the CA and the authorizer before this stream existed.
func nodeIDFromContext(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", errors.New("no peer information on the connection")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", errors.New("connection is not mutually authenticated TLS")
	}
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return "", errors.New("peer presented no verified certificate chain")
	}
	return ca.NodeIDFromCert(tlsInfo.State.VerifiedChains[0][0])
}
