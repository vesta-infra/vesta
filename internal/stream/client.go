package stream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"runtime"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"getvesta.sh/internal/stream/frozenpb"
	"getvesta.sh/internal/stream/nodepb"
	"getvesta.sh/internal/version"
)

// ClientConfig is what an agent needs to hold a control stream.
type ClientConfig struct {
	NodeID    string
	Endpoint  string // host:port of the control plane's agent endpoint
	TLS       *tls.Config
	Log       *slog.Logger
	Heartbeat time.Duration

	// AppliedRevision reports the Spec revision this node has converged on. It is a
	// function rather than a value because it changes as the agent works, and the
	// control plane learns of progress through it.
	AppliedRevision func() string
}

// Client is the agent's side of the control stream. It dials out and keeps dialling:
// app servers accept no inbound connections, so a dropped stream is the agent's problem
// to solve, not something the control plane can fix by reconnecting.
type Client struct {
	cfg ClientConfig
	log *slog.Logger
}

func NewClient(cfg ClientConfig) *Client {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Heartbeat == 0 {
		cfg.Heartbeat = 15 * time.Second
	}
	if cfg.AppliedRevision == nil {
		cfg.AppliedRevision = func() string { return "" }
	}
	return &Client{cfg: cfg, log: cfg.Log}
}

// Run holds the stream until ctx is cancelled, reconnecting with backoff.
//
// There is no replay log and no queue of missed messages, because a Spec is a full state
// transfer: reconnecting means saying hello again and being told the current desired
// state. That is what makes reconnection stateless and an outage merely a delay.
func (c *Client) Run(ctx context.Context, onMessage func(*nodepb.ServerMessage) error) error {
	backoff := time.Second
	const maxBackoff = 30 * time.Second

	for ctx.Err() == nil {
		err := c.session(ctx, onMessage)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			c.log.Warn("control stream ended", "error", err, "retry_in", backoff.Round(time.Millisecond))
		}

		// Jitter, so a control plane restarting does not meet the whole fleet
		// reconnecting in lockstep.
		jittered := backoff/2 + time.Duration(rand.Int64N(int64(backoff/2)+1))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(jittered):
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
	return ctx.Err()
}

func (c *Client) session(ctx context.Context, onMessage func(*nodepb.ServerMessage) error) error {
	conn, err := grpc.NewClient(c.cfg.Endpoint,
		grpc.WithTransportCredentials(credentials.NewTLS(c.cfg.TLS)))
	if err != nil {
		return fmt.Errorf("stream: dial %s: %w", c.cfg.Endpoint, err)
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	client := nodepb.NewNodeClient(conn)
	sc, err := client.Control(ctx)
	if err != nil {
		return fmt.Errorf("stream: open control stream: %w", err)
	}

	hello := &frozenpb.Hello{
		NodeId:          c.cfg.NodeID,
		Version:         version.Version,
		Protocol:        version.ProtocolVersion,
		AppliedRevision: c.cfg.AppliedRevision(),
		Arch:            hostArch(),
	}
	if err := sc.Send(&nodepb.NodeMessage{Msg: &nodepb.NodeMessage_Hello{Hello: hello}}); err != nil {
		return fmt.Errorf("stream: send hello: %w", err)
	}

	first, err := sc.Recv()
	if err != nil {
		return fmt.Errorf("stream: awaiting hello ack: %w", err)
	}
	ack := first.GetHelloAck()
	if ack == nil {
		return errors.New("stream: control plane did not answer Hello with HelloAck")
	}
	if !ack.Accepted {
		// Not fatal by itself: an unaccepted agent stays connected precisely so it can
		// be handed an update over the frozen channel.
		c.log.Warn("agent is out of contract with the control plane",
			"message", ack.Message, "server_protocol", ack.ServerProtocol,
			"min_supported", ack.MinSupportedProtocol, "update_offered", ack.UpdateOffered)
	} else {
		c.log.Info("connected to control plane",
			"endpoint", c.cfg.Endpoint, "server_protocol", ack.ServerProtocol)
	}

	go c.heartbeat(ctx, sc)

	for {
		msg, err := sc.Recv()
		if err != nil {
			return err
		}
		if onMessage != nil {
			if err := onMessage(msg); err != nil {
				return err
			}
		}
	}
}

func (c *Client) heartbeat(ctx context.Context, sc nodepb.Node_ControlClient) {
	t := time.NewTicker(c.cfg.Heartbeat)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			err := sc.Send(&nodepb.NodeMessage{Msg: &nodepb.NodeMessage_Status{
				Status: &nodepb.Status{AppliedRevision: c.cfg.AppliedRevision()},
			}})
			if err != nil {
				// The receive loop will observe the same failure and reconnect; saying
				// so twice would just be noise.
				return
			}
		}
	}
}

func hostArch() string { return runtime.GOOS + "/" + runtime.GOARCH }
