// Package stream carries the transport between the control plane and agents.
//
// The agent always dials. The control plane never opens a connection to a node, which is
// what lets app servers sit behind NAT with no inbound port, no public IP, and no SSH
// exposure — and what means there is no stored credential granting shell access to
// anything (PLAN §1.4). When the control plane needs a stream the agent has not opened,
// it asks over the control stream and the agent dials back.
//
// The generated contracts live in two sub-packages, and the split is load-bearing:
//
//   - frozenpb is the recovery path: Hello, UpdateOffer, UpdateChunk, UpdateResult. It may
//     only ever change additively, because it is how an agent too old to understand the
//     current Spec is recognised and handed a new binary. frozen_test.go pins it.
//   - nodepb is everything else, negotiated on version.ProtocolVersion, free to evolve.
//
// See ARCHITECTURE.md §6.1 and §23.2.
package stream
