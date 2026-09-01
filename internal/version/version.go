// Package version carries the identity every Vesta binary reports.
//
// Version is for humans. ProtocolVersion is what compatibility is actually decided on,
// and it moves far more slowly (ARCHITECTURE §23.1).
package version

import (
	"fmt"
	"runtime"
)

// Set at build time via -ldflags. The defaults are what a `go build` with no flags
// produces, so an unstamped binary is identifiable as such rather than claiming a release.
var (
	Version = "0.0.0-dev"
	Commit  = "unknown"
	Date    = "unknown"
)

const (
	// ProtocolVersion is the wire contract between control plane and agents. It is
	// bumped independently of Version, and only when the contract actually changes.
	ProtocolVersion uint32 = 1

	// MinPeerProtocol is the oldest peer this binary will exchange Specs with. An older
	// peer is not disconnected — it is marked outdated and offered an update over the
	// frozen channel (§23.2, §23.3), because refusing the connection would strand
	// exactly the nodes that most need reaching.
	MinPeerProtocol uint32 = 1
)

// String is the one-line identity used by --version and by Hello.
func String(component string) string {
	return fmt.Sprintf("%s %s (protocol %d, commit %s, built %s, %s/%s)",
		component, Version, ProtocolVersion, Commit, Date, runtime.GOOS, runtime.GOARCH)
}
