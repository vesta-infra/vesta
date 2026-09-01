# Protocol definitions

The `.proto` files here are the contract between the control plane, agents, and the proxy
(ARCHITECTURE §6.1). Generated Go is not committed; run `make proto`.

`protoc` is not vendored. Install it plus the Go plugins:

```
make tools                       # the two Go plugins
brew install protobuf            # macOS
apt install protobuf-compiler    # Debian/Ubuntu
```

## The frozen subset

`Hello`, `UpdateOffer`, `UpdateChunk` and `UpdateResult` are frozen at v1 and may only
change additively — forever. They are the path by which a stranded agent is recovered, so
an incompatible change to them means SSH-ing to every box, which is the failure the agent
exists to prevent. See ARCHITECTURE §23.2.

## Generated code is not committed

`make proto` regenerates into `internal/stream/{frozenpb,nodepb}`. Generated files are
excluded from version control so a stale checkout cannot silently disagree with the
contract; CI regenerates and fails if the result differs from what the build expects.
