# Vesta — Architecture

Companion to [PLAN.md](PLAN.md). The plan argues *what* to build and why; this document
specifies *how the pieces fit*, precisely enough to implement from. Where the two
disagree, this document wins on mechanism and the plan wins on scope.

Read in order: §2 for the process model, §3 for the Spec (everything else is downstream of
it), §6 for the reconciler, §10 for DNS, §11 for secrets. The rest can be read on demand.

---

## 1. Design axioms

Five rules. Every decision below is derived from one of them, and a change that violates
one is a change to the architecture, not an implementation detail.

1. **Desired state, not commands.** The control plane publishes what should be true. The
   agent makes it true. There is no "deploy" RPC — there is a new Spec, and convergence.
2. **The agent is authoritative for its host.** It never asks permission to fix drift. If
   the control plane vanishes, running apps stay running, stay health-checked, and stay
   routed.
3. **Never diff against Docker.** Docker normalizes, defaults, and reorders what you give
   it. Comparing a desired config to `ContainerInspect` output is an endless source of
   phantom diffs. We store our own hash in a label and compare strings.
4. **Plaintext secrets exist in exactly two places:** control-plane memory during sealing,
   and agent memory during unsealing. Never on any disk, never in any container config,
   never in any log.
5. **Every mutation is an event.** The audit log, the UI stream, webhooks, and
   notifications are all projections of one internal event bus. Nothing mutates silently.

---

## 2. Process model

| Process | Host | User | Restart | Talks to |
|---|---|---|---|---|
| `vestad` | control node | `vesta` (unprivileged) | systemd / container | store, agents (gRPC server), browsers |
| `vesta-agent` | every app server | `root` | systemd, `Restart=always` | dockerd socket, `vestad` (dials out), `vesta-proxy` socket |
| `vesta-proxy` | every app server | `vesta-proxy`, `CAP_NET_BIND_SERVICE` | systemd, `Restart=always` | container IPs, agent socket |
| `vesta-init` | inside every app container | container's user | n/a — `exec`s away | tmpfs file or agent socket |
| `vesta` (CLI) | anywhere | user | n/a | `vestad` REST |

**Why the proxy is a separate process from the agent.** The agent holds unsealed secrets
and root. The proxy parses untrusted network input from the internet. Putting those in one
address space means a proxy parsing bug is a secrets compromise. They are split, they
communicate over a unix socket with a narrow, one-directional config protocol, and the
proxy never receives or requests secret material.

**Why the agent is root.** The Docker socket is root-equivalent anyway; pretending
otherwise with a `docker` group buys nothing. The agent additionally needs `mlock`,
network namespace inspection for socket handoff peer checks, and tmpfs mount control.

### 2.1 On-disk layout

```
# control node
/var/lib/vesta/
├── vesta.db                 SQLite (single-node) — WAL mode
├── kek                      0600, only if using file-backed KEK (KMS/sealed: absent)
├── ca/                      internal CA for agent mTLS: ca.crt, ca.key (0600)
└── certs/                   certmagic storage, cluster-wide (see §9.4)

# app server
/var/lib/vesta/
├── agent.crt, agent.key     0600, issued at enrollment
├── ca.crt                   control-plane CA
├── node.id                  stable host identity
├── bin/vesta-init           bind-mounted read-only into every container
├── spec.json                last applied Spec, WITHOUT secrets — crash recovery only
├── logs/                    bounded ring buffers, one per container
└── volumes/                 app volumes when not using named Docker volumes

/run/vesta/                  tmpfs, 0700 root — sockets and ephemeral material only
├── agent.sock               CLI/debug
├── proxy.sock               agent → proxy config
└── secrets/<container>/     per-container handoff, unmounted on container stop
```

Note what is absent: no secret is written under `/var/lib`, and `spec.json` is
deliberately stripped of `Secrets` before it is persisted. On a cold boot the agent can
reconstruct containers but must re-obtain secrets from the control plane. That is a
deliberate availability-for-confidentiality trade (§15).

---

## 3. The Spec — the central contract

One document per host, produced by the control plane, consumed by the agent. Everything in
the system is either an input to computing a Spec or a consequence of applying one.

```go
package core

// Spec is the complete desired state of one host. It is a full state transfer, not a
// delta: the agent's job is to make its host look exactly like this and nothing more.
type Spec struct {
    Node     string        // node id this Spec is addressed to
    Revision string        // sha256 of canonical JSON of this struct with Revision=""
    Issued   time.Time
    Apps     []AppSpec
    Routes   []RouteSpec
    Jobs     []JobSpec
    Secrets  []SealedBundle // sealed to this node's key; opaque to everything but the agent
    Prune    PrunePolicy    // what the agent may delete when it finds unmanaged leftovers
}

type AppSpec struct {
    ID          string   // stable: app id + environment id
    App, Env    string   // human names, used for container naming and labels
    Release     string   // release id — immutable identity of what is being run
    Image       string   // ALWAYS a digest: registry/repo@sha256:... never a tag
    PullPolicy  PullPolicy
    RegistryRef string   // credential reference, resolved from Secrets

    Replicas    int
    Command     []string // override; empty means use the image's
    Entrypoint  []string // override; empty means use the image's
    WorkDir     string
    User        string

    Env         map[string]string // NON-SECRET only. Secrets never appear here.
    SecretRef   string            // bundle id in Spec.Secrets
    SecretsVer  int               // bump forces a rolling restart

    Resources   Resources         // cpu, memory, pids, ulimits
    Volumes     []VolumeMount     // per-replica templates expand at apply time
    Networks    []string          // always includes the app-env network
    Ports       []Port            // container ports; NEVER published to the host
    Health      HealthSpec        // startup / readiness / liveness
    Rollout     RolloutSpec
    Logging     LoggingSpec
    Labels      map[string]string // user labels, merged under ours
    StopGrace   time.Duration
    SpecHash    string            // sha256 of this AppSpec — stamped on containers (§6.3)
}

type SealedBundle struct {
    ID        string
    Version   int
    Alg       string // "x25519-xchacha20poly1305"
    Ephemeral []byte // sender ephemeral public key
    Nonce     []byte
    Payload   []byte // sealed map[string]string
    AAD       []byte // node|app|env|version — binds the bundle to its destination
}
```

### 3.1 Rules the Spec enforces by construction

- **`Image` is a digest, always.** Tags are resolved to digests at release creation. Two
  hosts running "the same release" run byte-identical images, and a rollback is exact.
- **`Env` cannot carry secrets.** The type doesn't forbid it; the *pipeline* does — the
  control plane's spec generator draws non-secret config from one table and secrets from
  another, and a validator rejects a Spec whose `Env` values match any known secret value.
- **`Ports` are container-internal.** There is no host-port field. The absence of the
  field is what makes replicas work (§7.1).
- **`SpecHash` covers everything that requires a container replacement.** Fields that can
  be changed in place (labels used only for display, log retention) are excluded from the
  hash so that changing them doesn't recreate a container.

### 3.2 Revision semantics

`Revision` is computed over canonical JSON (sorted keys, no whitespace, RFC 8785-style).
The agent reports its currently-applied revision on every status tick. The control plane
compares; a mismatch that persists past `progressDeadline` raises a `SpecStalled` event.

The agent applies revisions **monotonically by `Issued`** and ignores any Spec older than
what it has applied. This makes duplicate or reordered delivery harmless.

---

## 4. Control plane

```
   HTTP/WS  ─────────────────────────────────────────────────┐
                                                             ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │ api/         gin handlers · authn/authz · validation · DTOs          │
 ├──────────────────────────────────────────────────────────────────────┤
 │ core/        domain services — the only layer with business rules    │
 │              releases · deployments · environments · placement       │
 ├──────────┬───────────────┬──────────────┬────────────────────────────┤
 │ store/   │ secrets/      │ scheduler/   │ stream/                    │
 │ sqlc     │ KEK·DEK·seal  │ placement    │ agent registry, fan-out    │
 ├──────────┴───────────────┴──────────────┴────────────────────────────┤
 │ events/      internal bus → audit, websocket, webhooks, notifiers    │
 └──────────────────────────────────────────────────────────────────────┘
```

Strict downward dependency. `api` never touches `store` directly; `core` never imports
`gin`. This is what makes the CLI, the REST API, and any future gRPC surface share one set
of business rules instead of three.

### 4.1 Release and deployment lifecycle

Two entities that are constantly conflated elsewhere, kept separate here:

- **Release** — immutable. `(image digest, config snapshot, secret version set, build
  provenance)`. Created once. Never mutated. Identified by a short ulid.
- **Deployment** — the *act* of moving an environment to a release. Has a status, a
  timeline, logs, an actor, and an outcome.

```
      build or image ref
            │
            ▼
    ┌───────────────┐   create   ┌──────────────┐
    │   Release     │──────────▶ │  Deployment  │
    │  (immutable)  │            │  pending     │
    └───────────────┘            └──────┬───────┘
            ▲                           │ spec generated, sent to hosts
            │ rollback = new deployment  ▼
            │ pointing at an old release ├─ progressing  (replicas converging)
            │                            ├─ succeeded    (all replicas ready, old drained)
            └────────────────────────────┼─ failed       (deadline or health gate)
                                         └─ rolled_back  (auto-revert completed)
```

**Promotion** creates a Deployment in the target environment pointing at the *same
Release*, re-resolving only environment-scoped config and secret versions. The image
digest is carried across unchanged — the artifact that passed staging is the artifact that
enters production.

### 4.2 Spec generation

Triggered by any change to: app config, environment overlay, secrets version, replica
count, routes, server set, or placement. The generator:

1. Resolves config: `app base → environment overlay → deployment override`.
2. Runs placement (§5) to get `{node → replica count}`.
3. Resolves secret references, decrypts with the project DEK, seals per destination node.
4. Emits one Spec per affected node, hashes it, persists `(node, revision)`, and hands it
   to `stream` for delivery.

Generation is pure and total: same inputs, same Specs, byte for byte. It is unit-testable
without Docker, and it is the single place where "what should be running" is decided.

---

## 5. Placement

The scheduler is deliberately simple: it runs at spec-generation time, not continuously,
and it produces an assignment that is then sticky.

```go
type Placement struct {
    Mode     PlacementMode // Pinned | Spread | Binpack
    Nodes    []string      // Pinned: exact node ids
    Selector map[string]string // label constraints: region=eu, disk=nvme
    Replicas int
}
```

- **Pinned** — the user names the servers. Default for single-server installs.
- **Spread** — maximize distinct nodes, then balance by free reservable memory.
- **Binpack** — fewest nodes that fit, sorted by remaining capacity ascending.

**Reservation accounting.** Each node reports total CPU/memory; each `AppSpec` carries
requests. The scheduler refuses placements exceeding `overcommitRatio` (default 1.5 for
CPU, 1.0 for memory — memory overcommit is how you get an OOM cascade at 3am). Rejection
is a validation error surfaced in the UI at save time, not a silent pending state.

**Stickiness.** Once a replica is placed, it stays until the node is removed, drained, or
the placement policy changes. Rebalancing is an explicit operator action, never automatic.
Automatic rebalancing means containers move while you sleep, which is exactly the property
people fled Kubernetes to avoid.

---

## 6. Agent

### 6.1 Transport

The agent dials the control plane. One gRPC connection, mTLS both ways, HTTP/2 multiplexed.

```protobuf
service Node {
  // Long-lived control stream. Opened once, held forever, re-established with backoff.
  rpc Control(stream NodeMessage) returns (stream ServerMessage);

  // Opened on demand by the agent when the control stream tells it to.
  rpc Logs   (stream LogChunk)    returns (Ack);
  rpc Exec   (stream ExecFrame)   returns (stream ExecFrame);
  rpc Build  (stream BuildChunk)  returns (Ack);
  rpc CertStore(stream CertOp)    returns (stream CertReply); // certmagic backend, §9.4
}

message ServerMessage {
  oneof msg {
    ApplySpec   apply    = 1;  // full Spec
    OpenStream  open     = 2;  // "open an Exec stream with token X for container Y"
    Command     command  = 3;  // restart, pull, prune, drain-node, reissue-cert
    Pong        pong     = 4;
  }
}

message NodeMessage {
  oneof msg {
    Hello       hello    = 1;  // node id, version, arch, capacity, agent pubkey
    Status      status   = 2;  // applied revision, per-app replica states, resource usage
    Event       event    = 3;  // container started/died/health-changed/pull-failed
    Ping        ping     = 4;
  }
}
```

**Why the agent dials out:** app servers need no inbound port, no firewall rule, no public
IP, and no SSH exposure. It also means a NAT'd or Tailscale-only box works with zero extra
configuration. The cost is that the control plane cannot initiate a connection — hence
`OpenStream`, which asks the agent to dial back for exec/logs/build.

**Reconnect semantics.** Exponential backoff with jitter, capped at 30 s. On reconnect the
agent sends `Hello` with its applied revision; the control plane responds with the current
Spec if it differs. No replay log, no message queue — full state transfer makes
reconnection stateless.

**Backpressure.** Log and metric streams are lossy by design: a bounded channel with
drop-oldest and a dropped-count counter. Control messages are lossless. A slow control
plane must never block a container's stdout.

### 6.2 The reconcile loop

Level-triggered, edge-accelerated. Four trigger sources feed one coalescing queue:

```
  ApplySpec from CP ────┐
  Docker event stream ──┤
  Periodic resync (30s)─┼──▶ coalescing queue (keyed by app-env) ──▶ worker pool (N=8)
  Manual/CLI trigger ───┘         ▲                                        │
                                  └────────── requeue with backoff ────────┘
```

Invariants:

- **One reconcile in flight per key.** A burst of ten triggers for the same app-env
  collapses into one pass, plus one more if changes arrived mid-pass.
- **Idempotent.** Running a pass twice on unchanged state performs zero Docker calls.
- **Never partially applies.** A pass either reaches the target replica set or reports the
  precise step it stalled on, with the Docker error attached.
- **Bounded.** Every Docker call carries a context deadline. A hung `dockerd` degrades one
  app-env, not the agent.

Pass structure:

```
observe    list containers/networks/volumes by our label filter → actual state
plan       diff actual vs AppSpec → ordered []Action
apply      execute actions with per-action timeouts, honoring rollout strategy
report     emit events + status delta upstream
```

### 6.3 Diffing without asking Docker

Per axiom 3: we never compare our desired config to `ContainerInspect`. Instead every
container is stamped at creation:

```
sh.getvesta.managed    = "true"
sh.getvesta.node       = <node id>
sh.getvesta.app        = <app>
sh.getvesta.env        = <env>
sh.getvesta.appspec    = <AppSpec.ID>
sh.getvesta.release    = <release id>
sh.getvesta.replica    = "3"
sh.getvesta.spec-hash  = <AppSpec.SpecHash>
sh.getvesta.secrets-ver= "7"
```

The diff is then trivial and exact:

| Condition | Action |
|---|---|
| replica index present, `spec-hash` equal, `secrets-ver` equal, running | none |
| `spec-hash` differs | replace (rollout strategy applies) |
| `secrets-ver` differs | restart in place, rollout strategy applies |
| replica index missing | create |
| replica index > desired count | drain and remove |
| `managed=true` but no matching AppSpec | remove, subject to `PrunePolicy` |
| no `managed` label | **never touched** — unmanaged containers are invisible to us |

That last row matters: Vesta shares a Docker daemon with whatever else the user runs. We
list with a label filter and we prune only inside our own namespace.

### 6.4 Package boundaries

```
internal/reconcile   the loop, the queue, the planner (no Docker types leak out)
internal/dockerx     Moby SDK wrapper: containers, images, networks, volumes, events, exec
internal/secretsd    agent-side unsealing, tmpfs/socket handoff, zeroing
internal/probe       startup/readiness/liveness execution
internal/proxycfg    route model + socket protocol (shared with vesta-proxy)
internal/logship     container log tailing, ring buffers, upstream shipping
internal/buildd      BuildKit client, cache, image push
```

`dockerx` is the only package that imports the Moby SDK. Everything above it speaks
`core` types. This is what makes a future containerd or Podman backend a new package
rather than a rewrite.

---

## 7. Host topology

### 7.1 Networks, and why there are no host ports

Each app-environment gets one user-defined bridge network:

```
network:   vesta_<app>_<env>            172.x.0.0/24, internal DNS enabled
container: vesta_<app>_<env>_<replica>  e.g. vesta_api_prod_3
volume:    vesta_<app>_<env>_<name>_<replica>
```

Containers publish **nothing** to the host. The proxy — running in the host network
namespace — dials container IPs directly, which is routable because bridge networks are
attached to the host. Consequences:

- Replica #2 does not collide with replica #1, because neither owns a host port. This is
  the entire reason Coolify cannot do replicas on one server.
- `docker ps` shows no exposed ports, and nothing on the box is reachable from outside
  except through the proxy. Port exposure becomes a routing decision, not a runtime one.
- An app can be made deliberately host-published (legacy TCP services, a game server) via
  an explicit `hostPort` escape hatch, which sets `replicas: 1` and says why.

Docker's embedded DNS resolves sibling containers by service name inside the app-env
network, so service-to-service calls inside one environment work without the proxy.
Cross-environment traffic must go through the proxy, by design.

### 7.2 Volumes

```go
type VolumeMount struct {
    Name      string
    Path      string
    PerReplica bool   // expands to <name>_<replica>, StatefulSet-style
    ReadOnly  bool
    Source    VolumeSource // Named | HostPath | Tmpfs
}
```

Validation rejects `replicas > 1` with a shared writable named volume unless the app is
explicitly flagged `sharedWritableVolume: true` with an acknowledgement string. The
default is refusal, because the failure mode (two Postgres processes on one data
directory) is silent, delayed, and unrecoverable.

### 7.3 Resource limits and logging

Every container gets: `--memory`, `--memory-swap` equal to memory (no swap thrash),
`--cpus`, `--pids-limit`, and `--log-driver local --log-opt max-size=10m --log-opt
max-file=3`. The default `json-file` driver with no rotation is how self-hosted PaaS
installs fill their disks; we never use it.

---

## 8. Rollout state machine

Per app-environment, executed by the agent, coordinated across nodes by the control plane
for multi-node environments (one node at a time by default, `maxParallelNodes` to widen).

```
                  ┌─────────┐
                  │  Idle   │◀──────────────────────────────┐
                  └────┬────┘                               │
        new spec-hash  │                                    │
                       ▼                                    │
                 ┌───────────┐   pull fails / no capacity   │
                 │ Preparing │──────────────────────────────┤ Failed
                 │ (pull img)│                              │ (no change made)
                 └─────┬─────┘                              │
                       ▼                                    │
             ┌───────────────────┐                          │
        ┌───▶│ Starting replica  │                          │
        │    └─────────┬─────────┘                          │
        │              ▼                                    │
        │    ┌───────────────────┐  startup deadline / crash│
        │    │ Waiting readiness │──────────────────────────┤ Rollback
        │    └─────────┬─────────┘                          │ (destroy new,
        │              ▼ ready                              │  old untouched)
        │    ┌───────────────────┐                          │
        │    │ Add to proxy pool │                          │
        │    └─────────┬─────────┘                          │
        │              ▼                                    │
        │    ┌───────────────────┐                          │
        │    │ Drain old replica │  (remove from pool,      │
        │    │  → SIGTERM        │   wait drainSeconds,     │
        │    │  → SIGKILL @grace │   then signal)           │
        │    └─────────┬─────────┘                          │
        │   more       ▼                                    │
        └── replicas ──┴──▶ all done ──────────────────────▶┘ Succeeded
```

**The ordering is the whole point.** New replica is *ready and in the pool* before the old
one leaves it. At `replicas: 1` this means momentarily two containers and zero dropped
requests — the single-server zero-downtime deploy.

Strategy parameters: `maxSurge` (default 1), `maxUnavailable` (default 0), `drainSeconds`
(default 15), `stopGrace` (default 30 s), `progressDeadlineSeconds` (default 600),
`autoRollback` (default true).

**Blue/green** builds the full new pool, then performs one atomic pool swap in the proxy,
keeping the old pool alive for `keepPreviousFor` so rollback is a second atomic swap with
no container starts. **Canary** adds weights to the pool and a promotion gate.

### 8.1 Probes

Three probes, our own implementation rather than Docker `HEALTHCHECK`, because we need
different semantics per phase and Docker offers one:

| Probe | Purpose | On failure |
|---|---|---|
| startup | "has it finished booting" | after `failureThreshold`, abort the rollout |
| readiness | "should it receive traffic" | remove from proxy pool; do not restart |
| liveness | "is it wedged" | restart the container, with backoff |

Readiness controlling pool membership and liveness controlling restarts must be separate,
or a slow dependency turns a degraded app into a restart loop.

---

## 9. Proxy

### 9.1 Configuration protocol

The agent is the only writer. Over `/run/vesta/proxy.sock`:

```go
type ProxyConfig struct {
    Revision string
    Routes   []Route
}

type Route struct {
    Hosts      []string        // SNI/Host match, wildcards allowed
    PathPrefix string
    Upstreams  []Upstream
    TLS        TLSPolicy       // Auto (ACME) | Custom | Off
    Middleware []Middleware    // redirect, basic-auth, ip-allow, rate-limit, headers
    Sticky     StickyPolicy
}

type Upstream struct {
    Addr   string  // 172.20.0.11:3000 — container IP, never a host port
    Node   string  // owning node; empty or self = local, otherwise reachable via mesh (§10.1)
    Weight int
    State  UpstreamState // Ready | Draining | Down
}
```

The route table a proxy holds covers the **whole fleet**, not just local apps — that is what
lets any node accept traffic for any hostname. Upstream selection is local-first; §10.1 has
the mesh rules.

Apply is transactional: the proxy parses and validates the whole document, builds a new
immutable routing table, and swaps an `atomic.Pointer`. In-flight requests finish against
the table they started with. A malformed document is rejected wholesale with an error back
over the socket, and the previous table stays live. There is no restart, no reload signal,
and no window where routes are missing.

### 9.2 Load balancing and draining

Default is least-connections (better than round-robin when response times vary, which they
always do). `Sticky` supports cookie-based affinity for apps that need it.

Draining is a state, not a delete: `Draining` upstreams receive no new requests but keep
serving open ones. The agent only signals the container after the drain window, so
in-flight requests complete. This is the difference between "zero downtime" and "zero
downtime unless someone was mid-upload".

### 9.3 Health

The proxy runs its own passive health tracking (consecutive 5xx / connect failures eject
an upstream) *in addition to* the agent's active probes. Passive ejection reacts in
milliseconds to a container that died between probe intervals; active probes are
authoritative for pool membership. Ejection is temporary with exponential re-admission.

### 9.4 Certificates across a fleet

Three servers terminating TLS for `app.example.com` each running independent ACME is a
rate-limit incident waiting to happen. So: **the control plane is the cluster certificate
store.** `vesta-proxy` uses `certmagic` with a `Storage` implementation backed by the
`CertStore` RPC (§6.1) through the agent. That gives distributed locking (only one node
solves a given challenge), shared storage (all nodes serve the same cert), and shared
renewal. Local disk under `/var/lib/vesta/certs` is a read-through cache so a
control-plane outage cannot break TLS termination.

HTTP-01 challenges are routed to whichever node holds the lock; DNS-01 is supported for
wildcards and for nodes that aren't publicly reachable on :80.

---

## 10. DNS and fleet ingress

DNS is four separate problems that get conflated. Keeping them apart is most of the design.

1. **Public resolution** — how `app.example.com` reaches *a* Vesta node.
2. **Fleet ingress** — how a request that landed on node A reaches a replica on node C.
3. **Record management** — who creates the A/AAAA/CNAME records, and how they stay true.
4. **Internal discovery** — how a container addresses another app without leaving the fleet.

Only (2) is architecturally interesting, and solving it well makes (1) and (3) almost
trivial.

### 10.1 The core decision: any node is a valid entry point

**Every `vesta-proxy` holds the route table for the entire fleet, not just for the apps on
its own host.** Upstreams are tagged with the node that owns them. If a request arrives for
a hostname whose replicas live elsewhere, the receiving proxy forwards it to a peer proxy
that has one.

```
 DNS: app.example.com ─▶ A 10.0.0.1, A 10.0.0.2, A 10.0.0.3

    client ──▶ node2 :443            node2 has no replica of this app
                 │  vesta-proxy: route table says replicas are on node1, node3
                 │  TLS terminated here
                 ▼  mesh hop: HTTP/2 over mTLS (node certs, internal CA), :8443
              node3 :8443 ──▶ 172.20.0.11:3000   container, local to node3
```

Why this is worth the hop: **DNS no longer has to be correct about placement.** Point DNS
at all your nodes, or one, or two edge boxes — routing stays correct in every case. Scaling
an app from node1 to node3 touches no DNS record. A node dying doesn't produce a routing
hole, only a resolution hole for the fraction of clients holding that IP.

Mesh rules:

- **Local-first.** A proxy always prefers ready upstreams on its own host and only forwards
  when it has none. In the common case (small fleets, apps on every node) the hop never
  happens and costs nothing.
- **One hop, never two.** The forwarding proxy stamps `Vesta-Hop: 1`. A proxy receiving a
  hopped request serves it locally or returns 503 — it must never forward again. This is
  what makes loops structurally impossible rather than merely unlikely.
- **mTLS between proxies**, using the node certificates the internal CA already issues
  (§6.1). Inter-node traffic frequently crosses a public network between VPSes; it is never
  plaintext, and no WireGuard or private-network requirement is imposed on the user.
- **TLS terminates once**, at the entry node. The hop carries the original `Host`, the
  client address in `X-Forwarded-For`, and the original scheme.
- **Health is authoritative locally.** A proxy forwards only to peers reporting a ready
  upstream in the last status tick, so a hop never lands on a known-dead node.

Cost, stated plainly: one extra RTT (~0.3–1 ms same-datacenter, tens of ms cross-region)
and doubled internal bandwidth for hopped requests. For cross-region fleets, pin an
environment's placement to the region its DNS points at and the hop disappears.

### 10.2 The four public-DNS shapes

All four work identically, because §10.1 removed the requirement that DNS know where
anything runs. This is a deployment choice, not an architecture fork.

| Shape | Records | Failover behavior | Use when |
|---|---|---|---|
| **Single node** | one A (+ AAAA) | none | default; most installs |
| **Multi-A round-robin** | one A per node, TTL 60 | client-side retry; optional health-checked record removal | small fleets, no extra infrastructure |
| **Edge nodes** | A records for designated edge nodes only | mesh reaches compute nodes | separating ingress from compute; compute nodes need no public IP |
| **Floating IP / external LB** | one A at a VIP, or the LB's hostname | sub-second (VRRP / cloud API / provider) | when real failover matters |

**Multi-A is not failover, and we say so in the docs.** Browsers do retry the next A record
on connection *refused* (Happy Eyeballs makes this fast), but a firewalled or blackholed
node produces a TCP timeout instead, and clients sit through it. Resolvers and browsers
also cache past TTL freely. If sub-minute failover is a requirement, the answer is a
floating IP or an external load balancer — not a shorter TTL. Vesta will not pretend
otherwise.

### 10.3 Record management

Three tiers, from zero-setup to fully automatic.

**Zero-config (demos, local, first five minutes).** `sslip.io` / `nip.io` wildcards resolve
without any DNS setup at all: `api-prod.10-0-0-1.sslip.io`. Enough to see the product work
before touching a registrar.

**Wildcard default domain (recommended).** The operator points `*.apps.example.com` at the
node set **once**. Every app-environment then gets an automatic hostname
(`<app>-<env>.apps.example.com`) with no further DNS work, ever. Combined with a single
DNS-01 wildcard certificate shared through the cluster cert store (§9.4), adding an app
involves zero DNS operations and zero ACME issuances. This is the path the onboarding flow
pushes.

**Custom domains.** `vesta domain add app.example.com --app api --env prod`. The UI shows
the exact records to create, and then a **preflight check** resolves the hostname from the
control plane and compares against the expected node addresses:

```
  app.example.com    A  10.0.0.1   ✓ node-1
                     A  10.0.0.2   ✓ node-2
                     A  198.51.100.7  ✗ unknown address — not a Vesta node
  TTL 3600                          ⚠ shorten to 60 before changing node membership
```

Certificate issuance is **blocked** until preflight passes. ACME's failed-validation limit
(5 per hostname per hour) means a misconfigured record otherwise locks a user out of TLS
for an hour with an opaque error — the preflight check exists specifically to convert that
into a clear message before any ACME traffic happens.

**Provider automation (optional).** A `DNSProvider` interface backed by
[`libdns`](https://github.com/libdns) — Cloudflare, Route53, DigitalOcean, Hetzner, Gandi,
and the rest. One credential set, stored as an ordinary Vesta secret, serves **both**
record management and DNS-01 challenges, because `certmagic` consumes the same `libdns`
interfaces. With a provider configured, attaching a domain creates the record, detaching
removes it, and adding a node updates every record that references the node set.

Apex domains get an explicit note in the UI: the root of a zone cannot hold a CNAME, so it
needs A/AAAA records or a provider-specific ALIAS/flattening feature.

### 10.4 ACME interaction

- **HTTP-01 with multiple A records** is the subtle case: the CA may hit *any* node. Because
  all proxies share certificate storage through the control plane (§9.4), the challenge
  token written by the solving node is immediately readable by every other node, so whichever
  node the CA reaches can answer. Without shared storage this configuration fails
  intermittently and inexplicably; with it, it just works.
- **DNS-01** is required for wildcards and for nodes not reachable on :80. Challenges are
  solved by the **control plane**, not the nodes, so provider credentials live in exactly one
  place.
- **Renewal** is cluster-wide and locked: one node renews, all nodes serve the result.

### 10.5 Internal DNS

**Inside one environment.** Containers on a user-defined bridge network resolve each other
by container name through Docker's embedded resolver at `127.0.0.11`. Worth stating
precisely because it is commonly misunderstood: setting `--dns` on a container does **not**
replace the embedded resolver — it configures the *upstream* that `127.0.0.11` forwards
unresolved queries to. Container-name resolution keeps working regardless.

**Across environments, apps, and nodes.** The agent runs a small authoritative resolver
bound to the bridge gateway address and sets it as the containers' upstream. It answers one
zone:

```
  <app>.<env>.vesta.internal   →  the local vesta-proxy address
```

Everything else forwards to the host's configured resolvers. Traffic to
`api.prod.vesta.internal` therefore reaches the local proxy, which applies §10.1: local
replica if there is one, mesh hop if not. The consequences are the ones that matter:

- Service links inject `http://api.prod.vesta.internal` rather than a public URL, so
  east-west traffic never egresses to the internet and back.
- The name is stable across redeploys, rescheduling, and scaling — it resolves to a proxy,
  never to a container IP.
- Cross-environment calls remain explicit and routable, while staying inside the fleet.

**Ordering:** external DNS and the wildcard domain are M1 work; the proxy mesh and the
internal resolver land with multi-node support in M7. A single-server install needs neither
and pays for neither.

## 11. Secrets pipeline

The full path, end to end. Threat model is in [PLAN.md §6.1](PLAN.md); this is the
mechanism.

### 10.1 Key hierarchy

```
KEK   file | env | AWS KMS | GCP KMS | Vault Transit | sealed (Shamir)
 │
 ├─ wraps ─▶ DEK per project            AES-256-GCM, rotatable independently
 │            │
 │            └─ encrypts ─▶ secret value   AES-256-GCM
 │                            AAD = project_id | app_id | key_name | version
 │
 └─ never leaves the control-plane process; never written by us except file mode
```

The AAD binding means a ciphertext lifted from one row and pasted into another fails to
open. Database-level copy-paste privilege escalation is closed by construction.

### 10.2 Sealing to a node

At spec-generation time, for each (node, app-env) that needs secrets:

```
1. CP loads ciphertexts, unwraps project DEK with KEK, decrypts values   [CP memory]
2. CP serializes map[string]string
3. CP seals with X25519 + XChaCha20-Poly1305 to the node's public key,
   AAD = node|app|env|version                                            [SealedBundle]
4. Plaintext buffer is zeroed
5. SealedBundle travels inside the Spec over mTLS
```

The node's X25519 keypair is generated at enrollment. The private key lives in agent
memory only; it is regenerated on every agent restart and re-registered over the control
stream. An agent restart therefore invalidates every bundle it holds — which is the point:
there is no key on disk to steal, and sealed material captured from the wire is useless
after a restart.

### 10.3 Handoff into a container

The agent opens the bundle in memory (`mlock`ed where the OS permits, zeroed after use)
and delivers by one of two mechanisms.

**Default — tmpfs handoff:**

```
 agent                          container
   │  mount tmpfs /run/vesta/secrets (size 1m, mode 0400, uid = container user)
   │  write env file
   │  create container with:
   │    Entrypoint = ["/.vesta/init", "--", <resolved original entrypoint+cmd>]
   │    Binds      = /var/lib/vesta/bin/vesta-init:/.vesta/init:ro
   │  start ──────────────────▶ vesta-init:
   │                              1. open /run/vesta/secrets/env
   │                              2. parse, setenv into own process
   │                              3. unlink the file
   │                              4. execve(real entrypoint)   ← no wrapper process
   │  ◀── container reports started
   │  unmount tmpfs
```

Observable result: `docker inspect` has no env vars; the container config JSON on disk has
no env vars; the tmpfs file exists for microseconds and never touches a disk; the
application reads ordinary `process.env` with zero code changes.

**Hardened — socket handoff:** no file at all. The agent bind-mounts a unix socket and a
single-use token; `vesta-init` connects, presents the token, and the agent verifies peer
credentials against the container's PID namespace before answering, then revokes the
token. Values exist only in the process's memory, never in any filesystem.

### 10.4 `vesta-init` details

A static, dependency-free binary (~2 MB, `CGO_ENABLED=0`). Correctness requirements:

- It **`execve`s**, so it does not remain as a wrapper: the real app is PID 1, signals go
  straight to it, exit codes pass through unmodified, and there is no zombie-reaping
  behavior change.
- The original entrypoint is resolved by the **agent** from the image manifest
  (`ImageInspect` → `Config.Entrypoint` + `Config.Cmd`), not guessed by the init. Shell-form
  `ENTRYPOINT` is preserved verbatim as `["/bin/sh","-c", ...]`.
- If the secrets source is missing, it fails loudly with a distinctive exit code rather
  than starting an app with a half-populated environment.
- Per-app escape hatch `secretInjection: env` falls back to plain Docker env vars, with a
  persistent warning banner in the UI naming the app. Some images cannot be wrapped; we
  degrade visibly rather than silently.

### 10.5 Access control, rotation, redaction

- Four verbs, independent of RBAC role: `use` (inject at deploy, cannot see), `read`
  (reveal plaintext), `write`, `manage` (rotate, delete). Developers ship code with
  secrets they cannot read.
- `GET /secrets` returns names, versions, timestamps, and reveal history — never values.
  `POST /secrets/{name}/reveal` requires `read`, re-authentication for production
  environments, and writes an audit row with actor, IP, time, and reason.
- Values are versioned; a Release pins the version set it deployed with, so rollback
  restores the configuration that actually worked.
- Rotation bumps `SecretsVer`, which changes the container label, which the reconciler
  reads as "restart these replicas" — rotation flows through the ordinary rollout
  machinery with no special path.
- **Redaction:** build and deploy log streams pass through a filter seeded with the live
  values for that app-env, replacing matches with `***`. A secret echoed by a careless
  build script does not reach the log store.

---

## 12. Build pipeline

```
 git webhook / API / CLI
        │
        ▼
   ┌─────────┐  select strategy   ┌────────────────────────────────┐
   │ vestad  │───────────────────▶│ Dockerfile | Nixpacks | Pack   │
   └────┬────┘                    └───────────────┬────────────────┘
        │ assign build node                       │
        ▼                                         ▼
   ┌──────────────┐   BuildKit client    ┌──────────────────┐
   │ vesta-agent  │─────────────────────▶│ buildkitd (ctr)  │
   │ on build node│                      │ cache: local +   │
   └──────┬───────┘                      │ registry export  │
          │ stream logs (redacted)       └────────┬─────────┘
          ▼                                       │ push
   ┌──────────────┐                               ▼
   │ log store    │                    ┌────────────────────┐
   └──────────────┘                    │ registry (digest)  │
                                       └─────────┬──────────┘
                                                 ▼
                                         Release created,
                                         pinned to sha256:…
```

- `buildkitd` runs as a container the agent supervises, not a daemon we ask users to
  install. Any node can be a build node; `buildNode: true` marks preferred ones so builds
  don't compete with production workloads for CPU.
- Cache is exported to the registry (`--cache-to type=registry,mode=max`) so a build on
  node B benefits from node A's work.
- Build secrets use BuildKit's `--mount=type=secret`, never `ARG` — a build arg is baked
  into image history and is readable by anyone who pulls the image.
- The build's output is a **digest**. Releases never reference tags. A moving tag would
  break the "what you tested is what ships" guarantee that promotion depends on.
- "Build elsewhere, deploy the digest" is a first-class path for teams whose CI already
  builds images: `POST /apps/{app}/releases {image: "repo@sha256:..."}`.

---

## 13. Data model

Sketch of the schema, sqlc-generated accessors, goose migrations. Postgres and SQLite
share DDL except for type aliases.

```
teams ──┬── team_members ── users ──┬── api_tokens
        │                            └── mfa_credentials
        └── projects ──┬── apps ──┬── environments ──┬── deployments ── releases
                       │          │                  ├── routes (domains, TLS)
                       │          │                  ├── instances (replica state)
                       │          │                  ├── env_vars (non-secret)
                       │          │                  └── secret_bindings
                       │          └── app_config (base spec)
                       ├── secrets ── secret_versions
                       │      └── secret_acls
                       ├── services (managed pg/mysql/redis/mongo)
                       ├── volumes ── backups ── backup_schedules
                       ├── cron_jobs ── job_runs
                       └── quotas
servers ──┬── server_labels
          └── node_status (heartbeat, capacity, applied revision)
audit_log · events · outbound_webhooks · webhook_deliveries · notification_channels
```

Rules:

- **Every query is team-scoped.** The store layer takes `team_id` as a non-optional
  parameter on every read path. Enforcement lives below the handlers so a forgotten check
  in a handler cannot leak cross-tenant data.
- `secret_versions` is append-only. Deleting a secret tombstones it; the ciphertext is
  destroyed only after no live Release references the version.
- `instances` is a *cache* of agent-reported state, never a source of truth. If it
  disagrees with an agent, the agent is right.
- `events` is the append-only projection source for the UI stream and webhooks;
  `audit_log` is the security-relevant subset, retained separately and for longer.

---

## 14. Observability

**Logs.** The agent tails container stdout/stderr via the Docker API into a bounded
per-container ring buffer on the host (immediately available for `vesta logs`, survives a
control-plane outage), and ships asynchronously upstream for search and retention. Lossy
under backpressure by design, with a visible dropped-line counter — a full log pipeline
must never block or crash an application.

**Metrics.** Agent samples container CPU/memory/network/disk from Docker's stats stream at
a low frequency (10 s) and reports deltas on the control stream. Not a Prometheus
replacement; enough to drive the dashboard and autoscaling triggers. OTLP export is
available for people who want the real thing.

**Events.** Every state transition emits to the internal bus: deployment phases, replica
health flips, probe failures, cert issuance, secret reveals, quota rejections. The UI's
live view is a websocket subscription to this bus, filtered by team. Nothing in the UI
polls.

**Audit.** Actor, action, target, IP, timestamp, outcome, and — for secret reveals — the
stated reason. Immutable, exportable, retained independently of the general event log.

---

## 15. Failure modes

| Failure | Behavior | Recovery |
|---|---|---|
| Control plane down | Apps keep running, keep being health-checked, keep being routed and TLS-terminated (cert cache). No deploys, no config changes, no log shipping. | Agents reconnect with backoff; full state transfer on reconnect; no manual step. |
| Agent crashes | Containers keep running (they are not children of the agent). Proxy keeps serving its last table. | systemd restarts it; it re-observes, re-diffs, converges. Secrets are re-fetched because its keypair changed. |
| Agent restarts, CP unreachable | Containers keep running. New containers **cannot** be started for apps that need secrets — there is no secret on disk by design. | Availability cost accepted for confidentiality. Documented explicitly; do not "fix" it with a disk cache. |
| Proxy crashes | Traffic drops until systemd restarts it (~1 s). Containers unaffected. | Agent re-pushes config on proxy reconnect. |
| dockerd down/hung | Reconcile passes time out per-app; agent reports `RuntimeUnavailable`; no cascading restarts. | Bounded contexts everywhere; agent recovers when the socket answers. |
| Node unreachable | Marked unreachable after 3 missed heartbeats; its upstreams withdrawn from any other node's proxy; alert fires. Replicas are **not** rescheduled (v1). | Operator action. See PLAN §5.4. |
| DNS still resolves to a dead node | Clients holding that A record fail to connect. Other nodes serve normally — routing is unaffected, only resolution. | Client retries the next A record on refused connections; with a DNS provider configured, the record is pulled automatically. Blackholed (timeout) nodes are the bad case — see §10.2. |
| Mesh peer unreachable mid-request | Entry proxy returns 502 for that request and marks the peer down for subsequent ones. | Passive ejection with exponential re-admission; local upstreams are always preferred anyway. |
| Deploy fails health gate | New replicas destroyed, old ones never left the pool, deployment marked `failed` with the failing probe output. | Automatic. Nothing to undo. |
| Disk full on app server | Log rotation caps container logs; agent's ring buffers are bounded; image GC runs on a watermark. | Watermark-triggered prune of unreferenced images and stopped containers. |
| Clock skew between CP and node | Spec ordering uses `Issued`; large skew could cause a Spec to be ignored. | Agent rejects Specs more than 5 min in the future and raises an event. |
| Bad agent release | Workloads unaffected — containers are not children of the agent. The canary node fails to confirm and reverts to the previous binary. | Trial-and-revert (§17.6); the fleet rollout halts automatically, so only the canary was ever exposed. |
| Agent too old to understand the current Spec | Connects, is marked `outdated`, refuses the Spec, and is offered an update over the frozen channel. | The Hello/Update messages never change incompatibly (§17.2), so no agent is ever unreachable. |
| Migration fails mid-update | `vestad` aborts startup and does not serve; the previous binary can be restarted against the pre-migration backup. | Expand/contract means the prior release still reads the schema; SQLite is copied before migrating, Postgres uses an advisory lock. |

---

## 16. Security boundaries

```
   internet ──▶ vesta-proxy    untrusted input, no secrets, unprivileged, own process
                    │ unix socket, config in one direction only
                    ▼
                vesta-agent    root, holds unsealed secrets, no listening network socket
                    │ mTLS, agent-initiated
                    ▼
                  vestad       holds KEK, unprivileged, the only process that can decrypt
                    │
                    ▼
                  store        ciphertext only; a full dump yields no plaintext
```

- The agent listens on **no** network port. Its only inbound surface is a root-owned unix
  socket. Everything reaches it through a connection it opened.
- The proxy never holds, requests, or is told about secret material.
- Container-to-container isolation is Docker's, which means it is a boundary against
  accident, not against a determined hostile tenant. Stated plainly in the docs.
- Agent certificates are short-lived and renewed over the established stream; a revoked
  node loses access at the next renewal and is dropped from the CA's allow list
  immediately.

---

## 17. Versioning and updates

Updating a fleet is the operation with the worst failure mode in the whole system: a bad
update can strand every node at once, and the thing you would use to fix them is the thing
that just broke. The design is shaped around that single risk.

### 17.1 One version, one commit

`vestad`, `vesta-agent`, `vesta-proxy`, `vesta-init`, the CLI, and the embedded UI are built
from one commit and share one version, `v0.7.3`. Independent per-component versions would
produce a compatibility matrix nobody can test. Semver, with a specific meaning:

| Bump | Means | Agent action |
|---|---|---|
| patch | bug fixes, no wire or schema change | auto-update by default |
| minor | additive wire fields, additive migrations, new features | auto-update if policy allows |
| major | a compatibility break — removed proto fields, destructive migration | never automatic |

Each binary embeds, at build time:

```go
var (
    Version         = "0.7.3"  // release
    ProtocolVersion = 4        // wire contract, bumped independently of Version
    MinPeerProtocol = 2        // oldest peer this binary will talk to
)
```

`Version` is for humans. `ProtocolVersion` is what compatibility is actually decided on, and
it moves far more slowly than `Version`.

### 17.2 The frozen core

**The update path must keep working when everything else has broken**, because it is the
only way to repair a fleet remotely. So a small subset of the protocol is frozen at v1 and
may never change incompatibly, no matter what happens above it:

```protobuf
// FROZEN. Additive-only, forever. Changing these breaks fleet recovery.
message Hello       { string node_id = 1; string version = 2; uint32 protocol = 3;
                      bytes agent_pubkey = 4; string applied_revision = 5; }
message UpdateOffer { string version = 1; string sha256 = 2; bytes signature = 3;
                      uint64 size = 4; bool required = 5; }
message UpdateChunk { bytes data = 1; uint64 offset = 2; }
message UpdateResult{ bool ok = 1; string version = 2; string error = 3; }
```

Everything else — `ApplySpec`, `Command`, `Event`, exec, logs — negotiates on
`ProtocolVersion` and may evolve freely. The practical consequence: an agent too old to
understand the current `Spec` can still say hello, be recognized, be told to update, and
receive a new binary. **A stranded agent is always recoverable.** Without this rule, a
protocol break means SSH-ing to every box, which is the failure we built the agent to avoid.

### 17.3 Compatibility contract

**The control plane may be newer than an agent. It is never older.** Update order is always
control plane → agents → proxies, and the control plane supports agents for two minor
versions back (roughly a quarter). Concretely:

```
  vestad 0.9.x  ←→  agent 0.7.x, 0.8.x, 0.9.x     supported
  vestad 0.9.x  ←→  agent 0.6.x                    degraded: connects, refuses Spec,
                                                    is offered an update immediately
  vestad 0.7.x  ←→  agent 0.9.x                    refused — never run agents ahead of the CP
```

An out-of-contract agent is **not** disconnected. It connects, reports, appears in the fleet
view marked `outdated`, and is offered an update. Refusing the connection outright would
strand exactly the nodes that most need reaching.

### 17.4 Updating the control plane

1. Operator runs `vesta-update` (or pulls a new container image / systemd unit).
2. `vestad` starts, acquires a migration lock (Postgres advisory lock; for SQLite, an
   exclusive file lock plus an automatic pre-migration copy of `vesta.db`), and runs goose
   migrations.
3. Migrations follow **expand/contract**: the release that stops writing a column is never
   the release that drops it. A column is added and populated in one release, stops being
   read in the next, and is dropped in a third. This is what allows two `vestad` versions to
   run against one database during an HA rolling update — and what makes a same-day rollback
   of the binary possible without touching data.
4. Agents reconnect on their own (§6.1 backoff). No agent action is required.

**API downtime during a single-node CP update is seconds, and workloads are unaffected** —
per §16, apps keep running, keep being health-checked, and keep being routed while the
control plane is gone.

**Downgrades are honest:** binaries roll back freely, schema does not. Migrations are
forward-only. Rolling back across a migration boundary requires the pre-migration backup,
and the release notes say so explicitly for any release that migrates.

### 17.5 Updating an agent

The property that makes this safe: **containers are children of `containerd-shim`, not of
the agent.** Stopping, replacing, and restarting `vesta-agent` does not signal, stop, or
touch a single running workload. There is no drain, no cordon, no eviction. This is the
central advantage of not being Kubernetes, and it is why agent auto-update is a reasonable
default here and a fraught one there.

**Artifact delivery.** Two sources, same verification:

- **Over the control stream** (default). The control plane holds the release artifacts and
  streams the binary down the existing mTLS connection. No egress from app servers, no
  registry credentials, no dependency on GitHub being up, and it works on nodes with no
  internet access at all. Air-gapped installs do `vesta release import vesta-0.7.3.tar.gz`
  on the control node once and the whole fleet updates from it.
- **Direct download** from a configured URL, for operators who prefer a mirror.

**Verification is a signature, not a checksum.** Every release artifact is signed with the
project's Ed25519 release key; the public key is compiled into every agent binary. A SHA-256
alone protects against corruption, not against a compromised mirror. Honest limit: this does
not defend against a compromised control plane, which can already run arbitrary root
containers on every node (PLAN §6.1, T4). It defends the distribution path, which is the
part that is actually exposed.

**Atomic swap and re-exec:**

```
1. stream artifact to /var/lib/vesta/bin/.agent.tmp   (same filesystem, so rename is atomic)
2. verify Ed25519 signature and size; verify it runs: `.agent.tmp --version`
3. hard-link current binary to agent.prev             (rollback target)
4. write trial marker: /var/lib/vesta/update.trial {from, to, deadline}
5. rename(.agent.tmp, agent)                          (atomic; no torn binary can be executed)
6. exit(0) cleanly — systemd Restart=always starts the new one
```

### 17.6 Trial-and-revert

Step 4 is what stops a bad release from bricking a fleet. The new agent must *prove itself*:

```
        new agent starts
              │
              ▼
      trial marker present?
         │            │
        no           yes
         │            │
      normal          ▼
      startup   deadline passed without a confirmed session?
                   │                       │
                  yes                      no
                   │                       │
                   ▼                       ▼
          REVERT: rename(agent.prev,   connect to CP, apply a Spec,
          agent); clear marker;        report healthy → clear marker,
          exit → systemd restarts      update confirmed, delete agent.prev
          the known-good binary
```

Confirmation requires an authenticated session *and* one successful reconcile pass — not
merely "the process started". A binary that starts, connects, and then cannot converge is
still a failed update, and it reverts.

A reverted node reports `update-reverted` with the failing version, and the control plane
**stops the rollout fleet-wide**. One node's failure cancels the update for everyone who
hasn't taken it yet. This is the property that turns a bad release from a fleet-wide outage
into a single-node blip.

### 17.7 Rollout across the fleet

Never all at once:

```yaml
update:
  channel: stable          # stable | beta | edge
  policy: patch            # patch | minor | manual | pinned
  window: "Sun 02:00-06:00 Europe/Berlin"   # optional
  rollout:
    canary: 1              # nodes first
    soak: 30m              # healthy before widening
    batch: 25%             # then this fraction at a time
    haltOnFailure: true    # any revert cancels the remainder
  pinned:
    - node: db-1           # never auto-updates; operator handles it
```

Defaults: `policy: patch`, one canary node, 30-minute soak, 25% batches, halt on failure.
Security releases are flagged and surfaced loudly in the UI and via notification channels,
but they **do not** override the policy — an auto-apply-security opt-in exists for operators
who want it. A vendor-controlled switch that bypasses an operator's stated update policy is
a supply-chain lever, and we don't build one.

### 17.8 Updating the proxy — without dropping traffic

The agent owns the proxy binary's lifecycle. A naive restart costs ~1 s of refused
connections, which would make proxy updates user-visible. Instead the listening socket is
owned by systemd (`vesta-proxy.socket`) and passed in as a file descriptor:

```
  systemd holds :80/:443 listeners
        │ fd passed to
        ▼
   vesta-proxy (old) ──stop──▶ drains in-flight requests, exits
        │                                    ▲
        └── vesta-proxy (new) starts, ───────┘ inherits the same listeners
            accepts immediately
```

The socket is never closed, so nothing is refused; the old process finishes its in-flight
requests while the new one accepts. Same mechanism as a config reload, but with a new
binary. On systems without socket activation, the fallback is `SO_REUSEPORT` with an overlap
window.

### 17.9 Updating `vesta-init`

`vesta-init` is bind-mounted into every running container, so it cannot be replaced in place
in a way that affects them — and shouldn't be. It is written to a **versioned path**:

```
/var/lib/vesta/bin/vesta-init-0.7.3     mounted as /.vesta/init in containers created by 0.7.3
/var/lib/vesta/bin/vesta-init-0.7.1     retained while any running container references it
```

Running containers keep the exact binary they started with. A new `vesta-init` reaches a
workload only through an ordinary container replacement, which means it flows through the
rollout machinery in §8 with health gates and automatic rollback — the same path as any
other change. Old versions are garbage-collected when no container references them.

### 17.10 CLI and version skew

`vesta self-update` updates the CLI, verifying the same signature. The CLI warns — and does
not block — when its minor version differs from the control plane's, because an operator on
a slightly old laptop is normal and should not be a wall.

### 17.11 Visibility

`vesta version --fleet` and the fleet view show, per node: agent version, protocol version,
update policy, last update, and whether it reverted. Version drift is highlighted rather
than hidden, because an un-updated node is usually the one with a problem — a full disk, a
clock skew, a systemd unit someone edited by hand.

## 18. Invariants

Testable statements. A change that breaks one of these is a bug, and each has a
corresponding test.

1. A Spec applied twice performs zero Docker calls the second time.
2. No plaintext secret appears in: container config, `docker inspect`, any file under
   `/var/lib`, any log line, or any API response lacking a reveal grant.
3. `Image` in an applied Spec always contains `@sha256:`.
4. A container without `sh.getvesta.managed=true` is never modified or removed.
5. During a rolling deploy at any replica count, the proxy pool is never empty for a
   route that had a ready upstream before the deploy started.
6. Every store read path is parameterized by `team_id`.
7. A Release's image digest never changes after creation.
8. The agent applies Specs in `Issued` order and never regresses.
9. Every state mutation emits exactly one event to the internal bus.
10. A request is forwarded across the mesh at most once; a proxy receiving a request
    carrying `Vesta-Hop` serves it locally or fails, and never forwards.
11. Certificate issuance for a hostname is never attempted before its DNS preflight passes.
12. An agent update never signals, stops, or restarts a running container.
13. An agent binary is only executed after its Ed25519 signature verifies; a partially
    downloaded artifact can never be executed, because the swap is a `rename()`.
14. An agent that fails to confirm within its trial deadline reverts to the previous
    binary without operator action, and halts the rollout for the rest of the fleet.
15. Killing the control plane mid-deploy leaves the environment either fully on the old
    release or fully on the new one, never split — because the agent completes or rolls
    back the pass it started.

---

## 19. Extension points

- **Runtime** — `dockerx` is the only Moby importer. containerd/Podman is a sibling
  package satisfying the same interface.
- **Build strategy** — `Builder` interface: `Build(ctx, Source, Options) (Digest, error)`.
  Dockerfile, Nixpacks, and buildpacks are three implementations; a fourth is a plugin.
- **Secret backend** — `SecretProvider` abstracts the KEK and, later, external stores
  (Vault, AWS Secrets Manager) that hold values rather than just wrapping keys.
- **Proxy driver** — `proxycfg.Driver` has two implementations: the native Go proxy and a
  Caddy admin-API driver. The Caddy driver is the contingency named in PLAN §11; the
  interface exists specifically so choosing it is a one-line swap.
- **Store** — one repository interface, SQLite and Postgres implementations, both in CI.
- **Notifiers** — Slack, Discord, webhook, SMTP behind one `Notifier` interface, reusing
  the implementations already written in `vesta-kubernetes`.
