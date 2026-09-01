# Vesta — Architecture

Companion to [PLAN.md](PLAN.md). The plan argues *what* to build and why; this document
specifies *how the pieces fit*, precisely enough to implement from. Where the two
disagree, this document wins on mechanism and the plan wins on scope.

Read in order: §2 for the process model, §3 for the Spec (everything else is downstream of
it), §6 for the reconciler, §10 for DNS, §11 for secrets, §13 for jobs, §20.1–20.7 for
logs. The rest can be read on demand.

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
deliberate availability-for-confidentiality trade (§21).

### 2.2 Installation and enrollment

**Control plane.** One script, systemd unit by default. First run generates the internal CA,
establishes the KEK (file, or a prompt for KMS/sealed mode, §11.1), runs migrations, and
prints a **single-use setup token to the console**.

That token is the whole of the first-run security model, and it exists because the
alternative is worse: a setup page where the first visitor becomes administrator is a
well-worn way for self-hosted software to hand an unattended installation to whoever scans
port 443 first. The token is printed where only someone with shell access sees it, expires in
15 minutes, and is single-use. There is no window in which an unclaimed control plane is
claimable from the network.

**Nodes.** `vesta server add` mints a join token — single-use, expiring (default 1 h),
revocable, scoped to one node. The operator runs the printed one-liner on the server:

```
curl -fsSL https://<control-plane>/install.sh | VESTA_TOKEN=<token> sh
```

The script detects OS and architecture, downloads the agent and proxy, **verifies the Ed25519
release signature** with the same key used for updates (§23.5), installs the systemd units,
and starts the agent — which posts the token, receives a client certificate from the internal
CA, and dials the control stream (§6.1). The CA issues no certificate without a valid,
unused, unexpired token.

**Preflight runs before anything is written**, and fails with specifics rather than leaving a
half-installed node: Docker present and a supported version; cgroup v2; sufficient disk;
ports 80/443 free or already ours; clock within tolerance of the control plane (§21). "Docker
20.10 found, 24.0 or newer required" is a fixable message; a partially installed agent that
never connects is not.

**Re-running the installer repairs rather than duplicates.** It is idempotent by design,
because the realistic operator response to a half-failed install is to run it again.

**Removal** is `vesta server remove`: the node is drained (workloads rescheduled where policy
allows, §5), the agent deregisters, its certificate is revoked, and the uninstall script
removes the units. It says explicitly what it does *not* remove — volumes and their data
survive unless `--purge` is passed, because the destructive default here is unrecoverable.

**Air-gapped installs** side-load binaries from a bundle and enroll normally; the join token
travels over the control plane connection, which is the only network path required.

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
    Bindings []PortBinding // L4 host-port bindings owned by this node (§7.4)
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
    RegistryRef string   // Registry-type secret, resolved through the scope chain (§11.6)

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
- **`Ports` are container-internal.** `AppSpec` has no host-port field, and that absence is
  what makes replicas work (§7.1). Host ports are not forbidden — they are modeled
  separately as `PortBinding` (§7.4), owned by a registry that detects conflicts, so a
  binding is always a deliberate, named allocation and never an accident of app config.
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
  provenance)`. Created once. Never mutated. Identified by a short ulid. Where the app uses
  `vesta.yaml` (§18.1) the config snapshot is *authored* — reviewed in a PR, attributable to
  a commit — rather than a copy of whatever the database happened to hold at that instant.
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

1. Resolves config: `app base → environment overlay → deployment override`. Each layer may
   come from the database (UI/API) or from a `vesta.yaml` in the deployed commit; field
   ownership between the two is resolved by §18.1 before this step, so the generator sees a
   single settled input and does not know or care which source produced it.
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

### 6.5 Interactive sessions: exec

A shell inside a running container, from the browser or the CLI, over a transport where the
control plane cannot dial anything (§6.1).

```
browser ──WS──▶ vestad ──control stream──▶ agent: "open an exec stream, token T"
                   ▲                          │
                   │                          ▼  agent dials back
                   └────── Exec bidi RPC ─────┴──▶ docker exec attach ──▶ container
```

The agent initiates, as with logs. The token is single-use, short-lived, and bound to one
container and one command.

**Authorization: exec is equivalent to reading every secret the container holds.** A shell in
a container can print its own environment. So `exec` is a distinct permission, never implied
by deploy rights, and on production environments it requires re-authentication — the same
treatment as `reveal` on a secret (§11.5), for the same reason. Any design that lets a
Developer who cannot read `STRIPE_SECRET_KEY` open a shell in the container holding it has
not restricted anything; it has only added a step.

**Every session is audited**: actor, container, release, command, start and end, and source
IP. Optional **session recording** captures the full I/O stream in asciinema-compatible form,
retained per policy — the compliance feature, with a stated caveat that recordings capture
whatever is typed, including credentials pasted into a shell, so recording storage inherits
the same access controls as secrets.

Mechanics that decide whether it works:

- **TTY vs. no TTY.** With a TTY the stream is raw; without one it is `stdcopy`-framed, the
  same trap as logs (§20.3). Resize events are forwarded so a browser terminal's dimensions
  reach the process.
- **Orphan prevention.** If the WebSocket dies, the exec process is killed. Without this,
  abandoned browser tabs accumulate shells holding file handles and memory on production
  nodes.
- **Bounded.** Idle timeout, maximum session duration, and a cap on concurrent sessions per
  node and per user. An exec session is not a replica and receives no traffic.
- **Debug containers for images with no shell.** A `scratch` or distroless image has nothing
  to exec into. `vesta debug` starts an ephemeral container sharing the target's PID, network,
  and mount namespaces, carrying a toolbox image. This is why building minimal images does not
  have to mean losing the ability to inspect them — and it is the only supported way to get a
  shell "into" a container that never had one.
- **Parked apps** (§14.3) are not woken by an exec attempt. The choice is offered explicitly:
  wake the app, or attach a debug container to the stopped one's filesystem.

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
- Workloads that genuinely need a real port (Postgres, SMTP, game servers) get one through
  a registered `PortBinding` (§7.4) rather than an ad-hoc field. In the default *Proxied*
  mode a binding **keeps replicas** — the proxy owns the port and load-balances behind it.
  Only *Direct* mode, where Docker publishes the port itself, is limited to one replica.

Docker's embedded DNS resolves containers by service name inside a network, so a linked
service is reachable as `postgres:5432` with no proxy in the path. Which containers share a
network is not automatic: membership is granted by an explicit `ServiceLink` (§7.5), so
east-west connectivity is default-deny rather than "everything on one bridge".

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

### 7.4 Binding host ports, deliberately

§7.1 removes host ports from the *default* path. But plenty of real workloads must answer
on a real port: Postgres on 5432 for an external BI tool, SMTP on 25, a Gitea SSH endpoint
on 2222, MQTT on 8883, a game server on UDP 27015. "Everything is HTTP behind a
hostname-routing proxy" is a comfortable assumption that self-hosting reality punctures
within a week.

So a host port is a **first-class object with its own registry** — not a field someone types
into an app config and hopes about.

```go
type PortBinding struct {
    ID         string
    App, Env   string
    Proto      Proto      // TCP | UDP
    HostIP     string     // interface to bind; NOT 0.0.0.0 by default (see below)
    HostPort   int        // explicit, or 0 to allocate from the configured range
    TargetPort int        // the container port
    Mode       BindMode   // Proxied (default) | Direct
    TLS        TLSPolicy  // Terminate | Passthrough | Off — Proxied only
    ProxyProto bool       // send PROXY protocol v2 to the backend
    Nodes      []string   // which nodes bind it; resolved by placement
    AllowCIDR  []string   // source restriction
}
```

**This is not NodePort.** Kubernetes NodePort allocates an arbitrary high port on *every*
node and leaves you to put something in front of it. A Vesta binding is a named, registered
allocation of a *specific* port on *specific* nodes, chosen by the operator, with conflicts
detected before deployment rather than discovered during one.

#### Two modes, and why the default is the interesting one

| | **Proxied** (default) | **Direct** |
|---|---|---|
| Mechanism | `vesta-proxy` opens an L4 listener and forwards to container IPs | Docker publishes the port (`-p`) |
| **Replicas** | **N, load-balanced** | **1 per port per node** |
| Zero-downtime deploy | **yes** — replicas swap behind a stable listener | no — the port must be released before rebinding |
| Health-based ejection | yes | no |
| Source IP at backend | the proxy's, unless `ProxyProto` | preserved |
| TLS termination | yes, where the protocol allows | no |
| Source allowlist | enforced by the proxy | host firewall's job |
| UDP | session-based forwarding | full, lowest overhead |

The first two rows are the point. Docker's `-p` binds one container to one port, which is
precisely the constraint that forces one replica — the same limitation that stops Coolify at
one container per app, reappearing for TCP. **Putting the proxy on the port instead extends
the replica model to non-HTTP services**: four Postgres read replicas or four MQTT brokers
behind one bound port, health-checked, with a rolling deploy that never drops the listener.

Direct mode exists for the cases where proxying is genuinely wrong: a backend that needs the
real client IP and can't speak PROXY protocol (Postgres, notably), UDP workloads sensitive
to added latency, or protocols the L4 path handles poorly. It is a deliberate choice with
its costs written down, not a silent fallback.

#### TLS on bound ports

Where a protocol is *plain TLS from the first byte* — MQTTS 8883, SMTPS 465, TLS-wrapped
Redis — the proxy terminates with the same certificate machinery as HTTP (§9.4), and the
service behind it speaks plaintext. Where a protocol negotiates TLS mid-stream (STARTTLS on
SMTP 587, Postgres's own handshake), termination is impossible and the binding is
passthrough: the application does its own TLS with a certificate Vesta can still provision
and mount. Both are supported; the doc names which is which, because "why doesn't TLS
termination work for Postgres" is otherwise a support ticket.

SNI-based routing lets several TLS services share one bound port, the same way virtual hosts
share 443.

#### Allocation and conflict

The control plane owns a port registry, unique on `(node, host_ip, proto, host_port)`.

- **Conflicts are a validation error at save time**, with the conflicting app named — never
  a container that fails to start at 2 a.m. because something else already holds 5432.
- **Ports occupied by non-Vesta processes are detected too.** Agents report their listening
  sockets at enrollment and on each resync, so requesting a port already held by the host's
  own Postgres or sshd is refused with an explanation instead of producing a crash-looping
  container.
- 80 and 443 belong to `vesta-proxy`; 22 and a configurable reserved list are refused.
- `HostPort: 0` allocates from a configured range for people who just need *a* port.

#### Bind address defaults, which are a security decision

`HostIP` defaults to the **private interface, not `0.0.0.0`** — and on a node with no
private interface at all (a public-only fleet, §10.6) it falls back to `127.0.0.1`, never to
`0.0.0.0`. Publishing to every interface is an explicit opt-in that shows what it means
before you confirm it:

```
  This will expose postgres-prod on 5432 to the public internet.
  Reachable from: 0.0.0.0  ·  Source allowlist: none
  Managed databases are normally reached over the app network or a private interface.
```

Managed databases (§15) get **no binding at all** by default — they are reachable inside the
app-environment network by service name, which is what an application actually needs.
Exposing one is a decision someone makes on purpose. Self-hosted databases left listening on
`0.0.0.0` are a well-documented mass-scanning target, and a platform whose default quietly
does that is choosing convenience over its users.

`AllowCIDR` is enforced in the proxy for Proxied bindings. In Direct mode the host firewall
owns it; the agent can optionally manage an nftables set, but this is opt-in because
silently rewriting someone's firewall is not a thing a deployment tool should do uninvited.

#### Fleet behavior

A bound port lives on the nodes named in the binding, and placement keeps the app's replicas
on those nodes. Vesta does **not** open the port fleet-wide the way NodePort does — an
unused listener on every machine is attack surface with no benefit.

For multi-node reachability, the choices are the same as §10.2 and equally explicit: point
DNS at the bound nodes, put a floating IP in front, or enable L4 mesh forwarding so any node
accepts the port and forwards to an owner. Mesh forwarding for TCP is available but **off by
default** — an extra network hop matters far more for a database connection than for an HTTP
request, and pinning is usually the better answer.

### 7.5 Service links: how containers reach each other

Most PaaSes in this category put every container on one shared bridge network. It makes
`postgres:5432` work immediately, and it means any compromised container can reach every
database, cache, and internal API on the box — including other teams'. Convenience bought
with a flat network is the same trade as convenience bought with plaintext secrets.

**Vesta is default-deny east-west.** Two containers can talk if, and only if, a
`ServiceLink` says so. The link is the authorization, and Docker network membership is the
enforcement — not a convention, not a firewall rule someone can forget, but the absence of
a route.

```go
type ServiceLink struct {
    ID       string
    From     string // consuming app-environment
    To       string // target app-environment or managed service
    Alias    string // DNS name the consumer uses: "postgres", "api"
    Inject   []string // env vars to generate: DATABASE_URL, REDIS_URL, …
    Path     LinkPath // Direct (default) | Proxied
}
```

#### One declaration, three effects

Creating a link does three things at once, which is what makes it a useful primitive rather
than a naming convenience:

1. **Connectivity.** Both containers join a shared link network `vesta_link_<from>_<to>`,
   and the target gets the network alias `Alias`. Nothing else on the host joins it.
2. **Configuration.** Connection variables are generated and injected — `DATABASE_URL`,
   `REDIS_URL`, host/port/credential triplets — resolved at deploy time through the
   `{{services.*}}` template path, with credentials drawn from the secrets system (§11), not
   written into config.
3. **Placement affinity.** The scheduler prefers to co-locate linked workloads on the same
   node (§5). This is not cosmetic — see the cross-node problem below.

Unlinking removes all three. There is no orphaned network membership and no stale
`DATABASE_URL` pointing at something the app is no longer allowed to reach.

#### Two ways to address a service

| | **Direct** (`postgres:5432`) | **Proxied** (`api.prod.vesta.internal`) |
|---|---|---|
| Resolution | Docker embedded DNS, network alias | agent resolver → local `vesta-proxy` (§10.5) |
| Path | container → container, one hop | container → proxy → container |
| Works cross-node | no | yes, via the mesh (§10.1) |
| Load balancing | round-robin DNS, health-unaware | connection-level, health-aware, ejects failures |
| Best for | managed databases, caches, singletons | app → app, anything replicated |

**The rule: Direct for singletons, Proxied for replicated apps.** Docker's embedded DNS
returns every alias A-record in random order, and many clients use only the first and cache
it — so DNS round-robin across four replicas of an API silently becomes "one replica gets
everything, and keeps getting it after it dies." That is a bad default for app-to-app
traffic and a perfectly good one for reaching a single Postgres. Links to replicated targets
default to `Proxied`; links to singleton services default to `Direct`.

#### The cross-node problem, stated plainly

**Docker bridge networks are node-local.** A link network on node 1 does not extend to node
3. This is the single most important constraint in the whole east-west story, and it has
exactly three honest answers — we take the first two and refuse the third:

1. **Co-locate.** Linked workloads are scheduled together by default. An app and its
   database on one node is the common case, the fast case, and the case that needs no
   distributed anything. Most installs never leave here.
2. **Route through the proxy mesh.** When co-location is impossible — the target is pinned
   elsewhere, or the app spans nodes — the `Proxied` path handles it: the local proxy
   forwards to a peer over mTLS (§10.1). Costs a hop, gains health-aware balancing and
   encryption on the wire between machines.
3. ~~Build an overlay network.~~ We do not ship a CNI, VXLAN, or WireGuard mesh to make
   bridge networks span hosts. That is the machinery people left Kubernetes to escape, it is
   the component most likely to break at 3 a.m., and the proxy path already covers the case
   it would serve.

A `Direct` link whose target lands on another node is a **validation error at link time**,
naming the problem and offering the two fixes — not a connection refused discovered in
production. If the target later moves, the reconciler reports the link as broken rather than
silently failing to connect.

#### Boundaries

- **Within an environment**, links are ordinary and encouraged.
- **Across environments** (staging → production database) requires an explicit override with
  a warning and an audit record. It is a real thing people occasionally need and a much more
  common thing people do by accident, and the accident is expensive.
- **Across projects** requires authorization on both sides — the target project's owner
  approves. A link is an access grant, so it follows the same consent model as any other.
- **Across teams** is not offered. Publish an API through the proxy with real authentication
  instead; a Docker network is not an authorization system.

Every link creation, override, and removal is an audited event (axiom 5).

#### What this costs

Being honest about the trade: a flat network means `postgres:5432` works the instant you
create a database, and Vesta makes you create a link first. That is one extra step, and it
is generated for you when a database is provisioned from within a project — the common path
still feels automatic. What you get for the step is that a compromised container reaches
exactly the services it was granted and nothing else, which is the property that makes a
multi-app server survive a single bad dependency.

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
    Revision  string
    Routes    []Route      // HTTP/HTTPS, matched by host and path
    Listeners []L4Listener // raw TCP/UDP bound ports (§7.4), matched by port and SNI
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

### 9.5 Maintenance mode

Maintenance mode is enforced **at the proxy**, which is the property that makes it useful:
turning it on restarts nothing, changes no container, and can be turned off just as fast. The
application is not down — it is shielded.

Per environment, and optionally per route:

```go
type Maintenance struct {
    Active    bool
    Status    int      // default 503
    RetryAfter time.Duration
    Page      string   // custom HTML, served from proxy memory — no upstream needed
    AllowCIDR []string // operators fixing the thing
    BypassCookie string // signed; lets a named person through a public network
    Until     time.Time // scheduled windows
}
```

Four details that separate this from returning 503 from the app:

- **The people fixing it can still reach it.** A CIDR allowlist and a signed bypass cookie
  mean maintenance mode does not lock out the team debugging behind it.
- **ACME challenge paths stay open.** `/.well-known/acme-challenge/` is never intercepted.
  Certificate renewal during a long maintenance window otherwise fails silently and surfaces
  days later as an expired certificate — a genuinely nasty compound failure.
- **Probes keep running and alerts are suppressed** for the environment while it is active, so
  a planned window does not page anyone. Suppression has a **maximum duration**: a maintenance
  mode someone forgot to turn off must not silence alerting indefinitely, so it expires and
  starts alerting about *itself*.
- **Automatic activation** for operations that require it — a managed-database major upgrade
  (§15.2) sets and clears it around the cutover, so the window is exactly as long as the
  operation and no longer.

Scheduled windows announce themselves through notification channels (§20.13) in advance.

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

- **Local-preference with spillover.** A proxy prefers ready upstreams on its own host, so
  in the common case (small fleets, apps on every node) the hop never happens and costs
  nothing. But preference is not exclusivity: once local upstreams pass a saturation
  threshold — in-flight connections per upstream above `spilloverAt`, default 80% of the
  configured concurrency limit — the proxy starts distributing to peers by least-connections
  across the whole fleet. Pure local-first would mean a node holding one replica hammers it
  while a peer with four sits idle, because nothing but DNS decided how many clients each
  node got. Spillover is what makes the mesh an actual load balancer rather than only a
  failover path.
- **One hop, never two.** The forwarding proxy stamps `Vesta-Hop: 1`. A proxy receiving a
  hopped request serves it locally or returns 503 — it must never forward again. This is
  what makes loops structurally impossible rather than merely unlikely.
- **mTLS between proxies**, using the node certificates the internal CA already issues
  (§6.1). Inter-node traffic frequently crosses a public network between VPSes; it is never
  plaintext, and no WireGuard or private-network requirement is imposed on the user. Which
  address a peer is reached on — private or public — is resolved by zone (§10.6); the
  encryption is identical either way, because a VPC is someone else's network too.
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

#### Who actually balances the load

A question worth answering directly, because the topology determines it:

| Shape | Spreading clients across nodes | Balancing across replicas |
|---|---|---|
| Single node | n/a | `vesta-proxy`, least-connections |
| Multi-A DNS, replicas on every node | DNS, per client resolution | `vesta-proxy` locally; across hosts only on failure or spillover |
| **Edge nodes** (no replicas on the edge) | DNS, across edge nodes | **`vesta-proxy` does full cross-host balancing** — every request hops, least-connections over all remote upstreams |
| Floating IP | the VIP — all traffic to one node | that node's proxy, full cross-host balancing |
| External LB | the LB | `vesta-proxy` locally, with spillover |

**You never need an external load balancer for correctness.** Vesta balances across hosts on
its own — that is what the mesh is. What external infrastructure buys you is *entry-point
failover*, which is a different problem: DNS cannot fail over quickly (below), so a floating
IP or a cloud LB is how you avoid clients hitting a dead node's address. Load balancing and
entry-point HA are separate concerns, and only the second one is optional-to-outsource.

The honest caveat on the second row: with plain multi-A DNS and replicas everywhere, per-node
load is only as even as DNS makes it — even by client count, not by request cost. Spillover
corrects the extremes, not the fine grain. If you want genuinely even distribution, use the
edge-node or floating-IP shape, where one proxy sees all traffic and balances it properly.

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

- Service links (§7.5) inject `http://api.prod.vesta.internal` rather than a public URL, so
  east-west traffic never egresses to the internet and back. This is the `Proxied` link
  path; `Direct` links use the short alias and skip the proxy entirely.
- The name is stable across redeploys, rescheduling, and scaling — it resolves to a proxy,
  never to a container IP.
- Cross-environment calls remain explicit and routable, while staying inside the fleet.

**Ordering:** external DNS and the wildcard domain are M1 work; the proxy mesh and the
internal resolver land with multi-node support in M7. A single-server install needs neither
and pays for neither.

### 10.6 Network topologies: shared VPC vs. public-only fleets

Everything above assumes nodes can reach each other. *How* they reach each other is an
operator's circumstance, not a choice Vesta gets to make, and the two common cases have
genuinely different properties:

| | **Shared private network** (VPC, Hetzner private net, LAN) | **Public-only** (mixed providers, no private networking) |
|---|---|---|
| Peer address | private IP | public IP |
| Mesh traffic path | provider's internal network | the open internet |
| Encryption | mTLS anyway, defense in depth | mTLS is **load-bearing** |
| Mesh port exposure | not internet-reachable | internet-reachable, needs an allowlist |
| Egress cost of a hop | usually zero | billed per byte |
| Latency of a hop | 0.3–1 ms | 5–80 ms, variable |
| `HostIP` default has a private interface | yes | **no** — see below |

Vesta supports both, and a fleet that mixes them. What it does *not* do is guess.

#### Nodes advertise addresses, not an address

```go
type NodeNetwork struct {
    Zone     string // operator-declared; nodes sharing a Zone can reach each other privately
    Private  string // private IP, if the node has one
    Public   string // public IP
    MeshPort int    // default 8443
    Verified bool   // a probe confirmed the private path actually works
}
```

Peer selection is then a single rule: **same `Zone` → private address; different `Zone` →
public address.** A fleet spanning a Hetzner VPC and two DigitalOcean droplets is three
zones' worth of pairs computed correctly without anyone drawing a diagram.

`Zone` is declared by the operator, then **verified by probe** — at enrollment and on each
resync, agents test the private path to their zone peers. A mislabeled zone is the failure
that otherwise presents as "the mesh works from node 1 but not node 2, intermittently, and
only under load". Verification turns it into a startup error naming both nodes.

#### Protecting the mesh port when it faces the internet

In a public-only fleet, `:8443` is an internet-exposed port. Three layers, in order of what
does the work:

1. **mTLS with a required client certificate.** A scanner, or anyone without a node cert
   from our internal CA, completes no handshake and reaches no code path. This alone is the
   security boundary.
2. **A peer-IP allowlist enforced in the proxy**, derived from the fleet's node list and
   updated as nodes join and leave. Connections from anywhere else are dropped before the
   TLS handshake. No root, no firewall manipulation, no interaction with rules the operator
   already has.
3. **Optional nftables rules**, for operators who want the packet dropped in the kernel.
   Opt-in, and scoped strictly to ports Vesta itself opens — the distinction from §7.4 is
   that we will manage a rule for *our* port and will not touch anyone else's.

#### Cross-zone traffic is treated as expensive, because it is

A hop within a zone is cheap. A hop across zones costs money and tens of milliseconds, so
the topology feeds back into scheduling and balancing:

- **Placement prefers to keep an environment's replicas within one zone** (§5), and linked
  workloads (§7.5) co-locate at node granularity before they co-locate at zone granularity.
- **Spillover is zone-aware.** The saturation threshold that sends traffic to a peer in the
  same zone (§10.1) is lower than the one that sends it across zones — a busy local replica
  is preferable to a cheap remote one when "remote" means a billed 60 ms round trip.
- **Health probing between zones runs at a lower frequency** than within one, for the same
  reason.
- **Cross-zone bytes are reported** per environment, so the cost of a topology is visible
  rather than discovered on an invoice.

#### `HostIP` when there is no private interface

§7.4 defaults a `PortBinding` to the private interface. On a public-only node that
interface does not exist, and the tempting fallback — `0.0.0.0` — is exactly the mistake
that puts self-hosted databases on scanner lists. So the fallback is **`127.0.0.1`**, and a
binding that needs to be reachable from another host must say so explicitly and choose
between:

- reaching the service over the mesh (encrypted, authenticated, no exposed port), or
- a public binding with an explicit `AllowCIDR`, which the UI shows as a public exposure.

There is no configuration in which Vesta quietly binds a database to a public interface.

#### Bring your own overlay

Operators who want a public-only fleet to behave like a VPC should run Tailscale, Netbird,
or plain WireGuard, and then set `Private` to the overlay address and give those nodes a
shared `Zone`. Vesta consumes the result as an ordinary private network.

We do not ship one. §7.5 refuses an overlay for container-to-container routing because that
is a CNI in disguise; the same reasoning applies here with less force but the same
conclusion — mTLS already gives the mesh confidentiality and authentication, so a bundled
WireGuard would add operational surface (key distribution, MTU, NAT traversal, a new failure
mode at 3 a.m.) in exchange for hiding metadata. Integrating with the overlay a user already
trusts is the better trade.

One practical note for those setups: an overlay's MTU is typically 1280–1420, and Docker
bridges default to 1500. The agent detects the effective path MTU to zone peers and warns
when container networks are configured above it, because the symptom otherwise is large
responses hanging while small ones succeed — a genuinely miserable thing to debug.

#### What already works in both

The agent→control-plane path needs no attention here. Agents dial out over mTLS from
wherever they are (§6.1), so a node behind NAT, on a private-only subnet with a NAT gateway,
or on a home connection enrolls and operates identically. The topology question is entirely
about node↔node traffic.

## 11. Secrets pipeline

The full path, end to end. Threat model is in [PLAN.md §6.1](PLAN.md); this is the
mechanism.

### 11.1 Key hierarchy

```
KEK   file | env | AWS KMS | GCP KMS | Vault Transit | sealed (Shamir)
 │
 ├─ wraps ─▶ DEK per project            AES-256-GCM, rotatable independently
 │            │
 │            └─ encrypts ─▶ secret value   AES-256-GCM
 │                            AAD = scope_type | scope_id | key_name | version
 │
 └─ never leaves the control-plane process; never written by us except file mode
```

The AAD binding means a ciphertext lifted from one row and pasted into another fails to
open. Database-level copy-paste privilege escalation is closed by construction.

The AAD binds a ciphertext to the **secret's own identity** — its scope, its name, its
version — not to a consuming app, because a secret may legitimately be shared by many
(§11.6). What that still forecloses is what matters: a ciphertext cannot be moved to another
project, renamed to impersonate a different key, or replayed as an older version. *Which*
apps may use a secret is an authorization question, answered by bindings and ACLs (§11.5,
§11.6), not by encryption — conflating the two would mean either no sharing or an ACL system
you cannot change without re-encrypting.

### 11.2 Sealing to a node

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

### 11.3 Handoff into a container

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

### 11.4 `vesta-init` details

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

### 11.5 Access control, rotation, redaction

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

### 11.6 Scope, sharing, and bindings

A registry credential used by twenty apps should exist once. Copied twenty times it must be
rotated twenty times, and the one copy someone forgets is the one that keeps working after
the credential is revoked everywhere else. So secrets have a **scope**, and apps **bind** to
them — the same model as the Kubernetes edition, deliberately, so the two editions share
vocabulary and a team moving between them relearns nothing.

#### Scope chain

```
  org  ──▶  project  ──▶  environment  ──▶  app
   │                                          │
   └────────── most specific wins ────────────┘
```

A secret is defined at any level. Resolution walks from the app outward, so an app-level
`DATABASE_URL` shadows a project-level one of the same name. Shadowing is visible in the UI —
"this value is overridden for 2 of 6 apps" — because a silently shadowed shared secret is a
debugging session nobody enjoys.

#### Three types, matching the Kubernetes edition

| Type | Contents | Consumed by |
|---|---|---|
| `Opaque` | one or more key/value entries | apps, as env vars or files |
| `Registry` | server, username, password | image pulls — this is `AppSpec.RegistryRef` (§3) |
| `TLS` | certificate, private key | the proxy for custom certs (§9.1), or mounted into an app |

`Registry` secrets resolve through the same chain, which is what the Kubernetes edition
expresses as imagePullSecrets at global, pipeline, and app level: define the GHCR credential
once at the project, and every app in it pulls without further configuration.

#### Three ways to consume, also matching

```go
type SecretBinding struct {
    SecretID string
    App, Env string            // the consumer
    Mode     BindMode          // EnvAll | EnvSelected | File
    Keys     map[string]string // for EnvSelected: source key → env var name
    Path     string            // for File: mount point under /run/vesta/secrets
}
```

- **`EnvAll`** — every entry becomes an environment variable under its own name.
- **`EnvSelected`** — chosen entries, optionally renamed: a shared secret's `password` entry
  arrives as `PGPASSWORD` in one app and `DB_PASS` in another, with no duplication of the
  value.
- **`File`** — entries are written as files, for TLS pairs, CA bundles, service-account JSON,
  and anything else an application expects to read from disk rather than the environment.

All three travel the same tmpfs/`vesta-init` path as any other secret (§11.3). A shared
secret is not a weaker secret: it never appears in container config, never on disk, never in
`docker inspect`.

#### Sharing happens at authoring time, not at delivery time

This is the property that keeps sharing from widening the blast radius on the nodes:

```
  one stored ciphertext
        │
        ├─▶ bundle sealed for (node-1, api:prod)      ← contains it, because api is bound
        ├─▶ bundle sealed for (node-3, worker:prod)   ← contains it, because worker is bound
        └─▶ bundle for (node-3, billing:prod)         ← does NOT contain it
```

Each app-environment still receives its own sealed bundle (§11.2) holding exactly what it is
bound to and nothing else. Sharing removes duplication in the *database*; it does not put a
shared value on a node that has no consumer for it.

#### Rotation fans out, and the fan-out is shown before it happens

Rotating an app-scoped secret restarts one app. Rotating a project-scoped one restarts
everything bound to it, through the ordinary `SecretsVer` mechanism (§11.5) — which for a
widely-shared credential means a great many rollouts at once. That is the cost of sharing,
and it is made explicit rather than discovered:

- The rotate dialog names the blast radius first: *"this will roll 23 environments across 4
  projects"*, with the list.
- Restarts are **staged by default** — batched with a soak between batches, the same
  machinery as fleet updates (§23.7) — rather than all at once.
- Rotation can be scheduled into a window, and consumers can be rotated in a chosen order so
  a shared database credential reaches the migration runner before the web tier.

#### Authorization

Binding is an access grant, so it needs authority on both sides: `use` on the secret and
write on the consuming app. Binding never confers `read` — an app can be given a shared
credential by someone who cannot see its value, which is the same separation §11.5 draws for
app-local secrets.

Every binding, unbinding, and scope change is audited. A binding that has existed with no
deployment using it is surfaced for removal, for the same reason dead service links are
(§20.10): a stale grant is still a grant.

#### The honest cost

A shared secret is shared risk. Twenty apps holding one credential means compromising any one
of them compromises it for all twenty, and rotating it disrupts all twenty. Where a provider
supports per-app credentials — most databases, most cloud IAM — separate credentials are the
better answer, and the UI says so at the point of sharing rather than in documentation nobody
reads. The "used by 23 environments" count is shown on the secret precisely so the trade stays
in view.

`vesta.yaml` (§18.1) needs no concept of any of this: `secrets.requires` lists names, and
resolution walks the scope chain. Whether a requirement is satisfied by an app-local secret or
an org-wide one is an operator's decision, not something baked into the repo.


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

### 12.1 Registry cache and private registry

A five-node fleet pulling the same image five times is five times the bandwidth, five times
the latency, and a fast route to Docker Hub's anonymous rate limit (100 pulls per 6 hours
per IP) at the worst possible moment — during an incident, when you are redeploying
repeatedly.

`vesta-registry` is an optional container the agent supervises, running in one or both of
two modes:

- **Pull-through cache.** Agents point `dockerd`'s `registry-mirrors` at it. First pull of a
  layer fetches upstream; every subsequent pull on any node is local. Upstream credentials
  live in the secrets system (§11) and are used by the cache, so individual nodes never hold
  registry passwords.
- **Private registry.** Builds push here instead of to an external registry, removing an
  external dependency entirely for teams that don't have one. Content-addressed, so the
  digest-pinning guarantee (§3.1) is unaffected.

**One cache per zone** (§10.6). A cache reached across zones would convert a local pull into
a billed cross-zone transfer, which defeats the purpose.

Cache storage is garbage-collected on the same disk watermark as image GC, evicting by last
access. For air-gapped installs the cache is pre-warmed by `vesta image import`, which is
also how the update artifacts arrive (§23.5) — one mechanism, two uses.


### 12.2 Git providers and push-to-deploy

Supported: GitHub, GitLab, Gitea/Forgejo, Bitbucket — hosted and self-hosted.

**GitHub App, not a personal access token.** A PAT is bound to a person, carries their full
scope, and stops working the day they leave. An App installation is scoped to chosen
repositories, issues short-lived tokens, and survives staff changes. The same reasoning
applies to GitLab and Gitea where an equivalent exists; PATs remain available for
installations that cannot use an App, stored as secrets (§11.6).

**Webhook ingestion is the one unauthenticated endpoint in the system**, so it is treated
accordingly: per-provider HMAC signature verification, a timestamp window to bound replay,
and deduplication by delivery id. Nothing in the payload is trusted for authorization —
the repository is matched against a configured installation rather than taken from the body,
because otherwise anyone who can forge a payload chooses which app to deploy.

**Event mapping** is configuration, not convention:

| Event | Default behavior |
|---|---|
| push to a mapped branch | build → release → deploy to that environment |
| tag matching a pattern | build → release, deploy per policy (approval gate for production) |
| PR opened / synchronized | create or update a preview environment (§18.1 `preview:` overlay) |
| PR closed / merged | destroy the preview after its TTL |

**Deploys are deduplicated by commit SHA.** Providers redeliver webhooks, and a double
delivery must not produce two deployments of identical content. A redelivery for a SHA
already released is a no-op that reports the existing release.

**Status flows back.** Commit statuses and check runs move `pending → success | failure` with
a deep link to the deployment, and preview environments comment their URL on the pull
request. This is most of what makes the integration feel like part of the repository rather
than a service that occasionally notices it.

**`vesta.yaml` is read from the same commit** (§18.1), so configuration and code arrive
together and a redeploy of an old SHA gets that SHA's configuration.

**Monorepos** use path filters: a push touching only `services/billing/**` rebuilds billing
and nothing else.

**No webhook, no problem.** Private or air-gapped Git hosts can be polled at a configurable
interval, and `vesta deploy` from a CLI or CI system is a first-class path that needs no Git
integration at all.

---
## 13. Jobs and scheduled work

Cron is where PaaSes quietly get things wrong: a job that fires twice, a job that silently
stops firing for three weeks, a job that runs last month's code, a nightly batch that
starves the web replicas it shares a box with. Each of those is a design decision made
badly, so each gets made explicitly here.

### 13.1 Four kinds, one runner

| Kind | Trigger | Notes |
|---|---|---|
| `Cron` | schedule | recurring; the subject of most of this section |
| `Manual` | operator or API | `vesta job run migrate --env prod`; the same machinery |
| `PreDeploy` / `PostDeploy` | a deployment | a failing `PreDeploy` aborts the rollout (§8) |
| `Build` | a release | builds are one-shot jobs with a different image and no app secrets |

All four are *run-to-completion containers* and share one runner, one run-record table, one
log path, and one timeout mechanism. Only the trigger differs. Keeping them unified means
the run history, retry logic, and alerting written for cron work for deploy hooks for free.

### 13.2 Where the desired-state model stops

Jobs are the one place the reconciler's model does not apply cleanly, and pretending
otherwise produces bugs. **A schedule is desired state; a run is an event in time.** You
cannot converge toward "the 03:00 backup happened" — either it did or the moment passed.

So the split is:

- The **`JobSpec` is part of the Spec** and is reconciled like everything else: the agent
  guarantees the schedule is registered and matches. Idempotent, drift-correcting, ordinary.
- The **run is imperative** and is recorded, not reconciled. A missed run is a historical
  fact, not a diff to be repaired.

Getting this backwards — treating a run as state to converge on — is how schedulers end up
firing twelve accumulated executions at once after an outage.

### 13.3 The control plane decides *where*; the agent decides *when*

```go
type JobSpec struct {
    ID       string
    App, Env string
    Kind     JobKind        // Cron | Manual | PreDeploy | PostDeploy | Build
    Scope    JobScope       // SingleNode (default) | EveryNode

    Schedule string         // cron expression; Kind == Cron
    Timezone string         // IANA name, REQUIRED for Cron — no implicit UTC, no host local
    Image    string         // digest, pinned at spec generation
    Command  []string

    Env        map[string]string
    SecretRef  string       // same sealed-bundle path as an app (§11)
    SecretsVer int
    Resources  Resources    // mandatory, not optional — see §13.7
    Volumes    []VolumeMount
    Networks   []string     // usually the app-env network, to reach the database

    Timeout       time.Duration      // default 1h
    Concurrency   ConcurrencyPolicy  // Forbid (default) | Allow | Replace
    CatchUp       bool               // default false
    CatchUpWindow time.Duration      // how late is still acceptable; default 10m
    Retries       int                // default 0
    BackoffBase   time.Duration
    History       HistoryPolicy      // keep N runs / M days
}
```

**Exactly one node owns a `SingleNode` job.** The control plane picks the owner during spec
generation and simply *omits the job from every other node's Spec*. There is no election, no
lease, no distributed lock — the same placement machinery that decides where replicas run
decides where a job runs, and the property "only one node will fire this" is enforced by the
job not existing anywhere else.

**The agent, not the control plane, holds the timer.** The consequence is the one that
matters operationally: **cron keeps firing while the control plane is down.** A scheduler
that lives in the control plane makes every panel outage a silent data-pipeline outage, and
the alerting for it usually doesn't exist. This follows axiom 2 — the agent is authoritative
for its host.

`Scope: EveryNode` exists for genuinely per-host work (log pruning, image GC) and fires on
every node holding the Spec.

### 13.4 Firing semantics

The defaults are chosen so that the *surprising* behavior never happens silently.

**Missed windows do not accumulate.** If the node was down, or the previous run overran, the
missed window is recorded as `missed` and **never fired late** unless `CatchUp` is on. A
"send the daily report" job run six hours late is usually worse than one not run at all, and
the operator should decide which. With `CatchUp: true` a window is run only if discovered
within `CatchUpWindow`, and only **once** — accumulated windows collapse to a single
execution, always. Vesta will never fire a burst to "catch up."

**Concurrency** when the previous run is still going:

| Policy | Behavior |
|---|---|
| `Forbid` (default) | skip the new window, record `skipped_overlap`, alert if it repeats |
| `Allow` | run concurrently; the operator is asserting the job is safe to overlap |
| `Replace` | SIGTERM the running one, wait `StopGrace`, then start the new |

**Timezone is mandatory and DST is handled explicitly.** A cron expression without an IANA
timezone is rejected at validation, because the two implicit answers — UTC, or the host's
local zone — are each wrong half the time, and the host's zone means a job silently changes
behavior when it is rescheduled to a different server. Across DST transitions:

- **Nonexistent local time** (spring forward; 02:30 does not occur): the window is skipped
  and recorded as `skipped_dst`. It is not shifted to 03:30, because a job pinned to a
  maintenance window should not wander into business hours.
- **Ambiguous local time** (fall back; 02:30 occurs twice): fires **once**, on the first
  occurrence.
- **Interval schedules** (`@every 30m`) are computed in UTC and are unaffected by either.

### 13.5 At-most-once, and saying so

Vesta gives **at-most-once per window**, not exactly-once. Exactly-once across a network
does not exist, and a platform that implies otherwise teaches users to write jobs that
corrupt data when the guarantee turns out to be probabilistic. The documentation says: make
jobs idempotent.

What is guaranteed, and how:

- **No double-fire on one node.** Before starting, the agent writes a run record keyed by
  `(job_id, window_start)` to `/var/lib/vesta/jobs.db`. A window that already has a record is
  never started again — so an agent restart, a spec reapplication, or a duplicated timer
  cannot double-fire. This state is retained across restarts and contains no secrets.
- **No double-fire across nodes**, because only one node has the job (§13.3).
- **Owner reassignment is deliberate.** If the owner is unreachable, the control plane moves
  ownership on the next spec generation. Both being down means the window is missed and
  recorded as such — not run twice later.
- **A run interrupted by node death is recorded `lost`, never `failed` or `succeeded`.** We
  do not know whether the side effect happened, and the honest status is the one that says
  so. `lost` runs are surfaced distinctly in the UI because they are the ones a human must
  reason about.

### 13.6 What a job actually runs

A **fresh one-shot container from the environment's current release digest**, pinned at fire
time — the same image, secrets, environment, and network as the app's replicas, with its own
resource limits.

```
container: vesta_<app>_<env>_job_<jobname>_<runid>
labels:    sh.getvesta.managed=true  .job=<jobname>  .run=<runid>  .release=<release>
network:   the app-env network, so the database is reachable by service name
secrets:   the same sealed-bundle → tmpfs → vesta-init path as any container (§11.3)
```

Two properties fall out of this that are worth naming:

- **A cron job runs the same code as the app**, because it comes from the same release
  digest. Jobs quietly running a months-old image is a classic failure of platforms that
  build job images separately.
- **Pinning is at fire time.** A deploy landing mid-run does not change the image under a
  running job; the run completes on the release it started with, and its run record names
  that release.

**Exec mode.** As an option, `mode: exec` runs the command inside an existing replica
instead of starting a container. It is cheaper (no container start, warm caches) and some
frameworks assume it. The trade-offs are real and documented: the job shares the replica's
resource limits, it dies if that replica is redeployed or restarted mid-run, it cannot run
when the app is scaled to zero, and its resource usage is attributed to a serving container.
Default is a separate container; exec is opt-in per job.

### 13.7 Not starving production

Job containers are not replicas: they never join the proxy pool, never count toward replica
counts, and never receive traffic. But they compete for the same CPU and memory, and a
nightly batch that OOMs the web tier is a self-inflicted outage.

- **Resource limits on jobs are mandatory**, not optional. A `JobSpec` without them fails
  validation. Defaults are inherited from the app but must resolve to something concrete.
- Jobs run with reduced CPU shares by default, so a busy job yields to serving traffic
  rather than competing evenly with it.
- A per-environment cap limits concurrent job containers; excess windows are `skipped_cap`
  with an alert rather than being queued indefinitely.
- The scheduler counts job reservations against node capacity (§5), so a node packed to its
  memory limit is not also chosen as a job owner.

### 13.8 Runs, logs, retention

Every run produces a record: job, run id, release digest, node, trigger (schedule / manual /
API, with the actor for manual), window start, actual start, end, duration, exit code,
status, and retry index.

- **Output flows through the same redaction filter as build and deploy logs** (§11.5) — jobs
  receive secrets, and a job that echoes its environment on failure is a common leak.
- Retention per `HistoryPolicy`; run containers are removed after their logs are captured.
- On agent restart, running job containers are **adopted** via their labels rather than
  duplicated or orphaned.
- Timeout exceeded → SIGTERM, then SIGKILL after `StopGrace`, status `timed_out`.

### 13.9 Alerting — including the silence

Failure alerts are table stakes. The two that matter more, and that most platforms omit:

- **Missed and skipped windows alert.** A job that stops firing is invisible precisely
  because nothing happens. `missed`, `skipped_overlap`, and `skipped_cap` are alertable
  conditions, not just log lines.
- **Dead-man check.** Each cron job carries an expected-interval derived from its schedule;
  the control plane raises an alert when no run has *started* within that interval plus a
  grace factor. This catches the failure mode no per-run alert can: the schedule silently
  not being registered at all — a bad expression, an owner node that never came back, a spec
  that never reached anyone.

Both are computed by the control plane from run records, so they still fire when the problem
is that the agent has gone quiet.


## 14. Scaling: autoscaling and scale-to-zero

Replica count has so far been a number a human sets (§5). This section makes it a function
of load, and lets that function reach zero.

### 14.1 Where the decision lives

**The control plane decides replica counts; agents execute.** This is the opposite of the
cron decision (§13.3), and for a specific reason: scaling changes *placement*, which requires
fleet-wide capacity knowledge that only the control plane has. A node cannot know whether
adding two replicas is wise.

The consequence is stated rather than hidden: **while the control plane is down, replica
counts freeze.** Running apps keep serving at their current scale, health-checked and routed
as always — they simply do not grow or shrink. That is the safe failure direction, and it is
strictly better than the alternative where each node independently decides to scale up during
a partition.

Wake-from-zero is the deliberate exception (§14.3), because a sleeping app that cannot wake
is an outage.

### 14.2 Autoscaling on the right signal

CPU is the traditional autoscaling signal and it is usually the wrong one. An app blocked on
a slow database has low CPU and terrible latency; scaling on CPU does nothing while users
wait. Because the proxy sees every request (§20.9), we have a better signal available for
free.

```go
type AutoscalePolicy struct {
    Min, Max     int            // Max is REQUIRED — see below
    Metric       ScaleMetric    // Concurrency (default) | RPS | P95Latency | CPU | Memory | Custom
    Target       float64        // e.g. 50 in-flight requests per replica
    ScaleUpAfter   time.Duration // default 0s — react immediately
    ScaleDownAfter time.Duration // default 5m — leave slowly
    CooldownAfterDeploy time.Duration // default 5m
}
```

**Concurrency is the default metric**: in-flight requests per ready replica, measured at the
proxy. Desired replicas is `ceil(total_in_flight / Target)`, clamped to `[Min, Max]`. It
responds correctly to slow dependencies, it needs no instrumentation in the application, and
it degrades sensibly for both fast and slow endpoints. `RPS` and `P95Latency` come from the
same source; `CPU` and `Memory` come from container stats (§20.8); `Custom` polls an endpoint
or a queue depth for worker apps with no HTTP traffic at all.

Four rules that prevent the failure modes:

- **`Max` is mandatory.** An autoscaler without a ceiling is an unbounded bill and a way to
  exhaust a node. A policy without `Max` fails validation.
- **Asymmetric timing.** Scale up immediately, scale down after a stabilization window
  (default 5 minutes) using the *maximum* desired count observed in that window. Flapping
  costs more than a few extra minutes of a replica.
- **Paused during rollouts** and for `CooldownAfterDeploy` afterwards. A deployment already
  changes replica counts and health; letting two controllers fight over the same number
  produces exactly the incident you would expect.
- **Capacity-aware.** Scale-up that would breach node reservations (§5) does not silently
  fail — it scales as far as it can, emits a `ScaleCapped` event naming the constraint, and
  surfaces in the UI. Silent capping is how people discover their autoscaler never worked
  during the traffic spike it existed for.

Scale-down never removes a replica while it is draining, and never takes an environment below
`Min` or below what an active rollout requires.

### 14.3 Scale-to-zero and wake-on-request

With `Min: 0`, an environment with no requests for `IdleAfter` (default 15 minutes) is parked.

**Parked is stopped, not deleted.** The container remains on the node with its volumes and
its image; only the process is gone. `docker start` on a stopped container is a few hundred
milliseconds, where create-and-start after an image pull is seconds to minutes. Parked
containers are removed entirely after a longer `ReapAfter` (default 24 h) to reclaim disk, at
which point waking pays the full cost again.

The wake path — the reason this feature belongs to us and not to Coolify — is that the proxy
is already in the request path and can simply *not answer yet*:

```
  request ──▶ vesta-proxy: route is PARKED
                  │
                  │ 1. hold the connection. Do NOT return 503, do not read the body yet.
                  │ 2. one wake request to the agent over the unix socket
                  │    (deduplicated: 500 simultaneous requests produce ONE wake)
                  ▼
              agent: docker start  ──▶  readiness probe (§8.1)
                  │
                  │ 3. upstream ready → added to pool
                  ▼
              proxy: stream the held request through. The client saw one slow request,
                     not an error.
```

Details that decide whether this is delightful or infuriating:

- **The request body is not buffered.** The proxy holds the connection and reads the body
  only once the upstream is ready, then streams it through. Buffering would make a large
  upload during a wake into a memory problem.
- **Wake is deduplicated per app-environment.** A burst of traffic against a sleeping app
  produces one container start and many held connections, not a thundering herd.
- **`WakeTimeout`** (default 30 s) bounds the hold. On expiry the client gets a 503 with a
  real explanation, not a hung socket.
- **Parked is not unhealthy.** No probes run against stopped containers, no alerts fire, and
  the UI says *sleeping* rather than *down*. Getting this wrong turns a cost feature into a
  pager feature.
- **Cron and jobs still run.** Job containers are separate (§13.6), so a sleeping app's
  nightly batch executes normally — and does not itself wake the app.

**The honest limit: the first request after sleep pays cold start.** Container start plus
application boot is 300 ms for a Go binary and 5–20 seconds for a large Rails or Spring app.
That makes scale-to-zero excellent for preview environments, staging, internal tools, and
hobby projects — and wrong for production traffic that anyone is waiting on. So it is
**disabled by default for environments marked production**, and enabling it there prints the
measured cold-start time from that app's own history rather than a generic warning.

Managed services (§15) never scale to zero by default: a database that sleeps has a slow,
risky start and something is usually holding a connection anyway.

The savings are reported concretely (§20.11) — hours slept, and what those reservations would
have cost.

---

## 15. Managed services

Postgres, MySQL, Redis, MongoDB, ClickHouse and friends are not "apps that happen to store
data". They are singletons with durable state, version-specific upgrade paths, and failure
modes that destroy things permanently. They get their own object and their own rules: no
autoscaling, no scale-to-zero by default, no shared writable volume, replicas only where the
engine has real clustering.

### 15.1 Provisioning and connection

Choosing an engine and version creates a service: the agent pulls the official image, creates
the volume, generates credentials **directly into the secrets system** (§11) — no password is
ever displayed, written to a config file, or placed in an environment variable at rest — and
registers it as a link target.

Consumption is an ordinary `ServiceLink` (§7.5): network membership, injected `DATABASE_URL`,
and co-location, from one declaration. Credential rotation is secret rotation, which is a
`SecretsVer` bump, which is a rolling restart of consumers through the machinery in §8. No
special path.

**Connection pooling is first-class, and the replica model is why.** Four app replicas at 20
connections each is 80 connections to a Postgres whose default limit is 100 — a limit teams
discover by taking an outage. A pooler (pgbouncer for Postgres) can be attached to a service
with one setting; the injected `DATABASE_URL` points at the pooler, and the app is unaware.
Any platform offering easy replicas owes its users this, and most don't.

### 15.2 Upgrades — the part everyone hand-waves

**Patch upgrades** (15.4 → 15.6) share a data directory format: back up, stop, swap image,
start, verify. Safe enough to automate on a schedule.

**Major upgrades** (15 → 16) do not. The on-disk format changes, and starting a new major
version against an old data directory either refuses or corrupts. This is where platforms
stop and tell you to do it yourself, so it is where we should not.

A major upgrade runs as a **job** (§13), not a restart:

```
1. Pre-flight        disk free ≥ 2× data size · no long-running transactions ·
                     EXTENSION COMPATIBILITY · estimated downtime shown for approval
2. Fresh backup      taken and VERIFIED by restore (§16.3) — not merely written
3. Stop              consumers see the service go down; maintenance mode if configured
4. Upgrade container  one-shot, holding BOTH versions' binaries:
                       pg_upgrade --link   (fast, minutes, needs same filesystem)
                       or dump/restore     (slow, safe, used above a size threshold)
5. Start new version  on the migrated directory
6. Smoke checks       connect · row counts on sampled tables · extensions load
7. Retain old dir     for RetainOldDataFor (default 7 days)
```

Rollback is a directory swap and a start of the old image, which is possible *only* because
of step 7. If smoke checks fail, this happens automatically.

**Extension compatibility is the pre-flight check that actually earns its place.** PostGIS,
pgvector, TimescaleDB and friends are the usual cause of a failed Postgres major upgrade: the
target image simply does not carry a compatible build. We enumerate installed extensions,
check them against the target image, and refuse the upgrade with the specific extension named
— rather than discovering it in step 5 with the service down.

**Downtime is estimated and shown before you approve**, derived from data size and the chosen
method. A platform that says "upgrading…" with no estimate is asking you to gamble.

Zero-downtime major upgrades via logical replication (new instance, replicate, cut over) are
real and are *not* promised here. They belong post-v1, and claiming them early would be the
kind of promise that costs someone their data.

### 15.3 Replication and read scaling

Streaming replication and read-only link variants (`DATABASE_URL_RO`) are engine-specific and
land after the core is stable. Where an engine has genuine clustering (Redis Sentinel/Cluster,
Postgres with Patroni), it is an addon rather than something Vesta reimplements — the
orchestration of a database quorum is a specialty, and doing it badly is worse than not doing
it.

---

## 16. Data durability: volumes, backups, restore

### 16.1 Volume tiers — and the honest answer to portability

A local Docker volume cannot move to another host. This is the constraint behind the open
question in PLAN §12, and the resolution is not to build distributed storage — it is to make
the trade explicit per volume and tie failover capability to it.

| Tier | Mechanism | RPO | Failover | Cost |
|---|---|---|---|---|
| **Local** (default) | node-local volume | = backup interval | restore from backup onto another node | none; fastest I/O |
| **Replicated** | periodic snapshot sync to a standby node | = sync interval (minutes) | promote the standby | 2× storage, sync bandwidth |
| **Shared** | NFS / CIFS / iSCSI mounted on several nodes | 0 | mount elsewhere | you now operate storage |

**Local is the default and is right for most people**, because most self-hosted fleets are
one to three servers where a node loss is a restore, not a failover. Replicated is the opt-in
for those who want minutes-not-hours recovery and accept asynchronous loss. Shared is for
those who already run a NAS or SAN and would rather Vesta use it than duplicate it.

Two consequences worth naming:

- **Stateless apps have no volumes and can always move.** The portability problem constrains
  stateful workloads only, which is a minority of what runs on these fleets. Framing it as a
  fleet-wide limitation overstates it.
- **Automatic node failover (PLAN §5.4) becomes conditional rather than blocked.** It can be
  offered for stateless workloads and for Replicated/Shared volumes; it is refused, with the
  reason given, for Local ones. That turns an unsolved problem into a stated precondition,
  which is what unblocks the post-v1 work.

Replicated volumes use filesystem-level send/receive where available (ZFS, btrfs) and
snapshot-plus-rsync otherwise. Asynchronous replication means a hard node failure loses up to
one sync interval, and the UI states the current lag rather than implying continuity.

### 16.2 Backups that are actually restorable

**Consistency first, because this is where naive implementations quietly produce garbage.** A
`tar` of a running Postgres data directory is not a backup; it is a corrupt directory that
will restore successfully and fail later. So:

- **Databases** use engine-native dumps (`pg_dump`, `mysqldump`, `mongodump`) or a filesystem
  snapshot taken with the engine quiesced. Never a naive copy of live files.
- **Volumes** are snapshotted where the filesystem supports it, and otherwise copied with the
  writing container paused, with the pause duration reported.
- **Postgres PITR** via WAL archiving to object storage, giving recovery to a point in time
  rather than to the last nightly.

Backups are encrypted before they leave the node (§11 key hierarchy — the destination never
holds plaintext), destinations are S3-compatible, SFTP, or local disk, and retention follows
grandfather-father-son (hourly/daily/weekly/monthly) rather than a single count.

### 16.3 Restore drills

"Last backup succeeded" is the wrong metric. It reports that bytes were written, which is not
the property anyone cares about. The property is: *can we come back*.

A restore drill is a scheduled job (§13) that does the whole thing:

```
1. provision a scratch environment on a designated node, off-peak
2. restore the latest backup into it
3. run the operator's verification command
     e.g.  psql -c "select count(*) from users" | assert > 0
           curl -f localhost:3000/health
4. record: pass/fail · bytes restored · WALL-CLOCK DURATION
5. tear the scratch environment down
```

Two outputs, and the second is the one nobody has:

- **Verified-restore recency.** The dashboard shows "last verified restore: 3 days ago" and
  alerts when it exceeds a threshold. A backup chain that silently broke six weeks ago is
  caught by the drill, not by the incident.
- **Measured RTO.** Step 4 records how long a restore actually takes. Teams routinely
  discover during an outage that their 400 GB database takes four hours to restore. Knowing
  that number in advance changes decisions — retention, tier, whether to run Replicated.

Drills are capped by size and scheduled off-peak on a nominated node, because a restore drill
that competes with production is its own incident.

---

## 17. Identity and access

### 17.1 Layers

Four independent mechanisms, deliberately not collapsed into one role field:

| Layer | Governs |
|---|---|
| **Authentication** | who you are — local password + MFA, or OIDC |
| **Team role** | Owner / Admin / Developer / Viewer, per team |
| **Resource ACLs** | secret verbs `use`/`read`/`write`/`manage` (§11.5), `logs:read` (§20.7) |
| **Token scope** | what a given API credential may do, independent of its owner |

The separation is what allows a Developer to deploy code that *uses* a production secret
without being able to read it — the property from PLAN §6.1 that a single role enum cannot
express.

### 17.2 OIDC

Authorization Code with PKCE against any compliant provider — Google, Entra, Okta, Authentik,
Keycloak, Zitadel. Configuration is discovery-URL plus client credentials; nothing
provider-specific is hard-coded.

- **Group mapping.** A configurable claim path maps IdP groups to Vesta teams and roles, so
  access is administered where the rest of the company's access is administered.
- **Just-in-time provisioning**, optionally restricted to an email domain or a required
  group, with a default role for new users.
- **Group sync on every login**, so a demotion in the IdP takes effect at next sign-in rather
  than never. Full deprovisioning needs SCIM, which is named as post-v1 rather than implied:
  until then, removing someone from the IdP prevents new sessions, and an admin ends existing
  ones.

**Break-glass is mandatory, not optional.** At least one local administrator account always
remains enabled, and disabling the last one is refused. An identity provider outage that locks
you out of the platform managing your infrastructure — during the outage you are trying to
fix — is a self-inflicted disaster, and it happens to people who assumed SSO-only was the
secure choice. The account is MFA-required and its use is a loud, separately alerted audit
event.

SAML is post-v1. It is what large enterprises ask for, and it is a slog; OIDC covers everyone
else first.

### 17.3 Tokens and service accounts

API tokens are hashed at rest (SHA-256; only the prefix is stored in clear for
identification), always expiring, listed with last-used timestamp and source IP, and
revocable individually.

**Service accounts** exist for CI: a non-human identity holding a token scoped to one action
on one environment — `deploy` on `api:production` and nothing else. Handing a CI system a
human's credentials is the normal alternative and it is bad in every direction, so the
narrow-scope path is the documented one.

Sessions are short-lived with refresh, revocable per device, and every authentication event —
success, failure, MFA challenge, break-glass use — is audited.

### 17.4 Quotas and limits

Quotas exist so one team cannot consume an instance, and so a runaway autoscaler cannot
consume a fleet. They are set by an instance administrator per team, and a team owner may
subdivide them per project.

| Quota | Counted as |
|---|---|
| apps, environments | objects |
| replicas | desired count, not running count |
| CPU, memory | **reserved**, not used — consistent with placement (§5) |
| volume and backup storage | allocated bytes |
| build minutes, concurrent builds | consumed per period |
| egress, including cross-zone | bytes (§10.6) |

**Enforcement is at the API, before the object exists.** Creating the eleventh environment
against a quota of ten fails at save time, naming the quota and current usage — not at deploy
time, and never as a container that mysteriously does not start. This is the same principle
as port-conflict detection (§7.4): reject at the moment of authoring, when the person has
context.

**Soft and hard thresholds.** A soft quota notifies at 80% and again at 100% but permits the
operation; a hard quota rejects. Storage and object counts default to soft, capacity and
spend-shaped quotas to hard.

**Autoscaling respects quotas explicitly.** An `AutoscalePolicy.Max` above the team's replica
quota is capped, and the autoscaler emits `ScaleCapped` naming *the quota* as the constraint
(§14.2). Silent capping during the traffic spike the autoscaler existed for is the failure
this avoids.

Separately from resource quotas, the API applies rate limits — per token, per IP for
unauthenticated endpoints, and a distinct budget for webhook ingestion (§12.2), which is
publicly reachable and therefore the most abusable surface.

Quotas allocate; they do not bill. Cost figures (§20.11) are estimates and are not reconciled
against an invoice.

---

## 18. Configuration, import, and interoperability

### 18.1 `vesta.yaml` — configuration as a reviewable file

Application configuration can live in the control plane's database, edited through the UI, or
in the application's own repository as a file. Vesta supports both, and the file is the
interesting one because **it costs almost nothing here**: spec generation (§4.2) already
resolves `app base → environment overlay → deployment override` into a Spec, so a repo file
is one more reader feeding an existing pipeline, not a parallel system. In a product where
config exists only as database rows, the equivalent is a rewrite.

The file is **read from the commit being deployed**, which is the property everything else
follows from: configuration and the code that depends on it change together, review together,
and roll back together.

```yaml
version: 1
app: api

build:
  type: dockerfile            # dockerfile | nixpacks | buildpacks
  context: .

processes:
  web:
    command: ["bin/server"]
    port: 3000
    health:
      readiness: { path: /healthz, period: 5s }
      liveness:  { path: /healthz, period: 15s, failureThreshold: 3 }
  worker:
    command: ["bin/worker"]

resources: { cpu: 1, memory: 512Mi }

secrets:
  requires: [DATABASE_URL, STRIPE_SECRET_KEY]   # names only — never values
  optional: [SENTRY_DSN]

links:
  - service: postgres
    alias: postgres
    inject: [DATABASE_URL]

jobs:
  nightly-report:
    schedule: "0 3 * * *"
    timezone: Europe/Berlin     # required (§13.4)
    command: ["bin/report"]

environments:
  staging:
    replicas: 1
    domains: [api-staging.example.com]
    scaleToZero: { idleAfter: 15m }
  production:
    replicas: 4
    domains: [api.example.com]
    autoscale: { min: 4, max: 20, metric: concurrency, target: 50 }
    rollout: { strategy: rolling, maxSurge: 1, maxUnavailable: 0 }
  preview:
    replicas: 1
    scaleToZero: { idleAfter: 10m }
```

This is a serialization of the product model, not a new one: base plus environment overlays
(§4.2), links (§7.5), jobs (§13), probes (§8.1), autoscaling and parking (§14). If something
is expressible in the UI and not in the file, that is a bug in the schema.

#### Ownership: the problem that decides whether this is useful

Config in two places creates a precedence question, and answering it badly is how a feature
like this becomes a second place for configuration to rot. Three possible answers:

| Model | Consequence |
|---|---|
| Repo wins absolutely | clean, but you cannot scale up during an incident without commit → push → build |
| Repo is a template, UI wins | the file is decorative and drifts within a week |
| **Field-level ownership with expiring overrides** | what we build |

```yaml
configSource: repo-with-overrides   # repo | ui | repo-with-overrides (default when a file exists)
```

- **Fields present in the file are repo-owned.** Fields absent from it stay UI-owned, so
  adopting the file is incremental — declare three fields, keep clicking the rest.
- **A UI change to a repo-owned field creates an `Override`**, carrying the actor, a reason,
  and an expiry. The default expiry is *the next deploy from git*, which reasserts the file.
- **Overrides are visible as drift**, not silent: the environment shows "3 fields overridden"
  with who, why, and what the file says instead.
- **`sticky: true`** keeps an override until someone removes it, and requires Admin.

This handles both failure modes honestly. During an incident you scale to 20 replicas from
the UI without fighting the file; afterwards the next deploy restores the declared state
instead of leaving an undocumented change nobody remembers making.

#### Fences: what an application PR may not change

An operator can mark fields platform-owned per environment — production domains, a replica
floor, resource ceilings, placement, port bindings. A file that sets a fenced field fails
validation with the field named. Without this, adopting repo config would mean any developer
with merge rights can silently change production topology, which is a worse security posture
than the UI it replaced.

#### Secrets appear as requirements, never as values

`secrets.requires` lists the names an app needs. Deploy runs a pre-flight check and **fails
fast, naming the missing variable**, rather than letting the app crash-loop in staging because
someone forgot `STRIPE_SECRET_KEY`. This is the whole of the file's involvement with secrets:
values live in the secrets system (§11), and the validator rejects anything under `secrets:`
that looks like an actual value — a long high-entropy string — with a pointed error rather
than a warning, because a warning here gets committed anyway.

#### Validation that fails at review, not at deploy

- `version:` is required, so the schema can evolve without guessing at a file's vintage.
- **Unknown fields are errors, not warnings.** A misspelled key that silently does nothing is
  the classic way configuration files betray people.
- A JSON Schema is published, so editors autocomplete and validate as you type.
- `vesta validate` runs in CI against the PR. It is the *same validator the deploy runs*, so
  CI passing and deploy failing cannot disagree.

#### Releases capture the resolved config

§4.1 defines a Release as immutable — image digest, config snapshot, secret versions. With a
repo file, that snapshot is the **resolved** configuration: file, plus environment overlay,
plus any active overrides, frozen at deploy. Two consequences:

- **Rollback restores the configuration that actually worked**, not the current database
  state. Rolling back an image while config has drifted forward is otherwise a reliable way
  to produce a state that was never tested.
- **Two releases can be diffed** — the UI shows exactly which fields changed between them,
  authored by someone, with a commit and a reviewer attached.

#### Adoption, monorepos, previews

- **You do not hand-write the first one.** `vesta export --app api > vesta.yaml` emits the
  current configuration in this schema (§18.3), which is the on-ramp: export, commit, review,
  and the fields you kept become repo-owned.
- **Monorepos** declare several apps in one file's `apps:` list, or use per-directory
  `vesta.yaml` discovered by a configurable glob.
- **Preview environments** finally work without per-PR clicking: the `preview:` overlay gives
  every pull request a functioning environment with sensible parking, which is what makes the
  M4 preview feature usable rather than a thing you configure once and abandon.

The file is **opt-in**. Its absence changes nothing, and clickops remains fully supported —
this is an addition to how Vesta can be driven, not a migration users are pushed through.

### 18.2 Docker Compose import

Nearly everyone arriving at Vesta already has a `docker-compose.yml`. Whether they can bring
it decides whether they arrive at all.

Import parses Compose into the same intermediate representation the Coolify importer produces,
so both paths share one mapper, one preview, and one apply:

| Compose | Becomes | Notes |
|---|---|---|
| `services:` with an official DB image | a managed service (§15) | recognised by image name; overridable |
| other `services:` | apps | one app per service |
| `build:` | build config (§12) | context, dockerfile, args |
| `image:` | pinned release | tag resolved to a digest at import |
| `ports:` | `PortBinding` (§7.4) | HTTP-looking ports are offered as routes instead |
| `environment:` / `env_file:` | env vars — **with secret detection** | keys matching `*PASSWORD*`, `*SECRET*`, `*KEY*`, `*TOKEN*`, and high-entropy values are offered as secrets, not plain vars |
| `volumes:` named | volumes (§16.1), Local tier | |
| `volumes:` bind mounts | flagged, not silently imported | a host path is not portable and the user must confirm |
| `depends_on:` / shared networks | `ServiceLink`s (§7.5) | this is how default-deny stays usable on import |
| `deploy.replicas` | replica count | |
| `healthcheck:` | readiness probe (§8.1) | |
| `privileged`, `network_mode: host`, `pid: host`, `cap_add` | **reported, not imported** | each named, with what it would mean |

Two rules make this trustworthy:

- **Import is a preview and a diff, never a one-shot.** It shows every object it intends to
  create, what it could not map, and what it guessed — particularly the secret detection,
  where a wrong guess in either direction matters. Nothing is created until the user applies.
- **Re-import diffs against what exists.** An updated Compose file produces a change set, not
  a duplicate stack, so a repository's compose file can stay the working source during a
  migration rather than being a one-time throwaway.

The secret-detection step is the highest-value part and worth calling out: the single most
common condition of an incoming Compose file is a database password sitting in
`environment:`, and the moment of import is the one moment a user is receptive to moving it.

### 18.3 Coolify import

Point the importer at an existing Coolify install and it produces the equivalent Vesta
objects, through the same preview-and-diff pipeline as Compose import (§18.2).

| Comes across | Does not |
|---|---|
| projects, applications, environments | **secret values** — see below |
| domains and routes | Coolify's internal state and job history |
| resource limits, replica counts, restart policy | anything requiring Coolify's `APP_KEY` |
| volumes (as Local tier, §16.1) | |
| scheduled tasks → jobs (§13) | |
| environment variables Coolify held in plaintext, **subject to the same secret-detection heuristic as Compose import** — a plaintext value named `*_TOKEN` is offered as a secret, not copied forward as config | |

#### Secret values are not imported, and that is the design

Moving a secret requires seeing its plaintext, and Coolify's are encrypted under its
`APP_KEY`. Importing them therefore means Vesta asking for the key that decrypts a user's
entire Coolify installation.

**We do not build that code path.** Not a sealed-bundle exporter, not a decrypt-on-import
mode, not an optional flag. The importer needs read access to structure and nothing more, so
there is no configuration in which Vesta holds another platform's master key — and no
incident in which it can leak one. A migration tool is exactly the kind of software that is
run once, under time pressure, by someone who will grant it whatever it asks for; the right
design is to not ask.

What is imported instead is the **shape** of each app's secrets: every required name, at the
right scope, as an empty entry. Deployment then fails fast naming what is missing (§18.1
`secrets.requires`), rather than starting an app that crash-loops on a nil credential.

#### Re-entry is the rotation

The obvious objection is that someone must now enter those values by hand. The answer is that
they should not enter the *old* ones:

> Those credentials sat where anyone with server access could read them — in container
> config, in a compose file on disk, in a deploy log (PLAN §1.2). They should be treated as
> exposed. The migration is not the moment to carry them forward intact; it is the moment to
> issue new ones.

So the import checklist is a rotation checklist. For each required secret it offers the
source system's rotation URL where one is known, and records `origin: migrated` with the date
the value was first set. The end state is a fleet whose credentials are all newer than the
install they came from — which is a better outcome than a faithful copy, and unreachable by
any importer that succeeds silently.

#### Making it bearable

Hand-entering two hundred values through browser fields would be its own security problem, so
the ergonomics are part of the design:

- **Grouping.** Names recurring across apps are proposed as one project-scoped shared secret
  (§11.6), entered once rather than per app.
- **Offline template.** `vesta secret template --project acme > secrets.env` emits every
  required name with an empty value. The operator fills it on their own machine, applies it
  with `vesta secret set --from secrets.env`, and deletes it. One file, one place, one moment
  — instead of values scattered through a browser, a clipboard manager, and a chat window.
- **Progress is visible.** "14 of 22 required secrets set, 3 apps blocked" is shown until the
  migration is complete, so a half-migrated install is an obvious state rather than a
  surprise at the first deploy.

**The accepted trade, stated plainly:** this makes migration slower than a tool that carries
secrets across automatically, and some users will find that annoying. It is the deliberate
choice. The alternative buys convenience by building a mechanism whose whole purpose is to
handle someone else's master key, and that mechanism is a liability for as long as it exists.

### 18.4 Export, because lock-in is a trust problem

`vesta export` emits, in the same schema as `vesta.yaml` (§18.1), the full declarative
definition of a project — apps, environments,
links, schedules, routes, volume and backup policy — with secret *references* rather than
secret values. It reimports cleanly into another Vesta install.

This exists for three reasons: it makes disaster recovery of the control plane a file rather
than a database restore, it makes moving between installs (or from a trial to production) a
non-event, and it is an honest answer to "what happens if I want to leave". A platform whose
users cannot leave has to earn their stay some other way.

### 18.5 Templates

A template is a pre-authored `vesta.yaml` (§18.1) plus the managed services and secret
requirements an application needs — the one-click app catalog, expressed in the format that
already exists rather than a parallel mechanism.

```yaml
template: ghost
version: 2
variables:
  - name: DOMAIN
    prompt: Public hostname
    validate: hostname
  - name: ADMIN_EMAIL
    validate: email
  - name: DB_PASSWORD
    generate: { length: 32 }     # generated INTO the secrets system, never into the file
services:
  - type: mysql
    version: "8"
app:
  image: ghost:5
  # …ordinary vesta.yaml from here
```

**Instantiation produces an ordinary project.** Variables are filled, generated values are
written to the secrets system (§11.6), and the result is a normal app with no residual
coupling — the template is a starting point, not a controller. Nothing about the running
project is owned by the template afterwards.

**Templates are versioned, and updates are diffs.** An instantiated project records its
template and version, so "version 3 is available" can be surfaced — and applying it is a
reviewed diff through the same preview mechanism as Compose import (§18.2), never an
automatic overwrite of configuration someone has since edited.

**A template from a URL is untrusted input.** It can declare port bindings, links, and
resource requests, so instantiation runs under the *instantiating user's* authority: a
template cannot enable anything that user could not enable themselves, cannot bind a
privileged port they lack rights to, and cannot link across projects without the usual
consent (§7.5). The preview shows exactly what will be created before anything is.

**The honest note on effort:** the mechanism here is small. A useful catalog is a hundred
maintained templates, and that is a curation and maintenance commitment, not an engineering
one. It should be budgeted as ongoing content work rather than as a feature that ships once.


## 19. Data model

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
- `secrets` carry a scope (`org` | `project` | `environment` | `app`) and a type (`Opaque` |
  `Registry` | `TLS`); `secret_bindings` is the many-to-many between them and consumers
  (§11.6). A secret with no binding is inert — it exists and is reachable by no workload.
- `secret_versions` is append-only. Deleting a secret tombstones it; the ciphertext is
  destroyed only after no live Release references the version.
- **There is no `ssh_keys` table, and adding one is an architectural change, not a
  feature.** Node access is by short-lived certificate; nothing in this schema grants a
  shell on anything. The legacy Rust schema had `ssh-key.entity.ts` because it drove
  servers over SSH; porting it would reintroduce the skeleton-key problem (PLAN §1.4) that
  the transport design exists to eliminate.
- `job_runs` is append-only and is the source for both history and the dead-man checks in
  §13.9; a run row is written *before* the container starts, which is what makes the
  at-most-once dedupe key work across an agent restart.
- `instances` is a *cache* of agent-reported state, never a source of truth. If it
  disagrees with an agent, the agent is right.
- `events` is the append-only projection source for the UI stream and webhooks;
  `audit_log` is the security-relevant subset, retained separately and for longer.

---

## 20. Observability

### 20.1 Logs: two systems, not one

The common mistake is building one log pipeline and using it for both jobs it has to do.
They have opposite requirements:

| | Live tail | History and search |
|---|---|---|
| Question | "what is happening right now" | "what happened at 03:00 on Tuesday" |
| Latency | sub-second | seconds is fine |
| Loss | acceptable, if visible | not acceptable |
| Retention | none — it's a view | days to months |
| Volume handling | drop and say so | store and index |

Vesta builds both, with different guarantees, over one line format and one transport.

**The organizing decision: the node is the log store; the control plane is a query
router.** Logs are not continuously shipped to the control plane on the chance that someone
will look at them. They are read from the node on demand. This follows the same axiom as
everything else — the agent is authoritative for its host — and it means log viewing keeps
working during a control-plane outage, there is no ingest pipeline to fall over, and a
chatty app cannot fill the control plane's disk.

### 20.2 The line envelope

Every line from every source — app replicas, builds, job runs, deploy steps, the agent
itself — arrives in one shape, so one viewer, one filter language, and one retention policy
cover all of them.

```go
type LogLine struct {
    Time     time.Time  // the container's own timestamp, RFC3339Nano from Docker
    Seq      uint64     // per-container monotonic counter — exact intra-container ordering
    Node     string
    App, Env string
    Replica  int
    Release  string
    RunID    string     // job or build run, when applicable
    Source   LogSource  // Stdout | Stderr | Build | Job | Deploy | Agent
    Text     string
}
```

`Seq` matters: timestamps collide at high volume and clocks are not trustworthy across
nodes, so ordering *within* one container is defined by `Seq`, not by time. This is what
lets the UI guarantee that a stack trace is never interleaved with itself.

### 20.3 Reading from Docker

The agent reads via the Engine API's `ContainerLogs` with `Follow`, `Timestamps`, `Tail`,
and `Since`. Two mechanics that routinely cost people a day:

- **The stream is multiplexed.** Without a TTY, stdout and stderr arrive framed with an
  8-byte header per chunk and must be demultiplexed (`stdcopy`), not read as raw bytes.
- **Only the `json-file` and `local` drivers are readable.** We set `local` with rotation
  (§7.3), which the API can read across rotated files — so recent history is queryable from
  Docker itself with no storage of our own. A user who overrides the log driver to syslog or
  fluentd loses the log UI entirely; that escape hatch exists, and it says so at the moment
  it is chosen rather than producing an empty log pane later.

**Redaction happens at the agent, before a line leaves the node** (§11.5). Secrets never
traverse the network and never enter control-plane memory in order to be scrubbed at
display time.

**Logs survive the container that wrote them.** On container removal — including every
redeploy — the agent copies the final log to
`/var/lib/vesta/logs/<app>/<env>/<release>/<replica>.log` before removing it. This is
deliberate: "I redeployed and the crash logs vanished with the container" is the single most
common real-world log complaint in this category, and it is caused by treating Docker's
per-container log as the only copy.

### 20.4 Live tail across a fleet

```
 browser  ──WS subscribe {app, env, filter}──▶  vestad
                                                  │ authz: team scope + logs:read
                                                  │ fan out to nodes holding replicas
                          ┌───────────────────────┼───────────────────────┐
                          ▼                       ▼                       ▼
                    control stream          control stream          control stream
                    OpenStream{logs}        OpenStream{logs}        OpenStream{logs}
                          │                       │                       │
                    agent dials back        agent dials back        agent dials back
                    Logs RPC ──────┐        Logs RPC ──────┐        Logs RPC ──────┐
                                   ▼                       ▼                       ▼
                          ┌──────────────────────────────────────────────────┐
                          │  vestad: k-way merge, 250ms reorder buffer,      │
                          │  rate cap, drop accounting                       │
                          └───────────────────────┬──────────────────────────┘
                                                  ▼
                                          one merged WS stream
```

Five decisions in that path:

**Subscription-driven, not always-on.** The control plane asks for logs only for the
containers someone is actually watching, and tells the agent to stop when the last
subscriber disconnects. Idle apps cost nothing.

**A separate stream from the control stream.** Log volume must never apply backpressure to
Spec delivery or health reporting. The agent dials a distinct `Logs` RPC (§6.1) on the same
gRPC connection, so a torrent of log lines can be throttled or dropped without touching
control traffic.

**Filters are pushed down to the agent.** A substring, regex, level, or stream filter is
evaluated on the node. Shipping 50k lines/second across the network to discard 49.9k of them
at the control plane is the difference between a feature and an incident.

**Cross-node ordering is best-effort, and we say so.** The control plane k-way merges by
timestamp through a bounded ~250 ms reorder buffer. Within a container, order is exact
(`Seq`). Across nodes, it is as good as the nodes' clocks — which is why the agent reports
its clock offset and the UI shows a warning banner when a contributing node is skewed more
than a couple of seconds. Buffering longer to hide skew would trade the "live" out of live
tail; inventing a global order we cannot actually establish would be worse.

**Loss is bounded, visible, and never upstream.** Every hop drops rather than blocks: the
agent's per-container ring buffer, the CP's per-subscription rate cap, and the WebSocket
send buffer for a slow browser. Each drop emits a marker line — `… 4,812 lines dropped
(rate limit) …` — so a user is never shown a quiet, incomplete stream. The application is
never blocked by anyone reading its logs.

**Reconnection** resumes from the last seen `(node, container, Seq)` with a short backfill,
deduplicating on that key. At-most-once delivery with visible gaps, not silent ones.

### 20.5 History and search

A history query is a scatter-gather, not a database read:

1. The control plane resolves the time range to the set of `(node, release, replica)` that
   existed during it, using deployment records.
2. It queries only those nodes, passing the time range, filters, and a line limit.
3. Agents read from Docker's rotated files and from the preserved logs of removed
   containers, filter locally, and return bounded pages.
4. The control plane merges and returns a cursor for the next page.

Retention is per-environment `LogRetentionPolicy`, enforced by the agent on its own disk.

**Optional tiers**, for people who need more than this:

- **Persist to the control plane** — opt-in per environment, for cross-app search and for
  retaining logs beyond a node's life. Off by default, because it is the setting that turns
  a busy app into a control-plane disk problem.
- **Forward to an external sink** — a log drain (§20.6): OTLP, Loki, syslog, S3, or an HTTP
  endpoint. We are not building a log database, and the honest scope statement is that teams
  who need real log infrastructure should point Vesta at theirs rather than wait for us to
  grow one.

**Stated limit:** with the default configuration, losing a node loses that node's history.
Enabling a tier above is how you avoid that, and the docs say so plainly rather than
implying durability we do not provide.

### 20.6 Log drains

On-node history (§20.5) answers "what happened yesterday" and loses everything when a node
dies. A **drain** continuously forwards logs to somewhere you already run: an OTel collector,
Loki, a syslog host, object storage for retention, or a SaaS. It is the answer to long
retention, cross-fleet search, and compliance archival — none of which we build ourselves
(§20.5), and all of which someone else already does well.

```go
type Drain struct {
    ID     string
    Scope  Scope      // org | project | environment | app — the chain from §11.6
    Type   DrainType  // Syslog | HTTP | OTLP | Loki | S3 | Elasticsearch
    Target string
    Auth   string     // reference to a secret, never a literal credential

    Sources []LogSource // Stdout, Stderr, Build, Job, Deploy, Agent — default: all app sources
    Filter  Filter      // level, include/exclude regex, sample rate
    Format  Format      // JSON (default) | template, for text sinks

    Delivery DeliveryClass // BestEffort (default) | Reliable
    Buffer   ByteSize      // Reliable only; default 1 GiB or 24 h, whichever first
    Batch    BatchPolicy   // size + linger, default 1 MiB / 5 s, gzip
}
```

#### Drains run on the agent, not the control plane

Each node ships its own logs directly to the sink. The alternative — funnel everything
through `vestad` and forward from there — would put the control plane in the data path,
double the bandwidth, and make log delivery fail exactly when the control plane does. Since
the control plane is a query router and not a log store (§20.1), it is not the right place to
put a firehose either.

Agent-side shipping also means **drain credentials need no new distribution mechanism**: the
sink's API key is an ordinary scoped secret (§11.6), sealed to the node (§11.2), opened in
memory, and never written to disk. A drain is configured centrally and executed locally.

The trade is more connections to the sink — N nodes rather than one — which batching and
connection reuse make a non-issue for any sink built to receive logs.

#### Redaction comes first, always

Invariant 14 says no log line leaves a node before passing the redaction filter, and a drain
is the most literal case of leaving. The filter runs **before** the drain sees the line, so a
secret echoed by a crashing process is `***` by the time it reaches a third party. Getting
this order wrong would mean the feature that ships your logs off-box is also the feature that
ships your credentials to a vendor, permanently, into a system you cannot redact
retroactively.

Filters are likewise evaluated on the node, so a drain that only wants `stderr` above
`warn` ships that and not the 50k lines/second it discarded (§20.4).

#### Two delivery classes, because "lossy" is not always acceptable

Live tail is deliberately lossy (§20.4). A drain feeding a compliance archive cannot be.

| | `BestEffort` (default) | `Reliable` |
|---|---|---|
| Under sink slowness | drop oldest, count drops | spill to a bounded on-disk buffer |
| Sink outage | lines lost for its duration | replayed when it returns, up to the buffer |
| Buffer survives agent restart | n/a | yes |
| Guarantee | none, but drops are visible | at-least-once within the buffer |
| Cost | none | disk, and duplicate lines on retry |

Neither class ever blocks the container. Invariant 15 holds without exception: when a
`Reliable` drain's buffer fills, it drops the oldest lines and increments a counter — it does
not apply backpressure to the process that wrote them. A logging pipeline that can stall an
application is a worse outage than losing logs.

`Reliable` is **at-least-once, not exactly-once.** Retries after a partial failure can
duplicate lines, and the sink should dedupe on `(node, container, Seq)` — which the line
envelope (§20.2) already carries for exactly this kind of reason. Ordering within a container
is preserved; across containers and nodes it is not, for the same clock reasons as §20.4.

#### Sink drivers

One `Drain` interface, several drivers, so a new sink is a package rather than a change to
the shipping path (§25):

| Type | Notes |
|---|---|
| `Syslog` | RFC 5424 over TCP+TLS; metadata mapped into structured-data fields |
| `HTTP` | batched, gzipped JSON POST — the generic escape hatch |
| `OTLP` | logs over gRPC or HTTP; the right default for anyone already running OpenTelemetry |
| `Loki` | push API, labels derived from the envelope's app/env/node/replica |
| `S3` | gzipped batches partitioned by `app/env/date/hour`, for archival and compliance |
| `Elasticsearch` | bulk API |

#### Operating a drain

- **A drain never logs into its own stream.** Drain errors go to the agent's log, rate
  limited. Without that rule a failing HTTP drain writes an error, which becomes a line, which
  is shipped, which fails — an amplification loop that ends with a full disk.
- **Per-drain metrics**: lines and bytes sent, dropped, currently buffered, last success,
  error rate. A drain failing for longer than a threshold **alerts**, because a silently
  broken drain is a gap discovered during an audit rather than during operations.
- **Egress bytes are attributed** to the drain and feed cost allocation (§20.11). Shipping
  every line from five nodes to a per-GB SaaS is a real bill, and it should be visible before
  the invoice.
- **"Send test event"** exists, and validates connectivity, auth, and format against the real
  target. Configuring a drain and hoping is how people discover in an incident that the token
  expired months ago.
- Enabling a drain **does not disable on-node history**. `vesta logs` keeps working during a
  sink outage, which is the point of not having made the sink authoritative.

### 20.7 Access control

Logs routinely contain more sensitive data than the secrets people carefully protect.
Accordingly, log access is its own permission (`logs:read`), scoped by team and environment
and grantable separately from deploy rights; access to production log streams is recorded in
the audit log with actor, environment, and time range; and multi-line filters cannot be used
to exfiltrate around redaction, because redaction runs before filtering on the node.

Concurrent subscriptions are capped per user and per node — every followed container is a
goroutine and a file descriptor on someone's server.

### 20.8 Metrics

The agent samples container CPU, memory, network, and disk from Docker's stats stream at low
frequency (10 s) and reports deltas on the control stream. This is not a Prometheus
replacement; it exists to drive the dashboard and autoscaling triggers. OTLP export is
available for people who want the real thing, and the node exporter path is documented for
those who already run one.

### 20.9 Request metrics from the proxy

Container CPU and memory answer "is the box busy". They do not answer "is my app slow",
which is the question people actually have. The proxy sees every request already, so the
answer costs almost nothing to produce and requires no agent in the application, no SDK, and
no Prometheus.

Per `(route, app, env, replica)`, the proxy maintains:

| | |
|---|---|
| **R**ate | requests/sec |
| **E**rrors | count by class — 4xx, 5xx, upstream-refused, upstream-timeout, wake-timeout |
| **D**uration | histogram → p50, p90, p95, p99, plus time-to-first-byte |

Kept as counters and a bounded histogram in memory, reported to the control plane every 10 s
as deltas. Memory is O(routes × buckets), not O(requests) — a route costs a few kilobytes
regardless of traffic.

What this powers, all from the same data: the per-app dashboard, latency and error-rate
alerting, concurrency-based autoscaling (§14.2), and the health colouring on the topology map
(§20.10). One measurement, four consumers.

**The boundary, stated:** these are aggregates. Vesta does not store per-request records and
is not a tracing system — there is no "show me request 7f3a" and there will not be. Apps
that need distributed tracing emit OTLP to their own collector; the proxy propagates
`traceparent` so those traces stay connected across the mesh hop, and that is the whole of
our involvement.

A Prometheus-format `/metrics` endpoint is exposed for teams who already scrape.

### 20.10 Service topology

`ServiceLink` (§7.5) means the dependency graph is *declared*, not inferred — so rendering it
is a view over data we already have, not a discovery problem.

```
   ┌──────────┐        ┌──────────┐        ┌────────────┐
   │ web:prod │───────▶│ api:prod │───────▶│ postgres   │
   │  4 rep.  │  0.2%  │  6 rep.  │ 11.4% ⚠│  1 rep.    │
   └──────────┘        └────┬─────┘        └────────────┘
                            │  ⟿ cross-zone
                       ┌────▼─────┐
                       │ search   │
                       │  fra-1   │
                       └──────────┘
```

Edges carry the error rate and p95 from §20.9, so the map answers "which dependency is
failing" rather than merely "what exists". Cross-zone edges are marked, because they are the
ones costing money and latency (§10.6), and cross-environment links are marked in a warning
colour, because those are usually a mistake someone made once and forgot.

Where a link is `Proxied`, observed traffic is compared against declared links; a declared
link carrying no traffic for a long period is surfaced as a candidate for removal — dead
links are stale access grants (§7.5), and pruning them tightens the blast radius.

### 20.11 Cost allocation

Self-hosters choose this category to control spend, and then no self-hosted platform tells
them where the money goes. We already hold every input:

| Input | Source |
|---|---|
| Node cost | operator enters $/month per server (or per region) |
| Reserved vs. used CPU/memory | scheduler reservations (§5), agent stats (§20.8) |
| Storage | volume and backup sizes (§16) |
| Cross-zone transfer | mesh byte counters (§10.6) |

Node cost is allocated across the workloads on it by reserved share, with used share shown
alongside. The output is $/app/environment/month with a trend, and one derived number that
matters more than the rest: **idle waste** — reserved-but-unused capacity, in dollars. That
is the figure that actually changes behaviour, because it converts "we over-provisioned" from
a vague feeling into a line item.

Scale-to-zero savings (§14.3) are reported the same way: hours slept × the rate those
reservations would have cost.

**This is allocation, not billing.** The numbers are estimates derived from operator-supplied
costs; they are not an invoice and are not reconciled against one. Said plainly in the UI, so
nobody builds a chargeback process on top of a number we described as approximate.

### 20.12 Events

Every state transition emits to the internal bus: deployment phases, replica health flips,
probe failures, cert issuance, secret reveals, job runs, quota rejections. The UI's live view
is a WebSocket subscription to this bus, filtered by team — the same multiplexed connection
that carries log subscriptions, so a browser tab holds one socket, not one per panel.
Nothing in the UI polls.

### 20.13 Notifications and outbound webhooks

Both are projections of the internal event bus (axiom 5) — one subscription model, two
transports. Nothing generates notifications by side effect; if it is not an event, it cannot
be notified on.

**Subscriptions** are `scope × event types × severity`, where scope walks the same chain as
secrets and drains (org → project → environment → app). Separate routing matters: deployment
chatter and page-worthy failures should not arrive in the same place, and a single global
channel guarantees that either the noise is intolerable or the signal is missed.

**Channels**: Slack, Discord, Google Chat, email (SMTP), and generic HTTP — reusing the
notifier implementations already written for the Kubernetes edition.

**Outbound webhooks** are signed with HMAC-SHA256 using a per-webhook secret, over a payload
that includes its own timestamp so a captured delivery cannot be replayed later. Headers
carry the event type and a delivery id.

**Delivery is at-least-once**, with exponential backoff, bounded retries, and a visible
dead-letter state. Consumers deduplicate on the delivery id; ordering is not guaranteed. Every
attempt is recorded, so "did it fire?" is answerable without asking the receiving system.

Three behaviors that keep this from becoming a nuisance:

- **Continuously failing webhooks are auto-disabled** after a threshold of consecutive
  failures, with a notification saying so. Retrying a dead endpoint forever is a background
  load that grows silently and helps nobody.
- **Events are coalesced.** A rolling deploy across twenty replicas emits a great many
  events; the notifier batches and summarizes them into one message per deployment rather
  than sixty. Anyone who has watched a deploy fill a Slack channel understands why this is not
  optional.
- **Payloads never contain secret values.** They carry references — secret name, version,
  actor — and pass the same redaction filter as logs (§20.4). A webhook is an egress path to a
  third party and is treated as one.

A test-delivery action validates connectivity, auth, and signature handling against the real
endpoint, because a notification channel is discovered to be broken at exactly the moment it
is most needed.

### 20.14 Audit

Actor, action, target, IP, timestamp, outcome, and — for secret reveals — the stated reason.
Immutable, exportable, and retained independently of the general event log, so trimming
event history never trims the security record.

---

## 21. Failure modes

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
| Log volume exceeds what a viewer can consume | Lines are dropped at the narrowest hop and a `… N lines dropped …` marker is emitted. The application is never blocked. | Nothing to recover; the gap is visible, and history (§20.5) still has the lines Docker retained. |
| Node lost with default log config | That node's history is gone with it. | Accepted default (§20.5). Opt into control-plane persistence or an external sink to avoid it. |
| Linked target scheduled onto another node | A `Direct` link is refused at link time with both fixes offered; an existing link whose target moves is reported broken by the reconciler. | Co-location is the default (§7.5); switching the link to `Proxied` routes it over the mesh. |
| Requested host port already in use | Rejected at save time, naming the conflicting app or the non-Vesta process holding it. No container is created. | Agents report listening sockets at enrollment and each resync, so the registry knows about ports it does not own (§7.4). |
| Clock skew between CP and node | Spec ordering uses `Issued`; large skew could cause a Spec to be ignored. | Agent rejects Specs more than 5 min in the future and raises an event. |
| Bad agent release | Workloads unaffected — containers are not children of the agent. The canary node fails to confirm and reverts to the previous binary. | Trial-and-revert (§23.6); the fleet rollout halts automatically, so only the canary was ever exposed. |
| Agent too old to understand the current Spec | Connects, is marked `outdated`, refuses the Spec, and is offered an update over the frozen channel. | The Hello/Update messages never change incompatibly (§23.2), so no agent is ever unreachable. |
| Migration fails mid-update | `vestad` aborts startup and does not serve; the previous binary can be restarted against the pre-migration backup. | Expand/contract means the prior release still reads the schema; SQLite is copied before migrating, Postgres uses an advisory lock. |

---

## 22. Security boundaries

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
- **The control plane stores no SSH keys and holds no standing access to any node.** There
  is no `ssh_keys` table, no encrypted key blob, no credential of any kind that grants a
  shell. This is a direct consequence of the agent dialing out (§6.1): a system that never
  initiates a connection needs nothing to authenticate with. The legacy Rust schema's
  `ssh-key.entity.ts` is deliberately **not** ported (§19).
- Assisted bootstrap, if used, receives a key for the duration of one call and never writes
  it. A control plane that has enrolled a hundred nodes contains exactly as much SSH key
  material as one that has enrolled none.
- Consequently, a full offline compromise of the control plane — stolen backup, leaked disk
  image, exfiltrated key file — yields **no** route to any app server. Live compromise is a
  different matter and is addressed honestly in PLAN §6.1 (T4): the attacker can publish a
  Spec, which is root by another road, but only through an audited channel and only until
  the CA is rotated.
- The proxy never holds, requests, or is told about secret material.
- Container-to-container isolation is Docker's, which means it is a boundary against
  accident, not against a determined hostile tenant. Stated plainly in the docs.
- Agent certificates are short-lived and renewed over the established stream; a revoked
  node loses access at the next renewal and is dropped from the CA's allow list
  immediately.

---

## 23. Versioning and updates

Updating a fleet is the operation with the worst failure mode in the whole system: a bad
update can strand every node at once, and the thing you would use to fix them is the thing
that just broke. The design is shaped around that single risk.

### 23.1 One version, one commit

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

### 23.2 The frozen core

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

### 23.3 Compatibility contract

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

### 23.4 Updating the control plane

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
per §21, apps keep running, keep being health-checked, and keep being routed while the
control plane is gone.

**Downgrades are honest:** binaries roll back freely, schema does not. Migrations are
forward-only. Rolling back across a migration boundary requires the pre-migration backup,
and the release notes say so explicitly for any release that migrates.

### 23.5 Updating an agent

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

### 23.6 Trial-and-revert

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

### 23.7 Rollout across the fleet

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

### 23.8 Updating the proxy — without dropping traffic

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

### 23.9 Updating `vesta-init`

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

### 23.10 CLI and version skew

`vesta self-update` updates the CLI, verifying the same signature. The CLI warns — and does
not block — when its minor version differs from the control plane's, because an operator on
a slightly old laptop is normal and should not be a wall.

### 23.11 Visibility

`vesta version --fleet` and the fleet view show, per node: agent version, protocol version,
update policy, last update, and whether it reverted. Version drift is highlighted rather
than hidden, because an un-updated node is usually the one with a problem — a full disk, a
clock skew, a systemd unit someone edited by hand.

## 24. Invariants

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
12. The control plane never persists an SSH private key, or any other credential granting
    shell access to a node — verified by a schema assertion and a test that greps the
    store layer, so the property cannot be lost to a well-meaning feature PR.
13. Two containers share a network only if a `ServiceLink` authorizes it; there is no
    network every container joins.
14. No log line leaves a node before passing the redaction filter.
15. A log consumer — browser, CLI, or control plane — can never block or slow the process
    that wrote the line; every hop drops instead, and every drop is visible to the reader.
16. Ordering within a single container is exact, by `Seq`, regardless of timestamps.
17. An agent update never signals, stops, or restarts a running container.
18. An agent binary is only executed after its Ed25519 signature verifies; a partially
    downloaded artifact can never be executed, because the swap is a `rename()`.
19. An agent that fails to confirm within its trial deadline reverts to the previous
    binary without operator action, and halts the rollout for the rest of the fleet.
20. Killing the control plane mid-deploy leaves the environment either fully on the old
    release or fully on the new one, never split — because the agent completes or rolls
    back the pass it started.

---

## 25. Extension points

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
