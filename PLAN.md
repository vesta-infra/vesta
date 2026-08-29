# Vesta — Plan

Self-hosted PaaS for **plain Linux servers**. Docker as the runtime, no Kubernetes, no
control-plane-per-cluster tax. One static Go binary for the control plane, one for the
node agent, one for the edge proxy, one CLI.

**This is Vesta.** The name belongs to this project — the Docker/Linux edition is the
product. `vesta-kubernetes` is the sibling edition for teams that already run a cluster:
same product surface (projects, apps, environments, secrets, deploys), different substrate.
`vesta-kubernetes` reconciles CRDs into Deployments; Vesta reconciles a desired-state spec
into Docker containers on a fleet of ordinary VPS boxes. Shared vocabulary, shared UI
language, shared CLI verbs — a team can move between the two without relearning the model.

The earlier Rust-agent prototype that held this name now lives in `vesta-old/` and is
retired (§9).

---

## 1. Why this exists

Coolify proved the market: people want Heroku on a $12 Hetzner box. It has three
structural problems we are building around, not incremental gripes.

### 1.1 It is slow

Coolify drives servers over SSH, shelling out to the `docker` CLI, one command per
operation, from PHP. Every UI action is a fresh SSH handshake, a process spawn, and
output parsing. Deploys serialize. The dashboard polls.

**Our position:** a persistent agent per server holding an open Docker API connection and
a long-lived gRPC stream to the control plane. No SSH in the hot path. No `docker` CLI
subprocess anywhere — the Moby Go SDK, in-process. Reconciliation is concurrent across
apps and servers. State changes stream to the UI, nothing polls.

Budget (enforced in CI as benchmarks, not aspirations):

| Operation | Target (p95) |
|---|---|
| UI action → container state change | < 500 ms |
| Redeploy, image already present | < 5 s |
| Build + deploy, small Node app, warm cache | < 90 s |
| Control plane idle RSS | < 60 MB |
| Agent idle RSS | < 30 MB |
| Agent idle CPU | < 0.5% of one core |

### 1.2 Secrets are not secret

Coolify writes environment variables into container config. Anyone who can reach the
server — anyone in the `docker` group, anyone reading a `docker-compose.yml` under
`/data/coolify`, anyone with a stolen DB backup — reads production credentials in
plaintext. `docker inspect` is a credential dump.

**Our position:** secrets are encrypted at rest with envelope encryption, never written to
disk on the app server, never present in container config, and never returned by the API
without an explicit reveal grant and an audit record. Section 6 is the full design,
including an honest statement of what root on the box can still do.

### 1.3 The model is wrong in two places

**Environments are separate applications.** In Coolify, staging and production are two
apps you create twice and drift apart forever. There is no "same app, different config",
no diff, no promote.

**One replica per server.** Coolify scales an app *across* servers but cannot run N
containers of one app *on* one server. So a 32-core box runs one container, and there is
no way to do a zero-downtime rolling deploy on a single-server install — the most common
install there is.

**Our position:** an app is one object with a base spec and named environment overlays;
promotion moves an image digest, not source. And replicas are first-class per server:
N containers behind a health-aware load balancer, rolling/blue-green/canary, on a single
box or spread across a fleet.

---

## 2. Goals and non-goals

**Goals**

- Deploy from git push, image tag, or API call, on servers you already own.
- Multiple replicas per server, zero-downtime rolling deploys, on a one-server install.
- One app, many environments, with inheritance, diff, and promote-by-digest.
- Secrets that survive a hostile `docker inspect` and a leaked database backup.
- Managed databases, backups, cron, one-shot jobs, logs, exec — parity with Coolify's
  useful surface.
- Single binary per component. `curl | sh` install. No Redis, no queue broker, no PHP.

**Non-goals**

- Not a Kubernetes replacement. No pod scheduling guarantees, no CNI, no CSI.
- No automatic reschedule-on-node-death in v1 (opt-in later; see §5.4). A dead server's
  apps stay dead until someone acts. We say this out loud rather than implying HA.
- No multi-tenant untrusted workloads. Docker is not a security boundary against a
  hostile tenant. Teams are an organizational boundary, not a sandbox.
- No service mesh, no distributed tracing backend. We emit OTLP and get out of the way.

---

## 3. Language: Go, decided

The prototype in `vesta-old/` is a Rust agent behind a NestJS API. That combination is
being retired. Everything becomes Go.

**Why Go wins here specifically:**

- The Docker Engine API's reference client (`github.com/docker/docker/client`) is Go and
  first-party. The BuildKit client is Go. containerd is Go. Every type we need to model
  is already defined by the people who define the runtime. The Rust bindings are
  community-maintained and always a version behind.
- `certmagic` — the ACME/TLS engine inside Caddy — is an importable Go library. We get
  Caddy's certificate management inside our own proxy binary without running Caddy.
- `vesta-kubernetes` is already Go: Gin API, JWT + MFA auth, AES-GCM crypto, audit log,
  models, React UI, Cobra CLI. Reusing it is a fork-and-edit, not a rewrite (§9).
- `CGO_ENABLED=0` static binaries, cross-compiled from one machine to every arch we
  ship. `embed.FS` puts the UI inside the API binary.

**What we give up:** Rust's memory ceiling and the absence of GC pauses. Neither matters
for a supervisor process that spends its life blocked on epoll and a Docker socket. Our
agent budget is 30 MB; Go reaches that comfortably. This is not a hot path where Rust's
advantages are real.

**Stack**

| Layer | Choice | Note |
|---|---|---|
| Control plane API | Go 1.25, Gin | reused from `vesta-kubernetes/api` |
| Store | SQLite (modernc, pure Go) default; Postgres for HA | one repository interface, both behind it |
| Migrations / queries | goose + sqlc | typed queries, no ORM |
| CP ↔ agent | gRPC bidi stream over mTLS, **agent dials out** | no inbound port on app servers |
| Container runtime | Docker Engine API via Moby SDK | never the CLI |
| Builds | BuildKit; Dockerfile / Nixpacks / buildpacks strategies | remote cache export |
| Edge proxy | `vesta-proxy`, Go + certmagic | hot reload, no restart on config change |
| Jobs/scheduling | in-process, backed by the store | no Redis, no BullMQ |
| UI | React + TS + Tailwind, embedded via `embed.FS` | reused from `vesta-kubernetes/ui` |
| CLI | Cobra | reused from `vesta-kubernetes/cli` |
| Telemetry | OTLP export, optional | off by default |

---

## 4. Architecture

```
                    ┌──────────────────────────────────────┐
                    │  vestad  (control plane, 1 binary)   │
   browser ───────▶ │  REST + WS + embedded React UI       │
   CLI     ───────▶ │  scheduler · reconciler · secrets    │
   CI      ───────▶ │  store: SQLite | Postgres            │
                    └───────────────┬──────────────────────┘
                                    │ gRPC bidi stream, mTLS
                                    │ (agent dials out — no inbound port)
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
┌───────────────┐          ┌───────────────┐          ┌───────────────┐
│ vesta-agent   │          │ vesta-agent   │          │ vesta-agent   │
│  reconcile    │          │               │          │               │
│  secrets seal │          │               │          │               │
│  build (BK)   │          │               │          │               │
│  logs · exec  │          │               │          │               │
├───────────────┤          ├───────────────┤          ├───────────────┤
│ vesta-proxy   │          │ vesta-proxy   │          │ vesta-proxy   │
│  TLS · LB     │          │               │          │               │
├───────────────┤          ├───────────────┤          ├───────────────┤
│ dockerd       │          │ dockerd       │          │ dockerd       │
│  app:v3 ×4    │          │  app:v3 ×2    │          │  db, cache    │
└───────────────┘          └───────────────┘          └───────────────┘
```

**`vestad`** — API, UI, auth, store, and the *desired state* authority. Computes a target
spec per (app, environment, server) and hands it to agents. Holds the KEK. Never talks to
Docker.

**`vesta-agent`** — one per server, systemd unit, `root` (needs the Docker socket). Owns
the *actual state*: it reconciles containers, networks, volumes, and proxy config toward
the spec it was given, reports back continuously, and re-reconciles on Docker events and
on a periodic resync. It is authoritative for its own host and idempotent: if `vestad`
disappears, running apps keep running and the agent keeps them healthy.

**`vesta-proxy`** — per server. Terminates TLS (certmagic/ACME), load-balances across
replica IPs, health-gates, drains connections on rollout. Configured by the agent over a
unix socket; config swaps are atomic and never drop a connection. Runs as a separate
process from the agent so a proxy crash can't take down reconciliation and vice versa.

**`vesta`** — CLI. Everything the UI can do.

### 4.1 Reconciliation, not commands

The control plane never says "run `docker run`". It publishes a `Spec` — a content-hashed
document describing what should exist on a host. The agent diffs spec against reality and
converges. This is the one idea worth stealing from Kubernetes, and it is cheap to
implement without any of Kubernetes.

Consequences: crash-safety is free (restart, re-diff, converge), drift-correction is free
(someone `docker rm`s a container, it comes back), and the deploy path and the
self-healing path are the same code.

```go
type Spec struct {
    Revision   string          // sha256 of the canonical encoding, minus this field
    Apps       []AppSpec       // containers, replicas, networks, volumes, health
    Routes     []RouteSpec     // hostnames → app/env, TLS, middleware
    Secrets    []SealedBundle  // sealed to this agent's key, never plaintext in transit
    Jobs       []JobSpec       // cron, one-shot, pre/post-deploy hooks
}
```

### 4.2 Agent enrollment

`vesta server add` mints a one-time join token. The install script pulls the agent binary,
the agent posts the token, receives a client certificate from `vestad`'s internal CA, and
dials the stream. Certs auto-renew over the established stream. No SSH key on the control
plane, no inbound firewall rule on the app server, no port 22 dependency.

For servers where the user wants us to do the bootstrap, `vestad` will SSH **once** to run
the install script, and then never again. SSH is a provisioning tool here, not a transport.

---

## 5. The scaling model (the Coolify gap)

### 5.1 Replicas on one host

An app-environment gets a dedicated bridge network `vesta_<app>_<env>`. Replicas are
containers `vesta_<app>_<env>_<n>`, all on that network, **with no published host ports**.
The proxy dials container IPs directly. That single decision removes the host-port
conflict that stops Coolify from running replica #2.

```
vesta-proxy :443 ──┬─▶ 172.20.0.11:3000   app_prod_1   healthy
                   ├─▶ 172.20.0.12:3000   app_prod_2   healthy
                   ├─▶ 172.20.0.13:3000   app_prod_3   draining
                   └─▶ 172.20.0.14:3000   app_prod_4   starting (not in pool)
```

Scaling is `replicas: 4` on the environment. The agent creates or removes containers to
match, the proxy pool updates on the same reconcile pass.

### 5.2 Stateless vs stateful

Replicas > 1 requires the app to be marked stateless, or to declare **per-replica volume
templates** (`data-{n}`), the StatefulSet idea without the StatefulSet. A shared writable
volume across replicas is rejected at validation time with a message explaining why,
rather than silently corrupting SQLite at 3am. Managed databases are always
`replicas: 1` unless they run a real clustering addon.

### 5.3 Rollout strategies

- **Rolling** (default): `maxSurge: 1`, `maxUnavailable: 0`. Start new replica → wait for
  readiness probe → add to proxy pool → drain old replica (stop accepting new
  connections, wait `drainSeconds`, then SIGTERM, then SIGKILL after `stopGrace`) →
  remove. Works with `replicas: 1` — that's the zero-downtime single-server deploy
  Coolify can't do.
- **Blue/green**: full parallel pool, one atomic proxy switch, old pool held for
  `keepPreviousFor` so rollback is instant.
- **Canary**: weighted split in the proxy, promote or abort on metrics/error-rate gate.
- **Recreate**: for apps that genuinely can't overlap.

Automatic rollback on failed health gate is the default, with a hard deadline
(`progressDeadlineSeconds`) so a crash-looping deploy can't hang forever.

### 5.4 Across servers

Placement is explicit or policy-driven: pin an environment to named servers, or give it a
count and a strategy (`spread` across servers, `binpack` onto the fewest). Servers carry
labels; environments carry constraints (`region=eu`, `disk=nvme`). The scheduler tracks
CPU/memory reservations and refuses placements that overcommit past a configured ratio.

Node failure in v1: the fleet view marks the server unreachable, alerts fire, traffic to
its replicas is withdrawn at any upstream proxy, and the remaining replicas serve.
Replicas are **not** rescheduled elsewhere automatically. Opt-in auto-failover lands after
the core is stable, because it needs volume-portability answers we don't have yet.

---

## 6. Secrets

The headline feature. Threat-modeled explicitly, because "encrypted secrets" without a
threat model is marketing.

### 6.1 Threat model

| # | Adversary | Defended? |
|---|---|---|
| T0 | Stolen DB dump / backup file | **Yes** — envelope encryption, key not in the DB |
| T1 | Non-root shell on an app server, `docker` group | **Yes** — nothing in `docker inspect`, nothing in container config, nothing on disk |
| T2 | Read access to control-plane disk, no process access | **Yes** with external KMS or sealed mode |
| T3 | Root on an app server, live | **Partially** — see below |
| T4 | Root on the control plane, live | **No.** Compromise of `vestad` is game over |

**On T3, honestly:** root on a Linux box can read `/proc/<pid>/environ`, `nsenter` into a
container, and ptrace a running process. No user-space design changes that. What we do
change is the blast radius: root on server A recovers only the secrets of apps *currently
running on server A*, only while they run, with no at-rest copy to exfiltrate later and no
key material to reuse elsewhere. Compare with Coolify, where the same access yields every
secret for every app, at rest, forever. Anyone claiming to defend T3 without a TPM or a
confidential-computing enclave is selling something.

### 6.2 Key hierarchy

```
KEK  (root key — file | env | AWS KMS | GCP KMS | Vault Transit | sealed/Shamir)
 └── DEK per project        (AES-256-GCM, wrapped by KEK, rotatable)
      └── secret value      (AES-256-GCM, AAD = project|app|key|version)
```

The AAD binding matters: a ciphertext lifted from one app's row and pasted into another's
fails to decrypt. Copy-paste privilege escalation inside the database is closed.

`vestad` supports **sealed mode** (Vault's model): the KEK is never on disk; on boot the
process starts sealed and refuses secret operations until unsealed with Shamir shares.
Costs an operator step after every restart, defeats T2 completely. Default install uses a
key file with `0600` and a loud recommendation to move to KMS.

### 6.3 Delivery to a container

At deploy, `vestad` decrypts the bundle in memory and re-seals it to the **agent's**
X25519 public key (agent keypair generated at enrollment, private key in memory, never
written). The agent opens it in memory only — `mlock`ed where permitted, zeroed after use.
Then, per container:

**Default — tmpfs handoff.** A tmpfs mount at `/run/vesta/secrets` (memory-backed, mode
`0400`, container user). The agent writes the env file there. The image's entrypoint is
wrapped by `vesta-init` (a ~2 MB static binary bind-mounted read-only): it reads the file,
sets the variables in its own process environment, `unlink`s the file, then `exec`s the
real entrypoint as PID 1. Net result:

- `docker inspect` — no env vars, ever.
- Container config JSON on disk — no env vars.
- The tmpfs file — gone microseconds after start, and never touched the disk.
- The app — sees ordinary `process.env`. Zero application changes.

**Hardened — socket handoff.** No file at all. `vesta-init` fetches over a unix socket
bind-mounted into the container, authenticating with a single-use token; the agent checks
peer credentials against the container's PID namespace and revokes the token on first
read. Values exist only in the process's memory. For workloads where even a
microsecond-lived tmpfs file is unacceptable.

**Files, not env.** Secrets can also be declared as file mounts for apps that read
credentials from disk (`/run/vesta/secrets/db.pem`) — same tmpfs, kept for the lifetime of
the container.

### 6.4 API and access control

- Write is normal. **Read is a separate, audited privilege.** Roles: `use` (inject at
  deploy, cannot see), `read` (reveal plaintext), `write`, `manage` (rotate, delete).
  Developers ship code with secrets they cannot read — the ACL model carried over from the
  original Vesta spec, and the single most useful thing in it.
- `GET /secrets` returns names, versions, last-rotated, and who has revealed them. Never
  values. Revealing is `POST /secrets/{name}/reveal`, requires `read`, re-authentication
  for production environments, and writes an audit row naming actor, IP, time, and reason.
- Values are versioned. A release pins the secret versions it deployed with, so a rollback
  restores the config that actually worked.
- Rotation triggers a rolling restart of dependents, or a scheduled one, per policy.
- Build and deploy logs pass through a redaction filter seeded with the live values, so a
  secret echoed by a build script becomes `***`.
- `{{...}}` templating for cross-references (`{{services.postgres.url}}`,
  `{{secrets.stripe_key}}`) resolved at deploy time, never stored expanded.

---

## 7. Product model

```
Team
 └── Project                       billing/ownership boundary, quotas
      ├── App                      ONE object — code, build config, base spec
      │    ├── Environment: dev        overlay: replicas, resources, env, domains, secrets
      │    ├── Environment: staging    overlay
      │    ├── Environment: prod       overlay
      │    └── Environment: pr-482     ephemeral, TTL-reaped
      ├── Service                  managed Postgres/MySQL/Redis/Mongo/Clickhouse
      └── Resource                 volumes, backups, cron, one-shot jobs
```

**Config resolution:** `app base → environment overlay → release override`. The UI shows a
diff between any two environments — the question "what is actually different about
staging?" gets an answer instead of a guess.

**Promotion moves digests, not source.** `vesta promote api --from staging --to prod` takes
the exact image digest that passed staging and deploys it, carrying forward the release
notes and pinning prod's own secret versions. What you tested is what ships. Optional
approval gate on production targets.

**Preview environments:** a PR opens, an environment is created from a template overlay,
gets its own subdomain and its own secret set (with production values excluded by policy),
and is destroyed on merge or TTL.

**Feature surface for parity** — carried from the original Vesta spec and the Rust agent's
module list, which was already the right decomposition: builds, deployments, domains,
health, logs, exec, maintenance mode, backups, cron, deploy hooks, service links,
notifications, webhooks (HMAC-signed), audit, resource limits, team quotas, templates.

---

## 8. Repo layout

```
vesta/
├── cmd/
│   ├── vestad/          control plane (API + UI + scheduler + store)
│   ├── vesta-agent/     node agent
│   ├── vesta-proxy/     edge proxy
│   ├── vesta-init/      container entrypoint shim (static, tiny, no deps)
│   └── vesta/           CLI
├── internal/
│   ├── core/            domain types shared by CP and agent (Spec, AppSpec, RouteSpec…)
│   ├── api/             HTTP handlers, middleware, auth, websocket
│   ├── store/           sqlc queries, goose migrations, SQLite+Postgres
│   ├── secrets/         KEK/DEK envelope, sealing, ACL, reveal audit, redaction
│   ├── scheduler/       placement, resource accounting, spec generation
│   ├── reconcile/       agent-side converge loop
│   ├── dockerx/         Moby SDK wrapper: containers, networks, volumes, events
│   ├── build/           BuildKit driver, Dockerfile/Nixpacks/buildpack strategies
│   ├── proxycfg/        route model + unix-socket config protocol
│   ├── services/        managed databases, backups, cron
│   └── stream/          gRPC bidi transport, enrollment, mTLS
├── proto/               CP ↔ agent ↔ proxy contracts
├── ui/                  React + TS + Tailwind (embedded)
├── deploy/              install.sh, systemd units, compose for the CP itself
└── PLAN.md
```

Single Go module. `CGO_ENABLED=0`. `make build` produces five static binaries for
linux/amd64 and linux/arm64.

---

## 9. What we reuse

`vesta-kubernetes` is Go and already has the boring 40% built. The port is a fork of the
layers above the runtime, with the k8s reconciler swapped for a Docker one.

| From `vesta-kubernetes` | Action |
|---|---|
| `api/internal/handlers/*` (apps, projects, environments, secrets, teams, auth, audit, terminal, webhooks, github_app, templates) | Port. Rewrite the bodies that write CRDs to write specs. |
| `api/internal/crypto/aesgcm.go` | Keep verbatim. Already versioned-prefix AES-256-GCM; extend with DEK wrapping + AAD. |
| `api/internal/middleware`, `mfa`, `db/tokens.go`, `db/audit.go` | Port near-verbatim. |
| `api/internal/k8s/*` | **Delete.** Replaced by `internal/dockerx` + `internal/reconcile`. |
| `operator/` | **Delete.** Reconciliation moves into the agent. |
| `ui/` | Port. Add fleet view, replica view, environment diff, rollout progress. |
| `cli/` | Port. Add `server`, `scale`, `promote`, `secret reveal`. |

| From `vesta-old/` (Rust prototype) | Action |
|---|---|
| `apps/agent/src/{docker,proxy,secrets,health,builds,system,logs,exec,maintenance,backups,cron}` | Reimplement as Go packages. The module decomposition was right; the language wasn't. |
| `packages/db/src/entities/*` (30 TypeORM entities) | Translate to the sqlc schema. This is the fastest path to a complete data model. |
| `claude.md` security principles + secret ACL model | Carry forward wholesale. |
| NestJS API, Next.js web, BullMQ/Redis | **Retire.** |

`vesta-old/` is kept rather than deleted — the entity definitions and the spec are worth
grepping for a while. Nothing in it ships.

---

## 10. Milestones

Each milestone ends with something demonstrable, not a layer.

**M0 — Skeleton (week 1–2)**
Go module, five `cmd/` binaries, gRPC contracts, agent enrollment with mTLS, store with
migrations, `vesta server add` works end to end. Acceptance: a fresh VPS shows up in the
fleet view within 60 seconds of one curl command.

**M1 — Single container (week 3–4)**
Deploy a public image to one server, one replica. Reconciler, `dockerx`, health checks,
logs streaming, container exec. Proxy with certmagic terminating TLS on one route.
Acceptance: `vesta deploy nginx --domain x.example.com` serves HTTPS.

**M2 — Replicas and rollouts (week 5–6)** — *the differentiator*
Per-app networks, N replicas on one host, proxy load balancing with health ejection,
rolling deploy with drain, blue/green, automatic rollback. Acceptance: `replicas: 4` on a
single server, then a redeploy under continuous `hey` load with **zero** failed requests.

**M3 — Secrets (week 7–8)** — *the other differentiator*
Envelope encryption, KMS + sealed mode, per-agent sealing, `vesta-init` tmpfs handoff,
socket handoff, ACLs, reveal audit, log redaction, versioning and rotation. Acceptance:
deploy an app with 20 secrets; `docker inspect`, the on-disk container config, and a full
DB dump each yield zero plaintext; the app reads them from `process.env` unchanged.

**M4 — Environments (week 9–10)**
Overlays, inheritance, diff UI, promote-by-digest, approval gates, preview environments
with TTL. Acceptance: one app, three environments, promote staging→prod moves the digest
and nothing else.

**M5 — Builds and git (week 11–13)**
BuildKit integration with cache export, Dockerfile/Nixpacks/buildpack strategies, GitHub
App + GitLab/Gitea webhooks, push-to-deploy, build logs streaming, deploy hooks.
Acceptance: push to `main` → live in under 90 seconds warm.

**M6 — Services and operations (week 14–16)**
Managed Postgres/MySQL/Redis/Mongo, service links with template injection, encrypted
backups to S3-compatible storage with restore drills, cron jobs, one-shot jobs, resource
limits, quotas, notifications, maintenance mode.

**M7 — Fleet and polish (week 17–19)**
Multi-server placement and constraints, spread/binpack, proxy mesh and internal DNS
resolver, fleet dashboard, metrics, OTLP, audit UI, `install.sh`, docs, migration importer
that reads a Coolify install and produces Vesta projects/apps/environments.

Also **signed releases and agent auto-update** (ARCHITECTURE §17). This moved forward from
post-v1: the moment a fleet exists, hand-updating every node is untenable, and the frozen
update channel has to be in the protocol from the first release that ships to anyone —
retrofitting a recovery path into an already-deployed fleet means SSH-ing to every box,
which is the failure the agent exists to prevent. Acceptance: push a bad release to a
canary node and watch it revert itself and halt the rollout, with zero container restarts.

**Post-v1:** opt-in node failover, canary with metric gates, external secret stores
(Vault, AWS SM) as a `SecretProvider` backend, addon/template marketplace.

---

## 11. Risks

- **BuildKit is the heaviest dependency.** It wants a daemon. Mitigation: run `buildkitd`
  as a managed container per build server, treat it as an addon the agent supervises, and
  keep a "build elsewhere, deploy digest here" path for people who build in CI.
- **Writing our own proxy.** certmagic solves ACME; we still own HTTP/2, websockets, HTTP/3,
  connection draining, and the long tail. Mitigation: M1 ships a Caddy-admin-API driver
  behind the same `proxycfg` interface, so if the Go proxy slips we swap the driver without
  touching the reconciler. Decide by end of M2 based on the zero-downtime benchmark.
- **`vesta-init` is invasive.** Wrapping entrypoints breaks images with unusual `ENTRYPOINT`
  / `CMD` combinations, and confuses signal handling if done carelessly. Mitigation: it
  `exec`s (no extra process, no PID 1 substitution, signals go to the real app), it
  resolves the original entrypoint from the image manifest not from guessing, and there is
  a per-app escape hatch that falls back to plain env injection with a visible warning in
  the UI.
- **SQLite as the default store.** Fine for one control plane; wrong the moment someone
  wants two. Mitigation: repository interface from day one, Postgres tested in CI on every
  commit, and the docs say "Postgres for HA" without hedging.
- **Scope.** This document describes Coolify plus a real orchestrator plus a real secrets
  system. M2 and M3 are the product; everything else is table stakes that can slip. If a
  quarter has to be cut, cut M6 and M7, not M2 or M3.

---

## 12. Open questions

1. **Volume portability.** Node failover is meaningless without it. Do we require external
   storage (NFS/S3-backed) for failover-eligible stateful apps, or ship replicated volumes?
   Blocks the post-v1 failover work; does not block v1.
2. **Sealed mode ergonomics.** Requiring an unseal after every control-plane restart will
   annoy solo operators into disabling it. Is auto-unseal via a cloud KMS the real default,
   with Shamir as the paranoid option?
3. **Coolify importer fidelity.** Read-only import of apps and domains is achievable.
   Importing their secrets means asking users to paste plaintext once — is that acceptable
   as a one-time migration, with an immediate forced rotation prompt?
4. **Single-binary control plane vs. containerized.** Shipping `vestad` as a systemd unit
   is faster and lighter; shipping it as a container is what everyone expects. Probably
   both, with systemd as the documented default.
5. **Two editions, one name.** Naming is settled — this is Vesta, `vesta-kubernetes` is the
   Kubernetes edition — but the consequences are not. Open: does the Go module path become
   `getvesta.sh/vesta` (with the existing `kubernetes.getvesta.sh/*` left alone), do the two
   editions share a version number and release cadence or drift independently, and does the
   CLI stay a single `vesta` binary that detects its backend or ship as two? Recommendation:
   independent versions, one CLI with a `--context` that points at either control plane,
   since the verbs are identical by design.
