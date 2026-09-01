// Package core holds the domain types shared by the control plane and the agent.
//
// The Spec is the contract between them: the control plane publishes what should be true
// on a host, and the agent makes it true. Nothing here imports a runtime, a database, or a
// transport — those layers depend on core, never the reverse.
//
// See ARCHITECTURE.md §3.
package core

import "time"

// Spec is the complete desired state of one host. It is a full state transfer, not a
// delta: the agent's job is to make its host look exactly like this and nothing more.
type Spec struct {
	Node     string         `json:"node"`
	Revision string         `json:"revision"`
	Issued   time.Time      `json:"issued"`
	Apps     []AppSpec      `json:"apps,omitempty"`
	Routes   []RouteSpec    `json:"routes,omitempty"`
	Bindings []PortBinding  `json:"bindings,omitempty"`
	Jobs     []JobSpec      `json:"jobs,omitempty"`
	Secrets  []SealedBundle `json:"secrets,omitempty"`
	Prune    PrunePolicy    `json:"prune"`
}

// AppSpec is one app-environment on this node: its image, its replica count, and
// everything that decides whether a running container still matches.
type AppSpec struct {
	ID  string `json:"id"`  // stable: app id + environment id
	App string `json:"app"` // human names, used for container naming and labels
	Env string `json:"env"`

	Release     string     `json:"release"`               // immutable identity of what is running
	Image       string     `json:"image"`                 // ALWAYS a digest: repo@sha256:…
	PullPolicy  PullPolicy `json:"pullPolicy"`            //
	RegistryRef string     `json:"registryRef,omitempty"` // Registry secret, resolved via scope chain

	Replicas   int      `json:"replicas"`
	Command    []string `json:"command,omitempty"`    // empty means use the image's
	Entrypoint []string `json:"entrypoint,omitempty"` // empty means use the image's
	WorkDir    string   `json:"workDir,omitempty"`
	User       string   `json:"user,omitempty"`

	// Env carries NON-SECRET configuration only. Secrets reach a container through
	// SecretRef and the sealed bundle; the spec generator draws them from different
	// tables and a validator rejects any Env value matching a known secret.
	EnvVars    map[string]string `json:"envVars,omitempty"`
	SecretRef  string            `json:"secretRef,omitempty"`
	SecretsVer int               `json:"secretsVer"`

	Resources Resources         `json:"resources"`
	Volumes   []VolumeMount     `json:"volumes,omitempty"`
	Networks  []string          `json:"networks,omitempty"`
	Ports     []Port            `json:"ports,omitempty"` // container-internal; never published
	Health    HealthSpec        `json:"health"`
	Rollout   RolloutSpec       `json:"rollout"`
	Logging   LoggingSpec       `json:"logging"`
	Labels    map[string]string `json:"labels,omitempty"` // user labels, merged under ours
	StopGrace Duration          `json:"stopGrace"`

	// SpecHash covers everything that requires replacing a container. Fields that can be
	// changed in place are excluded, so editing them does not trigger a rollout.
	SpecHash string `json:"specHash"`
}

type PullPolicy string

const (
	PullIfAbsent PullPolicy = "ifAbsent"
	PullAlways   PullPolicy = "always"
	PullNever    PullPolicy = "never"
)

type Resources struct {
	CPU       float64 `json:"cpu,omitempty"`       // cores
	MemoryMB  int64   `json:"memoryMB,omitempty"`  //
	PidsLimit int64   `json:"pidsLimit,omitempty"` //
}

type Port struct {
	Container int    `json:"container"`
	Proto     Proto  `json:"proto"`
	Name      string `json:"name,omitempty"`
}

type Proto string

const (
	TCP Proto = "tcp"
	UDP Proto = "udp"
)

type VolumeMount struct {
	Name       string       `json:"name"`
	Path       string       `json:"path"`
	PerReplica bool         `json:"perReplica,omitempty"` // expands to <name>_<replica>
	ReadOnly   bool         `json:"readOnly,omitempty"`
	Source     VolumeSource `json:"source"`
	Tier       VolumeTier   `json:"tier,omitempty"`
}

type VolumeSource string

const (
	VolumeNamed   VolumeSource = "named"
	VolumeHostDir VolumeSource = "hostPath"
	VolumeTmpfs   VolumeSource = "tmpfs"
)

// VolumeTier decides what failover is possible for a stateful workload (§16.1).
type VolumeTier string

const (
	TierLocal      VolumeTier = "local"
	TierReplicated VolumeTier = "replicated"
	TierShared     VolumeTier = "shared"
)

// HealthSpec carries three probes with deliberately different consequences: startup
// aborts a rollout, readiness gates proxy membership, liveness restarts. Collapsing
// readiness and liveness turns a slow dependency into a restart loop (§8.1).
type HealthSpec struct {
	Startup   *Probe `json:"startup,omitempty"`
	Readiness *Probe `json:"readiness,omitempty"`
	Liveness  *Probe `json:"liveness,omitempty"`
}

type Probe struct {
	Type             ProbeType `json:"type"`
	Path             string    `json:"path,omitempty"` // HTTP
	Port             int       `json:"port,omitempty"`
	Command          []string  `json:"command,omitempty"` // Exec
	Period           Duration  `json:"period"`
	Timeout          Duration  `json:"timeout"`
	SuccessThreshold int       `json:"successThreshold,omitempty"`
	FailureThreshold int       `json:"failureThreshold,omitempty"`
}

type ProbeType string

const (
	ProbeHTTP ProbeType = "http"
	ProbeTCP  ProbeType = "tcp"
	ProbeExec ProbeType = "exec"
)

type RolloutSpec struct {
	Strategy                RolloutStrategy `json:"strategy"`
	MaxSurge                int             `json:"maxSurge"`
	MaxUnavailable          int             `json:"maxUnavailable"`
	DrainSeconds            Duration        `json:"drainSeconds"`
	ProgressDeadlineSeconds Duration        `json:"progressDeadlineSeconds"`
	AutoRollback            bool            `json:"autoRollback"`
	KeepPreviousFor         Duration        `json:"keepPreviousFor,omitempty"` // blue/green
}

type RolloutStrategy string

const (
	RolloutRolling   RolloutStrategy = "rolling"
	RolloutBlueGreen RolloutStrategy = "blueGreen"
	RolloutCanary    RolloutStrategy = "canary"
	RolloutRecreate  RolloutStrategy = "recreate"
)

type LoggingSpec struct {
	Driver  string            `json:"driver,omitempty"` // "local" — never json-file unrotated
	Options map[string]string `json:"options,omitempty"`
}

// RouteSpec is an HTTP/HTTPS route. Upstreams are resolved by the agent from running
// replicas; the control plane names the app-environment, not container addresses.
type RouteSpec struct {
	Hosts      []string  `json:"hosts"`
	PathPrefix string    `json:"pathPrefix,omitempty"`
	AppSpecID  string    `json:"appSpecId"`
	Port       int       `json:"port"`
	TLS        TLSPolicy `json:"tls"`
	Internal   bool      `json:"internal,omitempty"` // static control-plane route (§2.4)
}

type TLSPolicy string

const (
	TLSAuto        TLSPolicy = "auto" // ACME
	TLSCustom      TLSPolicy = "custom"
	TLSPassthrough TLSPolicy = "passthrough"
	TLSOff         TLSPolicy = "off"
)

// PortBinding is a deliberate host-port allocation (§7.4). It is a separate object from
// AppSpec on purpose: bindings are registry-tracked and conflict-checked, so a bound port
// is never an accident of app config.
type PortBinding struct {
	ID         string    `json:"id"`
	AppSpecID  string    `json:"appSpecId"`
	Proto      Proto     `json:"proto"`
	HostIP     string    `json:"hostIP"` // never 0.0.0.0 by default
	HostPort   int       `json:"hostPort"`
	TargetPort int       `json:"targetPort"`
	Mode       BindMode  `json:"mode"`
	TLS        TLSPolicy `json:"tls,omitempty"`
	ProxyProto bool      `json:"proxyProto,omitempty"`
	AllowCIDR  []string  `json:"allowCIDR,omitempty"`
}

// BindMode decides whether replicas survive a host-port binding. Proxied keeps them by
// putting the proxy on the port; Direct publishes with Docker and is limited to one.
type BindMode string

const (
	BindProxied BindMode = "proxied"
	BindDirect  BindMode = "direct"
)

// JobSpec is run-to-completion work: cron, manual, deploy hooks, builds. The schedule is
// desired state; a run is an event in time (§13.2).
type JobSpec struct {
	ID  string `json:"id"`
	App string `json:"app"`
	Env string `json:"env"`

	Kind  JobKind  `json:"kind"`
	Scope JobScope `json:"scope"`

	Schedule string `json:"schedule,omitempty"` // cron expression, Kind == Cron
	Timezone string `json:"timezone,omitempty"` // IANA name, REQUIRED for Cron

	Image   string   `json:"image"` // digest, pinned at spec generation
	Command []string `json:"command,omitempty"`

	EnvVars    map[string]string `json:"envVars,omitempty"`
	SecretRef  string            `json:"secretRef,omitempty"`
	SecretsVer int               `json:"secretsVer"`

	Resources Resources     `json:"resources"` // mandatory — see §13.7
	Volumes   []VolumeMount `json:"volumes,omitempty"`
	Networks  []string      `json:"networks,omitempty"`

	Timeout       Duration          `json:"timeout"`
	Concurrency   ConcurrencyPolicy `json:"concurrency"`
	CatchUp       bool              `json:"catchUp"`
	CatchUpWindow Duration          `json:"catchUpWindow,omitempty"`
	Retries       int               `json:"retries,omitempty"`
	BackoffBase   Duration          `json:"backoffBase,omitempty"`
}

type JobKind string

const (
	JobCron       JobKind = "cron"
	JobManual     JobKind = "manual"
	JobPreDeploy  JobKind = "preDeploy"
	JobPostDeploy JobKind = "postDeploy"
	JobBuild      JobKind = "build"
)

type JobScope string

const (
	ScopeSingleNode JobScope = "singleNode"
	ScopeEveryNode  JobScope = "everyNode"
)

type ConcurrencyPolicy string

const (
	ConcurrencyForbid  ConcurrencyPolicy = "forbid"
	ConcurrencyAllow   ConcurrencyPolicy = "allow"
	ConcurrencyReplace ConcurrencyPolicy = "replace"
)

// SealedBundle is secret material sealed to this node's X25519 public key. It is opaque
// to everything but the agent that holds the matching private key — which is regenerated
// on every agent restart, so captured bundles do not outlive the process (§11.2).
type SealedBundle struct {
	ID        string `json:"id"`
	Version   int    `json:"version"`
	Alg       string `json:"alg"` // "x25519-xchacha20poly1305"
	Ephemeral []byte `json:"ephemeral"`
	Nonce     []byte `json:"nonce"`
	Payload   []byte `json:"payload"`
	AAD       []byte `json:"aad"` // node|app|env|version
}

// PrunePolicy bounds what the agent may delete when it finds managed objects with no
// corresponding spec. Objects without our label are never touched, regardless (§6.3).
type PrunePolicy struct {
	Containers bool `json:"containers"`
	Networks   bool `json:"networks"`
	Volumes    bool `json:"volumes"` // default false: data loss is unrecoverable
	Images     bool `json:"images"`
}
