package core

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testApp() AppSpec {
	return AppSpec{
		ID:        "api:production",
		App:       "api",
		Env:       "production",
		Release:   "01J8",
		Image:     "ghcr.io/acme/api@sha256:" + strings.Repeat("a", 64),
		Replicas:  3,
		EnvVars:   map[string]string{"LOG_LEVEL": "info", "PORT": "3000"},
		Networks:  []string{"vesta_api_production"},
		Ports:     []Port{{Container: 3000, Proto: TCP}},
		Resources: Resources{CPU: 1, MemoryMB: 512},
		StopGrace: Duration(30 * time.Second),
	}
}

func mustHash(t *testing.T, a AppSpec) string {
	t.Helper()
	h, err := a.ComputeSpecHash()
	if err != nil {
		t.Fatalf("ComputeSpecHash: %v", err)
	}
	return h
}

func TestSpecHashIsDeterministic(t *testing.T) {
	a := testApp()
	first := mustHash(t, a)
	for i := 0; i < 50; i++ {
		if got := mustHash(t, a); got != first {
			t.Fatalf("hash not stable across calls: %s != %s", got, first)
		}
	}
}

// Map iteration order in Go is randomised, so a hash built from a map must be proven
// stable rather than assumed. This is the whole reason canonicalJSON sorts keys.
func TestSpecHashIgnoresMapOrder(t *testing.T) {
	a := testApp()
	a.EnvVars = map[string]string{"A": "1", "B": "2", "C": "3", "D": "4", "E": "5"}
	want := mustHash(t, a)

	b := testApp()
	b.EnvVars = map[string]string{"E": "5", "D": "4", "C": "3", "B": "2", "A": "1"}
	if got := mustHash(t, b); got != want {
		t.Fatalf("hash changed with map insertion order: %s != %s", got, want)
	}
}

// Scaling must not mark existing containers stale. If Replicas fed the hash, changing a
// replica count would recreate every running container instead of adding one — turning a
// scale-up into a full redeploy, which is exactly the failure this excludes.
func TestSpecHashIgnoresReplicaCount(t *testing.T) {
	a := testApp()
	a.Replicas = 1
	one := mustHash(t, a)
	a.Replicas = 40
	forty := mustHash(t, a)
	if one != forty {
		t.Fatalf("replica count changed the spec hash: scaling would recreate every container")
	}
}

// SecretsVer is compared through its own label so rotation restarts replicas without
// implying the image or configuration changed.
func TestSpecHashIgnoresSecretsVersion(t *testing.T) {
	a := testApp()
	a.SecretsVer = 1
	first := mustHash(t, a)
	a.SecretsVer = 99
	if second := mustHash(t, a); first != second {
		t.Fatal("secrets version leaked into the spec hash")
	}
}

// Rollout and health govern how the agent converges and probes; neither is baked into a
// container, so editing them must not trigger a rollout.
func TestSpecHashIgnoresRolloutAndHealth(t *testing.T) {
	a := testApp()
	base := mustHash(t, a)
	a.Rollout = RolloutSpec{Strategy: RolloutBlueGreen, MaxSurge: 4}
	a.Health = HealthSpec{Readiness: &Probe{Type: ProbeHTTP, Path: "/healthz"}}
	if got := mustHash(t, a); got != base {
		t.Fatal("rollout or health settings leaked into the spec hash")
	}
}

func TestSpecHashChangesForReplacementFields(t *testing.T) {
	base := mustHash(t, testApp())
	cases := map[string]func(*AppSpec){
		"image":      func(a *AppSpec) { a.Image = "ghcr.io/acme/api@sha256:" + strings.Repeat("b", 64) },
		"command":    func(a *AppSpec) { a.Command = []string{"/bin/other"} },
		"env value":  func(a *AppSpec) { a.EnvVars["LOG_LEVEL"] = "debug" },
		"env added":  func(a *AppSpec) { a.EnvVars["NEW"] = "1" },
		"resources":  func(a *AppSpec) { a.Resources.MemoryMB = 1024 },
		"user":       func(a *AppSpec) { a.User = "nobody" },
		"volume":     func(a *AppSpec) { a.Volumes = []VolumeMount{{Name: "data", Path: "/data"}} },
		"port":       func(a *AppSpec) { a.Ports = []Port{{Container: 8080, Proto: TCP}} },
		"stop grace": func(a *AppSpec) { a.StopGrace = Duration(90 * time.Second) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := testApp()
			mutate(&a)
			if got := mustHash(t, a); got == base {
				t.Fatalf("changing %s did not change the spec hash; the container would not be replaced", name)
			}
		})
	}
}

func TestRevisionExcludesItself(t *testing.T) {
	s := Spec{Node: "node-1", Issued: time.Unix(1700000000, 0).UTC(), Apps: []AppSpec{testApp()}}
	if err := s.Finalize(); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	stamped := s.Revision
	if stamped == "" {
		t.Fatal("revision was not stamped")
	}
	// Recomputing over the already-stamped Spec must reproduce the same value, or the
	// agent could never verify a revision it was sent.
	again, err := s.ComputeRevision()
	if err != nil {
		t.Fatalf("ComputeRevision: %v", err)
	}
	if again != stamped {
		t.Fatalf("revision is not self-consistent: %s != %s", again, stamped)
	}
}

func TestRevisionChangesWithContent(t *testing.T) {
	a := Spec{Node: "node-1", Apps: []AppSpec{testApp()}}
	b := a
	b.Apps = []AppSpec{testApp()}
	b.Apps[0].Replicas = 9

	if err := a.Finalize(); err != nil {
		t.Fatal(err)
	}
	if err := b.Finalize(); err != nil {
		t.Fatal(err)
	}
	// Replicas is excluded from the *container* hash but is still desired state, so the
	// Spec revision must change or the agent would never learn to scale.
	if a.Revision == b.Revision {
		t.Fatal("replica change did not alter the spec revision")
	}
}

func TestDurationRoundTrip(t *testing.T) {
	type holder struct {
		D Duration `json:"d"`
	}
	b, err := json.Marshal(holder{D: Duration(90 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"1m30s"`) {
		t.Fatalf("duration should marshal as a readable string, got %s", b)
	}
	var back holder
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.D.Duration() != 90*time.Second {
		t.Fatalf("round trip lost value: %v", back.D)
	}
	// Raw nanoseconds must still load, so older encodings do not read as corruption.
	if err := json.Unmarshal([]byte(`{"d":1500000000}`), &back); err != nil {
		t.Fatal(err)
	}
	if back.D.Duration() != 1500*time.Millisecond {
		t.Fatalf("integer form did not decode: %v", back.D)
	}
}

func TestValidateRejectsUnpinnedImage(t *testing.T) {
	a := testApp()
	a.Image = "ghcr.io/acme/api:latest"
	err := Spec{Apps: []AppSpec{a}}.Validate()
	if err == nil || !strings.Contains(err.Error(), "digest-pinned") {
		t.Fatalf("expected a digest-pinning failure, got %v", err)
	}
}

func TestValidateRejectsSharedWritableVolumeAcrossReplicas(t *testing.T) {
	a := testApp()
	a.Replicas = 3
	a.Volumes = []VolumeMount{{Name: "data", Path: "/data", Source: VolumeNamed}}
	err := Spec{Apps: []AppSpec{a}}.Validate()
	if err == nil || !strings.Contains(err.Error(), "shared and writable") {
		t.Fatalf("expected a shared-volume failure, got %v", err)
	}
	// The same volume is fine once it is per-replica.
	a.Volumes[0].PerReplica = true
	if err := (Spec{Apps: []AppSpec{a}}).Validate(); err != nil {
		t.Fatalf("per-replica volume should be accepted: %v", err)
	}
}

func TestValidateRejectsCronWithoutTimezone(t *testing.T) {
	s := Spec{Jobs: []JobSpec{{
		ID: "nightly", Kind: JobCron, Schedule: "0 3 * * *",
		Resources: Resources{CPU: 1, MemoryMB: 256},
	}}}
	err := s.Validate()
	if err == nil || !strings.Contains(err.Error(), "timezone") {
		t.Fatalf("expected a timezone failure, got %v", err)
	}
}

func TestValidateRejectsBindAllInterfaces(t *testing.T) {
	s := Spec{Bindings: []PortBinding{{ID: "pg", HostIP: "0.0.0.0", HostPort: 5432}}}
	err := s.Validate()
	if err == nil || !strings.Contains(err.Error(), "all interfaces") {
		t.Fatalf("expected a bind-address failure, got %v", err)
	}
}
