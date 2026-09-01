package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// canonicalJSON renders v as JSON with object keys sorted and no insignificant
// whitespace, so that logically identical values always produce identical bytes.
//
// It deliberately round-trips through a generic decode rather than trusting struct field
// order: reordering or renaming a Go field must not change a hash, only changing the JSON
// shape may. Numbers are decoded as json.Number so large int64 values are not silently
// mangled into float64.
func canonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("core: encode: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("core: decode: %w", err)
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, generic); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			ks, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(ks)
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case json.Number:
		buf.WriteString(t.String())
	case string:
		s, err := json.Marshal(t)
		if err != nil {
			return err
		}
		buf.Write(s)
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case nil:
		buf.WriteString("null")
	default:
		return fmt.Errorf("core: cannot canonicalize %T", v)
	}
	return nil
}

func hashOf(v any) (string, error) {
	b, err := canonicalJSON(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ComputeRevision returns the revision for this Spec: the hash of its canonical encoding
// with Revision itself blanked, so the field can hold its own hash without circularity.
func (s Spec) ComputeRevision() (string, error) {
	s.Revision = ""
	return hashOf(s)
}

// SetRevision stamps the computed revision onto the Spec.
func (s *Spec) SetRevision() error {
	rev, err := s.ComputeRevision()
	if err != nil {
		return err
	}
	s.Revision = rev
	return nil
}

// appSpecIdentity is the projection of an AppSpec that decides whether a running
// container still matches the desired one. What is *absent* matters as much as what is
// present:
//
//   - Replicas is excluded. Scaling adds or removes containers; it must never mark the
//     existing ones as stale, or changing a replica count would recreate the whole set.
//   - SecretsVer is excluded. It is stamped as its own label and compared separately, so
//     rotating a secret restarts replicas without implying the image or config changed.
//   - Rollout and Health are excluded. They govern how we converge and how we probe, both
//     of which live in the agent, not in the container.
type appSpecIdentity struct {
	ID          string            `json:"id"`
	App         string            `json:"app"`
	Env         string            `json:"env"`
	Release     string            `json:"release"`
	Image       string            `json:"image"`
	PullPolicy  PullPolicy        `json:"pullPolicy"`
	RegistryRef string            `json:"registryRef"`
	Command     []string          `json:"command"`
	Entrypoint  []string          `json:"entrypoint"`
	WorkDir     string            `json:"workDir"`
	User        string            `json:"user"`
	EnvVars     map[string]string `json:"envVars"`
	SecretRef   string            `json:"secretRef"`
	Resources   Resources         `json:"resources"`
	Volumes     []VolumeMount     `json:"volumes"`
	Networks    []string          `json:"networks"`
	Ports       []Port            `json:"ports"`
	Logging     LoggingSpec       `json:"logging"`
	Labels      map[string]string `json:"labels"`
	StopGrace   Duration          `json:"stopGrace"`
}

// ComputeSpecHash returns the hash stamped onto containers as sh.getvesta.spec-hash.
// The agent compares this string rather than diffing against ContainerInspect output,
// because Docker normalizes and reorders what it is given (axiom 3).
func (a AppSpec) ComputeSpecHash() (string, error) {
	return hashOf(appSpecIdentity{
		ID:          a.ID,
		App:         a.App,
		Env:         a.Env,
		Release:     a.Release,
		Image:       a.Image,
		PullPolicy:  a.PullPolicy,
		RegistryRef: a.RegistryRef,
		Command:     a.Command,
		Entrypoint:  a.Entrypoint,
		WorkDir:     a.WorkDir,
		User:        a.User,
		EnvVars:     a.EnvVars,
		SecretRef:   a.SecretRef,
		Resources:   a.Resources,
		Volumes:     a.Volumes,
		Networks:    a.Networks,
		Ports:       a.Ports,
		Logging:     a.Logging,
		Labels:      a.Labels,
		StopGrace:   a.StopGrace,
	})
}

// SetSpecHash stamps the computed hash onto the AppSpec.
func (a *AppSpec) SetSpecHash() error {
	h, err := a.ComputeSpecHash()
	if err != nil {
		return err
	}
	a.SpecHash = h
	return nil
}

// Finalize stamps every AppSpec hash and then the Spec revision, in that order — the
// revision covers the stamped hashes, so it must be computed last.
func (s *Spec) Finalize() error {
	for i := range s.Apps {
		if err := s.Apps[i].SetSpecHash(); err != nil {
			return fmt.Errorf("core: app %s: %w", s.Apps[i].ID, err)
		}
	}
	return s.SetRevision()
}

// Validate enforces the rules the Spec is supposed to make unrepresentable but that Go's
// type system cannot. A Spec failing this must never reach an agent.
func (s Spec) Validate() error {
	var problems []string
	seenApp := map[string]bool{}
	for _, a := range s.Apps {
		if a.ID == "" {
			problems = append(problems, "app with empty ID")
			continue
		}
		if seenApp[a.ID] {
			problems = append(problems, fmt.Sprintf("app %s: duplicated in spec", a.ID))
		}
		seenApp[a.ID] = true

		// Invariant 3: an applied Spec always names an image by digest. A tag would
		// break the guarantee that a release is exactly reproducible.
		if !strings.Contains(a.Image, "@sha256:") {
			problems = append(problems, fmt.Sprintf("app %s: image %q is not digest-pinned", a.ID, a.Image))
		}
		if a.Replicas < 0 {
			problems = append(problems, fmt.Sprintf("app %s: negative replica count", a.ID))
		}
		// §7.2: a shared writable volume across replicas corrupts data silently.
		if a.Replicas > 1 {
			for _, v := range a.Volumes {
				if v.Source == VolumeNamed && !v.ReadOnly && !v.PerReplica {
					problems = append(problems, fmt.Sprintf(
						"app %s: volume %q is shared and writable across %d replicas; mark it perReplica or readOnly",
						a.ID, v.Name, a.Replicas))
				}
			}
		}
	}
	for _, j := range s.Jobs {
		// §13.4: an implicit timezone is wrong half the year and changes meaning when a
		// job is rescheduled to another host.
		if j.Kind == JobCron && j.Timezone == "" {
			problems = append(problems, fmt.Sprintf("job %s: cron schedule without a timezone", j.ID))
		}
		if j.Resources == (Resources{}) {
			problems = append(problems, fmt.Sprintf("job %s: resource limits are mandatory", j.ID))
		}
	}
	for _, b := range s.Bindings {
		// §7.4: the fallback is loopback, never every interface.
		if b.HostIP == "0.0.0.0" || b.HostIP == "::" {
			problems = append(problems, fmt.Sprintf(
				"binding %s: refusing implicit bind to all interfaces; set HostIP explicitly", b.ID))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("core: invalid spec:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}
