package core

import (
	"encoding/json"
	"fmt"
	"time"
)

// Duration is a time.Duration that marshals as a Go duration string ("30s", "5m") rather
// than a nanosecond integer. Specs are read by humans during incidents; "1500000000000"
// is not something anyone should have to decode at 3am.
type Duration time.Duration

func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d Duration) String() string { return time.Duration(d).String() }

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	// Accept both "30s" and a raw nanosecond count, so hand-edited specs and older
	// encodings both load rather than failing in a way that looks like corruption.
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("core: invalid duration %q: %w", s, err)
		}
		*d = Duration(parsed)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("core: duration must be a string or integer: %w", err)
	}
	*d = Duration(n)
	return nil
}
