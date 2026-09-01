package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseAcceptsMultilineValues(t *testing.T) {
	// A TLS private key is the motivating case: any line-oriented format either mangles
	// this or needs an escaping convention something eventually gets wrong.
	key := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADAN\n-----END PRIVATE KEY-----\n"
	got, err := parse([]byte(`{"TLS_KEY":` + quote(key) + `,"PORT":"3000"}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got["TLS_KEY"] != key {
		t.Fatalf("multi-line value was altered:\n got %q\nwant %q", got["TLS_KEY"], key)
	}
	if got["PORT"] != "3000" {
		t.Fatalf("unexpected PORT %q", got["PORT"])
	}
}

// The parse error may be written to a log. If it echoed the payload, the shim would
// become the leak it exists to prevent.
func TestParseErrorNeverContainsThePayload(t *testing.T) {
	secret := "hunter2-do-not-log-this"
	_, err := parse([]byte(`{"API_KEY": "` + secret + `"`)) // truncated: invalid JSON
	if err == nil {
		t.Fatal("expected malformed JSON to fail")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("parse error leaked the payload: %v", err)
	}
}

func TestParseRejectsEmptyVariableName(t *testing.T) {
	if _, err := parse([]byte(`{"":"x"}`)); err == nil {
		t.Fatal("expected an empty variable name to be rejected")
	}
}

// The file is removed as soon as it is read, so the plaintext exists on the tmpfs for as
// close to zero time as we can arrange.
func TestLoadFileRemovesTheSourceAfterReading(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "env")
	if err := os.WriteFile(path, []byte(`{"A":"1"}`), 0o400); err != nil {
		t.Fatal(err)
	}
	got, err := loadFile(path)
	if err != nil {
		t.Fatalf("loadFile: %v", err)
	}
	if got["A"] != "1" {
		t.Fatalf("unexpected value %q", got["A"])
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("secrets file still present after being read")
	}
}

func TestLoadReportsMissingSourceDistinctly(t *testing.T) {
	// No source configured at all: the caller must be able to tell this apart from an
	// unreadable one, because only the former is legitimate under --optional.
	if _, err := load("", "", "", time.Second); !errors.Is(err, errNoSource) {
		t.Fatalf("expected errNoSource, got %v", err)
	}
	// Configured but absent: this is a failure regardless of --optional, because it
	// means the agent intended to supply secrets and something went wrong.
	_, err := load(filepath.Join(t.TempDir(), "absent"), "", "", time.Second)
	if !errors.Is(err, errUnreadable) {
		t.Fatalf("expected errUnreadable, got %v", err)
	}
}

func TestLoadSocketRequiresToken(t *testing.T) {
	if _, err := load("", "/tmp/nope.sock", "", time.Second); !errors.Is(err, errUnreadable) {
		t.Fatalf("socket mode without a token must fail, got %v", err)
	}
}

func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
