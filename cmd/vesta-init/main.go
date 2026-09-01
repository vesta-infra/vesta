// Command vesta-init is the entrypoint shim that puts secrets into a container's
// environment without ever putting them into its Docker configuration.
//
// It is bind-mounted read-only into every managed container and invoked in place of the
// image's entrypoint, which the agent resolves from the image manifest and passes after
// `--`. The shim reads the sealed material the agent placed on a tmpfs, sets it in its own
// process environment, removes the file, and then execve()s the real entrypoint.
//
// Because it execve()s rather than forking, the application becomes PID 1 itself: signals
// reach it directly, its exit code is preserved, and no supervision behaviour changes. The
// shim is not present in the running container at all.
//
// See ARCHITECTURE.md §11.3 and §11.4.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"

	"getvesta.sh/internal/version"
)

// Distinctive exit codes. A container that fails here must be diagnosable without a
// shell, because the image may not have one — and must never be confused with the
// application's own failures.
const (
	exitNoCommand   = 120 // nothing to exec: the agent built the entrypoint wrong
	exitNoSecrets   = 121 // the secrets source was absent or unreadable
	exitBadSecrets  = 122 // the source was present but not parseable
	exitExecFailed  = 123 // the real entrypoint could not be executed
	exitBadArgument = 124
)

func main() {
	var (
		file       = flag.String("secrets-file", "", "path to the tmpfs secrets file written by the agent")
		socket     = flag.String("secrets-socket", "", "unix socket to request secrets from (hardened mode)")
		token      = flag.String("token", "", "single-use token presented on the socket")
		optional   = flag.Bool("optional", false, "start even if no secrets source is configured")
		timeout    = flag.Duration("timeout", 10*time.Second, "deadline for obtaining secrets")
		showVer    = flag.Bool("version", false, "print version and exit")
		flagErrOut = os.Stderr
	)
	flag.CommandLine.SetOutput(flagErrOut)
	flag.Parse()

	if *showVer {
		fmt.Println(version.String("vesta-init"))
		return
	}

	argv := flag.Args()
	if len(argv) == 0 {
		fatal(exitNoCommand, "no command to execute; expected `vesta-init [flags] -- <entrypoint> [args...]`")
	}

	secrets, err := load(*file, *socket, *token, *timeout)
	switch {
	case errors.Is(err, errNoSource):
		if !*optional {
			fatal(exitNoSecrets, "no secrets source configured and --optional was not set; "+
				"refusing to start with a half-populated environment")
		}
	case errors.Is(err, errUnreadable):
		fatal(exitNoSecrets, "secrets source could not be read: %v", err)
	case err != nil:
		fatal(exitBadSecrets, "secrets source could not be parsed: %v", err)
	}

	for k, v := range secrets {
		if err := os.Setenv(k, v); err != nil {
			fatal(exitBadSecrets, "setting %s: %v", k, err)
		}
	}
	// Overwrite the decoded values before they become garbage. Go's GC makes this a
	// best-effort gesture rather than a guarantee, but it shortens the window in which a
	// core dump would contain plaintext, and costs nothing.
	for k := range secrets {
		secrets[k] = ""
	}

	path, err := exec.LookPath(argv[0])
	if err != nil {
		fatal(exitExecFailed, "resolving %q: %v", argv[0], err)
	}
	// execve replaces this process. Nothing after this line runs on success, which is the
	// point: the application is PID 1, not a child of a supervisor we invented.
	if err := syscall.Exec(path, argv, os.Environ()); err != nil {
		fatal(exitExecFailed, "executing %q: %v", path, err)
	}
}

var (
	errNoSource   = errors.New("no secrets source configured")
	errUnreadable = errors.New("secrets source unreadable")
)

// load obtains the secret map from whichever source the agent configured.
//
// The payload is JSON rather than KEY=VALUE lines because secret values are routinely
// multi-line — a TLS private key or a service-account credential — and a line-oriented
// format either mangles them or needs an escaping convention that something will get
// wrong.
func load(file, socket, token string, timeout time.Duration) (map[string]string, error) {
	switch {
	case file != "":
		return loadFile(file)
	case socket != "":
		return loadSocket(socket, token, timeout)
	default:
		return nil, errNoSource
	}
}

func loadFile(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errUnreadable, err)
	}
	// Remove it immediately. The file lives on a memory-backed tmpfs the agent unmounts
	// once the container starts, but the window should be as close to zero as we can make
	// it: after this line the values exist only in this process.
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("removing %s after read: %w", path, err)
	}
	return parse(raw)
}

func loadSocket(path, token string, timeout time.Duration) (map[string]string, error) {
	if token == "" {
		return nil, fmt.Errorf("%w: socket mode requires --token", errUnreadable)
	}
	deadline := time.Now().Add(timeout)
	conn, err := net.DialTimeout("unix", path, time.Until(deadline))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errUnreadable, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)

	if _, err := io.WriteString(conn, token+"\n"); err != nil {
		return nil, fmt.Errorf("%w: presenting token: %v", errUnreadable, err)
	}
	raw, err := io.ReadAll(conn)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errUnreadable, err)
	}
	return parse(raw)
}

func parse(raw []byte) (map[string]string, error) {
	var out map[string]string
	if err := json.Unmarshal(raw, &out); err != nil {
		// Deliberately does not include the payload in the error: this message may be
		// written to a log, and the payload is the secret.
		return nil, fmt.Errorf("expected a JSON object of string values (%d bytes read)", len(raw))
	}
	for k := range out {
		if k == "" {
			return nil, errors.New("secret payload contains an empty variable name")
		}
	}
	return out, nil
}

func fatal(code int, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "vesta-init: "+format+"\n", args...)
	os.Exit(code)
}
