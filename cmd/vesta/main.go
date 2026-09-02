// Command vesta is the CLI. One binary addresses both editions through contexts
// (ARCHITECTURE §2.3); M0 implements the subset `vesta server add` needs.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"getvesta.sh/internal/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "vesta: %v\n", err)
		os.Exit(1)
	}
}

const usage = `vesta — self-hosted PaaS for Linux servers

Usage:
  vesta server add <name>     mint a join token and print the command to run on that server
  vesta server list           list the fleet
  vesta server remove <id>    remove a server; its certificate stops working immediately
  vesta version

Flags:
  --endpoint URL   control plane API (default $VESTA_API, http://127.0.0.1:8080)
  --token TOKEN    API token (default $VESTA_TOKEN)
`

func run(args []string) error {
	endpoint := envOr("VESTA_API", "http://127.0.0.1:8080")
	token := os.Getenv("VESTA_TOKEN")

	// Flags may appear before or after the subcommand, because both read naturally and
	// insisting on one order is a papercut every user hits once.
	var positional []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--endpoint":
			if i+1 >= len(args) {
				return fmt.Errorf("--endpoint needs a value")
			}
			endpoint, i = args[i+1], i+1
		case "--token":
			if i+1 >= len(args) {
				return fmt.Errorf("--token needs a value")
			}
			token, i = args[i+1], i+1
		case "-h", "--help":
			fmt.Print(usage)
			return nil
		default:
			positional = append(positional, args[i])
		}
	}

	if len(positional) == 0 {
		fmt.Print(usage)
		return nil
	}

	c := &client{endpoint: endpoint, token: token}

	switch positional[0] {
	case "version":
		fmt.Println(version.String("vesta"))
		return nil
	case "server":
		if len(positional) < 2 {
			return fmt.Errorf("usage: vesta server <add|list|remove>")
		}
		switch positional[1] {
		case "add":
			if len(positional) < 3 {
				return fmt.Errorf("usage: vesta server add <name>")
			}
			return c.serverAdd(positional[2])
		case "list":
			return c.serverList()
		case "remove":
			if len(positional) < 3 {
				return fmt.Errorf("usage: vesta server remove <id>")
			}
			return c.serverRemove(positional[2])
		default:
			return fmt.Errorf("unknown subcommand %q", positional[1])
		}
	default:
		return fmt.Errorf("unknown command %q", positional[0])
	}
}

type client struct {
	endpoint string
	token    string
}

func (c *client) do(method, path string, body any, out any) error {
	if c.token == "" {
		return fmt.Errorf("no API token: pass --token or set VESTA_TOKEN (vestad prints one at first start)")
	}
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("contacting %s: %w", c.endpoint, err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))

	if res.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = res.Status
		}
		return fmt.Errorf("%s", e.Error)
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func (c *client) serverAdd(name string) error {
	var resp struct {
		Token         string `json:"token"`
		Endpoint      string `json:"endpoint"`
		CAFingerprint string `json:"caFingerprint"`
		ExpiresAt     string `json:"expiresAt"`
		Command       string `json:"command"`
	}
	if err := c.do(http.MethodPost, "/v1/servers", map[string]string{"name": name}, &resp); err != nil {
		return err
	}
	fmt.Printf("\nRun this on %s:\n\n  %s\n\n", name, resp.Command)
	fmt.Printf("The token is single-use and expires at %s. It is shown once.\n\n", resp.ExpiresAt)
	return nil
}

func (c *client) serverList() error {
	var resp struct {
		Servers []struct {
			ID              string `json:"id"`
			Name            string `json:"name"`
			Status          string `json:"status"`
			Arch            string `json:"arch"`
			Version         string `json:"version"`
			AppliedRevision string `json:"appliedRevision"`
			LastSeen        string `json:"lastSeen"`
		} `json:"servers"`
	}
	if err := c.do(http.MethodGet, "/v1/servers", nil, &resp); err != nil {
		return err
	}
	if len(resp.Servers) == 0 {
		fmt.Println("No servers yet. Add one with: vesta server add <name>")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tSTATUS\tARCH\tVERSION\tLAST SEEN\tID")
	for _, s := range resp.Servers {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			s.Name, s.Status, dash(s.Arch), dash(s.Version), dash(s.LastSeen), s.ID)
	}
	return w.Flush()
}

func (c *client) serverRemove(id string) error {
	if err := c.do(http.MethodDelete, "/v1/servers/"+id, nil, nil); err != nil {
		return err
	}
	fmt.Printf("Removed %s. Its certificate stops working at its next connection.\n", id)
	return nil
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
