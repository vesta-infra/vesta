// Command vesta-proxy is the edge proxy: TLS termination, routing, and load balancing.
//
// M0 scaffold: this reports its identity and exits. See PLAN.md §10 for what lands here.
package main

import (
	"flag"
	"fmt"
	"os"

	"getvesta.sh/internal/version"
)

func main() {
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVer {
		fmt.Println(version.String("vesta-proxy"))
		return
	}

	fmt.Fprintln(os.Stderr, version.String("vesta-proxy"))
	fmt.Fprintln(os.Stderr, "not implemented yet: the proxy is M0 scaffolding")
	os.Exit(1)
}
