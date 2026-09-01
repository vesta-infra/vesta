// Command vesta-agent is the node agent: reconciles this host toward the Spec it is given.
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
		fmt.Println(version.String("vesta-agent"))
		return
	}

	fmt.Fprintln(os.Stderr, version.String("vesta-agent"))
	fmt.Fprintln(os.Stderr, "not implemented yet: the agent is M0 scaffolding")
	os.Exit(1)
}
