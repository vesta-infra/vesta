// Command vesta is the command-line interface.
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
		fmt.Println(version.String("vesta"))
		return
	}

	fmt.Fprintln(os.Stderr, version.String("vesta"))
	fmt.Fprintln(os.Stderr, "not implemented yet: the cli is M0 scaffolding")
	os.Exit(1)
}
