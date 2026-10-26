package main

import (
	"fmt"
	"io"
	"os"
)

const version = "0.1.0"

func run(args []string, out, errOut io.Writer) int {
	if len(args) == 1 {
		switch args[0] {
		case "version", "--version":
			fmt.Fprintln(out, "tokening", version)
			return 0
		case "help", "--help", "-h":
			usage(out)
			return 0
		}
	}
	if len(args) > 0 {
		fmt.Fprintln(errOut, "unknown command or arguments; run tokening help")
		return 2
	}
	usage(out)
	return 0
}

func usage(out io.Writer) {
	fmt.Fprintln(out, "Tokening: narrow permissions for AI agents.")
	fmt.Fprintln(out, "Usage: tokening <command>")
	fmt.Fprintln(out, "Commands: version, help")
	fmt.Fprintln(out, "Development build. The gateway and grant commands are not available yet.")
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
