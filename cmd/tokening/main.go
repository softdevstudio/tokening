package main

import (
	"fmt"
	"io"
	"os"

	"github.com/softdevstudio/tokening/internal/policy"
	"github.com/softdevstudio/tokening/internal/vault"
	buildversion "github.com/softdevstudio/tokening/internal/version"
)

// version comes from internal/version, the one place it is written.
const version = buildversion.Version

func run(args []string, out, errOut io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "replay":
			return replayCommand(args[1:], out, errOut)
		case "flight":
			return flightCommand(args[1:], out, errOut)
		case "target", "template", "grant", "log":
			return adminCommand(args, out, errOut)
		case "doctor":
			if len(args) != 1 {
				return 2
			}
			return doctor(out)
		case "keygen":
			if len(args) != 1 {
				return 2
			}
			key, err := vault.GenerateKey()
			if err != nil {
				fmt.Fprintln(errOut, "Key generation failed.")
				return 1
			}
			fmt.Fprintln(out, key)
			return 0
		}
	}
	if len(args) > 0 && args[0] == "serve" {
		return serve(args[1:], out, errOut)
	}
	if len(args) == 2 && args[0] == "check" {
		_, warnings, err := policy.Load(args[1])
		if err != nil {
			fmt.Fprintln(errOut, "policy:", err)
			return 1
		}
		for _, warning := range warnings {
			fmt.Fprintln(errOut, "warning:", warning)
		}
		fmt.Fprintln(out, "Policy is valid.")
		return 0
	}
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
	fmt.Fprintln(out, "Commands: serve, check <policy.json>, target, template, grant, log, flight, replay, doctor, keygen, version, help")
	fmt.Fprintln(out, "Run tokening serve --help for listener options, tokening flight help for the flight recorder.")
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
