package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/softdevstudio/tokening/internal/panel"
)

func replayCommand(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("replay", flag.ContinueOnError)
	flags.SetOutput(errOut)
	input := flags.String("input", "-", "schema-1 replay JSON file, or - for stdin")
	output := flags.String("output", "-", "new HTML file, or - for stdout")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return 2
	}
	var source io.Reader = os.Stdin
	if *input != "-" {
		file, err := os.Open(*input)
		if err != nil {
			fmt.Fprintln(errOut, "Could not open replay input.")
			return 1
		}
		defer file.Close()
		source = file
	}
	var result bytes.Buffer
	if err := panel.Export(source, &result); err != nil {
		fmt.Fprintln(errOut, "replay:", err)
		return 1
	}
	if *output == "-" {
		if _, err := io.Copy(out, &result); err != nil {
			fmt.Fprintln(errOut, "Could not write replay.")
			return 1
		}
		return 0
	}
	file, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		fmt.Fprintln(errOut, "Could not create replay output; existing files are never overwritten.")
		return 1
	}
	_, err = io.Copy(file, &result)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		_ = os.Remove(*output)
		fmt.Fprintln(errOut, "Could not write complete replay.")
		return 1
	}
	return 0
}
