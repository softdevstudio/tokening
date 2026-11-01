package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/softdevstudio/tokening/internal/connect"
)

const connectUsage = `Usage: tokening connect URL

Relays an MCP client that launches servers as commands (Claude Desktop and
most local agents) to a Tokening gateway. URL is the gateway's MCP endpoint,
such as http://127.0.0.1:8080/mcp/fs. The grant secret comes from the
TOKENING_GRANT variable, never from the command line. Messages are read from
stdin and replies written to stdout, one JSON-RPC message per line; problems
reaching the gateway go to stderr.
`

func connectCommand(args []string, in io.Reader, out, errOut io.Writer) int {
	if len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h") {
		fmt.Fprint(out, connectUsage)
		return 0
	}
	if len(args) != 1 {
		fmt.Fprint(errOut, connectUsage)
		return 2
	}
	if err := connect.CheckURL(args[0]); err != nil {
		fmt.Fprintln(errOut, "tokening connect:", err)
		return 2
	}
	// Ctrl-C and the client closing stdin both end the relay; SIGINT keeps
	// its default action.
	err := connect.Run(context.Background(), connect.Options{URL: args[0], Grant: os.Getenv(connect.GrantEnv), Log: errOut}, in, out)
	if err != nil {
		fmt.Fprintln(errOut, "tokening connect:", err)
		return 2
	}
	return 0
}
