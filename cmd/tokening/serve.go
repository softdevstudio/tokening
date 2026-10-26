package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"

	"github.com/softdevstudio/tokening/internal/server"
)

func serve(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(errOut)
	policy := flags.String("policy", "tokening.json", "policy file")
	db := flags.String("db", "tokening.db", "SQLite file in a private directory")
	key := flags.String("key-file", "", "vault key file, instead of TOKENING_VAULT_KEY")
	agent := flags.String("agent", "127.0.0.1:8080", "agent listener")
	admin := flags.String("admin", "127.0.0.1:8081", "admin listener, keep unreachable by agents")
	origins := flags.String("origins", "", "comma-separated allowed agent browser origins")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, terminationSignal())
	defer stop()
	reload := make(chan struct{}, 1)
	stopReload := watchReload(ctx, reload)
	defer stopReload()
	allowed := []string{}
	if *origins != "" {
		allowed = strings.Split(*origins, ",")
	}
	err := server.Run(ctx, server.Config{PolicyFile: *policy, Database: *db, KeyFile: *key, AdminToken: os.Getenv("TOKENING_ADMIN_TOKEN"), AgentAddress: *agent, AdminAddress: *admin, AllowedOrigins: allowed, Reload: reload, Logger: log.New(errOut, "tokening: ", log.LstdFlags)}, func(a, b string) { fmt.Fprintf(out, "Agent listener %s\nAdmin listener %s\n", a, b) })
	if err != nil {
		fmt.Fprintln(errOut, "serve:", err)
		return 1
	}
	return 0
}
