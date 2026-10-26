package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/softdevstudio/tokening/internal/vault"
)

type bindings map[string]json.RawMessage

func (b bindings) String() string { return "JSON bindings" }
func (b bindings) Set(value string) error {
	name, raw, ok := strings.Cut(value, "=")
	if !ok || name == "" || !json.Valid([]byte(raw)) {
		return errors.New("binding must be name=JSON")
	}
	if _, exists := b[name]; exists {
		return errors.New("binding name is repeated")
	}
	b[name] = json.RawMessage(raw)
	return nil
}
func adminCommand(args []string, out, errOut io.Writer) int {
	fail := func(message string) int { fmt.Fprintln(errOut, message); return 2 }
	method, path := "GET", ""
	var body any
	follow := false
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(errOut)
	switch args[0] {
	case "template":
		if len(args) != 2 || args[1] != "list" {
			return fail("Usage: tokening template list")
		}
		path = "/admin/templates"
	case "target":
		if len(args) < 3 || args[1] != "add" {
			return fail("Usage: tokening target add <name> --cred-file <file>")
		}
		file := flags.String("cred-file", "", "credential JSON file")
		if flags.Parse(args[3:]) != nil || flags.NArg() != 0 || *file == "" {
			return 2
		}
		f, err := os.Open(*file)
		if err != nil {
			return fail("Cannot open credential file.")
		}
		plain, err := io.ReadAll(io.LimitReader(f, vault.MaxCredentialBytes+1))
		f.Close()
		defer clear(plain)
		if err != nil || len(plain) > vault.MaxCredentialBytes || !json.Valid(plain) {
			return fail("Credential must be a JSON object of at most 64 KiB.")
		}
		method, path = "POST", "/admin/targets"
		body = map[string]any{"name": args[2], "credential": json.RawMessage(plain)}
	case "grant":
		if len(args) < 3 {
			return fail("Usage: tokening grant issue|inspect|revoke <name> [flags]")
		}
		switch args[1] {
		case "inspect":
			if len(args) != 3 {
				return fail("Usage: tokening grant inspect <id>")
			}
			path = "/admin/grants/" + url.PathEscape(args[2])
		case "revoke":
			by := flags.String("by", "operator", "operator name")
			if flags.Parse(args[3:]) != nil || flags.NArg() != 0 {
				return 2
			}
			method, path = "POST", "/admin/grants/"+url.PathEscape(args[2])+"/revoke"
			body = map[string]string{"actor": *by}
		case "issue":
			uses := flags.Int("uses", 1, "use limit")
			ttl := flags.String("ttl", "15m", "time to live")
			to := flags.String("to", "", "agent name")
			reason := flags.String("reason", "", "reason for grant")
			by := flags.String("by", "operator", "operator name")
			argsBound, queryBound := bindings{}, bindings{}
			flags.Var(argsBound, "bind", "name=JSON argument binding, repeatable")
			flags.Var(queryBound, "query-bind", "name=JSON query binding, repeatable")
			if flags.Parse(args[3:]) != nil || flags.NArg() != 0 {
				return 2
			}
			method, path = "POST", "/admin/grants"
			body = map[string]any{"template": args[2], "uses": *uses, "ttl": *ttl, "issued_to": *to, "reason": *reason, "issued_by": *by, "args": argsBound, "query": queryBound}
		default:
			return fail("Unknown grant command.")
		}
	case "log":
		export := flags.Bool("export", false, "export JSONL")
		live := flags.Bool("follow", false, "follow decisions as SSE")
		since := flags.Int64("since", 0, "exclusive record ID")
		grant := flags.String("grant", "", "filter grant ID")
		if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *since < 0 || (*export && *live) {
			return fail("Use log [--export | --follow] [--since ID] [--grant ID].")
		}
		path = "/admin/decisions"
		if *export {
			path += ".jsonl"
		}
		query := url.Values{"since": {fmt.Sprint(*since)}}
		if *grant != "" {
			query.Set("grant", *grant)
		}
		follow = *live
		if follow {
			query.Set("follow", "true")
		}
		path += "?" + query.Encode()
	default:
		return fail("Unknown admin command.")
	}
	base := os.Getenv("TOKENING_ADMIN_URL")
	if base == "" {
		base = "http://127.0.0.1:8081"
	}
	address, err := url.Parse(base)
	if err != nil || address.Host == "" || address.User != nil || address.RawQuery != "" || address.Fragment != "" || address.Path != "" || (address.Scheme != "http" && address.Scheme != "https") {
		return fail("TOKENING_ADMIN_URL must be an HTTP(S) origin.")
	}
	token := os.Getenv("TOKENING_ADMIN_TOKEN")
	if token == "" {
		return fail("Set TOKENING_ADMIN_TOKEN for the admin client.")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, terminationSignal())
	defer stop()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fail("Could not encode request.")
		}
		defer clear(data)
		reader = io.NopCloser(bytes.NewReader(data))
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, reader)
	if err != nil {
		return fail("Could not build admin request.")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	transport := &http.Transport{DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, TLSHandshakeTimeout: 10 * time.Second, Proxy: nil, DisableKeepAlives: true, ResponseHeaderTimeout: 10 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if !follow {
		client.Timeout = 30 * time.Second
	}
	res, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(errOut, "Admin request failed. No request was retried; inspect state before issuing again.")
		return 1
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		fmt.Fprintf(errOut, "Admin HTTP %d: %s", res.StatusCode, data)
		return 1
	}
	if _, err = io.Copy(out, res.Body); err != nil && ctx.Err() == nil {
		fmt.Fprintln(errOut, "Admin response was interrupted. No request was retried.")
		return 1
	}
	if strings.HasPrefix(path, "/admin/decisions.jsonl") && res.Trailer.Get("Tokening-Export-Complete") != "true" {
		fmt.Fprintln(errOut, "Audit export is incomplete; resume from the last complete record.")
		return 1
	}
	return 0
}
func doctor(out io.Writer) int {
	names := []string{"TOKENING_VAULT_KEY", "TOKENING_ADMIN_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "GH_TOKEN", "WP_APPLICATION_PASSWORD"}
	found := false
	for _, name := range names {
		if value := os.Getenv(name); value != "" {
			fmt.Fprintf(out, "Visible credential environment variable: %s\n", name)
			found = true
		}
	}
	fmt.Fprintln(out, "Run doctor in the agent's environment. It cannot inspect another process or detect every credential name.")
	if found {
		return 1
	}
	return 0
}
