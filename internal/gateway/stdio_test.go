package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/softdevstudio/tokening/internal/policy"
	"github.com/softdevstudio/tokening/internal/store"
	"github.com/softdevstudio/tokening/internal/vault"
)

// The gateway's test binary doubles as a stdio MCP filesystem server, run as
// "-test.run=^TestFakeFilesystemServer$ -- fakefs LOGFILE". It reads any
// file it is asked for and appends each path it opened to LOGFILE, so a
// test can see which files the server was ever asked to read.
func TestFakeFilesystemServer(t *testing.T) {
	logFile := ""
	for i, a := range os.Args {
		if a == "fakefs" && i+1 < len(os.Args) {
			logFile = os.Args[i+1]
		}
	}
	if logFile == "" {
		t.Skip("only runs as a fake stdio MCP server")
	}
	in := bufio.NewScanner(os.Stdin)
	write := func(v any) {
		b, _ := json.Marshal(v)
		os.Stdout.Write(append(b, '\n'))
	}
	for in.Scan() {
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name      string `json:"name"`
				Arguments struct {
					Path string `json:"path"`
				} `json:"arguments"`
			} `json:"params"`
		}
		json.Unmarshal(in.Bytes(), &m)
		switch m.Method {
		case "initialize":
			write(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]string{"name": "fakefs", "version": "1"}}})
		case "tools/call":
			f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
			fmt.Fprintf(f, "%s %s token=%s vault=%s\n", m.Params.Name, m.Params.Arguments.Path, os.Getenv("FAKE_TOKEN"), os.Getenv("TOKENING_VAULT_KEY"))
			f.Close()
			b, err := os.ReadFile(m.Params.Arguments.Path)
			if err != nil {
				write(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{"isError": true, "content": []any{map[string]string{"type": "text", "text": "no such file"}}}})
			} else {
				write(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{"content": []any{map[string]string{"type": "text", "text": string(b)}}}})
			}
		}
	}
}

// A grant bound to one file reaches that file and no other: the other file,
// a path that walks out of the folder, an extra argument and another tool
// are refused before the server is even started.
func TestStdioSingleFileGrant(t *testing.T) {
	for _, withCredential := range []bool{true, false} {
		t.Run(fmt.Sprintf("credential=%v", withCredential), func(t *testing.T) {
			t.Setenv("TOKENING_VAULT_KEY", "must-not-reach-the-server")
			dir := t.TempDir()
			notes := filepath.Join(dir, "notes")
			os.MkdirAll(notes, 0o700)
			todo := filepath.Join(notes, "todo.md")
			secret := filepath.Join(notes, "passwords.md")
			os.WriteFile(todo, []byte("buy flour"), 0o600)
			os.WriteFile(secret, []byte("hunter2"), 0o600)
			logFile := filepath.Join(dir, "calls.log")

			ctx := context.Background()
			s, err := store.Open(ctx, filepath.Join(t.TempDir(), "db"))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			v, _ := vault.New(make([]byte, 32))
			command := []string{os.Args[0], "-test.run=^TestFakeFilesystemServer$", "--", "fakefs", logFile}
			p := policy.Policy{
				Targets: map[string]policy.Target{"fs": {Kind: "mcp_stdio", Command: command, Credential: policy.Credential{Type: "env", Ref: "vault:fs"}}},
				Templates: map[string]policy.Template{"fs.read-one-file": {Target: "fs", Tool: "read_text_file", MaxUses: 2, MaxTTL: "15m",
					Args: map[string]policy.Constraint{"path": {Bind: "required"}}}},
			}
			if err = s.ApplyPolicy(ctx, p); err != nil {
				t.Fatal(err)
			}
			if withCredential {
				if err := ValidateCredential("env", []byte(`{"env":{"FAKE_TOKEN":"fs-token"}}`)); err != nil {
					t.Fatal(err)
				}
				if err = s.SetCredential(ctx, "fs", v, []byte(`{"env":{"FAKE_TOKEN":"fs-token"}}`)); err != nil {
					t.Fatal(err)
				}
			}
			bound, _ := json.Marshal(todo)
			grant, err := s.IssueGrant(ctx, store.IssueRequest{Template: "fs.read-one-file", Uses: 2, TTL: time.Minute, Args: map[string]json.RawMessage{"path": bound}, IssuedTo: "desktop", IssuedBy: "owner", Reason: "test"})
			if err != nil {
				t.Fatal(err)
			}
			g, _ := New(s, v, Options{})
			f := fixture{gateway: g, store: s, vault: v, grant: grant}
			call := func(tool string, args map[string]string) string {
				a, _ := json.Marshal(args)
				body := fmt.Sprintf(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, tool, a)
				return f.serve(f.request("POST", "/mcp/fs", body)).Body.String()
			}

			for _, attempt := range []struct {
				tool string
				args map[string]string
			}{
				{"read_text_file", map[string]string{"path": secret}},
				{"read_text_file", map[string]string{"path": notes + string(filepath.Separator) + ".." + string(filepath.Separator) + "notes" + string(filepath.Separator) + "passwords.md"}},
				{"read_text_file", map[string]string{"path": todo + string(filepath.Separator) + ".." + string(filepath.Separator) + "passwords.md"}},
				{"read_text_file", map[string]string{"path": todo, "head": "1"}},
				{"write_file", map[string]string{"path": todo}},
				{"read_text_file", map[string]string{}},
			} {
				out := call(attempt.tool, attempt.args)
				if !strings.Contains(out, `"isError":true`) || strings.Contains(out, "hunter2") {
					t.Fatalf("%v: %s", attempt, out)
				}
			}
			if _, err := os.Stat(logFile); !os.IsNotExist(err) {
				t.Fatal("a refused call started the server")
			}
			if f.info(t).UsesLeft != 2 {
				t.Fatal("a refused call used the grant")
			}

			out := call("read_text_file", map[string]string{"path": todo})
			if !strings.Contains(out, "buy flour") || strings.Contains(out, `"isError":true`) {
				t.Fatalf("allowed call: %s", out)
			}
			log, _ := os.ReadFile(logFile)
			want := "read_text_file " + todo + " token="
			if withCredential {
				want += "fs-token"
			}
			want += " vault=\n"
			if string(log) != want {
				t.Fatalf("server saw %q, want %q", log, want)
			}
			if f.info(t).UsesLeft != 1 {
				t.Fatal("allowed call did not use the grant")
			}

			// tools/list shows only the granted tool; another target is refused.
			list := f.serve(f.request("POST", "/mcp/fs", `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)).Body.String()
			if !strings.Contains(list, `"name":"read_text_file"`) || strings.Contains(list, "write_file") {
				t.Fatalf("tools/list: %s", list)
			}
			if w := f.serve(f.request("POST", "/mcp/other", `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)); w.Code != 403 {
				t.Fatalf("other target: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

// A server that can't be started fails the call and keeps the use spent,
// the same as an HTTP upstream that is down.
func TestStdioServerMissing(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	v, _ := vault.New(make([]byte, 32))
	p := policy.Policy{
		Targets:   map[string]policy.Target{"fs": {Kind: "mcp_stdio", Command: []string{filepath.Join(t.TempDir(), "no-such-server")}, Credential: policy.Credential{Type: "env", Ref: "vault:fs"}}},
		Templates: map[string]policy.Template{"fs.read": {Target: "fs", Tool: "read_text_file", MaxUses: 1, MaxTTL: "15m", Args: map[string]policy.Constraint{"path": {Type: "string"}}}},
	}
	if err = s.ApplyPolicy(ctx, p); err != nil {
		t.Fatal(err)
	}
	grant, err := s.IssueGrant(ctx, store.IssueRequest{Template: "fs.read", Uses: 1, TTL: time.Minute, IssuedTo: "desktop", IssuedBy: "owner", Reason: "test"})
	if err != nil {
		t.Fatal(err)
	}
	g, _ := New(s, v, Options{})
	f := fixture{gateway: g, store: s, vault: v, grant: grant}
	out := f.serve(f.request("POST", "/mcp/fs", `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"x"}}}`)).Body.String()
	if !strings.Contains(out, "Upstream MCP request failed. The use remains consumed.") {
		t.Fatalf("%s", out)
	}
	if f.info(t).UsesLeft != 0 {
		t.Fatal("use refunded")
	}
}

func TestValidateEnvCredential(t *testing.T) {
	for _, ok := range []string{`{"env":{}}`, `{"env":{"GITHUB_PERSONAL_ACCESS_TOKEN":"ghp_x"}}`} {
		if err := ValidateCredential("env", []byte(ok)); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{`{"value":"x"}`, `{"env":{"TOKENING_VAULT_KEY":"x"}}`, `{"env":{"PATH":"/tmp"}}`} {
		if ValidateCredential("env", []byte(bad)) == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
