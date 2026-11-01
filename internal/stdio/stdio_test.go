package stdio

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The test binary doubles as a fake stdio MCP server. Run with
// "-test.run=TestFakeServer -- fake MODE [ARG]".
func fakeArgs() (string, string, bool) {
	for i, a := range os.Args {
		if a == "fake" && i+1 < len(os.Args) {
			arg := ""
			if i+2 < len(os.Args) {
				arg = os.Args[i+2]
			}
			return os.Args[i+1], arg, true
		}
	}
	return "", "", false
}

func fake(mode string, arg ...string) []string {
	cmd := []string{os.Args[0], "-test.run=^TestFakeServer$", "--", "fake", mode}
	return append(cmd, arg...)
}

func TestFakeServer(t *testing.T) {
	mode, arg, ok := fakeArgs()
	if !ok {
		t.Skip("only runs as a fake MCP server")
	}
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	out := bufio.NewWriter(os.Stdout)
	write := func(v any) {
		b, _ := json.Marshal(v)
		out.Write(append(b, '\n'))
		out.Flush()
	}
	read := func() map[string]json.RawMessage {
		if !in.Scan() {
			os.Exit(0)
		}
		var m map[string]json.RawMessage
		json.Unmarshal(in.Bytes(), &m)
		return m
	}
	answer := func(id json.RawMessage, result any) {
		write(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	}
	text := func(s string) any {
		return map[string]any{"content": []any{map[string]string{"type": "text", "text": s}}}
	}
	switch mode {
	case "exit":
		read()
		os.Exit(3)
	case "garbage":
		read()
		fmt.Println("this is not JSON")
		time.Sleep(10 * time.Second)
	case "hang":
		read()
		time.Sleep(time.Minute)
	case "big":
		read()
		fmt.Println(`{"jsonrpc":"2.0","id":1,"result":{"x":"` + strings.Repeat("a", 1<<16) + `"}}`)
		time.Sleep(10 * time.Second)
	}
	init := read()
	if mode == "deaf" || mode == "flood" {
		// Answer initialize, then never read stdin again.
		write(map[string]any{"jsonrpc": "2.0", "id": init["id"], "result": map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}}})
		if mode == "flood" {
			for i := 0; ; i++ {
				write(map[string]any{"jsonrpc": "2.0", "id": i, "method": "roots/list"})
			}
		}
		time.Sleep(time.Minute)
	}
	version := `"2025-06-18"`
	if mode == "oldversion" {
		version = `"2023-01-01"`
	}
	write(map[string]any{"jsonrpc": "2.0", "id": init["id"], "result": map[string]any{"protocolVersion": json.RawMessage(version), "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]string{"name": "fake", "version": "1"}}})
	if n := read(); string(n["method"]) != `"notifications/initialized"` {
		os.Exit(4)
	}
	call := read()
	var params struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments"`
	}
	json.Unmarshal(call["params"], &params)
	switch mode {
	case "fs":
		// read_file within the root given as arg; anything else is an error.
		p := filepath.Join(arg, filepath.FromSlash(params.Arguments["path"]))
		b, err := os.ReadFile(p)
		if err != nil {
			answer(call["id"], map[string]any{"isError": true, "content": []any{map[string]string{"type": "text", "text": "no such file"}}})
		} else {
			answer(call["id"], text(string(b)))
		}
	case "env":
		var names []string
		for _, kv := range os.Environ() {
			n, _, _ := strings.Cut(kv, "=")
			names = append(names, n)
		}
		sort.Strings(names)
		answer(call["id"], text(strings.Join(names, ",")+"|"+os.Getenv("FAKE_TOKEN")))
	case "error":
		write(map[string]any{"jsonrpc": "2.0", "id": call["id"], "error": map[string]any{"code": -32602, "message": "unknown tool"}})
	case "asks":
		// A request and a notification of its own before the answer.
		write(map[string]any{"jsonrpc": "2.0", "method": "notifications/message", "params": map[string]any{"level": "info", "data": "hello"}})
		write(map[string]any{"jsonrpc": "2.0", "id": "srv-1", "method": "roots/list"})
		reply := read()
		var e struct {
			Error struct{ Code int } `json:"error"`
		}
		json.Unmarshal(reply["error"], &e.Error)
		answer(call["id"], text(fmt.Sprintf("reply %s %d", reply["id"], e.Error.Code)))
	case "wrongid":
		answer(json.RawMessage(`99`), text("x"))
	case "child":
		// Start a grandchild that sleeps, record its pid, then answer.
		c := fakeChild()
		os.WriteFile(arg, []byte(strconv.Itoa(c)), 0o600)
		answer(call["id"], text("ok"))
		time.Sleep(time.Minute)
	default:
		answer(call["id"], text("echo "+params.Name))
	}
	read() // wait for stdin to close
}

func call(t *testing.T, command []string, env map[string]string, timeout time.Duration) (string, error) {
	t.Helper()
	res, err := Call(context.Background(), Options{Command: command, Env: env, Timeout: timeout, MaxLine: 1 << 15, ClientVersion: "test"}, "read_file", map[string]json.RawMessage{"path": json.RawMessage(`"notes/todo.md"`)})
	if err != nil {
		return "", err
	}
	var r struct {
		IsError bool `json:"isError"`
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(res, &r); err != nil || len(r.Content) == 0 {
		t.Fatalf("result %s", res)
	}
	if r.IsError {
		return "ERROR " + r.Content[0].Text, nil
	}
	return r.Content[0].Text, nil
}

func TestCallReadsOneFile(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "notes"), 0o700)
	os.WriteFile(filepath.Join(root, "notes", "todo.md"), []byte("buy flour"), 0o600)
	got, err := call(t, fake("fs", root), nil, 20*time.Second)
	if err != nil || got != "buy flour" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestChildEnvironment(t *testing.T) {
	t.Setenv("TOKENING_VAULT_KEY", "vault-secret")
	t.Setenv("TOKENING_ADMIN_TOKEN", "admin-secret")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
	got, err := call(t, fake("env"), map[string]string{"FAKE_TOKEN": "ghp_test"}, 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	names, token, _ := strings.Cut(got, "|")
	if token != "ghp_test" {
		t.Errorf("credential variable not passed: %q", token)
	}
	for _, bad := range []string{"TOKENING_VAULT_KEY", "TOKENING_ADMIN_TOKEN", "AWS_SECRET_ACCESS_KEY"} {
		if strings.Contains(","+names+",", ","+bad+",") {
			t.Errorf("%s reached the server", bad)
		}
	}
	if !strings.Contains(strings.ToUpper(","+names+","), ",PATH,") {
		t.Errorf("PATH missing: %s", names)
	}
}

func TestCheckEnv(t *testing.T) {
	for _, bad := range []map[string]string{
		{"path": "x"}, {"PATH": "/tmp"}, {"Path": "x"}, {"HOME": "/"}, {"TOKENING_VAULT_KEY": "x"},
		{"1ABC": "x"}, {"A-B": "x"}, {"TOKEN": "a\x00b"}, {"BIG": strings.Repeat("x", MaxEnvBytes)},
	} {
		if CheckEnv(bad) == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	for _, ok := range []map[string]string{nil, {}, {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_x"}, {"DATABASE_URL": "postgres://u:p@h/db"}} {
		if err := CheckEnv(ok); err != nil {
			t.Errorf("%v: %v", ok, err)
		}
	}
}

func TestServerMisbehaviour(t *testing.T) {
	cases := []struct {
		mode string
		want error
	}{
		{"exit", ErrExited},
		{"garbage", ErrProtocol},
		{"hang", ErrTimeout},
		{"big", ErrTooLarge},
		{"oldversion", ErrProtocol},
		{"wrongid", ErrProtocol},
	}
	for _, c := range cases {
		start := time.Now()
		_, err := call(t, fake(c.mode), nil, 3*time.Second)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.mode, err, c.want)
		}
		if time.Since(start) > 8*time.Second {
			t.Errorf("%s took %v", c.mode, time.Since(start))
		}
	}
	_, err := call(t, fake("error"), nil, 10*time.Second)
	var rpcErr *RPCError
	if !errors.As(err, &rpcErr) || rpcErr.Code != -32602 {
		t.Errorf("error: %v", err)
	}
	if _, err := call(t, []string{filepath.Join(t.TempDir(), "no-such-server")}, nil, time.Second); !errors.Is(err, ErrStart) {
		t.Errorf("missing command: %v", err)
	}
}

// Requests from the server get "method not found"; notifications are skipped.
func TestServerRequests(t *testing.T) {
	got, err := call(t, fake("asks"), nil, 20*time.Second)
	if err != nil || got != `reply "srv-1" -32601` {
		t.Fatalf("%q %v", got, err)
	}
}

// Stopping the server also stops what it started.
func TestStopsChildren(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	if got, err := call(t, fake("child", pidFile), nil, 20*time.Second); err != nil || got != "ok" {
		t.Fatalf("%q %v", got, err)
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(string(b))
	deadline := time.Now().Add(5 * time.Second)
	for alive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("grandchild %d still running", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// A server that stops reading can't hold a call past its deadline: not
// with a large argument blocking the write, not by flooding requests that
// each need an answer.
func TestDeadlineWhileWriting(t *testing.T) {
	big := map[string]json.RawMessage{"content": json.RawMessage(`"` + strings.Repeat("x", 1<<20) + `"`)}
	for _, mode := range []string{"deaf", "flood"} {
		start := time.Now()
		_, err := Call(context.Background(), Options{Command: fake(mode), Timeout: 2 * time.Second}, "write_file", big)
		if !errors.Is(err, ErrTimeout) {
			t.Errorf("%s: %v", mode, err)
		}
		if d := time.Since(start); d > 6*time.Second {
			t.Errorf("%s: returned after %v", mode, d)
		}
	}
}

func TestReadLine(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader("short\n"+strings.Repeat("x", 100)+"\nlast"), 16)
	if l, err := readLine(r, 50); err != nil || string(l) != "short\n" {
		t.Fatalf("%q %v", l, err)
	}
	if _, err := readLine(r, 50); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("long line: %v", err)
	}
}

func TestParseCredential(t *testing.T) {
	got, err := ParseCredential([]byte(`{"env":{"GITHUB_PERSONAL_ACCESS_TOKEN":"ghp_x"}}`))
	if err != nil || got["GITHUB_PERSONAL_ACCESS_TOKEN"] != "ghp_x" {
		t.Fatalf("%v %v", got, err)
	}
	if got, err := ParseCredential([]byte(`{"env":{}}`)); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
	for _, bad := range []string{`{}`, `{"env":[]}`, `{"env":{"A":1}}`, `{"env":{"A":"x"},"x":1}`, `{"env":{"A":"x","A":"y"}}`, `{"env":{"PATH":"x"}}`, `[]`, `{"env":{"A":"x"}} {}`} {
		if _, err := ParseCredential([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
