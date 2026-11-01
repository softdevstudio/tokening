package connect

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// gateway is a stand-in for Tokening's /mcp/fs endpoint.
func gateway(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tkg_test" {
			w.WriteHeader(401)
			w.Write([]byte(`{"code":"grant_unknown","reason":"No grant matches this token."}`))
			return
		}
		if r.URL.Path == "/mcp/moved" {
			http.Redirect(w, r, "http://example.com/", http.StatusFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		json.Unmarshal(body, &m)
		switch m.Method {
		case "notifications/initialized":
			w.WriteHeader(202)
		case "notifications/cancelled":
			w.WriteHeader(400)
			w.Write([]byte(`{"code":"invalid_request","reason":"Unsupported notification."}`))
		case "tools/list":
			w.Header().Set("Content-Type", "text/event-stream")
			w.Write([]byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":" + string(m.ID) + ",\n\n"))
			w.Write([]byte("data: \"result\":{\"tools\":[]}}\n\n"))
		case "resources/list":
			w.WriteHeader(403)
			w.Write([]byte(`{"code":"tool_not_allowed","reason":"This grant does not allow this MCP target."}`))
		default:
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("{\n  \"jsonrpc\": \"2.0\",\n  \"id\": " + string(m.ID) + ",\n  \"result\": {\"method\": \"" + m.Method + "\"}\n}"))
		}
	}))
}

func run(t *testing.T, url, grant, input string) []string {
	t.Helper()
	var out, log bytes.Buffer
	if err := Run(context.Background(), Options{URL: url, Grant: grant, Log: &log}, strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if out.Len() == 0 {
		lines = nil
	}
	sort.Strings(lines)
	return lines
}

func TestRelay(t *testing.T) {
	g := gateway(t)
	defer g.Close()
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		``,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":"three","method":"resources/list"}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_text_file"}}`,
	}, "\n")
	got := run(t, g.URL+"/mcp/fs", "tkg_test", input)
	want := []string{
		`{"error":{"code":-32001,"message":"Tokening refused (tool_not_allowed): This grant does not allow this MCP target."},"id":"three","jsonrpc":"2.0"}`,
		`{"jsonrpc":"2.0","id":1,"result":{"method":"initialize"}}`,
		`{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}`,
		`{"jsonrpc":"2.0","id":4,"result":{"method":"tools/call"}}`,
	}
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestRelayRefusalsAndFailures(t *testing.T) {
	g := gateway(t)
	got := run(t, g.URL+"/mcp/fs", "tkg_wrong", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	if len(got) != 1 || !strings.Contains(got[0], `"Tokening refused (grant_unknown): No grant matches this token."`) {
		t.Fatalf("unknown grant: %v", got)
	}
	got = run(t, g.URL+"/mcp/moved", "tkg_test", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	if len(got) != 1 || !strings.Contains(got[0], "answered HTTP 302") {
		t.Fatalf("redirect followed: %v", got)
	}
	url := g.URL
	g.Close()
	got = run(t, url+"/mcp/fs", "tkg_test", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`+"\n"+`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if len(got) != 1 || !strings.Contains(got[0], `"id":1`) || !strings.Contains(got[0], "could not be reached") {
		t.Fatalf("gateway down: %v", got)
	}
}

func TestRelayLargeMessage(t *testing.T) {
	g := gateway(t)
	defer g.Close()
	big := `{"jsonrpc":"2.0","id":9,"method":"x","params":{"p":"` + strings.Repeat("a", MaxMessage) + `"}}`
	got := run(t, g.URL+"/mcp/fs", "tkg_test", big+"\n"+`{"jsonrpc":"2.0","id":10,"method":"ping"}`)
	if len(got) != 2 || !strings.Contains(strings.Join(got, " "), "Message too large") || !strings.Contains(strings.Join(got, " "), `"id":10`) {
		t.Fatalf("%v", got)
	}
}

func TestCheckURLAndGrant(t *testing.T) {
	for _, bad := range []string{"", "ftp://h/mcp/fs", "http://h/http/fs", "http://h/mcp/", "http://h/mcp/a/b", "http://u:p@h/mcp/fs", "http://h/mcp/fs?grant=x", "http://h/mcp/fs#x", "http://gateway.example.com/mcp/fs", "http://10.0.0.5:8080/mcp/fs"} {
		if CheckURL(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	for _, ok := range []string{"http://127.0.0.1:8080/mcp/fs", "http://localhost:8080/mcp/fs", "http://[::1]:8080/mcp/fs", "https://gateway.example.com/mcp/fs"} {
		if err := CheckURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, grant := range []string{"", " ", "tkg x", "tkg\n"} {
		if Run(context.Background(), Options{URL: "http://127.0.0.1:1/mcp/fs", Grant: grant}, strings.NewReader(""), io.Discard) == nil {
			t.Errorf("accepted grant %q", grant)
		}
	}
}
