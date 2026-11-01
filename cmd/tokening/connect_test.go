package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConnectCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"connect", "--help"}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "TOKENING_GRANT") {
		t.Fatalf("help: %d %q", code, out.String())
	}
	for _, args := range [][]string{{"connect"}, {"connect", "http://127.0.0.1:1/http/fs"}, {"connect", "http://127.0.0.1:1/mcp/fs?grant=x"}, {"connect", "a", "b"}} {
		if code := run(args, &out, &errOut); code != 2 {
			t.Errorf("%v: %d", args, code)
		}
	}
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tkg_cli" {
			t.Error("grant not sent")
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"echo":` + string(body) + `}}`))
	}))
	defer gateway.Close()
	t.Setenv("TOKENING_GRANT", "tkg_cli")
	out.Reset()
	code := connectCommand([]string{gateway.URL + "/mcp/fs"}, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"), &out, &errOut)
	if code != 0 || !strings.Contains(out.String(), `"echo":{"jsonrpc":"2.0","id":1,"method":"ping"}`) {
		t.Fatalf("relay: %d %q %q", code, out.String(), errOut.String())
	}
	t.Setenv("TOKENING_GRANT", "")
	if code := connectCommand([]string{gateway.URL + "/mcp/fs"}, strings.NewReader(""), &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "TOKENING_GRANT") {
		t.Fatalf("no grant: %d %q", code, errOut.String())
	}
}
