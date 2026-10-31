package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/softdevstudio/tokening/internal/policy"
	"github.com/softdevstudio/tokening/internal/store"
	"github.com/softdevstudio/tokening/internal/vault"
	"github.com/softdevstudio/tokening/internal/version"
)

// v0.1.4: serverInfo said 0.1.1 in every later release. Both the version the
// gateway shows agents and the one it sends upstream must be the build's.
func TestMCPReportsBuildVersion(t *testing.T) {
	var mu sync.Mutex
	clientVersion := ""
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			w.WriteHeader(204)
			return
		}
		data, _ := io.ReadAll(r.Body)
		var request struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
			Params struct {
				ClientInfo struct {
					Version string `json:"version"`
				} `json:"clientInfo"`
			} `json:"params"`
		}
		_ = json.Unmarshal(data, &request)
		var result any
		switch request.Method {
		case "initialize":
			mu.Lock()
			clientVersion = request.Params.ClientInfo.Version
			mu.Unlock()
			w.Header().Set("Mcp-Session-Id", "s")
			result = map[string]any{"protocolVersion": mcpVersion, "capabilities": map[string]any{}, "serverInfo": map[string]string{"name": "test", "version": "1"}}
		case "notifications/initialized":
			w.WriteHeader(202)
			return
		default:
			result = map[string]any{"content": []any{map[string]string{"type": "text", "text": "ok"}}}
		}
		w.Header().Set("Content-Type", "application/json")
		response, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
		_, _ = w.Write(response)
	}))
	defer backend.Close()
	ctx := context.Background()
	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	v, _ := vault.New(make([]byte, 32))
	p := policy.Policy{Targets: map[string]policy.Target{"wp": {Kind: "mcp_http", URL: backend.URL, Credential: policy.Credential{Type: "bearer", Ref: "vault:wp"}}}, Templates: map[string]policy.Template{"edit": {Target: "wp", Tool: "edit", MaxUses: 1, MaxTTL: "15m", Args: map[string]policy.Constraint{"id": {Bind: "required"}}}}}
	if err = s.ApplyPolicy(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err = s.SetCredential(ctx, "wp", v, []byte(`{"value":"upstream-private"}`)); err != nil {
		t.Fatal(err)
	}
	grant, err := s.IssueGrant(ctx, store.IssueRequest{Template: "edit", Uses: 1, TTL: time.Minute, Args: map[string]json.RawMessage{"id": json.RawMessage(`2`)}, IssuedTo: "bot", IssuedBy: "owner", Reason: "test"})
	if err != nil {
		t.Fatal(err)
	}
	g, _ := New(s, v, Options{})
	f := fixture{gateway: g, store: s, vault: v, grant: grant}

	w := f.serve(f.request("POST", "/mcp/wp", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	var reply struct {
		Result struct {
			ServerInfo struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"serverInfo"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil || w.Code != 200 {
		t.Fatalf("initialize: %d %s", w.Code, w.Body.String())
	}
	if reply.Result.ServerInfo.Name != "tokening" || reply.Result.ServerInfo.Version != version.Version {
		t.Fatalf("serverInfo %+v, want tokening %s", reply.Result.ServerInfo, version.Version)
	}

	w = f.serve(f.request("POST", "/mcp/wp", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"edit","arguments":{"id":2}}}`))
	if w.Code != 200 {
		t.Fatalf("call: %d %s", w.Code, w.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if clientVersion != version.Version {
		t.Fatalf("upstream clientInfo version %q, want %s", clientVersion, version.Version)
	}
}
