package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/softdevstudio/tokening/internal/policy"
	"github.com/softdevstudio/tokening/internal/store"
	"github.com/softdevstudio/tokening/internal/vault"
)

func TestMCPScopedCall(t *testing.T) {
	for _, profile := range []struct {
		sse     bool
		version string
	}{{false, mcpVersion}, {true, mcpVersion}, {false, "2025-11-25"}, {true, "2025-11-25"}} {
		t.Run(fmt.Sprint(profile), func(t *testing.T) {
			sse := profile.sse
			var writes atomic.Int32
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer upstream-private" || r.Header.Get("Cookie") != "" {
					t.Error("credential boundary")
				}
				if r.Header.Get("MCP-Protocol-Version") != "2025-11-25" && r.Header.Get("MCP-Protocol-Version") != profile.version {
					t.Error("unsupported wire version")
				}
				if r.Method == "DELETE" {
					w.WriteHeader(204)
					return
				}
				data, _ := io.ReadAll(r.Body)
				var request struct {
					ID     int                        `json:"id"`
					Method string                     `json:"method"`
					Params map[string]json.RawMessage `json:"params"`
				}
				if json.Unmarshal(data, &request) != nil {
					t.Error("invalid request")
				}
				if request.Method != "initialize" && r.Header.Get("MCP-Protocol-Version") != profile.version {
					t.Error("negotiated version not used")
				}
				if request.Method != "initialize" && r.Header.Get("Mcp-Session-Id") != "private-session" {
					t.Error("missing private session")
				}
				var result any
				switch request.Method {
				case "initialize":
					w.Header().Set("Mcp-Session-Id", "private-session")
					result = map[string]any{"protocolVersion": profile.version, "capabilities": map[string]any{}, "serverInfo": map[string]string{"name": "test", "version": "1"}}
				case "notifications/initialized":
					w.WriteHeader(202)
					return
				case "tools/call":
					writes.Add(1)
					if string(request.Params["name"]) != `"edit"` || !strings.Contains(string(request.Params["arguments"]), `"id":2`) {
						t.Error("call changed")
					}
					result = map[string]any{"content": []any{map[string]string{"type": "text", "text": "updated"}}}
				default:
					t.Error("unexpected upstream method")
				}
				response, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
				if sse {
					w.Header().Set("Content-Type", "text/event-stream")
					fmt.Fprintf(w, "event: message\ndata: %s\n\n", response)
				} else {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(response)
				}
			}))
			defer backend.Close()
			ctx := context.Background()
			s, err := store.Open(ctx, filepath.Join(t.TempDir(), "db"))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			v, _ := vault.New(make([]byte, 32))
			p := policy.Policy{Targets: map[string]policy.Target{"wp": {Kind: "mcp_http", URL: backend.URL, Credential: policy.Credential{Type: "bearer", Ref: "vault:wp"}}}, Templates: map[string]policy.Template{"edit": {Target: "wp", Tool: "edit", MaxUses: 1, MaxTTL: "15m", Args: map[string]policy.Constraint{"id": {Bind: "required"}, "title": {Type: "string"}}}}}
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
			for _, method := range []string{"initialize", "tools/list", "ping"} {
				w := f.serve(f.request("POST", "/mcp/wp", fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"params":{}}`, method)))
				if w.Code != 200 || strings.Contains(w.Body.String(), `"error"`) {
					t.Fatal(w.Body.String())
				}
				if method == "tools/list" && !strings.Contains(w.Body.String(), `"name":"edit"`) {
					t.Fatal("missing allowed tool")
				}
			}
			if writes.Load() != 0 {
				t.Fatal("metadata made upstream write")
			}
			for _, body := range []string{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete","arguments":{"id":2}}}`, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"edit","arguments":{"id":3}}}`} {
				w := f.serve(f.request("POST", "/mcp/wp", body))
				if !strings.Contains(w.Body.String(), `"isError":true`) {
					t.Fatal(w.Body.String())
				}
			}
			body := `{"jsonrpc":"2.0","id":"agent-id","method":"tools/call","params":{"name":"edit","arguments":{"id":2,"title":"new"}}}`
			w := f.serve(f.request("POST", "/mcp/wp", body))
			if !strings.Contains(w.Body.String(), "updated") || !strings.Contains(w.Body.String(), `"id":"agent-id"`) || w.Header().Get("Mcp-Session-Id") != "" {
				t.Fatal(w.Body.String())
			}
			w = f.serve(f.request("POST", "/mcp/wp", body))
			if !strings.Contains(w.Body.String(), "grant_exhausted") || writes.Load() != 1 {
				t.Fatal(w.Body.String(), writes.Load())
			}
			for _, invalid := range []string{`[]`, `{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/call"}`, `{"jsonrpc":"2.0","id":null,"method":"ping"}`, `{"jsonrpc":"2.0","id":1,"method":"resources/read"}`} {
				w = f.serve(f.request("POST", "/mcp/wp", invalid))
				if !strings.Contains(w.Body.String(), `"error"`) {
					t.Fatal(w.Body.String())
				}
			}
			if writes.Load() != 1 {
				t.Fatal("invalid message forwarded")
			}
			unknown := f.request("POST", "/mcp/wp", body)
			unknown.Header.Set("Authorization", "Bearer unknown")
			response := f.serve(unknown)
			if response.Code != 401 || response.Header().Get("WWW-Authenticate") == "" || !strings.Contains(response.Body.String(), "grant_unknown") {
				t.Fatal(response.Body.String())
			}
			records, err := s.ListDecisions(ctx, store.DecisionFilter{}, 100)
			if err != nil {
				t.Fatal(err)
			}
			unknownRecorded := false
			for _, record := range records {
				if record.Code == "grant_unknown" {
					unknownRecorded = true
				}
			}
			if !unknownRecorded {
				t.Fatal("unknown call was not audited")
			}
			fresh, err := s.IssueGrant(ctx, store.IssueRequest{Template: "edit", Uses: 1, TTL: time.Minute, Args: map[string]json.RawMessage{"id": json.RawMessage(`2`)}, IssuedTo: "bot", IssuedBy: "owner", Reason: "parallel"})
			if err != nil {
				t.Fatal(err)
			}
			f.grant = fresh
			var wg sync.WaitGroup
			var winners atomic.Int32
			for i := 0; i < 16; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					response := f.serve(f.request("POST", "/mcp/wp", body))
					if strings.Contains(response.Body.String(), "updated") {
						winners.Add(1)
					}
				}()
			}
			wg.Wait()
			if winners.Load() != 1 || writes.Load() != 2 {
				t.Fatalf("parallel winners=%d writes=%d", winners.Load(), writes.Load())
			}

		})
	}
}
func TestSSEResponseRejectsMissingAndDuplicate(t *testing.T) {
	for _, data := range []string{"data: {}\n\n", "data: {\"id\":2}\n\ndata: {\"id\":2}\n\n"} {
		out, err := sseResponse([]byte(data), 2)
		if err == nil && json.Valid(out) {
			t.Fatal("accepted ambiguous response")
		}
	}
}

func TestSSELineEndingsAndBOM(t *testing.T) {
	for _, ending := range []string{"\n", "\r\n", "\r"} {
		for _, bom := range []string{"", "\xef\xbb\xbf"} {
			body := bom + "event: message" + ending + `data: {"jsonrpc":"2.0","id":2,"result":{"content":[]}}` + ending + ending
			got, err := sseResponse([]byte(body), 2)
			if err != nil || !json.Valid(got) {
				t.Fatalf("ending=%q bom=%q: %s %v", ending, bom, got, err)
			}
		}
	}
}
func TestMCPInitializationFailureKeepsHTTPStatus(t *testing.T) {
	for _, stage := range []string{"initialize", "notifications/initialized"} {
		t.Run(stage, func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request struct {
					ID     int    `json:"id"`
					Method string `json:"method"`
				}
				_ = json.NewDecoder(r.Body).Decode(&request)
				if request.Method == stage {
					w.WriteHeader(500)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": map[string]any{"protocolVersion": mcpVersion}})
			}))
			defer backend.Close()
			s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "db"))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			p := policy.Policy{Targets: map[string]policy.Target{"wp": {Kind: "mcp_http", URL: backend.URL, Credential: policy.Credential{Type: "bearer", Ref: "vault:wp"}}}, Templates: map[string]policy.Template{"edit": {Target: "wp", Tool: "edit", MaxUses: 1, MaxTTL: "15m"}}}
			if err = s.ApplyPolicy(context.Background(), p); err != nil {
				t.Fatal(err)
			}
			v, _ := vault.New(make([]byte, 32))
			if err = s.SetCredential(context.Background(), "wp", v, []byte(`{"value":"upstream"}`)); err != nil {
				t.Fatal(err)
			}
			g, _ := New(s, v, Options{})
			_, status, err := g.mcpCall(context.Background(), "wp", "edit", nil)
			if err == nil || status != 500 {
				t.Fatal(status, err)
			}
		})
	}
}
