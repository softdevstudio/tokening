package gateway

import (
	"net/http"
	"testing"
)

func TestCredentialInjection(t *testing.T) {
	for _, tt := range []struct {
		kind, payload, name, value string
		valid                      bool
	}{
		{"basic", `{"username":"user","password":"app:password"}`, "Authorization", "Basic dXNlcjphcHA6cGFzc3dvcmQ=", true},
		{"bearer", `{"value":"api-key"}`, "Authorization", "Bearer api-key", true},
		{"header", `{"name":"X-Api-Key","value":"api-key"}`, "X-Api-Key", "api-key", true},
		{"header", `{"name":"Content-Length","value":"10"}`, "", "", false},
		{"header", `{"name":"MCP-Session-Id","value":"session"}`, "", "", false},
		{"header", `{"name":"X-Key","value":"key\r\nHost: evil"}`, "", "", false},
		{"bearer", `{"value":"one two"}`, "", "", false},
		{"basic", `{"username":"a:b","password":"pw"}`, "", "", false},
		{"bearer", `{"value":"a","value":"b"}`, "", "", false},
		{"bearer", `{"value":"key","extra":"field"}`, "", "", false},
	} {
		r, _ := http.NewRequest("GET", "https://example.com", nil)
		err := inject(r, tt.kind, []byte(tt.payload))
		if (err == nil) != tt.valid {
			t.Fatalf("kind=%s valid=%v err=%v", tt.kind, tt.valid, err)
		}
		if tt.valid && r.Header.Get(tt.name) != tt.value {
			t.Fatal("credential injected incorrectly")
		}
	}
}
