package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
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

type fixture struct {
	gateway *Gateway
	store   *store.Store
	vault   *vault.Vault
	grant   store.IssuedGrant
	policy  policy.Policy
}

func setup(t *testing.T, upstream http.Handler, kind string, credential []byte) fixture {
	t.Helper()
	backend := httptest.NewServer(upstream)
	t.Cleanup(backend.Close)
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	v, err := vault.New(bytes.Repeat([]byte{17}, 32))
	if err != nil {
		t.Fatal(err)
	}
	max := 200
	p := policy.Policy{Targets: map[string]policy.Target{"wp": {Kind: "http", URL: backend.URL + "/api", Credential: policy.Credential{Type: kind, Ref: "vault:wp"}}}, Templates: map[string]policy.Template{"edit": {Target: "wp", Method: "PATCH", Path: "/posts/{id}", MaxTTL: "15m", MaxUses: 2, Args: map[string]policy.Constraint{"id": {Bind: "required"}, "title": {Type: "string", MaxLen: &max}}, Query: map[string]policy.Constraint{"context": {Type: "string", Bind: "required"}}}}}
	if err = s.ApplyPolicy(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if err = s.SetCredential(context.Background(), "wp", v, credential); err != nil {
		t.Fatal(err)
	}
	grant, err := s.IssueGrant(context.Background(), store.IssueRequest{Template: "edit", Uses: 1, TTL: 5 * time.Minute, Args: map[string]json.RawMessage{"id": json.RawMessage(`2`)}, Query: map[string]json.RawMessage{"context": json.RawMessage(`"edit"`)}, IssuedTo: "bot", IssuedBy: "operator", Reason: "fix title"})
	if err != nil {
		t.Fatal(err)
	}
	g, err := New(s, v, Options{ErrorLog: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{g, s, v, grant, p}
}
func (f fixture) request(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+string(f.grant.Secret))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	return r
}
func (f fixture) serve(r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.gateway.ServeHTTP(w, r)
	return w
}
func (f fixture) info(t *testing.T) store.GrantInfo {
	t.Helper()
	g, err := f.store.InspectGrant(context.Background(), f.grant.Grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func TestRESTForwardConsumesBeforeCredentialInjection(t *testing.T) {
	var calls atomic.Int32
	var observedAuth, observedBody string
	f := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		observedAuth = r.Header.Get("Authorization")
		data, _ := io.ReadAll(r.Body)
		observedBody = string(data)
		if r.Method != "PATCH" || r.URL.Path != "/api/posts/2" || r.URL.Query().Get("context") != "edit" {
			t.Error("upstream route was changed")
		}
		if r.Header.Get("Cookie") != "" || r.Header.Get("X-HTTP-Method-Override") != "" || r.Header.Get("X-Forwarded-Host") != "" {
			t.Error("untrusted headers forwarded")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "session=must-not-reach-agent")
		w.Header().Set("WWW-Authenticate", "private-auth-metadata")
		w.Header().Set("Connection", "X-Private-Hop, close")
		w.Header().Set("X-Private-Hop", "hidden")
		io.WriteString(w, `{"updated":true}`)
	}), "bearer", []byte(`{"value":"real-upstream-secret"}`))
	// A server-side check at upstream arrival proves reservation has committed.
	original := f.gateway.client.Transport
	f.gateway.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if f.info(t).UsesLeft != 0 {
			t.Error("forwarding began before consumption committed")
		}
		return original.RoundTrip(r)
	})
	r := f.request("PATCH", "/http/wp/posts/2?context=edit", ` { "title" : "fixed" } `)
	r.Header.Set("Cookie", "agent-cookie")
	r.Header.Set("X-HTTP-Method-Override", "DELETE")
	r.Header.Set("X-Forwarded-Host", "attacker.example")
	w := f.serve(r)
	if w.Code != 200 || w.Body.String() != `{"updated":true}` || calls.Load() != 1 {
		t.Fatalf("forward failed: %d %s", w.Code, w.Body)
	}
	if observedAuth != "Bearer real-upstream-secret" || strings.Contains(observedAuth, string(f.grant.Secret)) || observedBody != `{"title":"fixed"}` {
		t.Fatal("credential or normalized body incorrect")
	}
	if w.Header().Get("Set-Cookie") != "" || w.Header().Get("WWW-Authenticate") != "" || w.Header().Get("X-Private-Hop") != "" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unsafe headers: cookie=%q challenge=%q hop=%q cache=%q", w.Header().Get("Set-Cookie"), w.Header().Get("WWW-Authenticate"), w.Header().Get("X-Private-Hop"), w.Header().Get("Cache-Control"))
	}
	if strings.Contains(w.Body.String(), "real-upstream-secret") {
		t.Fatal("credential exposed")
	}
	info := f.info(t)
	if info.UsesLeft != 0 || info.DecisionCount != 2 {
		t.Fatal("authorization and completion not recorded")
	}
	records, err := f.store.ListDecisions(context.Background(), store.DecisionFilter{}, 10)
	if err != nil || len(records) != 2 || records[1].AuthorizationID == nil || *records[1].AuthorizationID != records[0].ID || records[1].UpstreamStatus == nil || *records[1].UpstreamStatus != 200 {
		t.Fatal("outcome linkage incorrect")
	}
	again := f.serve(f.request("PATCH", "/http/wp/posts/2?context=edit", `{"title":"again"}`))
	if again.Code != 403 || calls.Load() != 1 {
		t.Fatal("exhausted grant reached upstream")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestRESTRefusalsNeverReachUpstream(t *testing.T) {
	var calls atomic.Int32
	f := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }), "basic", []byte(`{"username":"wp-user","password":"private-app-password"}`))
	for _, tt := range []struct {
		name, method, path, body string
		status                   int
		change                   func(*http.Request)
	}{
		{name: "wrong post", method: "PATCH", path: "/http/wp/posts/3?context=edit", body: `{"title":"x"}`, status: 403},
		{name: "wrong target", method: "PATCH", path: "/http/other/posts/2?context=edit", body: `{"title":"x"}`, status: 403},
		{name: "delete", method: "DELETE", path: "/http/wp/posts/2?context=edit", status: 403},
		{name: "extra field", method: "PATCH", path: "/http/wp/posts/2?context=edit", body: `{"title":"x","status":"publish"}`, status: 403},
		{name: "missing bound query", method: "PATCH", path: "/http/wp/posts/2", body: `{"title":"x"}`, status: 403},
		{name: "duplicate JSON key", method: "PATCH", path: "/http/wp/posts/2?context=edit", body: `{"title":"x","title":"y"}`, status: 400},
		{name: "nested duplicate", method: "PATCH", path: "/http/wp/posts/2?context=edit", body: `{"title":{"x":1,"x":2}}`, status: 400},
		{name: "encoded path", method: "PATCH", path: "/http/wp/posts/%32?context=edit", body: `{"title":"x"}`, status: 400},
		{name: "path traversal", method: "PATCH", path: "/http/wp/posts/../2?context=edit", body: `{"title":"x"}`, status: 403},
		{name: "query override", method: "PATCH", path: "/http/wp/posts/2?context=edit&_method=DELETE", body: `{"title":"x"}`, status: 400},
		{name: "body override", method: "PATCH", path: "/http/wp/posts/2?context=edit", body: `{"title":"x","_method":"DELETE"}`, status: 400},
		{name: "query path shadow", method: "PATCH", path: "/http/wp/posts/2?context=edit&id=3", body: `{"title":"x"}`, status: 400},
		{name: "repeated query", method: "PATCH", path: "/http/wp/posts/2?context=edit&context=view", body: `{"title":"x"}`, status: 400},
		{name: "query body collision", method: "PATCH", path: "/http/wp/posts/2?context=edit", body: `{"title":"x","context":"view"}`, status: 400},
		{name: "invalid JSON", method: "PATCH", path: "/http/wp/posts/2?context=edit", body: `{"title":`, status: 400},
		{name: "array", method: "PATCH", path: "/http/wp/posts/2?context=edit", body: `[]`, status: 400},
		{name: "wrong content type", method: "PATCH", path: "/http/wp/posts/2?context=edit", body: `{"title":"x"}`, status: 415, change: func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }},
		{name: "missing bearer", method: "PATCH", path: "/http/wp/posts/2?context=edit", body: `{"title":"x"}`, status: 401, change: func(r *http.Request) { r.Header.Del("Authorization") }},
		{name: "duplicate bearer", method: "PATCH", path: "/http/wp/posts/2?context=edit", body: `{"title":"x"}`, status: 401, change: func(r *http.Request) { r.Header.Add("Authorization", "Bearer other") }},
		{name: "unknown bearer", method: "PATCH", path: "/http/wp/posts/2?context=edit", body: `{"title":"x"}`, status: 401, change: func(r *http.Request) { r.Header.Set("Authorization", "Bearer unknown") }},
		{name: "hostile origin", method: "PATCH", path: "/http/wp/posts/2?context=edit", body: `{"title":"x"}`, status: 403, change: func(r *http.Request) { r.Header.Set("Origin", "https://attacker.example") }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := f.request(tt.method, tt.path, tt.body)
			if tt.change != nil {
				tt.change(r)
			}
			w := f.serve(r)
			if w.Code != tt.status {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tt.status, w.Body)
			}
		})
	}
	if calls.Load() != 0 || f.info(t).UsesLeft != 1 {
		t.Fatal("refusal forwarded or consumed")
	}
	oversized := strings.Repeat(" ", MaxBodyBytes+1)
	if w := f.serve(f.request("PATCH", "/http/wp/posts/2?context=edit", oversized)); w.Code != 413 {
		t.Fatal("body cap was not enforced")
	}
}
func TestGrantDescriptionDoesNotSpendOrExposeAdminData(t *testing.T) {
	f := setup(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("description contacted upstream") }), "bearer", []byte(`{"value":"private-upstream"}`))
	w := f.serve(f.request("GET", "/grant", ""))
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"arguments"`) || !strings.Contains(w.Body.String(), `"max_len":200`) || strings.Contains(w.Body.String(), string(f.grant.Secret)) || strings.Contains(w.Body.String(), "private-upstream") || strings.Contains(w.Body.String(), "issued_by") {
		t.Fatal("description incomplete or exposed admin/secret data")
	}
	if f.info(t).UsesLeft != 1 || f.info(t).DecisionCount != 0 {
		t.Fatal("description consumed or logged a tool call")
	}
	if _, err := f.store.RevokeGrant(context.Background(), f.grant.Grant.ID, "operator"); err != nil {
		t.Fatal(err)
	}
	w = f.serve(f.request("GET", "/grant", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"revoked"`) {
		t.Fatal("description hid terminal state")
	}
	w = f.serve(f.request("PATCH", "/http/wp/posts/2?context=edit", `{"title":"x"}`))
	if w.Code != 403 {
		t.Fatal("revoked grant forwarded")
	}
}
func TestUpstreamFailureAndRedirectRemainSpent(t *testing.T) {
	for _, status := range []int{500, 307} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var leaked atomic.Int32
			other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { leaked.Add(1) }))
			defer other.Close()
			var attempts atomic.Int32
			f := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts.Add(1)
				w.Header().Set("Location", other.URL)
				w.WriteHeader(status)
				io.WriteString(w, "original-upstream-body")
			}), "bearer", []byte(`{"value":"private-upstream"}`))
			w := f.serve(f.request("PATCH", "/http/wp/posts/2?context=edit", `{"title":"x"}`))
			if w.Code != status || w.Body.String() != "original-upstream-body" || attempts.Load() != 1 || leaked.Load() != 0 || f.info(t).UsesLeft != 0 {
				t.Fatal("upstream result was replayed, redirected or refunded")
			}
			rows, err := f.store.ListDecisions(context.Background(), store.DecisionFilter{}, 10)
			if err != nil || len(rows) != 2 || rows[1].UpstreamStatus == nil || *rows[1].UpstreamStatus != status {
				t.Fatal("upstream result missing")
			}
		})
	}
}
func TestConcurrentHTTPCallsHaveOneWinner(t *testing.T) {
	var calls atomic.Int32
	f := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); io.WriteString(w, "ok") }), "bearer", []byte(`{"value":"private-upstream"}`))
	start := make(chan struct{})
	results := make(chan int, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- f.serve(f.request("PATCH", "/http/wp/posts/2?context=edit", `{"title":"x"}`)).Code
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	winners := 0
	for status := range results {
		if status == 200 {
			winners++
		} else if status != 403 {
			t.Fatalf("unexpected race status %d", status)
		}
	}
	if winners != 1 || calls.Load() != 1 {
		t.Fatal("HTTP race forwarded more than once")
	}
}
func TestMalformedStoredCredentialDoesNotReachUpstream(t *testing.T) {
	var calls atomic.Int32
	f := setup(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }), "header", []byte(`{"name":"Host","value":"attacker.example"}`))
	w := f.serve(f.request("PATCH", "/http/wp/posts/2?context=edit", `{"title":"x"}`))
	if w.Code != 502 || calls.Load() != 0 || f.info(t).UsesLeft != 0 {
		t.Fatal("invalid credential forwarded or refunded")
	}
}

func TestRevocationDuringInFlightHTTP(t *testing.T) {
	arrived := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	f := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(arrived)
		<-release
		io.WriteString(w, "completed-before-revocation-can-cancel")
	}), "bearer", []byte(`{"value":"private-upstream"}`))
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- f.serve(f.request("PATCH", "/http/wp/posts/2?context=edit", `{"title":"x"}`)) }()
	select {
	case <-arrived:
	case <-time.After(10 * time.Second):
		t.Fatal("authorized call did not reach upstream")
	}
	if _, err := f.store.RevokeGrant(context.Background(), f.grant.Grant.ID, "operator"); err != nil {
		t.Fatal(err)
	}
	second := f.serve(f.request("PATCH", "/http/wp/posts/2?context=edit", `{"title":"x"}`))
	if second.Code != 403 || !strings.Contains(second.Body.String(), "grant_revoked") {
		t.Fatal("revocation did not block later request")
	}
	releaseOnce.Do(func() { close(release) })
	first := <-done
	if first.Code != 200 || f.info(t).UsesLeft != 0 {
		t.Fatal("revocation canceled or refunded an already authorized request")
	}
}
func TestHTTPUsesSavedPolicyVersion(t *testing.T) {
	var calls atomic.Int32
	f := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); io.WriteString(w, "ok") }), "bearer", []byte(`{"value":"private-upstream"}`))
	template := f.policy.Templates["edit"]
	one := 1
	rule := template.Args["title"]
	rule.MaxLen = &one
	template.Args["title"] = rule
	f.policy.Templates["edit"] = template
	if err := f.store.ApplyPolicy(context.Background(), f.policy); err != nil {
		t.Fatal(err)
	}
	old := f.serve(f.request("PATCH", "/http/wp/posts/2?context=edit", `{"title":"long"}`))
	if old.Code != 200 {
		t.Fatal("reload changed live grant")
	}
	next, err := f.store.IssueGrant(context.Background(), store.IssueRequest{Template: "edit", Uses: 1, TTL: 5 * time.Minute, Args: map[string]json.RawMessage{"id": json.RawMessage(`2`)}, Query: map[string]json.RawMessage{"context": json.RawMessage(`"edit"`)}, IssuedTo: "bot", IssuedBy: "operator", Reason: "new policy"})
	if err != nil {
		t.Fatal(err)
	}
	f.grant = next
	w := f.serve(f.request("PATCH", "/http/wp/posts/2?context=edit", `{"title":"long"}`))
	if w.Code != 403 || calls.Load() != 1 || f.info(t).UsesLeft != 1 {
		t.Fatal("new grant did not use new policy")
	}
}
