package admin

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/softdevstudio/tokening/internal/matcher"
	"github.com/softdevstudio/tokening/internal/policy"
	"github.com/softdevstudio/tokening/internal/store"
	"github.com/softdevstudio/tokening/internal/vault"
)

const testToken = "admin-only-test-token-with-32-characters"

func testHandler(t *testing.T) (*Handler, *store.Store) {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	p, _, err := policy.Load("../../examples/wordpress.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ApplyPolicy(context.Background(), *p); err != nil {
		t.Fatal(err)
	}
	v, _ := vault.New(make([]byte, 32))
	h, err := New(s, v, testToken)
	if err != nil {
		t.Fatal(err)
	}
	return h, s
}
func request(h http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestAdminAuthenticationAndStrictRequests(t *testing.T) {
	h, _ := testHandler(t)
	for _, token := range []string{"", "tkn_agent-grant", "wrong-admin-token"} {
		if w := request(h, "GET", "/admin/templates", "", token); w.Code != 401 {
			t.Fatal(w.Code)
		}
	}
	r := httptest.NewRequest("GET", "/admin/templates", nil)
	r.Header.Set("Authorization", "Bearer "+testToken)
	r.Header.Set("Origin", "http://localhost")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	for _, body := range []string{`{"name":"a","name":"b","credential":{}}`, `{"name":"a","credential":{},"extra":true}`, `{"name":"a","credential":{"value":"x","value":"y"}}`, `[]`, `{} {}`} {
		if w := request(h, "POST", "/admin/targets", body, testToken); w.Code != 400 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	for _, path := range []string{"/admin/templates?x=y", "/admin/decisions?since=-1", "/admin/decisions?since=0&since=1", "/admin/decisions?grant=%zz", "/admin/decisions.jsonl?follow=true"} {
		if w := request(h, "GET", path, "", testToken); w.Code != 400 {
			t.Fatal(path, w.Code)
		}
	}
	if _, err := New(h.store, h.vault, "short"); err == nil {
		t.Fatal("accepted short admin token")
	}
}
func TestAdminIssueInspectRevokeExport(t *testing.T) {
	h, s := testHandler(t)
	templates := request(h, "GET", "/admin/templates", "", testToken)
	if templates.Code != 200 {
		t.Fatal(templates.Body.String())
	}
	var active map[string]policy.Template
	if err := json.Unmarshal(templates.Body.Bytes(), &active); err != nil {
		t.Fatal(err)
	}
	var name string
	var template policy.Template
	for key, value := range active {
		if value.Tool != "" {
			name, template = key, value
			break
		}
	}
	if name == "" {
		t.Fatal("missing MCP template")
	}
	upload, _ := json.Marshal(map[string]any{"name": template.Target, "credential": map[string]string{"username": "wp", "password": "upstream-private-password"}})
	w := request(h, "POST", "/admin/targets", string(upload), testToken)
	if w.Code != 200 || strings.Contains(w.Body.String(), "upstream-private") {
		t.Fatal(w.Code, w.Body.String())
	}
	body, _ := json.Marshal(map[string]any{"template": name, "uses": 1, "ttl": "1m", "args": map[string]int{"id": 2}, "issued_to": "bot", "issued_by": "owner", "reason": "test"})
	w = request(h, "POST", "/admin/grants", string(body), testToken)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var issued store.IssuedGrant
	if err := json.Unmarshal(w.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	if issued.Secret == "" {
		t.Fatal("secret not returned")
	}
	for _, action := range []struct{ method, path, body string }{{"GET", "/admin/grants/" + issued.Grant.ID, ""}, {"POST", "/admin/grants/" + issued.Grant.ID + "/revoke", `{"actor":"owner"}`}} {
		w = request(h, action.method, action.path, action.body, testToken)
		if w.Code != 200 || strings.Contains(w.Body.String(), string(issued.Secret)) || strings.Contains(w.Body.String(), "upstream-private") {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if info, err := s.InspectGrant(context.Background(), issued.Grant.ID); err != nil || info.State != "revoked" {
		t.Fatal(info.State, err)
	}
	w = request(h, "GET", "/admin/grants/missing", "", testToken)
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
	// Make a real refusal so both polling and JSONL have a record to return.
	_, err := s.Consume(context.Background(), "unknown", matcher.Call{Target: "missing", Tool: "edit"})
	if err != nil {
		t.Fatal(err)
	}
	w = request(h, "GET", "/admin/decisions.jsonl", "", testToken)
	res := w.Result()
	data, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(data), "grant_unknown") || res.Trailer.Get("Tokening-Export-Complete") != "true" {
		t.Fatal(string(data), res.Trailer)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequest("GET", "/admin/decisions?follow=true", nil).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer "+testToken)
	writer := &cancelWriter{ResponseRecorder: httptest.NewRecorder(), cancel: cancel}
	h.ServeHTTP(writer, r)
	if !strings.Contains(writer.Body.String(), "event: decision") {
		t.Fatal(writer.Body.String())
	}
}

type cancelWriter struct {
	*httptest.ResponseRecorder
	cancel context.CancelFunc
}

func (w *cancelWriter) Flush() { w.ResponseRecorder.Flush(); w.cancel() }
