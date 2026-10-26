package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/softdevstudio/tokening/internal/admin"
	"github.com/softdevstudio/tokening/internal/policy"
	"github.com/softdevstudio/tokening/internal/store"
	"github.com/softdevstudio/tokening/internal/vault"
)

func TestAdminCLIWorkflow(t *testing.T) {
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p, _, err := policy.Load("../../examples/wordpress.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ApplyPolicy(context.Background(), *p); err != nil {
		t.Fatal(err)
	}
	v, _ := vault.New(make([]byte, 32))
	token := "operator-cli-test-token-with-32-characters"
	h, _ := admin.New(s, v, token)
	backend := httptest.NewServer(h)
	defer backend.Close()
	t.Setenv("TOKENING_ADMIN_TOKEN", token)
	t.Setenv("TOKENING_ADMIN_URL", backend.URL)
	execute := func(args ...string) string {
		t.Helper()
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != 0 {
			t.Fatalf("%v: code=%d err=%s", args, code, &errOut)
		}
		return out.String()
	}
	if !strings.Contains(execute("template", "list"), "wp.edit-post-text") {
		t.Fatal("missing template")
	}
	credential := filepath.Join(t.TempDir(), "credential.json")
	if err = os.WriteFile(credential, []byte(`{"username":"wp","password":"private-upstream"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(execute("target", "add", "demo-wp", "--cred-file", credential), "private-upstream") {
		t.Fatal("credential echoed")
	}
	output := execute("grant", "issue", "wp.edit-post-text", "--bind", "id=2", "--uses", "1", "--ttl", "1m", "--to", "bot", "--reason", "fix title")
	var issued store.IssuedGrant
	if err = json.Unmarshal([]byte(output), &issued); err != nil || issued.Secret == "" {
		t.Fatal("issuance did not print secret", err)
	}
	if strings.Contains(execute("grant", "inspect", issued.Grant.ID), string(issued.Secret)) {
		t.Fatal("inspection printed secret")
	}
	if !strings.Contains(execute("grant", "revoke", issued.Grant.ID, "--by", "owner"), `"state":"revoked"`) {
		t.Fatal("revocation failed")
	}
	execute("log", "--export")
	for _, args := range [][]string{{"grant", "issue", "wp.edit-post-text", "--bind", "id=2", "--bind", "id=3"}, {"grant", "issue", "wp.edit-post-text", "--bind", "id=not-json"}, {"log", "--follow", "--export"}} {
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code == 0 {
			t.Fatal("invalid CLI input accepted")
		}
	}
}
func TestAdminClientNeverFollowsOrRetries(t *testing.T) {
	var calls atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Location", "/other")
		w.WriteHeader(307)
	}))
	defer backend.Close()
	t.Setenv("TOKENING_ADMIN_URL", backend.URL)
	t.Setenv("TOKENING_ADMIN_TOKEN", "operator-test-token-with-32-characters")
	var out, errOut bytes.Buffer
	if code := run([]string{"template", "list"}, &out, &errOut); code != 1 || calls.Load() != 1 {
		t.Fatal(code, calls.Load())
	}
}
func TestDoctorDoesNotPrintValues(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "never-print-this-secret")
	var out bytes.Buffer
	if code := run([]string{"doctor"}, &out, &bytes.Buffer{}); code != 1 || !strings.Contains(out.String(), "GITHUB_TOKEN") || strings.Contains(out.String(), "never-print-this-secret") {
		t.Fatal(code, out.String())
	}
}
