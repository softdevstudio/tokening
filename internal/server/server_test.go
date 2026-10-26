package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/softdevstudio/tokening/internal/policy"
	"github.com/softdevstudio/tokening/internal/store"
	"github.com/softdevstudio/tokening/internal/vault"
)

const adminToken = "test-operator-token-with-at-least-32-characters"

type logChannel chan string

func (l logChannel) Write(p []byte) (int, error) { l <- string(p); return len(p), nil }
func TestTwoListenersReloadAndShutdown(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	t.Setenv(vault.KeyEnv, key)
	var writes atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer real-upstream-key" {
			t.Error("wrong upstream credential")
		}
		writes.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"updated":true}`)
	}))
	defer backend.Close()
	max := 200
	p := policy.Policy{Targets: map[string]policy.Target{"wp": {Kind: "http", URL: backend.URL, Credential: policy.Credential{Type: "bearer", Ref: "vault:wp"}}}, Templates: map[string]policy.Template{"edit": {Target: "wp", Method: "PATCH", Path: "/posts/{id}", Args: map[string]policy.Constraint{"id": {Bind: "required"}, "title": {Type: "string", MaxLen: &max}}, MaxUses: 1, MaxTTL: "15m"}}}
	dir := t.TempDir()
	file := filepath.Join(dir, "policy.json")
	save := func() {
		data, _ := json.Marshal(p)
		if err := os.WriteFile(file, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	save()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reload := make(chan struct{}, 1)
	logs := make(logChannel, 32)
	ready := make(chan [2]string, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{PolicyFile: file, Database: filepath.Join(dir, "db"), AdminToken: adminToken, AgentAddress: "127.0.0.1:0", AdminAddress: "127.0.0.1:0", Reload: reload, Logger: log.New(logs, "", 0)}, func(a, b string) { ready <- [2]string{a, b} })
	}()
	var addresses [2]string
	select {
	case addresses = <-ready:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not start")
	}
	client := &http.Client{Timeout: 3 * time.Second}
	call := func(port, method, path, body, token string) (int, []byte) {
		t.Helper()
		r, _ := http.NewRequest(method, "http://"+port+path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		res, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		data, _ := io.ReadAll(res.Body)
		return res.StatusCode, data
	}
	if status, _ := call(addresses[0], "GET", "/admin/templates", "", adminToken); status != 404 {
		t.Fatal("admin exposed on agent port", status)
	}
	if status, _ := call(addresses[1], "GET", "/grant", "", adminToken); status != 404 {
		t.Fatal("agent exposed on admin port", status)
	}
	if status, data := call(addresses[1], "POST", "/admin/targets", `{"name":"wp","credential":{"value":"real-upstream-key"}}`, adminToken); status != 200 {
		t.Fatal(status, string(data))
	}
	status, data := call(addresses[1], "POST", "/admin/grants", `{"template":"edit","uses":1,"ttl":"1m","args":{"id":2},"issued_to":"bot","issued_by":"owner","reason":"test"}`, adminToken)
	if status != 201 {
		t.Fatal(status, string(data))
	}
	var issued store.IssuedGrant
	if err := json.Unmarshal(data, &issued); err != nil {
		t.Fatal(err)
	}
	if status, _ := call(addresses[1], "GET", "/admin/templates", "", string(issued.Secret)); status != 401 {
		t.Fatal("agent grant authenticated as admin")
	}
	// Failed reload leaves active templates intact.
	if err := os.WriteFile(file, []byte(`{`), 0600); err != nil {
		t.Fatal(err)
	}
	reload <- struct{}{}
	awaitLog := func(needle string) {
		t.Helper()
		select {
		case message := <-logs:
			if !strings.Contains(message, needle) {
				t.Fatal(message)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("reload was not handled")
		}
	}
	awaitLog("reload failed")
	max = 1
	save()
	reload <- struct{}{}
	awaitLog("policy reloaded")
	// The old grant keeps the saved 200-character limit after a successful reload.
	status, data = call(addresses[0], "PATCH", "/http/wp/posts/2", `{"title":"longer than the new limit"}`, string(issued.Secret))
	if status != 200 || !bytes.Contains(data, []byte("updated")) {
		t.Fatal(status, string(data))
	}
	status, _ = call(addresses[0], "PATCH", "/http/wp/posts/2", `{"title":"again"}`, string(issued.Secret))
	if status != 403 || writes.Load() != 1 {
		t.Fatal(status, writes.Load())
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("shutdown stalled")
	}
	for _, address := range addresses {
		connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			connection.Close()
			t.Fatal("listener remained open")
		}
	}
	// Persisted grants and credentials survive the running server's shutdown.
	s, err := store.Open(context.Background(), filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	info, err := s.InspectGrant(context.Background(), issued.Grant.ID)
	if err != nil || info.State != "exhausted" {
		t.Fatal(info.State, err)
	}
}

func TestBindFailureClosesOtherListener(t *testing.T) {
	t.Setenv(vault.KeyEnv, base64.StdEncoding.EncodeToString(make([]byte, 32)))
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	candidate, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := candidate.Addr().String()
	candidate.Close()
	announced := false
	err = Run(context.Background(), Config{PolicyFile: "../../examples/wordpress.json", Database: filepath.Join(t.TempDir(), "db"), AdminToken: adminToken, AgentAddress: address, AdminAddress: occupied.Addr().String(), Logger: log.New(io.Discard, "", 0)}, func(string, string) { announced = true })
	if err == nil || !strings.Contains(err.Error(), "bind admin listener") || announced {
		t.Fatal("partial startup", err, announced)
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal("agent listener leaked", err)
	}
	listener.Close()
}
