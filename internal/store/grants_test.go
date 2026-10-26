package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/softdevstudio/tokening/internal/matcher"
	"github.com/softdevstudio/tokening/internal/policy"
)

func testPolicy(t *testing.T) policy.Policy {
	t.Helper()
	p, _, err := policy.Load("../../examples/wordpress.json")
	if err != nil {
		t.Fatal(err)
	}
	target := p.Targets["demo-wp"]
	delete(p.Targets, "demo-wp")
	p.Targets["wp"] = target
	tmpl := p.Templates["wp.edit-post-text"]
	tmpl.Target = "wp"
	delete(p.Templates, "wp.edit-post-text")
	p.Templates["edit"] = tmpl
	return *p
}
func issueRequest() IssueRequest {
	return IssueRequest{Template: "edit", Uses: 1, TTL: 5 * time.Minute, Args: map[string]json.RawMessage{"id": json.RawMessage(`2`)}, IssuedTo: "editor-bot", IssuedBy: "operator", Reason: "fix typo"}
}
func applyTestPolicy(t *testing.T, s *Store) policy.Policy {
	t.Helper()
	p := testPolicy(t)
	if err := s.ApplyPolicy(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	return p
}
func issue(t *testing.T, s *Store, r IssueRequest) IssuedGrant {
	t.Helper()
	g, err := s.IssueGrant(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func TestIssueInspectConsumeRevoke(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	s := openTest(t, path)
	applyTestPolicy(t, s)
	r := issueRequest()
	r.Uses = 2
	g := issue(t, s, r)
	if g.Grant.State != "issued" || g.Grant.UsesLeft != 2 || g.Grant.TemplateVersion != 1 || !strings.HasPrefix(string(g.Secret), "tkn_") {
		t.Fatal("bad issue response")
	}
	if g.Grant.ExpiresAt.Sub(g.Grant.CreatedAt) != r.TTL {
		t.Fatal("issue widened requested TTL")
	}
	var storedHash []byte
	if err := s.db.QueryRow(`SELECT secret_hash FROM grants WHERE id=?`, g.Grant.ID).Scan(&storedHash); err != nil {
		t.Fatal(err)
	}
	wantHash := sha256.Sum256([]byte(g.Secret))
	if !bytes.Equal(storedHash, wantHash[:]) {
		t.Fatal("incorrect stored secret hash")
	}
	inspect, err := s.InspectGrant(context.Background(), g.Grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(inspect)
	if bytes.Contains(encoded, []byte(g.Secret)) || bytes.Contains(encoded, []byte("secret_hash")) {
		t.Fatal("inspection exposed a secret")
	}
	if strings.Contains(fmt.Sprintf("%+v", g), string(g.Secret)) || strings.Contains(fmt.Sprintf("%#v", g), string(g.Secret)) {
		t.Fatal("diagnostic formatting exposed issued secret")
	}
	consumeCheck(t, s, string(g.Secret), consumerCall(), matcher.Allowed)
	inspect, err = s.InspectGrant(context.Background(), g.Grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if inspect.State != "active" || inspect.UsesLeft != 1 || inspect.LastUsedAt == nil || inspect.DecisionCount != 1 || len(inspect.Decisions) != 1 {
		t.Fatal("active state or audit history incorrect")
	}
	revoked, err := s.RevokeGrant(context.Background(), g.Grant.ID, "operator")
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.RevokeGrant(context.Background(), g.Grant.ID, "another-operator")
	if err != nil {
		t.Fatal(err)
	}
	if again.State != "revoked" || again.RevokedBy != "operator" || !again.RevokedAt.Equal(*revoked.RevokedAt) {
		t.Fatal("repeat revocation changed original attribution")
	}
	consumeCheck(t, s, string(g.Secret), consumerCall(), matcher.GrantRevoked)
	files, _ := filepath.Glob(path + "*")
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(g.Secret)) {
			t.Fatal("bearer secret persisted on disk")
		}
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openTest(t, path)
	consumeCheck(t, s, string(g.Secret), consumerCall(), matcher.GrantRevoked)
}
func TestIssueRejectsWideningAndInvalidBindings(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	applyTestPolicy(t, s)
	for _, tt := range []struct {
		name   string
		change func(*IssueRequest)
	}{
		{"zero uses", func(r *IssueRequest) { r.Uses = 0 }}, {"too many uses", func(r *IssueRequest) { r.Uses = 4 }},
		{"zero ttl", func(r *IssueRequest) { r.TTL = 0 }}, {"negative ttl", func(r *IssueRequest) { r.TTL = -time.Second }},
		{"too much ttl", func(r *IssueRequest) { r.TTL = time.Hour }}, {"submillisecond ttl", func(r *IssueRequest) { r.TTL = time.Nanosecond }},
		{"missing binding", func(r *IssueRequest) { r.Args = nil }}, {"extra binding", func(r *IssueRequest) { r.Args["other"] = json.RawMessage(`1`) }},
		{"unbound field", func(r *IssueRequest) { r.Args["title"] = json.RawMessage(`"fix"`) }},
		{"null binding", func(r *IssueRequest) { r.Args["id"] = json.RawMessage(`null`) }},
		{"array binding", func(r *IssueRequest) { r.Args["id"] = json.RawMessage(`[2]`) }},
		{"missing identity", func(r *IssueRequest) { r.IssuedTo = "" }}, {"missing actor", func(r *IssueRequest) { r.IssuedBy = " " }},
		{"missing reason", func(r *IssueRequest) { r.Reason = "" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := issueRequest()
			tt.change(&r)
			g, err := s.IssueGrant(context.Background(), r)
			if err == nil || g.Secret != "" || g.Grant.ID != "" {
				t.Fatal("invalid request issued a grant")
			}
		})
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM grants`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("invalid issue persisted grants: %d %v", count, err)
	}
}
func TestPolicyVersioningAndRemoval(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	p := applyTestPolicy(t, s)
	old := issue(t, s, issueRequest())
	if err := s.ApplyPolicy(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	same := issue(t, s, issueRequest())
	if same.Grant.TemplateVersion != 1 {
		t.Fatal("unchanged policy created new version")
	}
	tmpl := p.Templates["edit"]
	tmpl.Tool = "wp_delete_post"
	p.Templates["edit"] = tmpl
	if err := s.ApplyPolicy(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	next := issue(t, s, issueRequest())
	if next.Grant.TemplateVersion != 2 {
		t.Fatal("changed policy did not create version")
	}
	consumeCheck(t, s, string(old.Secret), consumerCall(), matcher.Allowed)
	consumeCheck(t, s, string(next.Secret), consumerCall(), matcher.ToolNotAllowed)
	// Keep a different template active while removing edit. Live grants survive;
	// old template names must no longer be usable for issuing new grants.
	p.Templates["other"] = p.Templates["edit"]
	delete(p.Templates, "edit")
	if err := s.ApplyPolicy(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if g, err := s.IssueGrant(context.Background(), issueRequest()); !errors.Is(err, ErrTemplateUnknown) || g.Secret != "" {
		t.Fatal("removed template issued a grant")
	}
	consumeCheck(t, s, string(same.Secret), consumerCall(), matcher.Allowed)
	info, err := s.InspectGrant(context.Background(), old.Grant.ID)
	if err != nil || info.Tool != "wp_update_post" || info.TemplateVersion != 1 {
		t.Fatal("historical grant changed with policy")
	}
}
func TestTargetChangesAndPolicyRollback(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	p := applyTestPolicy(t, s)
	p.Targets["a-new"] = p.Targets["wp"]
	target := p.Targets["wp"]
	target.URL = "https://different.example/api"
	p.Targets["wp"] = target
	if err := s.ApplyPolicy(context.Background(), p); !errors.Is(err, ErrTargetChanged) {
		t.Fatal(err)
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM targets WHERE id='a-new'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed reload partially wrote targets")
	}
	issue(t, s, issueRequest()) // Old active set was preserved on rollback.
	mustExec(t, s, `CREATE TRIGGER fail_activation BEFORE INSERT ON active_templates BEGIN SELECT RAISE(ABORT,'injected activation failure'); END`)
	if err := s.ApplyPolicy(context.Background(), testPolicy(t)); err == nil {
		t.Fatal("injected reload failure succeeded")
	}
	mustExec(t, s, `DROP TRIGGER fail_activation`)
	issue(t, s, issueRequest())
}
func TestHashBoundIssueDoesNotPersistPlaintext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	s := openTest(t, path)
	p := testPolicy(t)
	tmpl := p.Templates["edit"]
	tmpl.Args["content"] = policy.Constraint{Type: "string", Bind: "required", SHA256: true}
	p.Templates["edit"] = tmpl
	if err := s.ApplyPolicy(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	r := issueRequest()
	plain := "test-only-hash-bound-content-834912"
	encoded, _ := json.Marshal(plain)
	r.Args["content"] = encoded
	g := issue(t, s, r)
	b := g.Grant.BoundArgs["content"]
	if b.SHA256 == "" || len(b.Value) != 0 {
		t.Fatal("hash binding kept plaintext")
	}
	c := consumerCall()
	c.Args["content"] = encoded
	consumeCheck(t, s, string(g.Secret), c, matcher.Allowed)
	files, _ := filepath.Glob(path + "*")
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(plain)) {
			t.Fatal("hash-bound plaintext persisted")
		}
	}
}
func TestIssueFailureAndUnknownOperations(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	applyTestPolicy(t, s)
	if _, err := s.InspectGrant(context.Background(), "missing"); !errors.Is(err, ErrGrantUnknown) {
		t.Fatal(err)
	}
	if _, err := s.RevokeGrant(context.Background(), "missing", "operator"); !errors.Is(err, ErrGrantUnknown) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if g, err := s.IssueGrant(ctx, issueRequest()); err == nil || g.Secret != "" {
		t.Fatal("canceled issue returned a secret")
	}
	mustExec(t, s, `CREATE TABLE issue_commit_failure (target_id TEXT REFERENCES targets(id) DEFERRABLE INITIALLY DEFERRED)`)
	mustExec(t, s, `CREATE TRIGGER inject_issue_commit_failure AFTER INSERT ON grants BEGIN INSERT INTO issue_commit_failure VALUES ('missing'); END`)
	if g, err := s.IssueGrant(context.Background(), issueRequest()); err == nil || g.Secret != "" || g.Grant.ID != "" {
		t.Fatal("failed commit returned an issued secret")
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM grants`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed commit left a grant")
	}
	mustExec(t, s, `DROP TRIGGER inject_issue_commit_failure`)
	issue(t, s, issueRequest())
}
func TestConcurrentRevokeAndConsume(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	a := openTest(t, path)
	applyTestPolicy(t, a)
	b := openTest(t, path)
	for i := 0; i < 25; i++ {
		g := issue(t, a, issueRequest())
		start := make(chan struct{})
		var wg sync.WaitGroup
		var d matcher.Decision
		var consumeErr, revokeErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			d, consumeErr = a.Consume(context.Background(), string(g.Secret), consumerCall())
		}()
		go func() {
			defer wg.Done()
			<-start
			_, revokeErr = b.RevokeGrant(context.Background(), g.Grant.ID, "operator")
		}()
		close(start)
		wg.Wait()
		if consumeErr != nil || revokeErr != nil {
			t.Fatalf("consume=%v revoke=%v", consumeErr, revokeErr)
		}
		info, err := a.InspectGrant(context.Background(), g.Grant.ID)
		if err != nil || info.State != "revoked" {
			t.Fatal("revocation lost")
		}
		if d.Allowed {
			if info.UsesLeft != 0 {
				t.Fatal("allowed call did not consume")
			}
		} else if d.Code != matcher.GrantRevoked || info.UsesLeft != 1 {
			t.Fatal("revocation race produced invalid outcome")
		}
	}
}

func TestSchemaOneUpgradePreservesData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = raw.Exec(initialSchema); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if _, err = raw.Exec(`PRAGMA user_version=1`); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	seed(t, &Store{db: raw})
	if err = raw.Close(); err != nil {
		t.Fatal(err)
	}
	s := openTest(t, path)
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM templates WHERE id='edit' AND version=1`).Scan(&count); err != nil || count != 1 {
		t.Fatal("upgrade lost historical templates")
	}
	if err = s.db.QueryRow(`SELECT count(*) FROM active_templates`).Scan(&count); err != nil || count != 0 {
		t.Fatal("upgrade unexpectedly activated historical templates")
	}
	if g, err := s.IssueGrant(context.Background(), issueRequest()); !errors.Is(err, ErrTemplateUnknown) || g.Secret != "" {
		t.Fatal("old schema's templates became issuable without applying policy")
	}
}

func TestRESTIssueAndExpiredInspection(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	p := testPolicy(t)
	target := p.Targets["wp"]
	target.Kind = "http"
	p.Targets["wp"] = target
	tmpl := p.Templates["edit"]
	tmpl.Tool = ""
	tmpl.Method = "PATCH"
	tmpl.Path = "/posts/{id}"
	tmpl.Query = map[string]policy.Constraint{"context": {Type: "string", Bind: "required"}}
	p.Templates["edit"] = tmpl
	if err := s.ApplyPolicy(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	r := issueRequest()
	r.Query = map[string]json.RawMessage{"context": json.RawMessage(`"edit"`)}
	g := issue(t, s, r)
	c := consumerCall()
	c.Tool = ""
	c.Method = "PATCH"
	c.Path = "/posts/2"
	delete(c.Args, "id")
	c.Query = r.Query
	consumeCheck(t, s, string(g.Secret), c, matcher.Allowed)
	info, err := s.InspectGrant(context.Background(), g.Grant.ID)
	if err != nil || info.State != "exhausted" || info.Decisions[0].Action != "PATCH /posts/2" {
		t.Fatal("REST inspection incorrect")
	}
	g = issue(t, s, r)
	at := time.Now()
	mustExec(t, s, `UPDATE grants SET created_at=?,expires_at=? WHERE id=?`, at.Add(-time.Minute).UnixMilli(), at.Add(-time.Second).UnixMilli(), g.Grant.ID)
	info, err = s.InspectGrant(context.Background(), g.Grant.ID)
	if err != nil || info.State != "expired" {
		t.Fatal("expired inspection incorrect")
	}
	consumeCheck(t, s, string(g.Secret), c, matcher.GrantExpired)
}

func TestInspectionDecisionWindow(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	applyTestPolicy(t, s)
	g := issue(t, s, issueRequest())
	c := consumerCall()
	c.Args["id"] = json.RawMessage(`3`)
	for i := 0; i < 105; i++ {
		consumeCheck(t, s, string(g.Secret), c, matcher.ArgMismatch)
	}
	info, err := s.InspectGrant(context.Background(), g.Grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if info.DecisionCount != 105 || len(info.Decisions) != 100 || info.Decisions[0].ID <= info.Decisions[99].ID {
		t.Fatal("inspection history was not bounded and newest first")
	}
}
