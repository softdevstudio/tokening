package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/softdevstudio/tokening/internal/matcher"
)

func consumerCall() matcher.Call {
	return matcher.Call{Target: "wp", Tool: "wp_update_post", Args: map[string]json.RawMessage{"id": json.RawMessage(`2`), "title": json.RawMessage(`"Fixed title"`)}}
}
func seedConsumer(t *testing.T, s *Store, count int) {
	t.Helper()
	mustExec(t, s, `INSERT INTO targets (id,kind,url_or_cmd,credential_type,credential_ref,created_at) VALUES ('wp','mcp_http','https://example.com/mcp','basic','vault:wp',?)`, time.Now().UnixMilli())
	mustExec(t, s, `INSERT INTO templates (id,version,target_id,tool,constraints_json,max_ttl_s,max_uses,created_at) VALUES ('edit',1,'wp','wp_update_post',?,900,3,?)`, `{"args":{"id":{"bind":"required"},"title":{"type":"string","max_len":200}}}`, time.Now().UnixMilli())
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO grants (id,secret_hash,template_id,template_version,bound_args_json,initial_uses,uses_left,expires_at,issued_to,reason,issued_by,created_at) VALUES (?,?,'edit',1,'{"id":{"value":2}}',1,1,?,'test-bot','fix title','operator',?)`)
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()
	at := time.Now()
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("g_%d", i)
		hash := sha256.Sum256([]byte(fmt.Sprintf("test-secret-%d", i)))
		if _, err = stmt.Exec(id, hash[:], at.Add(10*time.Minute).UnixMilli(), at.UnixMilli()); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
}
func consumeCheck(t *testing.T, s *Store, secret string, call matcher.Call, want matcher.Code) {
	t.Helper()
	d, err := s.Consume(context.Background(), secret, call)
	if err != nil || d.Code != want || d.Allowed != (want == matcher.Allowed) {
		t.Fatalf("want=%s decision=%+v error=%v", want, d, err)
	}
}
func remaining(t *testing.T, s *Store, id string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT uses_left FROM grants WHERE id=?`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
func TestConsumeAndRefuse(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	seedConsumer(t, s, 1)
	c := consumerCall()
	c.Args["id"] = json.RawMessage(`3`)
	consumeCheck(t, s, "test-secret-0", c, matcher.ArgMismatch)
	if remaining(t, s, "g_0") != 1 {
		t.Fatal("refusal consumed a use")
	}
	consumeCheck(t, s, "wrong-secret", consumerCall(), matcher.GrantUnknown)
	consumeCheck(t, s, "g_0", consumerCall(), matcher.GrantUnknown) // An ID is not a bearer secret.
	consumeCheck(t, s, "test-secret-0", consumerCall(), matcher.Allowed)
	consumeCheck(t, s, "test-secret-0", consumerCall(), matcher.GrantExhausted)
	if remaining(t, s, "g_0") != 0 {
		t.Fatal("allowed call did not consume exactly one use")
	}
	var used sql.NullInt64
	if err := s.db.QueryRow(`SELECT last_used_at FROM grants WHERE id='g_0'`).Scan(&used); err != nil || !used.Valid {
		t.Fatalf("last-used not recorded: %v", err)
	}
	var unknowns, allowed, refused int
	if err := s.db.QueryRow(`SELECT count(*) FROM decisions WHERE grant_id IS NULL AND code='grant_unknown'`).Scan(&unknowns); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM decisions WHERE outcome='allowed'`).Scan(&allowed); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM decisions WHERE outcome='refused'`).Scan(&refused); err != nil {
		t.Fatal(err)
	}
	if unknowns != 2 || allowed != 1 || refused != 4 {
		t.Fatalf("audit counts unknown=%d allowed=%d refused=%d", unknowns, allowed, refused)
	}
}
func TestConsumeSingleUseRace1000(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	first := openTest(t, path)
	seedConsumer(t, first, 1000)
	second := openTest(t, path)
	stores := []*Store{first, second}
	completedRuns := 0
	for run := 0; run < 1000; run++ {
		start := make(chan struct{})
		results := make(chan matcher.Decision, 2)
		errs := make(chan error, 2)
		var wg sync.WaitGroup
		for _, s := range stores {
			wg.Add(1)
			go func(s *Store) {
				defer wg.Done()
				<-start
				d, err := s.Consume(context.Background(), fmt.Sprintf("test-secret-%d", run), consumerCall())
				results <- d.Decision
				errs <- err
			}(s)
		}
		close(start)
		wg.Wait()
		close(results)
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("run %d: %v", run, err)
			}
		}
		winners, losers := 0, 0
		for d := range results {
			if d.Allowed && d.Code == matcher.Allowed {
				winners++
			} else if !d.Allowed && d.Code == matcher.GrantExhausted {
				losers++
			} else {
				t.Fatalf("run %d: unexpected decision %+v", run, d)
			}
		}
		if winners != 1 || losers != 1 {
			t.Fatalf("run %d: winners=%d losers=%d", run, winners, losers)
		}
		completedRuns++
	}
	var left, winners, losers int
	if err := first.db.QueryRow(`SELECT sum(uses_left) FROM grants`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if err := first.db.QueryRow(`SELECT count(*) FROM decisions WHERE code='allowed'`).Scan(&winners); err != nil {
		t.Fatal(err)
	}
	if err := first.db.QueryRow(`SELECT count(*) FROM decisions WHERE code='grant_exhausted'`).Scan(&losers); err != nil {
		t.Fatal(err)
	}
	if left != 0 || winners != 1000 || losers != 1000 {
		t.Fatalf("left=%d winners=%d losers=%d", left, winners, losers)
	}
	t.Logf(`{"consumer_race":{"runs":%d,"callers_per_run":%d,"allowed":%d,"exhausted":%d,"remaining_uses":%d}}`, completedRuns, len(stores), winners, losers, left)
}
func TestConsumeAuditFailureRollsBack(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	seedConsumer(t, s, 1)
	mustExec(t, s, `CREATE TRIGGER fail_decision BEFORE INSERT ON decisions BEGIN SELECT RAISE(ABORT,'injected audit failure'); END`)
	if d, err := s.Consume(context.Background(), "test-secret-0", consumerCall()); err == nil || d.Allowed {
		t.Fatalf("audit failure allowed forwarding: %+v %v", d, err)
	}
	if remaining(t, s, "g_0") != 1 {
		t.Fatal("audit failure left a partial decrement")
	}
	mustExec(t, s, `DROP TRIGGER fail_decision`)
	consumeCheck(t, s, "test-secret-0", consumerCall(), matcher.Allowed)
}
func TestConsumeExpiryAfterMatch(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	seedConsumer(t, s, 1)
	expiry := time.Now().Add(time.Minute).Truncate(time.Millisecond)
	mustExec(t, s, `UPDATE grants SET expires_at=? WHERE id='g_0'`, expiry.UnixMilli())
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	samples := 0
	clock := func() time.Time {
		samples++
		if samples == 1 {
			return expiry.Add(-time.Millisecond)
		}
		return expiry
	}
	d, err := consumeInTx(context.Background(), tx, sha256.Sum256([]byte("test-secret-0")), consumerCall(), clock)
	if err != nil || d.Code != matcher.GrantExpired || d.Allowed {
		t.Fatalf("expiry during match: %+v %v", d, err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if remaining(t, s, "g_0") != 1 {
		t.Fatal("expired grant consumed")
	}
}
func TestConsumeSavedTemplateAndRevocation(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	seedConsumer(t, s, 2)
	// A policy reload adds a new version. Existing grants keep version one.
	mustExec(t, s, `INSERT INTO templates (id,version,target_id,tool,constraints_json,max_ttl_s,max_uses,created_at) VALUES ('edit',2,'wp','wp_delete_post','{"args":{"id":{"bind":"required"}}}',900,3,?)`, time.Now().UnixMilli())
	attempt := consumerCall()
	attempt.Tool = "wp_delete_post"
	consumeCheck(t, s, "test-secret-0", attempt, matcher.ToolNotAllowed)
	consumeCheck(t, s, "test-secret-0", consumerCall(), matcher.Allowed)
	// A grant revoked before consumption must keep its allowance.
	mustExec(t, s, `UPDATE grants SET revoked_at=?,revoked_by='operator' WHERE id='g_1'`, time.Now().UnixMilli())
	consumeCheck(t, s, "test-secret-1", consumerCall(), matcher.GrantRevoked)
	if remaining(t, s, "g_1") != 1 {
		t.Fatal("revoked grant consumed")
	}
}
func TestConsumeCanceledAndCorrupt(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	seedConsumer(t, s, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if d, err := s.Consume(ctx, "test-secret-0", consumerCall()); err == nil || d.Allowed {
		t.Fatal("canceled request accepted")
	}
	mustExec(t, s, `UPDATE grants SET bound_args_json='{}' WHERE id='g_0'`)
	if d, err := s.Consume(context.Background(), "test-secret-0", consumerCall()); err == nil || d.Allowed {
		t.Fatal("corrupt snapshot accepted")
	}
	if remaining(t, s, "g_0") != 1 {
		t.Fatal("error consumed a use")
	}
}

func TestConsumeCommitFailureRollsBack(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	seedConsumer(t, s, 1)
	mustExec(t, s, `CREATE TABLE commit_failure (target_id TEXT REFERENCES targets(id) DEFERRABLE INITIALLY DEFERRED)`)
	mustExec(t, s, `CREATE TRIGGER inject_commit_failure AFTER UPDATE OF uses_left ON grants BEGIN INSERT INTO commit_failure VALUES ('missing-target'); END`)
	d, err := s.Consume(context.Background(), "test-secret-0", consumerCall())
	if err == nil || d.Allowed {
		t.Fatalf("commit failure permitted forwarding: %+v %v", d, err)
	}
	if remaining(t, s, "g_0") != 1 {
		t.Fatalf("commit failure did not roll back the decrement: %v", err)
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM decisions`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("failed commit left an audit row")
	}
	mustExec(t, s, `DROP TRIGGER inject_commit_failure`)
	consumeCheck(t, s, "test-secret-0", consumerCall(), matcher.Allowed)
}

func TestConsumeQueuedStateChange(t *testing.T) {
	for _, mode := range []string{"revoke", "expire"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "db")
			first := openTest(t, path)
			seedConsumer(t, first, 1)
			second := openTest(t, path)
			tx, err := first.db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			want := matcher.GrantRevoked
			if mode == "revoke" {
				_, err = tx.Exec(`UPDATE grants SET revoked_at=?,revoked_by='operator' WHERE id='g_0'`, time.Now().UnixMilli())
			} else {
				want = matcher.GrantExpired
				now := time.Now()
				_, err = tx.Exec(`UPDATE grants SET created_at=?,expires_at=? WHERE id='g_0'`, now.Add(-2*time.Minute).UnixMilli(), now.Add(-time.Minute).UnixMilli())
			}
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			type result struct {
				d   Consumption
				err error
			}
			started := make(chan struct{})
			done := make(chan result, 1)
			go func() {
				close(started)
				d, err := second.Consume(ctx, "test-secret-0", consumerCall())
				done <- result{d, err}
			}()
			<-started
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			got := <-done
			if got.err != nil || got.d.Code != want || got.d.Allowed {
				t.Fatalf("queued %s: %+v %v", mode, got.d, got.err)
			}
			if remaining(t, first, "g_0") != 1 {
				t.Fatal("state change consumed a use")
			}
		})
	}
}

func TestRevokeAfterAuthorization(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	seedConsumer(t, s, 1)
	mustExec(t, s, `UPDATE grants SET initial_uses=2,uses_left=2 WHERE id='g_0'`)
	consumeCheck(t, s, "test-secret-0", consumerCall(), matcher.Allowed)
	// The first call is now authorized to start forwarding. Revocation cannot
	// undo that committed reservation; it prevents all subsequent reservations.
	mustExec(t, s, `UPDATE grants SET revoked_at=?,revoked_by='operator' WHERE id='g_0'`, time.Now().UnixMilli())
	consumeCheck(t, s, "test-secret-0", consumerCall(), matcher.GrantRevoked)
	if remaining(t, s, "g_0") != 1 {
		t.Fatal("revocation refunded or consumed a use")
	}
}

func TestConsumeRESTSnapshot(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	seedConsumer(t, s, 1)
	mustExec(t, s, `UPDATE targets SET kind='http' WHERE id='wp'`)
	mustExec(t, s, `INSERT INTO templates (id,version,target_id,method,path,constraints_json,max_ttl_s,max_uses,created_at) VALUES ('rest',1,'wp','PATCH','/posts/{id}',?,900,3,?)`, `{"args":{"id":{"bind":"required"},"title":{"type":"string","max_len":200}},"query":{"context":{"type":"string","bind":"required"}}}`, time.Now().UnixMilli())
	mustExec(t, s, `UPDATE grants SET template_id='rest',bound_query_json='{"context":{"value":"edit"}}' WHERE id='g_0'`)
	c := consumerCall()
	c.Tool = ""
	c.Method = "PATCH"
	c.Path = "/posts/2"
	delete(c.Args, "id")
	c.Query = map[string]json.RawMessage{"context": json.RawMessage(`"edit"`)}
	consumeCheck(t, s, "test-secret-0", c, matcher.Allowed)
	var action string
	if err := s.db.QueryRow(`SELECT tool FROM decisions WHERE code='allowed'`).Scan(&action); err != nil || action != "PATCH /posts/2" {
		t.Fatalf("REST action=%q err=%v", action, err)
	}
}
