package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func mustExec(t *testing.T, s *Store, query string, args ...any) {
	t.Helper()
	if _, err := s.db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}
func openTest(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func seed(t *testing.T, s *Store) {
	t.Helper()
	mustExec(t, s, `INSERT INTO targets (id,kind,url_or_cmd,credential_type,credential_ref,created_at) VALUES ('wp','mcp_http','https://example.com/mcp','basic','vault:wp',1000)`)
	mustExec(t, s, `INSERT INTO templates (id,version,target_id,tool,constraints_json,max_ttl_s,max_uses,created_at) VALUES ('edit',1,'wp','wp_update_post','{}',900,1,1000)`)
}
func insertGrant(s *Store, id string, version, uses int, hash []byte) error {
	_, err := s.db.Exec(`INSERT INTO grants (id,secret_hash,template_id,template_version,bound_args_json,initial_uses,uses_left,expires_at,issued_to,reason,issued_by,created_at) VALUES (?,?,'edit',?,'{"id":2}',1,?,2000,'bot','fix typo','operator',1000)`, id, hash, version, uses)
	return err
}
func TestOpenReopenAndSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokening ?#%.db")
	s := openTest(t, path)
	for _, tt := range []struct{ pragma, want string }{{"journal_mode", "wal"}, {"foreign_keys", "1"}, {"synchronous", "2"}, {"busy_timeout", "5000"}, {"user_version", "1"}} {
		var got string
		if err := s.db.QueryRow("PRAGMA " + tt.pragma).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != tt.want {
			t.Errorf("%s=%s want %s", tt.pragma, got, tt.want)
		}
	}
	seed(t, s)
	if err := insertGrant(s, "g1", 1, 1, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openTest(t, path)
	var uses int
	if err := s.db.QueryRow(`SELECT uses_left FROM grants WHERE id='g1'`).Scan(&uses); err != nil || uses != 1 {
		t.Fatalf("uses=%d err=%v", uses, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("mode=%v", info.Mode())
		}
	}
}
func TestConnectionReplacementRetainsSettings(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	s.db.SetMaxIdleConns(0)
	for _, pragma := range []string{"foreign_keys", "synchronous", "busy_timeout"} {
		var got int
		if err := s.db.QueryRow("PRAGMA " + pragma).Scan(&got); err != nil {
			t.Fatal(err)
		}
		want := map[string]int{"foreign_keys": 1, "synchronous": 2, "busy_timeout": 5000}[pragma]
		if got != want {
			t.Fatalf("%s=%d", pragma, got)
		}
	}
}
func TestGrantAndTemplateIntegrity(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	seed(t, s)
	for _, tt := range []struct {
		name                   string
		version, uses, hashLen int
	}{{"missing version", 2, 1, 32}, {"negative uses", 1, -1, 32}, {"increased uses", 1, 2, 32}, {"short hash", 1, 1, 31}} {
		t.Run(tt.name, func(t *testing.T) {
			if err := insertGrant(s, "bad", tt.version, tt.uses, make([]byte, tt.hashLen)); err == nil {
				t.Fatal("invalid grant accepted")
			}
		})
	}
	if err := insertGrant(s, "g1", 1, 1, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if err := insertGrant(s, "g2", 1, 1, make([]byte, 32)); err == nil {
		t.Fatal("duplicate secret hash accepted")
	}
	for _, q := range []string{
		`UPDATE templates SET max_uses=99 WHERE id='edit'`,
		`DELETE FROM templates WHERE id='edit'`,
		`UPDATE grants SET bound_args_json='[]' WHERE id='g1'`,
		`UPDATE grants SET bound_args_json='not json' WHERE id='g1'`,
		`UPDATE grants SET secret_hash='plaintext' WHERE id='g1'`,
		`UPDATE grants SET expires_at=created_at WHERE id='g1'`,
		`UPDATE grants SET revoked_at=1500 WHERE id='g1'`,
	} {
		if _, err := s.db.Exec(q); err == nil {
			t.Errorf("accepted: %s", q)
		}
	}
	mustExec(t, s, `INSERT INTO templates (id,version,target_id,tool,constraints_json,max_ttl_s,max_uses,created_at) VALUES ('edit',2,'wp','wp_update_post','{"changed":true}',300,2,1500)`)
	var version int
	if err := s.db.QueryRow(`SELECT template_version FROM grants WHERE id='g1'`).Scan(&version); err != nil || version != 1 {
		t.Fatalf("live grant changed version: %d %v", version, err)
	}
}
func TestDecisionsAppendOnly(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	// Unknown tokens have no grant ID. A refusal must still be recordable.
	mustExec(t, s, `INSERT INTO decisions (grant_id,at,agent,tool,args_digest,outcome,code,reason) VALUES (NULL,1000,'bot','wp_update_post',?,'refused','grant_unknown','No grant matches this token.')`, make([]byte, 32))
	for _, q := range []string{`UPDATE decisions SET reason='changed'`, `DELETE FROM decisions`} {
		if _, err := s.db.Exec(q); err == nil {
			t.Fatalf("accepted audit mutation: %s", q)
		}
	}
}
func TestMigrationRollbackAndFutureVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	s := openTest(t, path)
	steps := []string{initialSchema, `CREATE TABLE rollback_probe (id INTEGER); INSERT INTO nonexistent_table VALUES (1);`}
	if err := migrate(context.Background(), s.db, steps); err == nil {
		t.Fatal("invalid migration succeeded")
	}
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 1 {
		t.Fatalf("failed migration advanced version: %d", version)
	}
	var count int
	if err := s.db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='rollback_probe'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("failed migration left partial schema")
	}
	mustExec(t, s, "PRAGMA user_version=999")
	s.Close()
	if next, err := Open(context.Background(), path); err == nil {
		next.Close()
		t.Fatal("newer schema accepted")
	} else if !strings.Contains(err.Error(), "newer") {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := raw.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 999 {
		t.Fatalf("newer schema was modified: %d %v", version, err)
	}
}
func TestConcurrentOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			s, err := Open(context.Background(), path)
			if err == nil {
				err = s.Close()
			}
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
}
func TestInvalidPathsAndCancellation(t *testing.T) {
	for _, path := range []string{"", ":memory:", "file:bad?mode=memory", t.TempDir(), filepath.Join(t.TempDir(), "missing", "db")} {
		if s, err := Open(context.Background(), path); err == nil {
			s.Close()
			t.Errorf("accepted path %q", path)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s, err := Open(ctx, filepath.Join(t.TempDir(), "db")); err == nil {
		s.Close()
		t.Fatal("canceled open succeeded")
	}
	if runtime.GOOS != "windows" {
		dir := t.TempDir()
		target := filepath.Join(dir, "target")
		if err := os.WriteFile(target, nil, 0600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if s, err := Open(context.Background(), link); err == nil {
			s.Close()
			t.Fatal("database symlink accepted")
		}
	}
}
