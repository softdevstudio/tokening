package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/softdevstudio/tokening/internal/matcher"
	"github.com/softdevstudio/tokening/internal/vault"
)

func auditRecords(t *testing.T, data []byte) []DecisionRecord {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	var records []DecisionRecord
	for {
		var row DecisionRecord
		err := decoder.Decode(&row)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, row)
	}
	return records
}
func seedAudit(t *testing.T, s *Store, count int) {
	t.Helper()
	seedConsumer(t, s, 1)
	if err := s.writeTx(context.Background(), func(tx *sql.Tx) error {
		for i := 0; i < count; i++ {
			d := matcher.Decision{Grant: "g_0", Code: matcher.ArgMismatch, Reason: "argument id does not match its bound value"}
			if i%3 == 0 {
				d = matcher.Decision{Code: matcher.GrantUnknown, Reason: "No grant matches this token."}
			}
			if err := recordDecision(context.Background(), tx, d, consumerCall(), "test-bot", time.UnixMilli(int64(10000-i))); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
func TestAuditExportDecisionsAndSecrecy(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	applyTestPolicy(t, s)
	g := issue(t, s, issueRequest())
	v, _ := vault.New(bytes.Repeat([]byte{17}, 32))
	if err := s.SetCredential(context.Background(), "wp", v, []byte("private-upstream-credential")); err != nil {
		t.Fatal(err)
	}
	c := consumerCall()
	c.Args["title"] = json.RawMessage(`"private-agent-title-content"`)
	c.Args["id"] = json.RawMessage(`3`)
	consumeCheck(t, s, string(g.Secret), c, matcher.ArgMismatch)
	c.Args["id"] = json.RawMessage(`2`)
	consumeCheck(t, s, string(g.Secret), c, matcher.Allowed)
	consumeCheck(t, s, string(g.Secret), c, matcher.GrantExhausted)
	consumeCheck(t, s, "unknown-private-bearer", c, matcher.GrantUnknown)
	var out bytes.Buffer
	result, err := s.ExportDecisions(context.Background(), &out, DecisionFilter{})
	if err != nil {
		t.Fatal(err)
	}
	rows := auditRecords(t, out.Bytes())
	if len(rows) != 4 || result.Rows != 4 || result.LastID != 4 || result.ThroughID != 4 {
		t.Fatalf("bad export result: %+v", result)
	}
	hash := sha256.Sum256([]byte(g.Secret))
	for _, secret := range []string{string(g.Secret), "unknown-private-bearer", "private-upstream-credential", "private-agent-title-content", hex.EncodeToString(hash[:])} {
		if strings.Contains(out.String(), secret) {
			t.Fatal("export included secret material")
		}
	}
	for i, row := range rows {
		if row.ID != int64(i+1) || len(row.ArgsDigest) != 64 || row.At.Location() != time.UTC {
			t.Fatal("invalid ordered audit record")
		}
		if row.UpstreamStatus != nil || row.LatencyMS != nil {
			t.Fatal("authorization row invented upstream metadata")
		}
	}
	if rows[0].GrantID == nil || *rows[0].GrantID != g.Grant.ID || rows[3].GrantID != nil {
		t.Fatal("grant association incorrect")
	}
	if bytes.Count(out.Bytes(), []byte{'\n'}) != 4 {
		t.Fatal("not one JSON object per line")
	}
	info, err := s.InspectGrant(context.Background(), g.Grant.ID)
	if err != nil || info.DecisionCount != 3 {
		t.Fatal("export altered decision history")
	}
}
func TestAuditPagingFiltersAndResume(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	seedAudit(t, s, 1005)
	page, err := s.ListDecisions(context.Background(), DecisionFilter{}, 3)
	if err != nil || len(page) != 3 || page[2].ID != 3 {
		t.Fatal("first page incorrect")
	}
	defaults, err := s.ListDecisions(context.Background(), DecisionFilter{}, 0)
	if err != nil || len(defaults) != 100 {
		t.Fatal("default page size incorrect")
	}
	missing, err := s.ListDecisions(context.Background(), DecisionFilter{GrantID: "missing"}, MaxDecisionPage)
	if err != nil || len(missing) != 0 {
		t.Fatal("unknown grant filter returned rows")
	}
	page, err = s.ListDecisions(context.Background(), DecisionFilter{AfterID: 3, GrantID: "g_0"}, 3)
	if err != nil || len(page) != 3 {
		t.Fatal(err)
	}
	for _, row := range page {
		if row.ID <= 3 || row.GrantID == nil || *row.GrantID != "g_0" {
			t.Fatal("filter or cursor ignored")
		}
	}
	var out bytes.Buffer
	result, err := s.ExportDecisions(context.Background(), &out, DecisionFilter{AfterID: 2})
	if err != nil {
		t.Fatal(err)
	}
	rows := auditRecords(t, out.Bytes())
	if len(rows) != 1003 || result.Rows != 1003 || rows[0].ID != 3 || rows[len(rows)-1].ID != 1005 {
		t.Fatal("multi-page export lost rows")
	}
	for i, row := range rows {
		if row.ID != int64(i+3) {
			t.Fatal("multi-page export duplicated or skipped rows")
		}
	}
	out.Reset()
	future, err := s.ExportDecisions(context.Background(), &out, DecisionFilter{AfterID: 2000})
	if err != nil || future.Rows != 0 || future.LastID != 2000 || future.ThroughID != 1005 || out.Len() != 0 {
		t.Fatal("future cursor was not preserved")
	}
	out.Reset()
	result, err = s.ExportDecisions(context.Background(), &out, DecisionFilter{AfterID: 1000, GrantID: "g_0"})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range auditRecords(t, out.Bytes()) {
		if row.ID <= 1000 || row.GrantID == nil {
			t.Fatal("filtered export incorrect")
		}
	}
	out.Reset()
	result, err = s.ExportDecisions(context.Background(), &out, DecisionFilter{AfterID: result.ThroughID})
	if err != nil || out.Len() != 0 || result.Rows != 0 {
		t.Fatal("exclusive cursor replayed old rows")
	}
}

type callbackWriter struct {
	buffer   bytes.Buffer
	callback func() error
	called   bool
}

func (w *callbackWriter) Write(p []byte) (int, error) {
	if !w.called {
		w.called = true
		if err := w.callback(); err != nil {
			return 0, err
		}
	}
	return w.buffer.Write(p)
}
func TestAuditExportReleasesConnectionAndFixesBoundary(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	seedAudit(t, s, 300)
	w := &callbackWriter{callback: func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		d, err := s.Consume(ctx, "fresh-unknown-bearer", consumerCall())
		if err != nil {
			return err
		}
		if d.Code != matcher.GrantUnknown {
			return errors.New("unexpected callback decision")
		}
		return nil
	}}
	result, err := s.ExportDecisions(context.Background(), w, DecisionFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Rows != 300 || result.ThroughID != 300 || len(auditRecords(t, w.buffer.Bytes())) != 300 {
		t.Fatal("concurrent append entered fixed export")
	}
	var next bytes.Buffer
	result, err = s.ExportDecisions(context.Background(), &next, DecisionFilter{AfterID: result.ThroughID})
	if err != nil || result.Rows != 1 || result.LastID != 301 {
		t.Fatal("next export did not pick up concurrent append")
	}
}

type failingWriter struct {
	calls int
	short bool
}

func (w *failingWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.short {
		return len(p) - 1, nil
	}
	if w.calls == 3 {
		return len(p) / 2, io.ErrClosedPipe
	}
	return len(p), nil
}
func TestAuditWriterErrorsAndCancellation(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	seedAudit(t, s, 5)
	result, err := s.ExportDecisions(context.Background(), &failingWriter{}, DecisionFilter{})
	if !errors.Is(err, io.ErrClosedPipe) || result.Rows != 2 || result.LastID != 2 {
		t.Fatalf("writer failure lost cursor: %+v %v", result, err)
	}
	result, err = s.ExportDecisions(context.Background(), &failingWriter{short: true}, DecisionFilter{})
	if !errors.Is(err, io.ErrShortWrite) || result.Rows != 0 || result.LastID != 0 {
		t.Fatal("short write was reported as successful")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	if _, err = s.ExportDecisions(ctx, &out, DecisionFilter{}); !errors.Is(err, context.Canceled) || out.Len() != 0 {
		t.Fatal("canceled export wrote output")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	w := &callbackWriter{callback: func() error { cancel(); return nil }}
	result, err = s.ExportDecisions(ctx, w, DecisionFilter{})
	if !errors.Is(err, context.Canceled) || result.Rows != 1 || result.LastID != 1 {
		t.Fatalf("mid-export cancellation cursor incorrect: %+v %v", result, err)
	}
	// Failed exports and cancellation must not damage the connection or mutate rows.
	page, err := s.ListDecisions(context.Background(), DecisionFilter{}, 10)
	if err != nil || len(page) != 5 {
		t.Fatal("export failure damaged store")
	}
}
func TestAuditEmptyAndInvalidQueries(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	var out bytes.Buffer
	result, err := s.ExportDecisions(context.Background(), &out, DecisionFilter{})
	if err != nil || out.Len() != 0 || result.Rows != 0 || result.ThroughID != 0 {
		t.Fatal("empty export incorrect")
	}
	for _, limit := range []int{-1, 1001} {
		if _, err := s.ListDecisions(context.Background(), DecisionFilter{}, limit); !errors.Is(err, ErrInvalidAuditQuery) {
			t.Fatal("invalid page limit accepted")
		}
	}
	if _, err = s.ListDecisions(context.Background(), DecisionFilter{AfterID: -1}, 1); !errors.Is(err, ErrInvalidAuditQuery) {
		t.Fatal("negative list cursor accepted")
	}
	if _, err = s.ExportDecisions(context.Background(), &out, DecisionFilter{AfterID: -1}); !errors.Is(err, ErrInvalidAuditQuery) {
		t.Fatal("negative export cursor accepted")
	}
	if _, err = s.ExportDecisions(context.Background(), nil, DecisionFilter{}); err == nil {
		t.Fatal("nil writer accepted")
	}
	s.Close()
	if _, err = s.ExportDecisions(context.Background(), &out, DecisionFilter{}); err == nil {
		t.Fatal("closed database export succeeded")
	}
}
func TestAuditOptionalUpstreamMetadata(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	seedAudit(t, s, 1)
	digest := sha256.Sum256([]byte("normalized call"))
	mustExec(t, s, `INSERT INTO decisions (grant_id,at,agent,tool,args_digest,outcome,code,reason,upstream_status,latency_ms)
 VALUES ('g_0',12345,'bot','wp_update_post',?,'allowed','upstream_error','The use remains consumed.',500,75)`, digest[:])
	var out bytes.Buffer
	if _, err := s.ExportDecisions(context.Background(), &out, DecisionFilter{}); err != nil {
		t.Fatal(err)
	}
	rows := auditRecords(t, out.Bytes())
	last := rows[len(rows)-1]
	if last.UpstreamStatus == nil || *last.UpstreamStatus != 500 || last.LatencyMS == nil || *last.LatencyMS != 75 || last.At.UnixMilli() != 12345 || last.Code != matcher.UpstreamError {
		t.Fatal(fmt.Sprintf("optional audit metadata incorrect: %+v", last))
	}
}
