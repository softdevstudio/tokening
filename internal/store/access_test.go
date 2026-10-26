package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestUpstreamCompletionIsLinkedAndAppendOnly(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	seedConsumer(t, s, 1)
	receipt, err := s.Consume(context.Background(), "test-secret-0", consumerCall())
	if err != nil || receipt.ReceiptID <= 0 {
		t.Fatal("missing authorization receipt")
	}
	if err = s.CompleteUpstream(context.Background(), receipt, 500, 25*time.Millisecond, true); err != nil {
		t.Fatal(err)
	}
	if err = s.CompleteUpstream(context.Background(), receipt, 200, time.Millisecond, false); err == nil {
		t.Fatal("duplicate completion accepted")
	}
	rows, err := s.ListDecisions(context.Background(), DecisionFilter{}, 10)
	if err != nil || len(rows) != 2 || rows[0].AuthorizationID != nil || rows[1].AuthorizationID == nil || *rows[1].AuthorizationID != receipt.ReceiptID || rows[1].Code != "upstream_error" {
		t.Fatal("completion linkage incorrect")
	}
	if remaining(t, s, "g_0") != 0 {
		t.Fatal("completion refunded a use")
	}
	receipt.ReceiptID = 99999
	if err = s.CompleteUpstream(context.Background(), receipt, 200, 0, false); err == nil {
		t.Fatal("forged receipt accepted")
	}
}
