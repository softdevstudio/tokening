package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/softdevstudio/tokening/internal/matcher"
	"github.com/softdevstudio/tokening/internal/policy"
	"github.com/softdevstudio/tokening/internal/store"
)

// flightDB builds a database through the real store: one grant, a refused
// call, an allowed call with its upstream result, and a revocation.
func flightDB(t *testing.T) (string, string) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tokening.db")
	s, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p, _, err := policy.Load("../../examples/wordpress.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ApplyPolicy(ctx, *p); err != nil {
		t.Fatal(err)
	}
	g, err := s.IssueGrant(ctx, store.IssueRequest{Template: "wp.edit-post-text", Uses: 1, TTL: 5 * time.Minute, Args: map[string]json.RawMessage{"id": json.RawMessage(`2`)}, IssuedTo: "editor-bot", IssuedBy: "operator", Reason: "fix title"})
	if err != nil {
		t.Fatal(err)
	}
	call := matcher.Call{Target: "demo-wp", Tool: "wp_update_post", Args: map[string]json.RawMessage{"id": json.RawMessage(`3`), "title": json.RawMessage(`"Private draft words"`)}}
	if _, err = s.Consume(ctx, string(g.Secret), call); err != nil {
		t.Fatal(err)
	}
	call.Args["id"] = json.RawMessage(`2`)
	ok, err := s.Consume(ctx, string(g.Secret), call)
	if err != nil || !ok.Allowed {
		t.Fatalf("%+v %v", ok, err)
	}
	if err = s.CompleteUpstream(ctx, ok, 200, 40*time.Millisecond, false); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RevokeGrant(ctx, g.Grant.ID, "operator"); err != nil {
		t.Fatal(err)
	}
	return path, g.Grant.ID
}

func flightRun(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := run(append([]string{"flight"}, args...), &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestFlightCLI(t *testing.T) {
	db, grant := flightDB(t)
	code, out, errOut := flightRun("verify", "--db", db)
	if code != 0 || !strings.Contains(out, "Intact: 7 entries, 1 to 7.") || !strings.Contains(out, "Head: 7:") {
		t.Fatalf("verify: %d %s %s", code, out, errOut)
	}
	code, head, _ := flightRun("head", "--db", db)
	head = strings.TrimSpace(head)
	if code != 0 || !strings.HasPrefix(head, "7:") || len(head) != 66 {
		t.Fatalf("head: %d %q", code, head)
	}
	if code, out, _ = flightRun("verify", "--db", db, "--head", head); code != 0 || !strings.Contains(out, "saved head is in the chain") {
		t.Fatalf("verify head: %d %s", code, out)
	}
	export := filepath.Join(t.TempDir(), "flight.jsonl")
	if code, _, errOut = flightRun("export", "--db", db, "--output", export); code != 0 || !strings.Contains(errOut, "Exported 7 entries.") {
		t.Fatalf("export: %d %s", code, errOut)
	}
	if code, _, errOut = flightRun("export", "--db", db, "--output", export); code != 1 || !strings.Contains(errOut, "never overwritten") {
		t.Fatalf("overwrite: %d %s", code, errOut)
	}
	data, _ := os.ReadFile(export)
	if strings.Contains(string(data), "Private draft words") || strings.Contains(string(data), "tkn_") {
		t.Fatal("export holds argument text or a secret")
	}
	if code, out, _ = flightRun("verify", "--file", export, "--head", head); code != 0 || !strings.Contains(out, "Intact: 7 entries") {
		t.Fatalf("verify file: %d %s", code, out)
	}
	code, out, _ = flightRun("replay", "--db", db, "--agent", "editor-bot")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if code != 0 || len(lines) != 8 || !strings.Contains(lines[0], "issued to editor-bot by operator: wp.edit-post-text") ||
		!strings.Contains(lines[2], "refused (arg_mismatch)") || !strings.Contains(lines[4], "allowed") ||
		!strings.Contains(lines[5], "HTTP 200") || !strings.Contains(lines[6], "revoked by operator") || lines[7] != "Chain intact through entry 7." {
		t.Fatalf("replay: %d\n%s", code, out)
	}
	if code, out, _ = flightRun("replay", "--db", db, "--grant", "g_none"); code != 0 || !strings.Contains(out, "No entries match.") {
		t.Fatalf("replay filter: %d %s", code, out)
	}
	if code, out, _ = flightRun("replay", "--file", export, "--grant", grant); code != 0 || strings.Count(out, "\n") != 8 {
		t.Fatalf("replay file: %d %s", code, out)
	}
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	filtered := filepath.Join(t.TempDir(), "filtered.jsonl")
	if code, _, errOut = flightRun("export", "--db", db, "--since", future, "--output", filtered); code != 0 || !strings.Contains(errOut, "Exported 0 entries.") {
		t.Fatalf("since filter: %d %s", code, errOut)
	}
	decisions := filepath.Join(t.TempDir(), "decisions.jsonl")
	if code, _, _ = flightRun("export", "--db", db, "--agent", "editor-bot", "--until", "2999-01-01", "--output", decisions); code != 0 {
		t.Fatal("until filter")
	}
}

func TestFlightCLIBrokenFiles(t *testing.T) {
	db, _ := flightDB(t)
	_, export, _ := flightRun("export", "--db", db)
	lines := strings.SplitAfter(export, "\n")
	dir := t.TempDir()
	write := func(name, text string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	edited := strings.Replace(export, `"reason":"fix title"`, `"reason":"routine"`, 1)
	if code, out, _ := flightRun("verify", "--file", write("edited", edited)); code != 1 || !strings.Contains(out, "Broken at entry 1:") {
		t.Fatalf("edited: %d %s", code, out)
	}
	deleted := strings.Join(append(append([]string{}, lines[:3]...), lines[4:]...), "")
	if code, out, _ := flightRun("verify", "--file", write("deleted", deleted)); code != 1 || !strings.Contains(out, "Broken at entry 5: entry 4 is missing") || !strings.Contains(out, "Entries 1 to 3 verify") {
		t.Fatalf("deleted: %d %s", code, out)
	}
	cut := export[:len(export)-20]
	if code, out, _ := flightRun("verify", "--file", write("cut", cut)); code != 1 || !strings.Contains(out, "entries up to 6 verify; line 7") {
		t.Fatalf("cut: %d %s", code, out)
	}
	_, head, _ := flightRun("head", "--db", db)
	truncated := strings.Join(lines[:6], "")
	if code, out, _ := flightRun("verify", "--file", write("truncated", truncated), "--head", strings.TrimSpace(head)); code != 1 || !strings.Contains(out, "removed from the end") {
		t.Fatalf("truncated: %d %s", code, out)
	}
	partial := strings.Join([]string{lines[0], lines[2], lines[5]}, "")
	path := write("partial", partial)
	if code, _, _ := flightRun("verify", "--file", path); code != 1 {
		t.Fatal("a partial export must not pass as whole")
	}
	if code, out, _ := flightRun("verify", "--file", path, "--partial"); code != 0 || !strings.Contains(out, "partial export: 3 entries") {
		t.Fatalf("partial: %d %s", code, out)
	}
	if code, out, _ := flightRun("replay", "--file", write("edited2", edited)); code != 1 || !strings.Contains(out, "Warning: the chain is broken at entry 1") {
		t.Fatalf("replay broken: %d %s", code, out)
	}
}

func TestFlightCLIUsageErrors(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{
		{},
		{"unknown"},
		{"verify", "--db", "x", "--file", "y"},
		{"verify", "--db", "x", "--partial"},
		{"verify", "--file", "y", "--head", "bad"},
		{"export", "--since", "yesterday"},
		{"export", "--since", "2026-10-31", "--until", "2026-10-30"},
		{"head", "extra"},
	} {
		if code, _, _ := flightRun(args...); code != 2 {
			t.Fatalf("%v exit %d", args, code)
		}
	}
	if code, _, errOut := flightRun("verify", "--db", filepath.Join(dir, "missing.db")); code != 1 || errOut == "" {
		t.Fatalf("missing db: %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "missing.db")); err == nil {
		t.Fatal("verify created a database")
	}
	if code, out, _ := flightRun("help"); code != 0 || !strings.Contains(out, "tokening flight verify") {
		t.Fatal("help")
	}
	empty := filepath.Join(dir, "empty.db")
	s, err := store.Open(context.Background(), empty)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if code, _, errOut := flightRun("head", "--db", empty); code != 1 || !strings.Contains(errOut, "empty") {
		t.Fatalf("empty head: %d %s", code, errOut)
	}
	if code, out, _ := flightRun("verify", "--db", empty); code != 0 || !strings.Contains(out, "empty") {
		t.Fatalf("empty verify: %d %s", code, out)
	}
}

// Review v0.1.3: replay --file used to end with "Chain intact" even when
// entries had been cut out of the file. A file with gaps must say so.
func TestFlightReplayFileWithGapsIsNotCalledIntact(t *testing.T) {
	db, _ := flightDB(t)
	_, export, _ := flightRun("export", "--db", db)
	lines := strings.SplitAfter(export, "\n")
	deleted := strings.Join(append(append([]string{}, lines[:2]...), lines[3:]...), "")
	path := filepath.Join(t.TempDir(), "deleted.jsonl")
	if err := os.WriteFile(path, []byte(deleted), 0600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := flightRun("replay", "--file", path)
	if strings.Contains(out, "Chain intact") || !strings.Contains(out, "missing from this file") {
		t.Fatalf("replay of a file with a removed entry: %d\n%s", code, out)
	}
	whole := filepath.Join(t.TempDir(), "whole.jsonl")
	if err := os.WriteFile(whole, []byte(export), 0600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ = flightRun("replay", "--file", whole); code != 0 || !strings.Contains(out, "Chain intact through entry 7.") {
		t.Fatalf("whole file: %d\n%s", code, out)
	}
}
