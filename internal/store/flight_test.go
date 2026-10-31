package store

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/softdevstudio/tokening/internal/flight"
	"github.com/softdevstudio/tokening/internal/matcher"
)

func flightEntries(t *testing.T, s *Store, f flight.Filter) []flight.Entry {
	t.Helper()
	var out []flight.Entry
	if err := s.WalkFlight(context.Background(), f, func(e flight.Entry) error { out = append(out, e); return nil }); err != nil {
		t.Fatal(err)
	}
	return out
}

func verifyFlight(t *testing.T, s *Store, opts flight.Options) flight.Report {
	t.Helper()
	r, err := s.VerifyFlight(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// buildFlight runs rounds of issue, allowed call, upstream result, refused call
// and revocation through the real store methods: seven entries per round.
func buildFlight(t *testing.T, s *Store, rounds int) {
	t.Helper()
	ctx := context.Background()
	applyTestPolicy(t, s)
	for i := 0; i < rounds; i++ {
		r := issueRequest()
		r.Uses = 2
		g := issue(t, s, r)
		ok, err := s.Consume(ctx, string(g.Secret), consumerCall())
		if err != nil || !ok.Allowed {
			t.Fatalf("consume: %+v %v", ok, err)
		}
		if err = s.CompleteUpstream(ctx, ok, 200, 12*time.Millisecond, false); err != nil {
			t.Fatal(err)
		}
		wrong := consumerCall()
		wrong.Args["id"] = json.RawMessage(`3`)
		if d, err := s.Consume(ctx, string(g.Secret), wrong); err != nil || d.Code != matcher.ArgMismatch {
			t.Fatalf("refusal: %+v %v", d, err)
		}
		if _, err = s.RevokeGrant(ctx, g.Grant.ID, "operator"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFlightRecordsGrantRequestDecisionResult(t *testing.T) {
	ctx := context.Background()
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	applyTestPolicy(t, s)
	r := issueRequest()
	r.Uses = 2
	r.Reason = "fix <title> & intro"
	g := issue(t, s, r)
	wrong := consumerCall()
	wrong.Args["id"] = json.RawMessage(`3`)
	if _, err := s.Consume(ctx, string(g.Secret), wrong); err != nil {
		t.Fatal(err)
	}
	ok, err := s.Consume(ctx, string(g.Secret), consumerCall())
	if err != nil || !ok.Allowed {
		t.Fatal(err)
	}
	if err = s.CompleteUpstream(ctx, ok, 200, 84*time.Millisecond, false); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Consume(ctx, "tkn_not_a_grant", consumerCall()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err = s.RevokeGrant(ctx, g.Grant.ID, "night shift"); err != nil {
			t.Fatal(err)
		}
	}
	entries := flightEntries(t, s, flight.Filter{})
	want := []flight.Kind{flight.KindGrant, flight.KindRequest, flight.KindDecision, flight.KindRequest, flight.KindDecision, flight.KindResult, flight.KindRequest, flight.KindDecision, flight.KindGrant}
	if len(entries) != len(want) {
		t.Fatalf("entries=%d want %d", len(entries), len(want))
	}
	for i, e := range entries {
		if e.Kind != want[i] || e.Seq != uint64(i+1) {
			t.Fatalf("entry %d: %s seq %d", i, e.Kind, e.Seq)
		}
		unknown := i == 6 || i == 7
		if unknown != (e.Grant == "") || unknown != (e.Agent == "") {
			t.Fatalf("entry %d grant %q agent %q", i, e.Grant, e.Agent)
		}
		if !unknown && (e.Grant != g.Grant.ID || e.Agent != "editor-bot") {
			t.Fatalf("entry %d grant %q agent %q", i, e.Grant, e.Agent)
		}
	}
	var issued flight.GrantBody
	if err = json.Unmarshal(entries[0].Body, &issued); err != nil || issued.Event != "issued" || issued.Template != "edit" || issued.Uses != 2 || issued.IssuedBy != "operator" || issued.Reason != r.Reason || len(issued.Bound) != 1 || issued.Bound[0] != "id" || len(issued.BindingsDigest) != 64 {
		t.Fatalf("issued body %s", entries[0].Body)
	}
	var request flight.RequestBody
	if err = json.Unmarshal(entries[3].Body, &request); err != nil || request.Target != "wp" || request.Action != "wp_update_post" || strings.Join(request.Args, ",") != "id,title" || len(request.ArgsDigest) != 64 {
		t.Fatalf("request body %s", entries[3].Body)
	}
	var refused, allowed flight.DecisionBody
	json.Unmarshal(entries[2].Body, &refused)
	json.Unmarshal(entries[4].Body, &allowed)
	if refused.Code != "arg_mismatch" || refused.UsesLeft == nil || *refused.UsesLeft != 2 || allowed.Code != "allowed" || *allowed.UsesLeft != 1 || allowed.DecisionID != ok.ReceiptID {
		t.Fatalf("decisions %s %s", entries[2].Body, entries[4].Body)
	}
	var result flight.ResultBody
	if err = json.Unmarshal(entries[5].Body, &result); err != nil || result.AuthorizationID != ok.ReceiptID || result.UpstreamStatus == nil || *result.UpstreamStatus != 200 || result.LatencyMS != 84 {
		t.Fatalf("result %s", entries[5].Body)
	}
	var unknownDecision flight.DecisionBody
	json.Unmarshal(entries[7].Body, &unknownDecision)
	if unknownDecision.Code != "grant_unknown" || unknownDecision.UsesLeft != nil {
		t.Fatalf("unknown %s", entries[7].Body)
	}
	var revoked flight.GrantBody
	if json.Unmarshal(entries[8].Body, &revoked); revoked.Event != "revoked" || revoked.By != "night shift" {
		t.Fatalf("revoked %s", entries[8].Body)
	}
	// The request digest is the same one the decisions table holds.
	var digest []byte
	if err = s.db.QueryRow(`SELECT args_digest FROM decisions WHERE id=?`, ok.ReceiptID).Scan(&digest); err != nil || fmt.Sprintf("%x", digest) != request.ArgsDigest {
		t.Fatalf("digest mismatch %x %s", digest, request.ArgsDigest)
	}
	if rep := verifyFlight(t, s, flight.Options{}); !rep.OK || rep.Entries != 9 {
		t.Fatalf("verify %+v", rep)
	}
	head, found, err := s.FlightHead(ctx)
	if err != nil || !found || head.Seq != 9 || head.Hash != entries[8].Hash {
		t.Fatalf("head %+v %v %v", head, found, err)
	}
	if rep := verifyFlight(t, s, flight.Options{Head: &head}); !rep.OK || !rep.HeadFound {
		t.Fatalf("verify with head %+v", rep)
	}
	var buf bytes.Buffer
	n, err := s.ExportFlight(ctx, &buf, flight.Filter{})
	if err != nil || n != 9 {
		t.Fatal(n, err)
	}
	for _, secret := range []string{string(g.Secret), "Fixed title", "tkn_not_a_grant"} {
		if strings.Contains(buf.String(), secret) {
			t.Fatalf("export contains %q", secret)
		}
	}
	if rep, err := flight.VerifyReader(&buf, flight.Options{Head: &head}); err != nil || !rep.OK || rep.Entries != 9 {
		t.Fatalf("file verify %+v %v", rep, err)
	}
	if got := flightEntries(t, s, flight.Filter{Grant: g.Grant.ID}); len(got) != 7 {
		t.Fatalf("grant filter %d", len(got))
	}
	since, until := entries[3].Time(), entries[5].Time().Add(time.Millisecond)
	got := flightEntries(t, s, flight.Filter{Agent: "editor-bot", Since: since, Until: until})
	if len(got) < 3 {
		t.Fatalf("time filter %d", len(got))
	}
	for _, e := range got {
		if e.Agent != "editor-bot" || e.AtMS < since.UnixMilli() || e.AtMS >= until.UnixMilli() {
			t.Fatalf("time filter returned %+v", e)
		}
	}
	if got := flightEntries(t, s, flight.Filter{Agent: "nobody"}); len(got) != 0 {
		t.Fatal("agent filter")
	}
}

func TestFlightIsAppendOnly(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	buildFlight(t, s, 1)
	if _, err := s.db.Exec(`UPDATE flight SET agent='x' WHERE seq=1`); err == nil {
		t.Fatal("update allowed")
	}
	if _, err := s.db.Exec(`DELETE FROM flight WHERE seq=1`); err == nil {
		t.Fatal("delete allowed")
	}
}

// A failed flight append must undo the decision and the use with it.
func TestFlightAppendFailureRollsBackDecision(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	seedConsumer(t, s, 1)
	mustExec(t, s, `CREATE TRIGGER fail_flight BEFORE INSERT ON flight BEGIN SELECT RAISE(ABORT,'injected flight failure'); END`)
	if _, err := s.Consume(context.Background(), "test-secret-0", consumerCall()); err == nil {
		t.Fatal("consume succeeded without a flight entry")
	}
	var decisions int
	s.db.QueryRow(`SELECT count(*) FROM decisions`).Scan(&decisions)
	if decisions != 0 || remaining(t, s, "g_0") != 1 {
		t.Fatalf("decisions=%d uses=%d", decisions, remaining(t, s, "g_0"))
	}
}

// tamperCase copies a built database, applies raw SQL with the triggers
// dropped, and returns the verify report.
func tamperCase(t *testing.T, golden []byte, sqlText string, opts flight.Options) flight.Report {
	t.Helper()
	path := filepath.Join(t.TempDir(), "db")
	if err := os.WriteFile(path, golden, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.db.Exec(`DROP TRIGGER flight_no_update; DROP TRIGGER flight_no_delete; ` + sqlText); err != nil {
		t.Fatalf("%s: %v", sqlText, err)
	}
	return verifyFlight(t, s, opts)
}

func goldenFlight(t *testing.T, rounds int) ([]byte, []flight.Entry) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "golden")
	s := openTest(t, path)
	buildFlight(t, s, rounds)
	entries := flightEntries(t, s, flight.Filter{})
	if _, err := s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data, entries
}

type flightEvidence struct {
	Entries          int `json:"chain_entries"`
	Edits            int `json:"edits"`
	Deletions        int `json:"deletions"`
	Reorders         int `json:"reorders"`
	Truncations      int `json:"truncations"`
	CounterReset     int `json:"truncations_with_counter_reset"`
	Caught           int `json:"tamper_caught"`
	Cases            int `json:"tamper_cases"`
	ThreadWriters    int `json:"thread_writers"`
	ThreadEntries    int `json:"thread_entries"`
	ProcessWriters   int `json:"process_writers"`
	ProcessEntries   int `json:"process_entries"`
	CrashKills       int `json:"crash_kills"`
	CrashVerified    int `json:"crash_verified"`
	CrashEntriesKept int `json:"crash_entries_kept"`
}

var evidence struct {
	sync.Mutex
	flightEvidence
	parts int
}

func record(update func(*flightEvidence)) {
	evidence.Lock()
	defer evidence.Unlock()
	update(&evidence.flightEvidence)
	evidence.parts++
}

// Every edit, deletion, adjacent swap and truncation of a real database log is
// caught, and the report names the right entry.
func TestFlightTamperingIsCaught(t *testing.T) {
	golden, entries := goldenFlight(t, 6)
	n := len(entries)
	if n != 42 {
		t.Fatalf("chain has %d entries", n)
	}
	caught, cases := 0, 0
	check := func(ok bool, label string, r flight.Report) {
		cases++
		if ok {
			caught++
		} else {
			t.Errorf("%s not caught as expected: %+v", label, r.Problem)
		}
	}
	for seq := 1; seq <= n; seq++ {
		r := tamperCase(t, golden, fmt.Sprintf(`UPDATE flight SET body=json_set(body,'$.forged',1) WHERE seq=%d`, seq), flight.Options{})
		check(!r.OK && r.Problem.Seq == uint64(seq), fmt.Sprintf("edit %d", seq), r)
	}
	for seq := 1; seq < n; seq++ {
		r := tamperCase(t, golden, fmt.Sprintf(`DELETE FROM flight WHERE seq=%d`, seq), flight.Options{})
		check(!r.OK && r.Problem.Seq == uint64(seq+1) && strings.Contains(r.Problem.Reason, "missing"), fmt.Sprintf("delete %d", seq), r)
	}
	for seq := 1; seq < n; seq++ {
		r := tamperCase(t, golden, fmt.Sprintf(`UPDATE flight SET seq=1000000 WHERE seq=%d; UPDATE flight SET seq=%d WHERE seq=%d; UPDATE flight SET seq=%d WHERE seq=1000000`, seq, seq, seq+1, seq+1), flight.Options{})
		check(!r.OK && r.Problem.Seq == uint64(seq), fmt.Sprintf("swap %d/%d", seq, seq+1), r)
	}
	for keep := 0; keep < n; keep++ {
		r := tamperCase(t, golden, fmt.Sprintf(`DELETE FROM flight WHERE seq>%d`, keep), flight.Options{})
		check(!r.OK && r.Shortened && strings.Contains(r.Problem.Reason, "entries were removed, or the chain was rebuilt shorter"), fmt.Sprintf("truncate to %d", keep), r)
	}
	head := flight.Anchor{Seq: entries[n-1].Seq, Hash: entries[n-1].Hash}
	for keep := 0; keep < n; keep++ {
		reset := fmt.Sprintf(`DELETE FROM flight WHERE seq>%d; UPDATE sqlite_sequence SET seq=%d WHERE name='flight'`, keep, keep)
		if r := tamperCase(t, golden, reset, flight.Options{}); !r.OK && keep > 0 {
			t.Fatalf("a clean truncation with a reset counter should only be caught by a saved head: %+v", r.Problem)
		}
		r := tamperCase(t, golden, reset, flight.Options{Head: &head})
		check(!r.OK && r.HeadMismatch && strings.Contains(r.Problem.Reason, "entries were removed, or the chain was rebuilt shorter"), fmt.Sprintf("truncate to %d with counter reset", keep), r)
	}
	// After a tail deletion the next append leaves a permanent gap.
	path := filepath.Join(t.TempDir(), "db")
	os.WriteFile(path, golden, 0600)
	s := openTest(t, path)
	mustExec(t, s, `DROP TRIGGER flight_no_delete; DELETE FROM flight WHERE seq>40`)
	if _, err := s.Consume(context.Background(), "tkn_unknown", consumerCall()); err != nil {
		t.Fatal(err)
	}
	if r := verifyFlight(t, s, flight.Options{}); r.OK || !strings.Contains(r.Problem.Reason, "entries 41 to 42 are missing") {
		t.Fatalf("gap after tail deletion: %+v", r.Problem)
	}
	record(func(e *flightEvidence) {
		e.Entries, e.Edits, e.Deletions, e.Reorders, e.Truncations, e.CounterReset = n, n, n-1, n-1, n, n
		e.Caught, e.Cases = caught, cases
	})
}

// Many connections in one process append at the same time; the chain stays
// whole and every entry is there.
func TestFlightConcurrentWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	s := openTest(t, path)
	const writers, calls = 8, 50
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for w := 0; w < writers; w++ {
		conn, err := Open(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		wg.Add(1)
		go func(conn *Store, w int) {
			defer wg.Done()
			for i := 0; i < calls; i++ {
				if _, err := conn.Consume(context.Background(), fmt.Sprintf("tkn_%d_%d", w, i), consumerCall()); err != nil {
					errs <- err
					return
				}
			}
		}(conn, w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	r := verifyFlight(t, s, flight.Options{})
	if !r.OK || r.Entries != writers*calls*2 {
		t.Fatalf("report %+v", r)
	}
	assertPairs(t, s)
	record(func(e *flightEvidence) { e.ThreadWriters, e.ThreadEntries = writers, r.Entries })
}

// Each request entry is followed directly by its own decision: no other
// writer's entry lands between them.
func assertPairs(t *testing.T, s *Store) {
	t.Helper()
	entries := flightEntries(t, s, flight.Filter{})
	for i := 0; i+1 < len(entries); i += 2 {
		if entries[i].Kind != flight.KindRequest || entries[i+1].Kind != flight.KindDecision {
			t.Fatalf("entries %d and %d are %s and %s", entries[i].Seq, entries[i+1].Seq, entries[i].Kind, entries[i+1].Kind)
		}
	}
}

// TestFlightHelper is launched as a child process by the tests below.
func TestFlightHelper(t *testing.T) {
	mode := os.Getenv("TOKENING_FLIGHT_HELPER")
	if mode == "" {
		return
	}
	ctx := context.Background()
	s, err := Open(ctx, os.Getenv("TOKENING_FLIGHT_DB"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	switch mode {
	case "burst":
		count, _ := strconv.Atoi(os.Getenv("TOKENING_FLIGHT_COUNT"))
		for i := 0; i < count; i++ {
			if _, err = s.Consume(ctx, fmt.Sprintf("tkn_%d_%d", os.Getpid(), i), consumerCall()); err != nil {
				t.Fatal(err)
			}
		}
		fmt.Println("done")
	case "loop":
		for i := 0; ; i++ {
			if _, err = s.Consume(ctx, fmt.Sprintf("tkn_loop_%d", i), consumerCall()); err != nil {
				t.Fatal(err)
			}
			if i == 0 {
				fmt.Println("ready")
			}
		}
	default:
		t.Fatal("unknown helper mode")
	}
}

func helper(t *testing.T, mode, path string, count int) (*exec.Cmd, *bufio.Reader, *bytes.Buffer) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestFlightHelper$")
	cmd.Env = append(os.Environ(), "TOKENING_FLIGHT_HELPER="+mode, "TOKENING_FLIGHT_DB="+path, "TOKENING_FLIGHT_COUNT="+strconv.Itoa(count))
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
	return cmd, bufio.NewReader(out), &stderr
}

// Separate processes append to one database file at the same time.
func TestFlightConcurrentProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	s := openTest(t, path)
	const processes, calls = 4, 50
	type child struct {
		cmd    *exec.Cmd
		out    *bufio.Reader
		stderr *bytes.Buffer
	}
	var children []child
	for p := 0; p < processes; p++ {
		cmd, out, stderr := helper(t, "burst", path, calls)
		children = append(children, child{cmd, out, stderr})
	}
	for _, c := range children {
		line, _ := c.out.ReadString('\n')
		io.Copy(io.Discard, c.out)
		if err := c.cmd.Wait(); err != nil || strings.TrimSpace(line) != "done" {
			t.Fatalf("writer process failed: %v %q %s", err, line, c.stderr)
		}
	}
	r := verifyFlight(t, s, flight.Options{})
	if !r.OK || r.Entries != processes*calls*2 {
		t.Fatalf("report %+v", r)
	}
	assertPairs(t, s)
	record(func(e *flightEvidence) { e.ProcessWriters, e.ProcessEntries = processes, r.Entries })
}

// A writer process is killed at a random moment, again and again. Each time
// the log verifies up to its last complete entry, and every committed decision
// has its flight entries.
func TestFlightCrashMidWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	s := openTest(t, path)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	const kills = 20
	verified := 0
	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	var last int
	for k := 0; k < kills; k++ {
		cmd, out, stderr := helper(t, "loop", path, 0)
		line, err := out.ReadString('\n')
		if err != nil || strings.TrimSpace(line) != "ready" {
			t.Fatalf("helper did not start: %q %v %s", line, err, stderr)
		}
		time.Sleep(time.Duration(random.Intn(40)) * time.Millisecond)
		if err = cmd.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		cmd.Wait()
		reopened, err := Open(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		r, err := reopened.VerifyFlight(context.Background(), flight.Options{})
		var decisions int
		reopened.db.QueryRow(`SELECT count(*) FROM decisions`).Scan(&decisions)
		reopened.Close()
		if err != nil || !r.OK || r.Entries != decisions*2 || r.Entries <= last {
			t.Fatalf("kill %d: %+v %v decisions=%d previous=%d", k, r, err, decisions, last)
		}
		last = r.Entries
		verified++
	}
	record(func(e *flightEvidence) { e.CrashKills, e.CrashVerified, e.CrashEntriesKept = kills, verified, last })
}

func TestFlightReadOnlyOpen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if _, err := OpenReadOnly(ctx, filepath.Join(dir, "missing")); err == nil {
		t.Fatal("opened a missing file")
	}
	if _, err := os.Stat(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read-only open created a file")
	}
	path := filepath.Join(dir, "db")
	writer := openTest(t, path)
	buildFlight(t, writer, 2)
	ro, err := OpenReadOnly(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if r, err := ro.VerifyFlight(ctx, flight.Options{}); err != nil || !r.OK || r.Entries != 14 {
		t.Fatalf("%+v %v", r, err)
	}
	// The writer keeps going while the reader is open.
	if _, err = writer.Consume(ctx, "tkn_x", consumerCall()); err != nil {
		t.Fatal(err)
	}
	if r, _ := ro.VerifyFlight(ctx, flight.Options{}); !r.OK || r.Entries != 16 {
		t.Fatalf("after append %+v", r)
	}
	if _, err = ro.db.Exec(`INSERT INTO targets (id,kind,url_or_cmd,credential_type,credential_ref,created_at) VALUES ('x','http','http://x','bearer','vault:x',1)`); err == nil {
		t.Fatal("read-only store accepted a write")
	}
	old := filepath.Join(dir, "old")
	raw, err := Open(ctx, old)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, raw, `PRAGMA user_version=3`)
	raw.Close()
	if _, err = OpenReadOnly(ctx, old); !errors.Is(err, ErrNoFlightLog) {
		t.Fatalf("old schema: %v", err)
	}
}

// TestFlightRecorderEvidence runs last in this file and prints the measured
// summary that scripts/release.py copies into test-results.json.
func TestFlightRecorderEvidence(t *testing.T) {
	evidence.Lock()
	defer evidence.Unlock()
	e := evidence.flightEvidence
	if evidence.parts != 4 || e.Cases == 0 || e.Caught != e.Cases || e.ThreadEntries == 0 || e.ProcessEntries == 0 || e.CrashVerified != e.CrashKills || e.CrashKills == 0 {
		t.Fatalf("flight recorder evidence incomplete: %+v parts=%d (run the whole package)", e, evidence.parts)
	}
	data, err := json.Marshal(map[string]flightEvidence{"flight_recorder": e})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(data))
}

// Review v0.1.3: the tool name and argument names come from the agent. A tool
// name of 300,000 U+2028 characters fits in a 1 MiB request but doubles when
// JSON-escaped, so the request entry used to be longer than the 1 MiB line
// limit and the export could no longer be verified or replayed from a file.
func TestFlightOversizedAgentInputStillExportsVerifiably(t *testing.T) {
	ctx := context.Background()
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	applyTestPolicy(t, s)
	g := issue(t, s, issueRequest())
	call := consumerCall()
	call.Tool = strings.Repeat(" ", 300000)
	call.Args = map[string]json.RawMessage{}
	for i := 0; i < 20000; i++ {
		call.Args[fmt.Sprintf("n %06d", i)] = json.RawMessage(`0`)
	}
	if _, err := s.Consume(ctx, string(g.Secret), call); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := s.ExportFlight(ctx, &buf, flight.Filter{}); err != nil {
		t.Fatal(err)
	}
	r, err := flight.VerifyReader(&buf, flight.Options{})
	if err != nil || !r.OK || r.Entries != 3 {
		t.Fatalf("export of an oversized request does not verify: %+v %v", r, err)
	}
}
