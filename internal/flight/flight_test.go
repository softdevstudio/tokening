package flight

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

func chain(t *testing.T, n int) []Entry {
	t.Helper()
	var prev [sha256.Size]byte
	out := make([]Entry, 0, n)
	kinds := []Kind{KindGrant, KindRequest, KindDecision, KindResult}
	for i := 1; i <= n; i++ {
		body, err := NewBody(map[string]any{"i": i, "note": "<b> & more"})
		if err != nil {
			t.Fatal(err)
		}
		agent := "editor-bot"
		if i%3 == 0 {
			agent = "other bot"
		}
		e := Seal(Entry{Seq: uint64(i), AtMS: 1793000000000 + int64(i)*1000, Kind: kinds[(i-1)%4], Agent: agent, Grant: fmt.Sprintf("g_%d", (i-1)/4), Body: body}, prev)
		prev = e.Hash
		out = append(out, e)
	}
	return out
}

func verify(entries []Entry, opts Options) Report {
	v := NewVerifier(opts)
	for _, e := range entries {
		if !v.Add(e) {
			break
		}
	}
	return v.Finish()
}

func encode(t *testing.T, entries []Entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, e := range entries {
		line, err := MarshalLine(e)
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(line)
	}
	return buf.Bytes()
}

func TestIntactChainVerifies(t *testing.T) {
	entries := chain(t, 40)
	r := verify(entries, Options{})
	if !r.OK || r.Entries != 40 || r.FirstSeq != 1 || r.LastSeq != 40 || r.LastHash != hex.EncodeToString(entries[39].Hash[:]) {
		t.Fatalf("report %+v", r)
	}
	fr, err := VerifyReader(bytes.NewReader(encode(t, entries)), Options{})
	if err != nil || !fr.OK || fr.Entries != 40 {
		t.Fatalf("file report %+v %v", fr, err)
	}
	if verify(nil, Options{}).OK != true {
		t.Fatal("an empty log is intact")
	}
}

func TestJSONLRoundTripIsExact(t *testing.T) {
	for _, e := range chain(t, 8) {
		line, err := MarshalLine(e)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(line, []byte(`"<b> & more"`)) {
			t.Fatalf("body must be written unchanged: %s", line)
		}
		back, err := UnmarshalLine(line)
		if err != nil {
			t.Fatal(err)
		}
		if back.Seq != e.Seq || back.AtMS != e.AtMS || back.Kind != e.Kind || back.Agent != e.Agent || back.Grant != e.Grant || !bytes.Equal(back.Body, e.Body) || back.Prev != e.Prev || back.Hash != e.Hash {
			t.Fatalf("round trip changed entry %d", e.Seq)
		}
	}
}

// Every single-field edit of every entry must be caught at that entry.
func TestEveryEditIsCaught(t *testing.T) {
	base := chain(t, 12)
	edits := map[string]func(*Entry){
		"seq":  func(e *Entry) { e.Seq += 100 },
		"time": func(e *Entry) { e.AtMS++ },
		"kind": func(e *Entry) {
			if e.Kind == KindDecision {
				e.Kind = KindGrant
			} else {
				e.Kind = KindDecision
			}
		},
		"agent": func(e *Entry) { e.Agent = "someone-else" },
		"grant": func(e *Entry) { e.Grant = "g_forged" },
		"body":  func(e *Entry) { e.Body = []byte(`{"i":999}`) },
		"prev":  func(e *Entry) { e.Prev[0] ^= 1 },
		"hash":  func(e *Entry) { e.Hash[31] ^= 1 },
	}
	runs := 0
	for name, edit := range edits {
		for i := range base {
			entries := append([]Entry(nil), base...)
			edit(&entries[i])
			r := verify(entries, Options{})
			if r.OK || r.Problem == nil {
				t.Fatalf("%s edit of entry %d not caught", name, i+1)
			}
			if r.Problem.Seq != entries[i].Seq {
				t.Fatalf("%s edit of entry %d reported at %d: %s", name, i+1, r.Problem.Seq, r.Problem.Reason)
			}
			runs++
		}
	}
	if runs != 8*12 {
		t.Fatal("not every edit ran")
	}
}

// An attacker who edits an entry and recomputes its hash breaks the next link.
func TestRehashedEditBreaksNextLink(t *testing.T) {
	entries := chain(t, 10)
	entries[4].Body = []byte(`{"i":5,"note":"forged"}`)
	entries[4] = Seal(entries[4], entries[4].Prev)
	r := verify(entries, Options{})
	if r.OK || r.Problem.Seq != 6 || !strings.Contains(r.Problem.Reason, "entry 5 was changed") {
		t.Fatalf("report %+v", r.Problem)
	}
}

func TestDeletionIsCaught(t *testing.T) {
	base := chain(t, 10)
	for i := range base {
		entries := append(append([]Entry(nil), base[:i]...), base[i+1:]...)
		r := verify(entries, Options{})
		if i == len(base)-1 {
			// Removing the last entry leaves a valid shorter chain; only a saved
			// head shows it. That case is covered below.
			if !r.OK {
				t.Fatalf("shorter chain should verify on its own: %+v", r.Problem)
			}
			continue
		}
		if r.OK || !strings.Contains(r.Problem.Reason, fmt.Sprintf("entry %d is missing", i+1)) && !strings.Contains(r.Problem.Reason, "entries 1 to 1 are missing") {
			t.Fatalf("deleting entry %d: %+v", i+1, r.Problem)
		}
	}
	two := append(append([]Entry(nil), base[:3]...), base[6:]...)
	if r := verify(two, Options{}); r.OK || !strings.Contains(r.Problem.Reason, "entries 4 to 6 are missing") {
		t.Fatalf("range deletion: %+v", r.Problem)
	}
}

func TestReorderIsCaught(t *testing.T) {
	base := chain(t, 10)
	for i := 0; i+1 < len(base); i++ {
		entries := append([]Entry(nil), base...)
		entries[i], entries[i+1] = entries[i+1], entries[i]
		if r := verify(entries, Options{}); r.OK {
			t.Fatalf("swap %d/%d not caught", i+1, i+2)
		}
		// Renumbering the swapped pair changes their hashes.
		entries[i].Seq, entries[i+1].Seq = entries[i+1].Seq, entries[i].Seq
		if r := verify(entries, Options{}); r.OK {
			t.Fatalf("renumbered swap %d/%d not caught", i+1, i+2)
		}
	}
	dup := append(append([]Entry(nil), base...), base[9])
	if r := verify(dup, Options{}); r.OK || !strings.Contains(r.Problem.Reason, "reordered or repeated") {
		t.Fatalf("repeat: %+v", r.Problem)
	}
}

func TestTruncationIsCaughtWithSavedHead(t *testing.T) {
	base := chain(t, 20)
	head := Anchor{Seq: 20, Hash: base[19].Hash}
	if r := verify(base, Options{Head: &head}); !r.OK || !r.HeadFound {
		t.Fatalf("intact chain with head: %+v", r)
	}
	for keep := 0; keep < 20; keep++ {
		r := verify(base[:keep], Options{Head: &head})
		if r.OK || !strings.Contains(r.Problem.Reason, "entries were removed, or the chain was rebuilt shorter") {
			t.Fatalf("truncated to %d: %+v", keep, r.Problem)
		}
	}
	// An earlier head still verifies after more entries are appended.
	early := Anchor{Seq: 7, Hash: base[6].Hash}
	if r := verify(base, Options{Head: &early}); !r.OK {
		t.Fatalf("early head: %+v", r.Problem)
	}
	// A rewritten chain with the same length does not match the saved head.
	rewritten := chain(t, 20)
	rewritten[0].Agent = "x"
	var prev [sha256.Size]byte
	for i := range rewritten {
		rewritten[i] = Seal(rewritten[i], prev)
		prev = rewritten[i].Hash
	}
	if r := verify(rewritten, Options{Head: &head}); r.OK || r.Problem.Seq != 20 {
		t.Fatalf("rewritten chain: %+v", r.Problem)
	}
}

func TestCutOffLastLineVerifiesUpToLastCompleteEntry(t *testing.T) {
	entries := chain(t, 6)
	data := encode(t, entries)
	last, _ := MarshalLine(entries[5])
	full := len(data)
	for cut := full - len(last) + 1; cut < full; cut++ {
		r, err := VerifyReader(bytes.NewReader(data[:cut]), Options{})
		if err != nil {
			t.Fatal(err)
		}
		if cut == full-1 {
			// Only the newline is missing: the entry is complete.
			if !r.OK || r.Entries != 6 {
				t.Fatalf("missing newline only: %+v", r)
			}
			continue
		}
		if r.OK || r.Entries != 5 || r.LastSeq != 5 || r.Problem.Line != 6 || !strings.Contains(r.Problem.Reason, "entries up to 5 verify; line 6") {
			t.Fatalf("cut at %d: %+v %+v", cut, r, r.Problem)
		}
	}
}

func TestMalformedMiddleLineIsReported(t *testing.T) {
	lines := strings.SplitAfter(string(encode(t, chain(t, 5))), "\n")
	lines[2] = "{not json}\n"
	r, err := VerifyReader(strings.NewReader(strings.Join(lines, "")), Options{})
	if err != nil || r.OK || r.Problem.Line != 3 || !strings.Contains(r.Problem.Reason, "not a valid entry") {
		t.Fatalf("%+v %v", r.Problem, err)
	}
	for _, bad := range []string{
		`{"seq":1,"at":"2026-10-31T10:00:00Z","kind":"grant","agent":"","grant":"","body":{},"prev":"` + strings.Repeat("0", 64) + `","hash":"` + strings.Repeat("0", 64) + `"}`,
		`{"seq":1,"at":"2026-10-31T10:00:00.000Z","kind":"grant","agent":"","grant":"","body":{ },"prev":"` + strings.Repeat("0", 64) + `","hash":"` + strings.Repeat("0", 64) + `"}`,
		`{"seq":1,"at":"2026-10-31T10:00:00.000Z","kind":"grant","agent":"","grant":"","body":{},"prev":"` + strings.Repeat("A", 64) + `","hash":"` + strings.Repeat("0", 64) + `"}`,
		`{"seq":1,"at":"2026-10-31T10:00:00.000Z","kind":"other","agent":"","grant":"","body":{},"prev":"` + strings.Repeat("0", 64) + `","hash":"` + strings.Repeat("0", 64) + `"}`,
		`{"seq":1,"at":"2026-10-31T10:00:00.000Z","kind":"grant","agent":"","grant":"","body":{},"prev":"` + strings.Repeat("0", 64) + `","hash":"` + strings.Repeat("0", 64) + `","extra":1}`,
	} {
		if _, err := UnmarshalLine([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

func TestPartialExports(t *testing.T) {
	base := chain(t, 30)
	var filtered []Entry
	f := Filter{Agent: "editor-bot"}
	for _, e := range base {
		if f.Match(e) {
			filtered = append(filtered, e)
		}
	}
	if r := verify(filtered, Options{}); r.OK {
		t.Fatal("a filtered export is not a complete log")
	}
	r := verify(filtered, Options{Partial: true})
	if !r.OK || r.Entries != 20 || r.Gaps == 0 {
		t.Fatalf("partial: %+v", r)
	}
	filtered[3].Body = []byte(`{"forged":true}`)
	if r := verify(filtered, Options{Partial: true}); r.OK || r.Problem.Seq != filtered[3].Seq {
		t.Fatalf("edit in partial export: %+v", r.Problem)
	}
	tail := base[10:]
	if r := verify(tail, Options{Partial: true}); !r.OK || r.FirstSeq != 11 {
		t.Fatalf("tail export: %+v", r)
	}
	if r := verify(tail, Options{}); r.OK || !strings.Contains(r.Problem.Reason, "entries 1 to 10 are missing") {
		t.Fatalf("tail strict: %+v", r.Problem)
	}
	head := Anchor{Seq: 3, Hash: base[2].Hash}
	if r := verify(tail, Options{Partial: true, Head: &head}); r.OK || !strings.Contains(r.Problem.Reason, "not in this export") {
		t.Fatalf("head outside export: %+v", r.Problem)
	}
}

func TestAnchorParsing(t *testing.T) {
	e := chain(t, 1)[0]
	a := Anchor{Seq: 1, Hash: e.Hash}
	back, err := ParseAnchor(a.String())
	if err != nil || back != a {
		t.Fatalf("%v %v", back, err)
	}
	for _, bad := range []string{"", "1", "0:" + strings.Repeat("0", 64), "x:" + strings.Repeat("0", 64), "1:abc", "1:" + strings.Repeat("G", 64)} {
		if _, err := ParseAnchor(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestFilter(t *testing.T) {
	e := Entry{Agent: "a", Grant: "g", AtMS: time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC).UnixMilli()}
	at := e.Time()
	cases := []struct {
		f    Filter
		want bool
	}{
		{Filter{}, true},
		{Filter{Agent: "a"}, true},
		{Filter{Agent: "b"}, false},
		{Filter{Grant: "g"}, true},
		{Filter{Grant: "h"}, false},
		{Filter{Since: at}, true},
		{Filter{Since: at.Add(time.Millisecond)}, false},
		{Filter{Until: at}, false},
		{Filter{Until: at.Add(time.Millisecond)}, true},
	}
	for i, c := range cases {
		if c.f.Match(e) != c.want {
			t.Fatalf("case %d", i)
		}
	}
}

func TestFormatEntry(t *testing.T) {
	left := 0
	status := 200
	cases := []struct {
		kind Kind
		body any
		want string
	}{
		{KindGrant, GrantBody{Event: "issued", Template: "wp.edit-post-text", Action: "wp_update_post", Uses: 1, ExpiresAt: "2026-10-31T10:15:00.000Z", IssuedBy: "operator", Reason: "fix title", Bound: []string{"id"}}, `g_1 issued to editor-bot by operator: wp.edit-post-text on wp_update_post, 1 use, expires 2026-10-31T10:15:00.000Z, bound id, reason "fix title"`},
		{KindGrant, GrantBody{Event: "revoked", By: "night shift"}, `g_1 revoked by "night shift"`},
		{KindRequest, RequestBody{Target: "demo-wp", Action: "wp_update_post", ArgsDigest: strings.Repeat("ab", 32), Args: []string{"id", "title"}}, "g_1 editor-bot asked for wp_update_post on demo-wp with arguments id, title (digest abababababab)"},
		{KindDecision, DecisionBody{Outcome: "allowed", Code: "allowed", Reason: "Call fits this grant.", UsesLeft: &left}, "g_1 allowed: Call fits this grant. 0 uses left."},
		{KindDecision, DecisionBody{Outcome: "refused", Code: "arg_mismatch", Reason: "Grant is bound to id 2; call sent id 3."}, "g_1 refused (arg_mismatch): Grant is bound to id 2; call sent id 3."},
		{KindResult, ResultBody{Code: "allowed", UpstreamStatus: &status, LatencyMS: 84}, "g_1 upstream answered HTTP 200 in 84 ms"},
		{KindResult, ResultBody{Code: "upstream_error", LatencyMS: 5}, "g_1 upstream gave no HTTP answer after 5 ms (upstream_error)"},
	}
	for _, c := range cases {
		body, err := NewBody(c.body)
		if err != nil {
			t.Fatal(err)
		}
		line := FormatEntry(Entry{Seq: 3, AtMS: 1793000000000, Kind: c.kind, Agent: "editor-bot", Grant: "g_1", Body: body})
		if !strings.HasSuffix(line, c.want) || !strings.HasPrefix(line, "#3  ") {
			t.Fatalf("got  %s\nwant ...%s", line, c.want)
		}
	}
	unknown := FormatEntry(Entry{Seq: 1, Kind: KindRequest, Body: []byte(`{"target":5}`)})
	if !strings.Contains(unknown, "(no grant)") {
		t.Fatal(unknown)
	}
}

func TestFormatEntryQuotesControlCharacters(t *testing.T) {
	body, _ := NewBody(GrantBody{Event: "issued", Template: "edit", Action: "wp_update_post", Uses: 1, IssuedBy: "op\x1b[2K", Reason: "line\n#99 fake", Bound: []string{"id\nx"}})
	line := FormatEntry(Entry{Seq: 1, Kind: KindGrant, Agent: "bot\n#2  2026-10-31T00:00:00.000Z  decision  forged", Grant: "g_1", Body: body})
	if strings.ContainsAny(line, "\n\x1b") {
		t.Fatalf("control characters reached the replay: %q", line)
	}
	if !strings.Contains(line, `"bot\n#2`) || !strings.Contains(line, `"op\x1b[2K"`) {
		t.Fatalf("names not quoted: %s", line)
	}
}
