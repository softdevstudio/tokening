package flight

import (
	"bytes"
	"strings"
	"testing"
)

// Review v0.1.3: a line verify accepts must be the exact bytes an export
// writes. Duplicate or case-variant keys and extra spaces let a file show one
// value to a reader that takes the first key, or greps, while verify checks
// another.
func TestNonCanonicalLinesAreRefused(t *testing.T) {
	entries := chain(t, 3)
	lines := strings.SplitAfter(string(encode(t, entries)), "\n")
	first := lines[0]
	variants := map[string]string{
		"duplicate key, first value forged": strings.Replace(first, `{"seq":1,`, `{"agent":"mallory","seq":1,`, 1),
		"case-variant key":                  strings.Replace(first, `"grant":"g_0"`, `"grant":"g_0","Grant":"g_0"`, 1),
		"upper-case key":                    strings.Replace(first, `"kind":`, `"KIND":`, 1),
		"space after colon":                 strings.Replace(first, `"seq":1`, `"seq": 1`, 1),
		"leading space":                     " " + first,
	}
	for name, line := range variants {
		if line == first {
			t.Errorf("%s: variant did not change the line", name)
			continue
		}
		file := line + strings.Join(lines[1:], "")
		r, err := VerifyReader(strings.NewReader(file), Options{})
		if err != nil {
			t.Fatal(err)
		}
		if r.OK || r.Problem == nil || r.Problem.Line != 1 {
			t.Errorf("%s: a non-canonical line verified: %+v", name, r)
		}
	}
}

// A line with characters Go escapes (U+2028, U+2029) still round-trips byte
// for byte under the stricter check.
func TestCanonicalLineWithLineSeparators(t *testing.T) {
	body, err := NewBody(map[string]string{"reason": "a b c <&>"})
	if err != nil {
		t.Fatal(err)
	}
	e := Seal(Entry{Seq: 1, AtMS: 1793000000000, Kind: KindDecision, Agent: "bot x", Grant: "g_1", Body: body}, [32]byte{})
	line, err := MarshalLine(e)
	if err != nil {
		t.Fatal(err)
	}
	r, err := VerifyReader(bytes.NewReader(line), Options{})
	if err != nil || !r.OK {
		t.Fatalf("%+v %v\n%s", r, err, line)
	}
}

// Agent-chosen tool names reach the replay. A name with spaces must be quoted
// so it cannot pass as the rest of the sentence.
func TestFormatEntryQuotesActionsWithSpaces(t *testing.T) {
	body, _ := NewBody(RequestBody{Target: "demo-wp", Action: "wp_get_post on demo-wp with no arguments (digest 000000000000); refused", ArgsDigest: strings.Repeat("ab", 32)})
	line := FormatEntry(Entry{Seq: 2, Kind: KindRequest, Agent: "bot", Grant: "g_1", Body: body})
	if !strings.Contains(line, `asked for "wp_get_post on demo-wp`) {
		t.Fatalf("tool name not quoted: %s", line)
	}
	body, _ = NewBody(RequestBody{Target: "demo-wp", Action: "PATCH /wp/v2/posts/2", ArgsDigest: strings.Repeat("ab", 32)})
	line = FormatEntry(Entry{Seq: 2, Kind: KindRequest, Agent: "bot", Grant: "g_1", Body: body})
	if !strings.Contains(line, "asked for PATCH /wp/v2/posts/2 on demo-wp") {
		t.Fatalf("plain REST action quoted: %s", line)
	}
	body, _ = NewBody(RequestBody{Target: "demo-wp", Action: "GET /a b", ArgsDigest: strings.Repeat("ab", 32)})
	line = FormatEntry(Entry{Seq: 2, Kind: KindRequest, Agent: "bot", Grant: "g_1", Body: body})
	if !strings.Contains(line, `asked for "GET /a b"`) {
		t.Fatalf("REST action with a space not quoted: %s", line)
	}
}

func TestFormatEntryQuotesUnicodeSpaces(t *testing.T) {
	body, _ := NewBody(RequestBody{Target: "demo-wp", Action: "wp_get_post on demo-wp", ArgsDigest: strings.Repeat("ab", 32), Args: []string{"id　x"}})
	line := FormatEntry(Entry{Seq: 2, Kind: KindRequest, Agent: "bot x", Grant: "g_1", Body: body})
	for _, want := range []string{`"wp_get_post on demo-wp"`, `"bot x"`, `"id　x"`} {
		if !strings.Contains(line, want) {
			t.Fatalf("missing %s in %s", want, line)
		}
	}
}

func TestBoundNamesAndClip(t *testing.T) {
	if got := Clip(strings.Repeat("é", 200), 11); got != "éééé…" {
		t.Fatalf("clip %q", got)
	}
	if Clip("short", MaxActionBytes) != "short" {
		t.Fatal("short text clipped")
	}
	names := make([]string, 150)
	for i := range names {
		names[i] = strings.Repeat("x", 500)
	}
	out, omitted := BoundNames(names)
	if len(out) != MaxNames || omitted != 50 || len(out[0]) > MaxNameBytes {
		t.Fatalf("%d %d %d", len(out), omitted, len(out[0]))
	}
	body, _ := NewBody(RequestBody{Action: "x", Args: out, ArgsOmitted: omitted})
	line := FormatEntry(Entry{Seq: 2, Kind: KindRequest, Grant: "g_1", Body: body})
	if !strings.Contains(line, "and 50 more") {
		t.Fatal(line)
	}
}
