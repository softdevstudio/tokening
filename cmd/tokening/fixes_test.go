package main

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/softdevstudio/tokening/internal/flight"
	"github.com/softdevstudio/tokening/internal/version"
)

// v0.1.4: --head given but empty used to skip the head check and exit 0, so a
// script reading an empty heads file passed unchecked. Any --head that is
// given must be a valid SEQ:HASH, checked before anything is opened.
func TestFlightVerifyRefusesEmptyOrMalformedHead(t *testing.T) {
	db, _ := flightDB(t)
	export := filepath.Join(t.TempDir(), "flight.jsonl")
	if code, _, errOut := flightRun("export", "--db", db, "--output", export); code != 0 {
		t.Fatalf("export: %d %s", code, errOut)
	}
	missing := filepath.Join(t.TempDir(), "missing.db")
	for _, args := range [][]string{
		{"verify", "--db", db, "--head", ""},
		{"verify", "--db", db, "--head="},
		{"verify", "--db", db, "--head", "   "},
		{"verify", "--file", export, "--head", ""},
		{"verify", "--file", export, "--head", "\n"},
		{"verify", "--db", missing, "--head", ""},
	} {
		code, out, errOut := flightRun(args...)
		if code != 2 || out != "" || !strings.Contains(errOut, "--head is empty") {
			t.Fatalf("%q: exit %d, out %q, err %q", args, code, out, errOut)
		}
	}
	for _, args := range [][]string{
		{"verify", "--db", db, "--head", "bad"},
		{"verify", "--db", missing, "--head", "7:abc"},
		{"verify", "--file", export, "--head", "0:" + strings.Repeat("a", 64)},
	} {
		code, out, errOut := flightRun(args...)
		if code != 2 || out != "" || !strings.Contains(errOut, "head") {
			t.Fatalf("%q: exit %d, out %q, err %q", args, code, out, errOut)
		}
	}
	if _, err := os.Stat(missing); err == nil {
		t.Fatal("verify created a database")
	}
}

// reseal rewrites an export as an attacker with full control of the file
// would: renumber, recompute every hash, keep it internally consistent.
func reseal(t *testing.T, lines []string, edit func(i int, e *flight.Entry)) string {
	t.Helper()
	var prev [sha256.Size]byte
	var b strings.Builder
	for i, line := range lines {
		e, err := flight.UnmarshalLine([]byte(line))
		if err != nil {
			t.Fatal(err)
		}
		e.Seq = uint64(i + 1)
		if edit != nil {
			edit(i, &e)
		}
		e = flight.Seal(e, prev)
		prev = e.Hash
		out, err := flight.MarshalLine(e)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(out)
	}
	return b.String()
}

// v0.1.4: after a saved-head mismatch verify printed "Entries 1 to N verify.
// Last good head: N", calling rewritten entries good, and a shorter rebuilt
// chain was said to have lost entries "from the end".
func TestFlightVerifyHeadMismatchWording(t *testing.T) {
	db, _ := flightDB(t)
	_, export, _ := flightRun("export", "--db", db)
	_, head, _ := flightRun("head", "--db", db)
	head = strings.TrimSpace(head)
	lines := strings.SplitAfter(strings.TrimSuffix(export, "\n"), "\n")
	if len(lines) != 7 {
		t.Fatalf("export has %d lines", len(lines))
	}
	dir := t.TempDir()
	write := func(name, text string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	sameLength := write("rewritten", reseal(t, lines, func(i int, e *flight.Entry) {
		if i == 1 {
			e.Agent = "someone-else"
		}
	}))
	if code, out, _ := flightRun("verify", "--file", sameLength); code != 0 {
		t.Fatalf("a resealed file verifies on its own: %d %s", code, out)
	}
	code, out, _ := flightRun("verify", "--file", sameLength, "--head", head)
	if code != 1 || !strings.Contains(out, "Broken at entry 7: entry 7 has a different hash from the saved head") ||
		!strings.Contains(out, "The chain does not match the saved head.") ||
		!strings.Contains(out, "Entries 1 to 6 link to each other, but so would a rebuilt chain") ||
		!strings.Contains(out, "cannot be trusted") ||
		strings.Contains(out, "verify. Last good head") {
		t.Fatalf("same-length rebuild: %d\n%s", code, out)
	}

	shorter := write("shorter", reseal(t, append([]string{lines[0]}, lines[3:]...), nil))
	code, out, _ = flightRun("verify", "--file", shorter, "--head", head)
	if code != 1 || !strings.Contains(out, "the saved head is entry 7 but the log ends at entry 5: entries were removed, or the chain was rebuilt shorter") ||
		!strings.Contains(out, "The chain does not match the saved head.") ||
		!strings.Contains(out, "Entries 1 to 5 link to each other") ||
		strings.Contains(out, "from the end") || strings.Contains(out, "Last good head") {
		t.Fatalf("shorter rebuild: %d\n%s", code, out)
	}

	// An ordinary break with no head keeps naming the entries that verify.
	deleted := write("deleted", strings.Join(append(append([]string{}, lines[:3]...), lines[4:]...), ""))
	if code, out, _ := flightRun("verify", "--file", deleted); code != 1 || !strings.Contains(out, "Entries 1 to 3 verify. Last good head: 3:") || strings.Contains(out, "saved head.") {
		t.Fatalf("plain deletion: %d\n%s", code, out)
	}
}

// v0.1.4: one version, from internal/version, everywhere.
func TestVersionCommandUsesBuildVersion(t *testing.T) {
	var stdout, stderr strings.Builder
	code := run([]string{"version"}, &stdout, &stderr)
	out := stdout.String()
	if code != 0 || strings.TrimSpace(out) != "tokening "+version.Version {
		t.Fatalf("version: %d %q, want tokening %s", code, out, version.Version)
	}
}
