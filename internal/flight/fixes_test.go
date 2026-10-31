package flight

import (
	"crypto/sha256"
	"strings"
	"testing"
)

// v0.1.4: after a saved-head mismatch the report must not let the caller call
// earlier entries good, and a shorter chain must not be described as entries
// removed from the end, because a rebuilt chain looks the same.

func TestHeadMismatchIsMarked(t *testing.T) {
	base := chain(t, 20)
	head := Anchor{Seq: 20, Hash: base[19].Hash}

	rewritten := chain(t, 20)
	rewritten[2].Agent = "x"
	var prev [sha256.Size]byte
	for i := range rewritten {
		rewritten[i] = Seal(rewritten[i], prev)
		prev = rewritten[i].Hash
	}
	r := verify(rewritten, Options{Head: &head})
	if r.OK || !r.HeadMismatch || r.Shortened || r.Problem.Seq != 20 {
		t.Fatalf("same-length rebuild: %+v %+v", r, r.Problem)
	}

	// A shorter rebuild: entries 2 and 3 dropped, the rest renumbered and
	// resealed. Nothing in the chain shows where entries went.
	short := append([]Entry{base[0]}, base[3:]...)
	prev = [sha256.Size]byte{}
	for i := range short {
		short[i].Seq = uint64(i + 1)
		short[i] = Seal(short[i], prev)
		prev = short[i].Hash
	}
	r = verify(short, Options{Head: &head})
	if r.OK || !r.HeadMismatch || r.Entries != 18 {
		t.Fatalf("shorter rebuild: %+v %+v", r, r.Problem)
	}
	reason := r.Problem.Reason
	if strings.Contains(reason, "from the end") || !strings.Contains(reason, "the saved head is entry 20 but the log ends at entry 18") || !strings.Contains(reason, "entries were removed, or the chain was rebuilt shorter") {
		t.Fatalf("shorter rebuild reason: %q", reason)
	}

	// Plain truncation reads the same way: the evidence cannot tell them apart.
	for keep := 1; keep < 20; keep++ {
		r := verify(base[:keep], Options{Head: &head})
		if r.OK || !r.HeadMismatch || strings.Contains(r.Problem.Reason, "from the end") {
			t.Fatalf("truncated to %d: %+v", keep, r.Problem)
		}
	}
	if r := verify(nil, Options{Head: &head}); r.OK || !r.HeadMismatch || !strings.Contains(r.Problem.Reason, "the log is empty") {
		t.Fatalf("empty log with a head: %+v", r.Problem)
	}

	// Problems that have nothing to do with the head are not marked.
	edited := chain(t, 20)
	edited[4].Agent = "x"
	if r := verify(edited, Options{Head: &head}); r.OK || r.HeadMismatch || r.Shortened {
		t.Fatalf("plain edit marked as a head problem: %+v", r)
	}
	if r := verify(base[5:], Options{Partial: true, Head: &Anchor{Seq: 2, Hash: base[1].Hash}}); r.OK || r.HeadMismatch {
		t.Fatalf("head outside a partial export marked as a mismatch: %+v", r)
	}
}

func TestShorterThanCounterIsNeutral(t *testing.T) {
	base := chain(t, 17)
	v := NewVerifier(Options{})
	for _, e := range base {
		v.Add(e)
	}
	v.Shorter(20, 17)
	r := v.Finish()
	if r.OK || !r.Shortened || r.HeadMismatch || r.Problem.Seq != 20 || r.Entries != 17 {
		t.Fatalf("counter ahead: %+v %+v", r, r.Problem)
	}
	if want := "the database assigned entries up to 20 but the log ends at entry 17: entries were removed, or the chain was rebuilt shorter"; r.Problem.Reason != want {
		t.Fatalf("reason %q", r.Problem.Reason)
	}
	// A problem already found wins over the counter.
	edited := chain(t, 17)
	edited[3].Agent = "x"
	v = NewVerifier(Options{})
	for _, e := range edited {
		if !v.Add(e) {
			break
		}
	}
	v.Shorter(20, 17)
	if r := v.Finish(); r.Shortened || r.Problem.Seq != 4 {
		t.Fatalf("counter overrode the first problem: %+v", r.Problem)
	}
}
