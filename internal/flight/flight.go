// Package flight defines Tokening's flight recorder: an append-only log of
// grants, requests, decisions and upstream results in which every entry is
// hash-chained to the one before it. This package has no storage or network
// code. It computes hashes, encodes and decodes JSONL entries, verifies a
// chain and formats a replay. internal/store does the appends.
package flight

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Domain separates flight hashes from every other SHA-256 use in Tokening.
const Domain = "tokening-flight-v1"

// TimeLayout is the only accepted text form of an entry time: UTC, milliseconds.
const TimeLayout = "2006-01-02T15:04:05.000Z"

// MaxLine bounds one JSONL entry when reading a file.
const MaxLine = 1 << 20

type Kind string

const (
	KindGrant    Kind = "grant"
	KindRequest  Kind = "request"
	KindDecision Kind = "decision"
	KindResult   Kind = "result"
)

func (k Kind) Valid() bool {
	return k == KindGrant || k == KindRequest || k == KindDecision || k == KindResult
}

// Entry is one chained record. AtMS is milliseconds since the Unix epoch, UTC.
// Body is compact JSON and is hashed byte for byte.
type Entry struct {
	Seq   uint64
	AtMS  int64
	Kind  Kind
	Agent string
	Grant string
	Body  json.RawMessage
	Prev  [sha256.Size]byte
	Hash  [sha256.Size]byte
}

// Sum returns the hash an entry must carry, given its fields and Prev.
func Sum(e Entry) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte(Domain))
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], e.Seq)
	h.Write(n[:])
	binary.BigEndian.PutUint64(n[:], uint64(e.AtMS))
	h.Write(n[:])
	for _, field := range [][]byte{[]byte(e.Kind), []byte(e.Agent), []byte(e.Grant), e.Body} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		h.Write(size[:])
		h.Write(field)
	}
	h.Write(e.Prev[:])
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Seal fills Prev and Hash for a new entry that follows prev. A zero prev is
// used for the first entry.
func Seal(e Entry, prev [sha256.Size]byte) Entry {
	e.Prev = prev
	e.Hash = Sum(e)
	return e
}

// Time returns the entry time in UTC.
func (e Entry) Time() time.Time { return time.UnixMilli(e.AtMS).UTC() }

type wire struct {
	Seq   uint64          `json:"seq"`
	At    string          `json:"at"`
	Kind  Kind            `json:"kind"`
	Agent string          `json:"agent"`
	Grant string          `json:"grant"`
	Body  json.RawMessage `json:"body"`
	Prev  string          `json:"prev"`
	Hash  string          `json:"hash"`
}

// MarshalLine encodes one entry as a JSONL line, newline included. Body bytes
// are written unchanged so a file verifies against the same hashes.
func MarshalLine(e Entry) ([]byte, error) {
	if err := checkFields(e); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(wire{Seq: e.Seq, At: e.Time().Format(TimeLayout), Kind: e.Kind, Agent: e.Agent, Grant: e.Grant, Body: e.Body, Prev: hex.EncodeToString(e.Prev[:]), Hash: hex.EncodeToString(e.Hash[:])})
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalLine decodes one JSONL line. It accepts only the exact field set,
// the canonical time form, lowercase hex hashes and a compact JSON object body.
func UnmarshalLine(line []byte) (Entry, error) {
	line = bytes.TrimRight(line, "\r\n")
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	var w wire
	if err := d.Decode(&w); err != nil {
		return Entry{}, fmt.Errorf("not a flight entry: %v", err)
	}
	if d.More() {
		return Entry{}, errors.New("not a flight entry: trailing content")
	}
	at, err := time.Parse(TimeLayout, w.At)
	if err != nil || at.Format(TimeLayout) != w.At {
		return Entry{}, errors.New("time is not in the form 2006-01-02T15:04:05.000Z")
	}
	e := Entry{Seq: w.Seq, AtMS: at.UnixMilli(), Kind: w.Kind, Agent: w.Agent, Grant: w.Grant, Body: w.Body}
	if err = decodeHash(w.Prev, &e.Prev); err != nil {
		return Entry{}, fmt.Errorf("prev: %v", err)
	}
	if err = decodeHash(w.Hash, &e.Hash); err != nil {
		return Entry{}, fmt.Errorf("hash: %v", err)
	}
	if err = checkFields(e); err != nil {
		return Entry{}, err
	}
	// Accept only the exact bytes an export writes. JSON readers differ on
	// duplicate keys, key case and whitespace; a line that is not canonical
	// could show one value to another tool while verify checks a different one.
	canonical, err := MarshalLine(e)
	if err != nil {
		return Entry{}, err
	}
	if !bytes.Equal(bytes.TrimSuffix(canonical, []byte("\n")), line) {
		return Entry{}, errors.New("not in the exact form tokening flight export writes (duplicate or renamed keys, extra spaces or different escapes)")
	}
	return e, nil
}

func checkFields(e Entry) error {
	if e.Seq == 0 {
		return errors.New("seq must start at 1")
	}
	if !e.Kind.Valid() {
		return fmt.Errorf("unknown kind %q", e.Kind)
	}
	if !utf8.ValidString(e.Agent) || !utf8.ValidString(e.Grant) {
		return errors.New("agent and grant must be UTF-8")
	}
	if len(e.Body) == 0 || e.Body[0] != '{' || !json.Valid(e.Body) {
		return errors.New("body must be a JSON object")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, e.Body); err != nil || !bytes.Equal(compact.Bytes(), e.Body) {
		return errors.New("body must be compact JSON")
	}
	return nil
}

func decodeHash(text string, out *[sha256.Size]byte) error {
	if len(text) != 2*sha256.Size || strings.ToLower(text) != text {
		return errors.New("must be 64 lowercase hex characters")
	}
	_, err := hex.Decode(out[:], []byte(text))
	return err
}

// Anchor is a seq and hash saved outside the database, as printed by
// tokening flight head.
type Anchor struct {
	Seq  uint64
	Hash [sha256.Size]byte
}

func (a Anchor) String() string {
	return strconv.FormatUint(a.Seq, 10) + ":" + hex.EncodeToString(a.Hash[:])
}

// ParseAnchor reads SEQ:HASH.
func ParseAnchor(text string) (Anchor, error) {
	seqText, hashText, ok := strings.Cut(strings.TrimSpace(text), ":")
	seq, err := strconv.ParseUint(seqText, 10, 64)
	if !ok || err != nil || seq == 0 {
		return Anchor{}, errors.New("head must be SEQ:HASH, as printed by tokening flight head")
	}
	var a Anchor
	a.Seq = seq
	if err = decodeHash(hashText, &a.Hash); err != nil {
		return Anchor{}, fmt.Errorf("head hash %v", err)
	}
	return a, nil
}

// Options control verification.
type Options struct {
	// Partial accepts an export that does not start at seq 1 or skips seq
	// numbers, such as a filtered export. Each entry's own hash is still
	// checked, and links are checked wherever seq numbers are consecutive.
	Partial bool
	// Head, when set, must appear in the chain with the same hash.
	Head *Anchor
}

// Problem names the first broken entry. Seq is zero when the problem is not
// tied to one entry, such as a missing head. Line is set when reading a file.
type Problem struct {
	Seq    uint64 `json:"seq"`
	Line   int    `json:"line,omitempty"`
	Reason string `json:"reason"`
}

// Report is the result of a verification.
type Report struct {
	OK        bool   `json:"ok"`
	Entries   int    `json:"entries"`
	FirstSeq  uint64 `json:"first_seq"`
	LastSeq   uint64 `json:"last_seq"`
	LastHash  string `json:"last_hash"`
	Gaps      int    `json:"gaps"`
	HeadFound bool   `json:"head_found"`
	// HeadMismatch is set when the chain does not match a saved head: the
	// entry at the head's seq has another hash, or the log is shorter. The
	// entries before the problem still link to each other, but a rebuilt chain
	// does too, so none of them is confirmed by the head.
	HeadMismatch bool `json:"head_mismatch,omitempty"`
	// Shortened is set when the database counter shows more entries were
	// assigned than the log holds. Entries were removed, or the chain was
	// rebuilt shorter; the counter cannot tell which, or where.
	Shortened bool     `json:"shortened,omitempty"`
	Problem   *Problem `json:"problem,omitempty"`
}

// Verifier checks entries in the order they are given.
type Verifier struct {
	opts    Options
	report  Report
	last    *Entry
	stopped bool
}

func NewVerifier(opts Options) *Verifier { return &Verifier{opts: opts} }

// Add checks one entry. It returns false once a problem has been found; later
// entries are ignored so the report names the first broken one.
func (v *Verifier) Add(e Entry) bool { return v.add(e, 0) }

func (v *Verifier) add(e Entry, line int) bool {
	if v.stopped {
		return false
	}
	fail := func(seq uint64, format string, args ...any) bool {
		v.report.Problem = &Problem{Seq: seq, Line: line, Reason: fmt.Sprintf(format, args...)}
		v.stopped = true
		return false
	}
	if err := checkFields(e); err != nil {
		return fail(e.Seq, "entry %d is malformed: %v", e.Seq, err)
	}
	if Sum(e) != e.Hash {
		return fail(e.Seq, "entry %d does not match its own hash: its contents were changed after it was written", e.Seq)
	}
	var zero [sha256.Size]byte
	if e.Seq == 1 && e.Prev != zero {
		return fail(1, "entry 1 must not link to an earlier entry")
	}
	if v.last == nil {
		if e.Seq != 1 && !v.opts.Partial {
			return fail(e.Seq, "the log starts at entry %d: entries 1 to %d are missing", e.Seq, e.Seq-1)
		}
		v.report.FirstSeq = e.Seq
	} else {
		switch {
		case e.Seq <= v.last.Seq:
			return fail(e.Seq, "entry %d comes after entry %d: entries were reordered or repeated", e.Seq, v.last.Seq)
		case e.Seq == v.last.Seq+1:
			if e.Prev != v.last.Hash {
				return fail(e.Seq, "entry %d does not link to entry %d: entry %d was changed, replaced or moved", e.Seq, v.last.Seq, v.last.Seq)
			}
		case v.opts.Partial:
			v.report.Gaps++
		case e.Seq == v.last.Seq+2:
			return fail(e.Seq, "entry %d is missing between entries %d and %d", v.last.Seq+1, v.last.Seq, e.Seq)
		default:
			return fail(e.Seq, "entries %d to %d are missing between entries %d and %d", v.last.Seq+1, e.Seq-1, v.last.Seq, e.Seq)
		}
	}
	if h := v.opts.Head; h != nil && h.Seq == e.Seq {
		if h.Hash != e.Hash {
			v.report.HeadMismatch = true
			return fail(e.Seq, "entry %d has a different hash from the saved head: the log was rewritten from entry %d or earlier", e.Seq, e.Seq)
		}
		v.report.HeadFound = true
	}
	copied := e
	v.last = &copied
	v.report.Entries++
	v.report.LastSeq = e.Seq
	v.report.LastHash = hex.EncodeToString(e.Hash[:])
	return true
}

// shorterReason is the wording for a log that ends before a point known to
// exist. Plain truncation and a chain rebuilt without some entries look the
// same from here, so it does not say where the entries went.
const shorterReason = "entries were removed, or the chain was rebuilt shorter"

// Finish returns the report. A saved head that was never reached is a problem:
// the log is shorter than when the head was saved, or the head belongs to
// another log.
func (v *Verifier) Finish() Report {
	r := v.report
	if r.Problem == nil {
		if h := v.opts.Head; h != nil && !r.HeadFound {
			if v.last == nil {
				r.HeadMismatch = true
				r.Problem = &Problem{Reason: fmt.Sprintf("the saved head is entry %d but the log is empty: %s", h.Seq, shorterReason)}
			} else if h.Seq > v.last.Seq {
				r.HeadMismatch = true
				r.Problem = &Problem{Reason: fmt.Sprintf("the saved head is entry %d but the log ends at entry %d: %s", h.Seq, r.LastSeq, shorterReason)}
			} else {
				r.Problem = &Problem{Reason: fmt.Sprintf("the saved head, entry %d, is not in this export", h.Seq)}
			}
		}
	}
	r.OK = r.Problem == nil
	return r
}

// Shorter records that the database assigned entries up to assigned but the
// log ends at last. It does nothing if a problem was already found.
func (v *Verifier) Shorter(assigned, last uint64) {
	if !v.stopped {
		v.report.Problem = &Problem{Seq: assigned, Reason: fmt.Sprintf("the database assigned entries up to %d but the log ends at entry %d: %s", assigned, last, shorterReason)}
		v.report.Shortened = true
		// A saved head past the end of the log is not in it either.
		if h := v.opts.Head; h != nil && !v.report.HeadFound && h.Seq > last {
			v.report.HeadMismatch = true
		}
		v.stopped = true
	}
}

// VerifyReader checks a JSONL file. A last line without a newline that does not
// decode is reported as cut off: everything before it is verified and named.
func VerifyReader(r io.Reader, opts Options) (Report, error) {
	v := NewVerifier(opts)
	br := bufio.NewReaderSize(r, 64*1024)
	line := 0
	for {
		text, err := readLine(br)
		if len(text) > 0 {
			line++
			complete := text[len(text)-1] == '\n'
			e, decodeErr := UnmarshalLine(text)
			if decodeErr != nil {
				report := v.Finish()
				if !v.stopped {
					if !complete && err == io.EOF {
						reason := fmt.Sprintf("line %d is cut off, as an interrupted write leaves it", line)
						if report.Entries > 0 {
							reason = fmt.Sprintf("entries up to %d verify; line %d after them is cut off, as an interrupted write leaves it", report.LastSeq, line)
						}
						report.Problem = &Problem{Line: line, Reason: reason}
					} else {
						report.Problem = &Problem{Line: line, Reason: fmt.Sprintf("line %d is not a valid entry: %v", line, decodeErr)}
					}
					report.OK = false
				}
				return report, nil
			}
			if !v.add(e, line) {
				return v.Finish(), nil
			}
		}
		if err == io.EOF {
			return v.Finish(), nil
		}
		if err != nil {
			return v.Finish(), err
		}
	}
}

var errLongLine = errors.New("line is longer than 1 MiB")

func readLine(br *bufio.Reader) ([]byte, error) {
	var out []byte
	for {
		chunk, err := br.ReadSlice('\n')
		out = append(out, chunk...)
		if len(out) > MaxLine {
			return nil, errLongLine
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return out, err
	}
}

// Filter selects entries for export and replay. Since is inclusive, Until is
// exclusive. Empty fields match everything.
type Filter struct {
	Agent string
	Grant string
	Since time.Time
	Until time.Time
}

func (f Filter) Match(e Entry) bool {
	if f.Agent != "" && e.Agent != f.Agent {
		return false
	}
	if f.Grant != "" && e.Grant != f.Grant {
		return false
	}
	if !f.Since.IsZero() && e.AtMS < f.Since.UnixMilli() {
		return false
	}
	if !f.Until.IsZero() && e.AtMS >= f.Until.UnixMilli() {
		return false
	}
	return true
}

// IsZero reports whether the filter selects every entry.
func (f Filter) IsZero() bool {
	return f.Agent == "" && f.Grant == "" && f.Since.IsZero() && f.Until.IsZero()
}
