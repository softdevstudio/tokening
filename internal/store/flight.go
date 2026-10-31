package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/softdevstudio/tokening/internal/flight"
	"github.com/softdevstudio/tokening/internal/matcher"
)

const flightPageSize = 256

// appendFlight adds one chained entry inside the caller's write transaction.
// The transaction already holds SQLite's write lock (_txlock=immediate), so
// reading the last entry and inserting the next cannot interleave with another
// writer, in this process or another one.
func appendFlight(ctx context.Context, tx *sql.Tx, kind flight.Kind, agent, grant string, at time.Time, body any) error {
	data, err := flight.NewBody(body)
	if err != nil {
		return fmt.Errorf("encode flight entry: %w", err)
	}
	var last, counter int64
	var prev [sha256.Size]byte
	var prevBytes []byte
	err = tx.QueryRowContext(ctx, `SELECT seq,hash FROM flight ORDER BY seq DESC LIMIT 1`).Scan(&last, &prevBytes)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return fmt.Errorf("read flight head: %w", err)
	case len(prevBytes) != sha256.Size:
		return errors.New("invalid flight hash in database")
	default:
		copy(prev[:], prevBytes)
	}
	// If entries were removed from the end, continue after the largest seq ever
	// assigned. The gap stays in the chain, where verify reports it.
	err = tx.QueryRowContext(ctx, `SELECT coalesce((SELECT seq FROM sqlite_sequence WHERE name='flight'),0)`).Scan(&counter)
	if err != nil {
		return fmt.Errorf("read flight counter: %w", err)
	}
	next := max(last, counter) + 1
	e := flight.Seal(flight.Entry{Seq: uint64(next), AtMS: at.UnixMilli(), Kind: kind, Agent: strings.ToValidUTF8(agent, "�"), Grant: strings.ToValidUTF8(grant, "�"), Body: data}, prev)
	_, err = tx.ExecContext(ctx, `INSERT INTO flight (seq,at,kind,agent,grant_id,body,prev,hash) VALUES (?,?,?,?,?,?,?,?)`,
		next, e.AtMS, string(e.Kind), e.Agent, e.Grant, string(e.Body), e.Prev[:], e.Hash[:])
	if err != nil {
		return fmt.Errorf("append flight entry: %w", err)
	}
	return nil
}

func callAction(call matcher.Call) string {
	if call.Tool != "" {
		return call.Tool
	}
	return call.Method + " " + call.Path
}

func callDigest(call matcher.Call) ([sha256.Size]byte, error) {
	data, err := json.Marshal(call)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("digest call: %w", err)
	}
	return sha256.Sum256(data), nil
}

// recordFlightCall appends the request and its decision, in that order.
func recordFlightCall(ctx context.Context, tx *sql.Tx, grant *matcher.Grant, agent string, call matcher.Call, d matcher.Decision, decisionID int64, now time.Time) error {
	digest, err := callDigest(call)
	if err != nil {
		return err
	}
	grantID := d.Grant
	// Tool and argument names come from the agent. They are bounded so one
	// request cannot produce an entry too long to verify from an export; the
	// digest still covers the whole call.
	request := flight.RequestBody{Target: flight.Clip(call.Target, flight.MaxActionBytes), Action: flight.Clip(callAction(call), flight.MaxActionBytes), ArgsDigest: hex.EncodeToString(digest[:])}
	request.Args, request.ArgsOmitted = flight.BoundNames(flight.SortedNames(call.Args))
	if len(call.Query) > 0 {
		request.Query, request.QueryOmitted = flight.BoundNames(flight.SortedNames(call.Query))
	}
	if err = appendFlight(ctx, tx, flight.KindRequest, agent, grantID, now, request); err != nil {
		return err
	}
	outcome := "refused"
	if d.Allowed {
		outcome = "allowed"
	}
	decision := flight.DecisionBody{DecisionID: decisionID, Outcome: outcome, Code: string(d.Code), Reason: d.Reason}
	if grant != nil {
		left := grant.UsesLeft
		if d.Allowed {
			left--
		}
		decision.UsesLeft = &left
	}
	return appendFlight(ctx, tx, flight.KindDecision, agent, grantID, now, decision)
}

// FlightHead returns the last entry's seq and hash. ok is false for an empty log.
func (s *Store) FlightHead(ctx context.Context) (head flight.Anchor, ok bool, err error) {
	var seq int64
	var hash []byte
	err = s.db.QueryRowContext(ctx, `SELECT seq,hash FROM flight ORDER BY seq DESC LIMIT 1`).Scan(&seq, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return head, false, nil
	}
	if err != nil {
		return head, false, fmt.Errorf("read flight head: %w", err)
	}
	if len(hash) != sha256.Size || seq <= 0 {
		return head, false, errors.New("invalid flight entry in database")
	}
	head.Seq = uint64(seq)
	copy(head.Hash[:], hash)
	return head, true, nil
}

// WalkFlight calls fn for each matching entry in seq order, up to the last
// entry committed when the walk started. Pages are read without holding a
// connection while fn runs.
func (s *Store) WalkFlight(ctx context.Context, filter flight.Filter, fn func(flight.Entry) error) error {
	var upper int64
	if err := s.db.QueryRowContext(ctx, `SELECT coalesce(max(seq),0) FROM flight`).Scan(&upper); err != nil {
		return fmt.Errorf("read flight boundary: %w", err)
	}
	return s.walkFlight(ctx, filter, upper, fn)
}

func (s *Store) walkFlight(ctx context.Context, filter flight.Filter, upper int64, fn func(flight.Entry) error) error {
	var after int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		page, err := s.readFlight(ctx, filter, after, upper)
		if err != nil {
			return err
		}
		if len(page) == 0 {
			return nil
		}
		for _, e := range page {
			if err = fn(e); err != nil {
				return err
			}
			after = int64(e.Seq)
		}
	}
}

func (s *Store) readFlight(ctx context.Context, filter flight.Filter, after, upper int64) ([]flight.Entry, error) {
	query := `SELECT seq,at,kind,agent,grant_id,body,prev,hash FROM flight WHERE seq>? AND seq<=?`
	args := []any{after, upper}
	if filter.Agent != "" {
		query += ` AND agent=?`
		args = append(args, filter.Agent)
	}
	if filter.Grant != "" {
		query += ` AND grant_id=?`
		args = append(args, filter.Grant)
	}
	if !filter.Since.IsZero() {
		query += ` AND at>=?`
		args = append(args, filter.Since.UnixMilli())
	}
	if !filter.Until.IsZero() {
		query += ` AND at<?`
		args = append(args, filter.Until.UnixMilli())
	}
	query += ` ORDER BY seq LIMIT ?`
	args = append(args, flightPageSize)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("read flight page: %w", err)
	}
	defer rows.Close()
	var out []flight.Entry
	for rows.Next() {
		var e flight.Entry
		var seq int64
		var kind, body string
		var prev, hash []byte
		if err = rows.Scan(&seq, &e.AtMS, &kind, &e.Agent, &e.Grant, &body, &prev, &hash); err != nil {
			return nil, fmt.Errorf("decode flight row: %w", err)
		}
		if seq <= 0 || len(prev) != sha256.Size || len(hash) != sha256.Size {
			return nil, errors.New("invalid flight entry in database")
		}
		e.Seq = uint64(seq)
		e.Kind = flight.Kind(kind)
		e.Body = json.RawMessage(body)
		copy(e.Prev[:], prev)
		copy(e.Hash[:], hash)
		out = append(out, e)
	}
	return out, rows.Err()
}

// VerifyFlight checks the whole chain in the database. Besides the chain, it
// compares the last entry with the largest seq SQLite ever assigned: a higher
// counter means entries were removed, or the chain was rebuilt shorter.
func (s *Store) VerifyFlight(ctx context.Context, opts flight.Options) (flight.Report, error) {
	opts.Partial = false
	var counter, upper int64
	// The counter is read first: an append between the two reads can only make
	// upper larger than the counter seen, never the other way round.
	if err := s.db.QueryRowContext(ctx, `SELECT coalesce((SELECT seq FROM sqlite_sequence WHERE name='flight'),0)`).Scan(&counter); err != nil {
		return flight.Report{}, fmt.Errorf("read flight counter: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT coalesce(max(seq),0) FROM flight`).Scan(&upper); err != nil {
		return flight.Report{}, fmt.Errorf("read flight boundary: %w", err)
	}
	v := flight.NewVerifier(opts)
	stop := errors.New("stop")
	err := s.walkFlight(ctx, flight.Filter{}, upper, func(e flight.Entry) error {
		if !v.Add(e) {
			return stop
		}
		return nil
	})
	if err != nil && !errors.Is(err, stop) {
		return flight.Report{}, err
	}
	if err == nil && counter > upper {
		v.Shorter(uint64(counter), uint64(upper))
	}
	return v.Finish(), nil
}

// ExportFlight writes matching entries as JSONL and returns how many were
// written. On failure the output may end in a partial line.
func (s *Store) ExportFlight(ctx context.Context, out io.Writer, filter flight.Filter) (int64, error) {
	if out == nil {
		return 0, errors.New("flight export needs a writer")
	}
	var rows int64
	err := s.WalkFlight(ctx, filter, func(e flight.Entry) error {
		line, err := flight.MarshalLine(e)
		if err != nil {
			return fmt.Errorf("encode flight entry %d: %w", e.Seq, err)
		}
		n, err := out.Write(line)
		if err == nil && n != len(line) {
			err = io.ErrShortWrite
		}
		if err != nil {
			return fmt.Errorf("write flight export: %w", err)
		}
		rows++
		return nil
	})
	return rows, err
}

// ErrNoFlightLog means the database predates the flight recorder.
var ErrNoFlightLog = errors.New("this database has no flight log yet; start tokening serve once with this version to upgrade it")

// OpenReadOnly opens an existing database for the flight commands. It never
// creates a file, applies migrations or takes a write lock, so it is safe next
// to a running server.
func OpenReadOnly(ctx context.Context, path string) (*Store, error) {
	if strings.TrimSpace(path) == "" || path == ":memory:" || strings.HasPrefix(path, "file:") {
		return nil, fmt.Errorf("store needs a filesystem path, not a SQLite URI or in-memory database")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("database path: %w", err)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("database must be a regular file")
	}
	uriPath := filepath.ToSlash(abs)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	u := url.URL{Scheme: "file", Path: uriPath}
	q := url.Values{}
	q.Set("mode", "ro")
	q.Add("_pragma", "busy_timeout(5000)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	var version int
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		db.Close()
		return nil, fmt.Errorf("open SQLite: %w", err)
	}
	if version > len(migrations) {
		db.Close()
		return nil, fmt.Errorf("database schema %d is newer than supported schema %d; use a newer Tokening binary", version, len(migrations))
	}
	if version < 4 {
		db.Close()
		return nil, ErrNoFlightLog
	}
	return &Store{db: db}, nil
}
