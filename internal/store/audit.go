package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/softdevstudio/tokening/internal/matcher"
)

const auditPageSize = 256
const MaxDecisionPage = 1000

var ErrInvalidAuditQuery = errors.New("invalid audit query: cursor must be nonnegative and page size must be between 1 and 1000")

// DecisionRecord selects only audit columns. It never joins credentials, bearer
// hashes, binding plaintext or upstream response bodies into an export.
type DecisionRecord struct {
	ID             int64        `json:"id"`
	GrantID        *string      `json:"grant_id"`
	At             time.Time    `json:"at"`
	Agent          string       `json:"agent"`
	Action         string       `json:"action"`
	ArgsDigest     string       `json:"args_digest"`
	Outcome        string       `json:"outcome"`
	Code           matcher.Code `json:"code"`
	Reason         string       `json:"reason"`
	UpstreamStatus *int         `json:"upstream_status"`
	LatencyMS      *int64       `json:"latency_ms"`
}
type DecisionFilter struct {
	// AfterID is an exclusive cursor. Zero starts at the first record.
	AfterID int64
	GrantID string
}
type AuditExport struct {
	Rows int64 `json:"rows"`
	// LastID advances only after a whole JSONL record was successfully written.
	LastID int64 `json:"last_id"`
	// ThroughID is the largest committed audit ID seen at export start.
	ThroughID int64 `json:"through_id"`
}

// ListDecisions returns a bounded, ID-ordered page for future admin polling/SSE.
// A zero limit selects the default page size of 100.
func (s *Store) ListDecisions(ctx context.Context, filter DecisionFilter, limit int) ([]DecisionRecord, error) {
	if limit == 0 {
		limit = 100
	}
	if filter.AfterID < 0 || limit < 1 || limit > MaxDecisionPage {
		return nil, ErrInvalidAuditQuery
	}
	through, err := s.auditUpperID(ctx)
	if err != nil {
		return nil, err
	}
	return s.readDecisions(ctx, filter, through, limit)
}

// ExportDecisions writes one JSON object per line. Appends after the initial
// ThroughID belong to the next export. No database connection is held while
// writing to the caller, and memory is bounded to one page plus one JSON record.
// On failure the output may end in a partial line; it must not be treated as a
// completed export. Context is checked between writes, not inside an arbitrary
// blocking io.Writer implementation.
func (s *Store) ExportDecisions(ctx context.Context, out io.Writer, filter DecisionFilter) (AuditExport, error) {
	result := AuditExport{LastID: filter.AfterID}
	if filter.AfterID < 0 {
		return result, ErrInvalidAuditQuery
	}
	if out == nil {
		return result, errors.New("audit export needs a writer")
	}
	through, err := s.auditUpperID(ctx)
	if err != nil {
		return result, err
	}
	result.ThroughID = through
	for {
		if err = ctx.Err(); err != nil {
			return result, err
		}
		page, err := s.readDecisions(ctx, filter, through, auditPageSize)
		if err != nil {
			return result, err
		}
		if len(page) == 0 {
			return result, nil
		}
		for _, record := range page {
			if err = ctx.Err(); err != nil {
				return result, err
			}
			line, err := json.Marshal(record)
			if err != nil {
				return result, fmt.Errorf("encode audit record: %w", err)
			}
			line = append(line, '\n')
			n, err := out.Write(line)
			if err != nil {
				return result, fmt.Errorf("write audit export: %w", err)
			}
			if n != len(line) {
				return result, fmt.Errorf("write audit export: %w", io.ErrShortWrite)
			}
			result.Rows++
			result.LastID = record.ID
			filter.AfterID = record.ID
		}
	}
}
func (s *Store) auditUpperID(ctx context.Context) (int64, error) {
	var upper int64
	if err := s.db.QueryRowContext(ctx, `SELECT coalesce(max(id),0) FROM decisions`).Scan(&upper); err != nil {
		return 0, fmt.Errorf("read audit boundary: %w", err)
	}
	return upper, nil
}
func (s *Store) readDecisions(ctx context.Context, filter DecisionFilter, through int64, limit int) ([]DecisionRecord, error) {
	query := `SELECT id,grant_id,at,agent,tool,args_digest,outcome,code,reason,upstream_status,latency_ms
 FROM decisions WHERE id>? AND id<=?`
	args := []any{filter.AfterID, through}
	if filter.GrantID != "" {
		query += ` AND grant_id=?`
		args = append(args, filter.GrantID)
	}
	query += ` ORDER BY id LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("read audit page: %w", err)
	}
	defer rows.Close()
	records := make([]DecisionRecord, 0, limit)
	for rows.Next() {
		var r DecisionRecord
		var grant sql.NullString
		var status, latency sql.NullInt64
		var at int64
		var digest []byte
		if err = rows.Scan(&r.ID, &grant, &at, &r.Agent, &r.Action, &digest, &r.Outcome, &r.Code, &r.Reason, &status, &latency); err != nil {
			return nil, fmt.Errorf("decode audit row: %w", err)
		}
		if len(digest) != 32 {
			return nil, errors.New("invalid audit digest in database")
		}
		if grant.Valid {
			id := grant.String
			r.GrantID = &id
		}
		r.At = time.UnixMilli(at).UTC()
		r.ArgsDigest = hex.EncodeToString(digest)
		if status.Valid {
			n := int(status.Int64)
			r.UpstreamStatus = &n
		}
		if latency.Valid {
			n := latency.Int64
			r.LatencyMS = &n
		}
		records = append(records, r)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("read audit page: %w", err)
	}
	return records, nil
}
