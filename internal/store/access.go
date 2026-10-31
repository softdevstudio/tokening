package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/softdevstudio/tokening/internal/flight"
	"github.com/softdevstudio/tokening/internal/matcher"
)

// Consumption is returned only after its authorization record has committed.
// ReceiptID stays on the trusted server side and links a later outcome record.
type Consumption struct {
	matcher.Decision
	ReceiptID int64 `json:"-"`
}
type TargetInfo struct{ ID, Kind, Destination, CredentialType string }

// ResolveGrant returns a saved permission snapshot without spending a use. It
// exposes no bearer hash, real credential or admin audit history.
func (s *Store) ResolveGrant(ctx context.Context, secret string) (*matcher.Grant, error) {
	var grant *matcher.Grant
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		var err error
		grant, _, err = loadGrant(ctx, tx, sha256.Sum256([]byte(secret)))
		if err != nil {
			return err
		}
		if grant != nil {
			return matcher.ValidateGrant(grant)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return grant, nil
}
func (s *Store) Target(ctx context.Context, id string) (TargetInfo, error) {
	out := TargetInfo{ID: id}
	err := s.db.QueryRowContext(ctx, `SELECT kind,url_or_cmd,credential_type FROM targets WHERE id=?`, id).Scan(&out.Kind, &out.Destination, &out.CredentialType)
	if errors.Is(err, sql.ErrNoRows) {
		return TargetInfo{}, ErrTargetUnknown
	}
	return out, err
}

// CompleteUpstream appends one completion record per allowed authorization.
// It cannot refund a use or mutate an authorization. A failure status of zero
// means no upstream HTTP response was received.
func (s *Store) CompleteUpstream(ctx context.Context, receipt Consumption, status int, latency time.Duration, failed bool) error {
	if !receipt.Allowed || receipt.ReceiptID <= 0 || receipt.Grant == "" || status < 0 || status > 599 || status > 0 && status < 100 || latency < 0 {
		return errors.New("invalid upstream completion")
	}
	code := matcher.Allowed
	reason := fmt.Sprintf("Authorized call completed with upstream HTTP %d. The use remains consumed.", status)
	if failed || status == 0 || status >= 400 {
		code = matcher.UpstreamError
		reason = "Authorized forwarding failed. The use remains consumed."
	}
	var statusValue any
	if status != 0 {
		statusValue = status
	}
	return s.writeTx(ctx, func(tx *sql.Tx) error {
		now := time.Now().UTC()
		result, err := tx.ExecContext(ctx, `INSERT INTO decisions (grant_id,at,agent,tool,args_digest,outcome,code,reason,upstream_status,latency_ms,authorization_id)
   SELECT grant_id,?,agent,tool,args_digest,'allowed',?,?,?,?,id FROM decisions
   WHERE id=? AND grant_id=? AND outcome='allowed' AND code='allowed' AND authorization_id IS NULL`, now.UnixMilli(), string(code), reason, statusValue, latency.Milliseconds(), receipt.ReceiptID, receipt.Grant)
		if err != nil {
			return fmt.Errorf("append upstream completion: %w", err)
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return errors.New("authorization receipt not found")
		}
		id, err := result.LastInsertId()
		if err != nil {
			return err
		}
		var agent string
		if err = tx.QueryRowContext(ctx, `SELECT agent FROM decisions WHERE id=?`, id).Scan(&agent); err != nil {
			return fmt.Errorf("read completion record: %w", err)
		}
		body := flight.ResultBody{DecisionID: id, AuthorizationID: receipt.ReceiptID, Code: string(code), LatencyMS: latency.Milliseconds()}
		if status != 0 {
			body.UpstreamStatus = &status
		}
		return appendFlight(ctx, tx, flight.KindResult, agent, receipt.Grant, now, body)
	})
}
