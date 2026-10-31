package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/softdevstudio/tokening/internal/matcher"
	"github.com/softdevstudio/tokening/internal/policy"
)

// templateConstraints is the wire shape in templates.constraints_json. Scope,
// limits and version identity live in the other template columns.
type templateConstraints struct {
	Args           map[string]policy.Constraint `json:"args,omitempty"`
	Query          map[string]policy.Constraint `json:"query,omitempty"`
	AdditionalArgs string                       `json:"additional_args,omitempty"`
}

// Consume authenticates the bearer secret, matches the persisted grant and
// atomically spends a use with its authorization audit row. Only an allowed
// decision AND a nil error permit forwarding. A commit error must fail closed:
// the caller cannot assume that the transaction did not reach durable storage.
func (s *Store) Consume(ctx context.Context, secret string, call matcher.Call) (Consumption, error) {
	var decision Consumption
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		var err error
		decision, err = consumeInTx(ctx, tx, sha256.Sum256([]byte(secret)), call, time.Now)
		return err
	})
	if err != nil {
		return Consumption{}, err
	}

	return decision, nil
}

// The transaction owns the write lock before this function runs. Keeping this
// core separate also lets crash tests stop after the real update and audit write
// but before commit, without production test hooks or timing-based sleeps.
func consumeInTx(ctx context.Context, tx *sql.Tx, hash [sha256.Size]byte, call matcher.Call, clock func() time.Time) (Consumption, error) {
	grant, agent, err := loadGrant(ctx, tx, hash)
	if err != nil {
		return Consumption{}, err
	}
	now := clock().UTC()
	decision, err := matcher.Match(grant, call, now)
	if err != nil {
		return Consumption{}, err
	}
	if decision.Allowed {
		// Recheck expiry against a fresh server time after matching, never a time
		// supplied by the agent or sampled before waiting for the write lock.
		now = clock().UTC()
		decision, err = matcher.Match(grant, call, now)
		if err != nil {
			return Consumption{}, err
		}
		if decision.Allowed {
			result, err := tx.ExecContext(ctx, `UPDATE grants
    SET uses_left=uses_left-1,last_used_at=?
    WHERE id=? AND uses_left>0 AND expires_at>? AND revoked_at IS NULL`, now.UnixMilli(), grant.ID, now.UnixMilli())
			if err != nil {
				return Consumption{}, fmt.Errorf("consume grant use: %w", err)
			}
			changed, err := result.RowsAffected()
			if err != nil {
				return Consumption{}, err
			}
			if changed != 1 {
				return Consumption{}, fmt.Errorf("grant state changed unexpectedly inside consumption transaction")
			}
		}
	}
	if decision.Allowed {
		decision.Reason = "Call fits this grant. One use was consumed before forwarding."
	}
	id, err := insertDecision(ctx, tx, decision, call, agent, now)
	if err != nil {
		return Consumption{}, err
	}
	// The flight entries share this transaction: they commit with the use and
	// the audit row, or not at all.
	if err = recordFlightCall(ctx, tx, grant, agent, call, decision, id, now); err != nil {
		return Consumption{}, err
	}
	return Consumption{Decision: decision, ReceiptID: id}, nil
}

func loadGrant(ctx context.Context, tx *sql.Tx, hash [sha256.Size]byte) (*matcher.Grant, string, error) {
	var g matcher.Grant
	var constraints, args, query string
	var ttlSeconds, expires int64
	var revoked, lastUsed sql.NullInt64
	var revokedBy sql.NullString
	var agent string
	err := tx.QueryRowContext(ctx, `SELECT g.id,t.kind,tpl.target_id,tpl.tool,tpl.method,tpl.path,
  tpl.constraints_json,tpl.max_ttl_s,tpl.max_uses,g.bound_args_json,g.bound_query_json,
  g.initial_uses,g.uses_left,g.expires_at,g.revoked_at,g.revoked_by,g.last_used_at,g.issued_to
  FROM grants g JOIN templates tpl ON tpl.id=g.template_id AND tpl.version=g.template_version
  JOIN targets t ON t.id=tpl.target_id WHERE g.secret_hash=?`, hash[:]).Scan(
		&g.ID, &g.TargetKind, &g.Template.Target, &g.Template.Tool, &g.Template.Method, &g.Template.Path,
		&constraints, &ttlSeconds, &g.Template.MaxUses, &args, &query, &g.InitialUses, &g.UsesLeft,
		&expires, &revoked, &revokedBy, &lastUsed, &agent)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("read grant snapshot: %w", err)
	}
	if ttlSeconds <= 0 || ttlSeconds > math.MaxInt64/int64(time.Second) {
		return nil, "", fmt.Errorf("invalid template TTL in database")
	}
	g.Template.MaxTTL = (time.Duration(ttlSeconds) * time.Second).String()
	var rules templateConstraints
	if err = decodeStored(constraints, &rules); err != nil {
		return nil, "", fmt.Errorf("read template constraints: %w", err)
	}
	g.Template.Args = rules.Args
	g.Template.Query = rules.Query
	g.Template.AdditionalArgs = rules.AdditionalArgs
	if err = decodeStored(args, &g.Args); err != nil {
		return nil, "", fmt.Errorf("read argument bindings: %w", err)
	}
	if err = decodeStored(query, &g.Query); err != nil {
		return nil, "", fmt.Errorf("read query bindings: %w", err)
	}
	g.ExpiresAt = time.UnixMilli(expires).UTC()
	if revoked.Valid {
		t := time.UnixMilli(revoked.Int64).UTC()
		g.RevokedAt = &t
	}
	if lastUsed.Valid {
		t := time.UnixMilli(lastUsed.Int64).UTC()
		g.LastUsedAt = &t
	}
	g.RevokedBy = revokedBy.String
	return &g, agent, nil
}
func decodeStored(text string, out any) error {
	d := json.NewDecoder(bytes.NewBufferString(text))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("stored JSON has trailing content")
	}
	return nil
}
func recordDecision(ctx context.Context, tx *sql.Tx, d matcher.Decision, call matcher.Call, agent string, now time.Time) error {
	_, err := insertDecision(ctx, tx, d, call, agent, now)
	return err
}
func insertDecision(ctx context.Context, tx *sql.Tx, d matcher.Decision, call matcher.Call, agent string, now time.Time) (int64, error) {
	digest, err := callDigest(call)
	if err != nil {
		return 0, err
	}
	var grantID any
	if d.Grant != "" {
		grantID = d.Grant
	}
	action := callAction(call)
	outcome := "refused"
	if d.Allowed {
		outcome = "allowed"
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO decisions (grant_id,at,agent,tool,args_digest,outcome,code,reason)
  VALUES (?,?,?,?,?,?,?,?)`, grantID, now.UnixMilli(), agent, action, digest[:], outcome, string(d.Code), d.Reason)
	if err != nil {
		return 0, fmt.Errorf("record authorization decision: %w", err)
	}
	return result.LastInsertId()
}
