package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/softdevstudio/tokening/internal/matcher"
)

var ErrGrantUnknown = errors.New("grant does not exist")
var ErrInvalidIssue = errors.New("invalid grant issue request")

type IssueRequest struct {
	Template string
	Uses     int
	TTL      time.Duration
	Args     map[string]json.RawMessage
	Query    map[string]json.RawMessage
	IssuedTo string
	Reason   string
	IssuedBy string
}

// Secret may be serialized only in an issuance reply. Diagnostic formatting is
// redacted. Neither inspection nor the database contains this value.
type Secret string

func (Secret) String() string   { return "<grant secret>" }
func (Secret) GoString() string { return "<grant secret>" }

type IssuedGrant struct {
	Grant  GrantInfo `json:"grant"`
	Secret Secret    `json:"secret"`
}
type GrantInfo struct {
	ID              string                     `json:"id"`
	Template        string                     `json:"template"`
	TemplateVersion int                        `json:"template_version"`
	Target          string                     `json:"target"`
	Tool            string                     `json:"tool,omitempty"`
	Method          string                     `json:"method,omitempty"`
	Path            string                     `json:"path,omitempty"`
	BoundArgs       map[string]matcher.Binding `json:"bound_args"`
	BoundQuery      map[string]matcher.Binding `json:"bound_query"`
	State           string                     `json:"state"`
	InitialUses     int                        `json:"initial_uses"`
	UsesLeft        int                        `json:"uses_left"`
	CreatedAt       time.Time                  `json:"created_at"`
	ExpiresAt       time.Time                  `json:"expires_at"`
	IssuedTo        string                     `json:"issued_to"`
	Reason          string                     `json:"reason"`
	IssuedBy        string                     `json:"issued_by"`
	RevokedAt       *time.Time                 `json:"revoked_at,omitempty"`
	RevokedBy       string                     `json:"revoked_by,omitempty"`
	LastUsedAt      *time.Time                 `json:"last_used_at,omitempty"`
	DecisionCount   int64                      `json:"decision_count"`
	Decisions       []GrantDecision            `json:"decisions"`
}
type GrantDecision struct {
	ID      int64        `json:"id"`
	At      time.Time    `json:"at"`
	Action  string       `json:"action"`
	Outcome string       `json:"outcome"`
	Code    matcher.Code `json:"code"`
	Reason  string       `json:"reason"`
}

// IssueGrant narrows an active template. The random bearer secret is returned
// after commit, exactly once, and only its SHA-256 hash is stored.
func (s *Store) IssueGrant(ctx context.Context, request IssueRequest) (IssuedGrant, error) {
	var issued IssuedGrant
	if request.Uses <= 0 || request.TTL <= 0 || request.TTL%time.Millisecond != 0 || !validMetadata(request.IssuedTo, 256) || !validMetadata(request.IssuedBy, 256) || !validMetadata(request.Reason, 4096) {
		return issued, ErrInvalidIssue
	}
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		saved, err := loadActiveTemplate(ctx, tx, request.Template)
		if err != nil {
			return err
		}
		maximum, _ := time.ParseDuration(saved.template.MaxTTL)
		if request.Uses > saved.template.MaxUses || request.TTL > maximum {
			return fmt.Errorf("%w: uses or TTL exceeds the template limit", ErrInvalidIssue)
		}
		args, err := matcher.Bind(saved.template.Args, request.Args)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrInvalidIssue, err)
		}
		query, err := matcher.Bind(saved.template.Query, request.Query)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrInvalidIssue, err)
		}
		var idBytes [16]byte
		var secretBytes [32]byte
		if _, err = rand.Read(idBytes[:]); err != nil {
			return errors.New("generate grant ID failed")
		}
		if _, err = rand.Read(secretBytes[:]); err != nil {
			return errors.New("generate grant secret failed")
		}
		defer clear(secretBytes[:])
		id := "g_" + hex.EncodeToString(idBytes[:])
		secret := "tkn_" + base64.RawURLEncoding.EncodeToString(secretBytes[:])
		hash := sha256.Sum256([]byte(secret))
		at := time.Now().UTC().Truncate(time.Millisecond)
		expiry := at.Add(request.TTL)
		snapshot := matcher.Grant{ID: id, TargetKind: saved.kind, Template: saved.template, Args: args, Query: query, InitialUses: request.Uses, UsesLeft: request.Uses, ExpiresAt: expiry}
		if err = matcher.ValidateGrant(&snapshot); err != nil {
			return fmt.Errorf("%w: binding snapshot is invalid", ErrInvalidIssue)
		}
		argsJSON, err := json.Marshal(args)
		if err != nil {
			return err
		}
		queryJSON, err := json.Marshal(query)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO grants
   (id,secret_hash,template_id,template_version,bound_args_json,bound_query_json,initial_uses,uses_left,expires_at,issued_to,reason,issued_by,created_at)
   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, hash[:], request.Template, saved.version, string(argsJSON), string(queryJSON), request.Uses, request.Uses, expiry.UnixMilli(), request.IssuedTo, request.Reason, request.IssuedBy, at.UnixMilli())
		if err != nil {
			return fmt.Errorf("store issued grant: %w", err)
		}
		info, err := inspectGrant(ctx, tx, id)
		if err != nil {
			return err
		}
		issued = IssuedGrant{Grant: info, Secret: Secret(secret)}
		return nil
	})
	if err != nil {
		return IssuedGrant{}, err
	}
	return issued, nil
}

func (s *Store) InspectGrant(ctx context.Context, id string) (GrantInfo, error) {
	var info GrantInfo
	err := s.writeTx(ctx, func(tx *sql.Tx) error { var err error; info, err = inspectGrant(ctx, tx, id); return err })
	if err != nil {
		return GrantInfo{}, err
	}
	return info, nil
}

// RevokeGrant is idempotent and preserves the first revocation's time and actor.
func (s *Store) RevokeGrant(ctx context.Context, id, actor string) (GrantInfo, error) {
	if !validMetadata(actor, 256) {
		return GrantInfo{}, errors.New("revocation needs an actor")
	}
	var info GrantInfo
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE grants SET revoked_at=?,revoked_by=? WHERE id=? AND revoked_at IS NULL`, time.Now().UTC().UnixMilli(), actor, id); err != nil {
			return err
		}
		var err error
		info, err = inspectGrant(ctx, tx, id)
		return err
	})
	if err != nil {
		return GrantInfo{}, err
	}
	return info, nil
}
func inspectGrant(ctx context.Context, tx *sql.Tx, id string) (GrantInfo, error) {
	var info GrantInfo
	var args, query string
	var created, expires int64
	var revoked, lastUsed sql.NullInt64
	var actor sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT g.id,g.template_id,g.template_version,t.target_id,t.tool,t.method,t.path,g.bound_args_json,g.bound_query_json,
 g.initial_uses,g.uses_left,g.created_at,g.expires_at,g.issued_to,g.reason,g.issued_by,g.revoked_at,g.revoked_by,g.last_used_at
 FROM grants g JOIN templates t ON t.id=g.template_id AND t.version=g.template_version WHERE g.id=?`, id).Scan(
		&info.ID, &info.Template, &info.TemplateVersion, &info.Target, &info.Tool, &info.Method, &info.Path, &args, &query, &info.InitialUses, &info.UsesLeft, &created, &expires, &info.IssuedTo, &info.Reason, &info.IssuedBy, &revoked, &actor, &lastUsed)
	if errors.Is(err, sql.ErrNoRows) {
		return info, ErrGrantUnknown
	}
	if err != nil {
		return info, err
	}
	if err = decodeStored(args, &info.BoundArgs); err != nil {
		return info, err
	}
	if err = decodeStored(query, &info.BoundQuery); err != nil {
		return info, err
	}
	info.CreatedAt = time.UnixMilli(created).UTC()
	info.ExpiresAt = time.UnixMilli(expires).UTC()
	info.RevokedBy = actor.String
	if revoked.Valid {
		at := time.UnixMilli(revoked.Int64).UTC()
		info.RevokedAt = &at
	}
	if lastUsed.Valid {
		at := time.UnixMilli(lastUsed.Int64).UTC()
		info.LastUsedAt = &at
	}
	switch {
	case info.RevokedAt != nil:
		info.State = "revoked"
	case !time.Now().Before(info.ExpiresAt):
		info.State = "expired"
	case info.UsesLeft == 0:
		info.State = "exhausted"
	case info.LastUsedAt != nil:
		info.State = "active"
	default:
		info.State = "issued"
	}
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM decisions WHERE grant_id=?`, id).Scan(&info.DecisionCount); err != nil {
		return info, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,at,tool,outcome,code,reason FROM decisions WHERE grant_id=? ORDER BY id DESC LIMIT 100`, id)
	if err != nil {
		return info, err
	}
	defer rows.Close()
	info.Decisions = make([]GrantDecision, 0)
	for rows.Next() {
		var d GrantDecision
		var at int64
		if err = rows.Scan(&d.ID, &at, &d.Action, &d.Outcome, &d.Code, &d.Reason); err != nil {
			return info, err
		}
		d.At = time.UnixMilli(at).UTC()
		info.Decisions = append(info.Decisions, d)
	}
	return info, rows.Err()
}
func validMetadata(text string, max int) bool {
	return strings.TrimSpace(text) != "" && len(text) <= max && utf8.ValidString(text)
}
