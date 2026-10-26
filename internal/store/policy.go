package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/softdevstudio/tokening/internal/policy"
)

var ErrTemplateUnknown = errors.New("template is not active in the current policy")
var ErrTargetChanged = errors.New("an existing target definition cannot change; use a new target ID")

type savedTemplate struct {
	template policy.Template
	version  int
	kind     string
}

// ApplyPolicy atomically activates the supplied templates and preserves all
// historical versions. A target ID has a fixed destination and credential shape.
func (s *Store) ApplyPolicy(ctx context.Context, p policy.Policy) error {
	// Snapshot caller-owned maps before validating or entering the transaction.
	data, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("encode policy: %w", err)
	}
	snapshot, _, err := policy.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}
	p = *snapshot
	return s.writeTx(ctx, func(tx *sql.Tx) error {
		at := time.Now().UTC().UnixMilli()
		for _, name := range sortedKeys(p.Targets) {
			target := p.Targets[name]
			destination := target.URL
			if target.Kind == "mcp_stdio" {
				encoded, _ := json.Marshal(target.Command)
				destination = string(encoded)
			}
			var kind, urlOrCmd, credType, credRef string
			err := tx.QueryRowContext(ctx, `SELECT kind,url_or_cmd,credential_type,credential_ref FROM targets WHERE id=?`, name).Scan(&kind, &urlOrCmd, &credType, &credRef)
			if errors.Is(err, sql.ErrNoRows) {
				if _, err = tx.ExecContext(ctx, `INSERT INTO targets (id,kind,url_or_cmd,credential_type,credential_ref,created_at) VALUES (?,?,?,?,?,?)`, name, target.Kind, destination, target.Credential.Type, target.Credential.Ref, at); err != nil {
					return err
				}
			} else if err != nil {
				return err
			} else if kind != target.Kind || urlOrCmd != destination || credType != target.Credential.Type || credRef != target.Credential.Ref {
				return fmt.Errorf("target %s: %w", name, ErrTargetChanged)
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM active_templates`); err != nil {
			return err
		}
		for _, name := range sortedKeys(p.Templates) {
			t := p.Templates[name]
			ttl, _ := time.ParseDuration(t.MaxTTL)
			rules, err := json.Marshal(templateConstraints{Args: t.Args, Query: t.Query, AdditionalArgs: t.AdditionalArgs})
			if err != nil {
				return err
			}
			version := 1
			var priorVersion, priorUses int
			var priorTTL int64
			var priorTarget, tool, method, path, priorRules string
			err = tx.QueryRowContext(ctx, `SELECT version,target_id,tool,method,path,constraints_json,max_ttl_s,max_uses FROM templates WHERE id=? ORDER BY version DESC LIMIT 1`, name).Scan(&priorVersion, &priorTarget, &tool, &method, &path, &priorRules, &priorTTL, &priorUses)
			same := false
			if err == nil {
				version = priorVersion + 1
				same = priorTarget == t.Target && tool == t.Tool && method == t.Method && path == t.Path && priorRules == string(rules) && priorTTL == int64(ttl/time.Second) && priorUses == t.MaxUses
				if same {
					version = priorVersion
				}
			} else if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if !same {
				if _, err = tx.ExecContext(ctx, `INSERT INTO templates (id,version,target_id,tool,method,path,constraints_json,max_ttl_s,max_uses,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)`, name, version, t.Target, t.Tool, t.Method, t.Path, string(rules), int64(ttl/time.Second), t.MaxUses, at); err != nil {
					return err
				}
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO active_templates (id,version) VALUES (?,?)`, name, version); err != nil {
				return err
			}
		}
		return nil
	})
}
func loadActiveTemplate(ctx context.Context, tx *sql.Tx, name string) (savedTemplate, error) {
	var out savedTemplate
	var rules string
	var ttl int64
	err := tx.QueryRowContext(ctx, `SELECT tpl.version,t.kind,tpl.target_id,tpl.tool,tpl.method,tpl.path,tpl.constraints_json,tpl.max_ttl_s,tpl.max_uses
 FROM active_templates a JOIN templates tpl ON tpl.id=a.id AND tpl.version=a.version JOIN targets t ON t.id=tpl.target_id WHERE a.id=?`, name).Scan(&out.version, &out.kind, &out.template.Target, &out.template.Tool, &out.template.Method, &out.template.Path, &rules, &ttl, &out.template.MaxUses)
	if errors.Is(err, sql.ErrNoRows) {
		return out, ErrTemplateUnknown
	}
	if err != nil {
		return out, err
	}
	if ttl <= 0 || ttl > int64((1<<63-1)/time.Second) {
		return out, fmt.Errorf("invalid saved template TTL")
	}
	out.template.MaxTTL = (time.Duration(ttl) * time.Second).String()
	var c templateConstraints
	if err = decodeStored(rules, &c); err != nil {
		return out, err
	}
	out.template.Args = c.Args
	out.template.Query = c.Query
	out.template.AdditionalArgs = c.AdditionalArgs
	if _, err = out.template.Validate(out.kind); err != nil {
		return out, err
	}
	return out, nil
}
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
