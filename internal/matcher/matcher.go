// Package matcher checks a normalized call against an immutable grant snapshot.
// It performs no I/O and never consumes a grant use.
package matcher

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/softdevstudio/tokening/internal/number"
	"github.com/softdevstudio/tokening/internal/policy"
)

type Code string

const (
	Allowed        Code = "allowed"
	GrantUnknown   Code = "grant_unknown"
	GrantExpired   Code = "grant_expired"
	GrantExhausted Code = "grant_exhausted"
	GrantRevoked   Code = "grant_revoked"
	ToolNotAllowed Code = "tool_not_allowed"
	ArgMismatch    Code = "arg_mismatch"
	ArgNotAllowed  Code = "arg_not_allowed"
	ArgLimit       Code = "arg_limit"
	UpstreamError  Code = "upstream_error"
)

// Allowed describes authorization. A forwarded call with an upstream error was
// still authorized and its use remains spent.
type Decision struct {
	Allowed bool   `json:"allowed"`
	Code    Code   `json:"code"`
	Reason  string `json:"reason"`
	Grant   string `json:"grant,omitempty"`
}

// Binding contains either a JSON scalar value or a lowercase SHA-256 digest.
// Hash-bound values are never stored here as plaintext.
type Binding struct {
	Value  json.RawMessage `json:"value,omitempty"`
	SHA256 string          `json:"sha256,omitempty"`
}
type Grant struct {
	ID          string
	TargetKind  string
	Template    policy.Template
	Args        map[string]Binding
	Query       map[string]Binding
	InitialUses int
	UsesLeft    int
	ExpiresAt   time.Time
	RevokedAt   *time.Time
	RevokedBy   string
	LastUsedAt  *time.Time
}

// Call contains parsed JSON scalar arguments. Path is the decoded REST path,
// without a query, percent escapes or dot segments. Query values have already
// been normalized to their declared scalar types by the transport adapter.
type Call struct {
	Target string
	Tool   string
	Method string
	Path   string
	Args   map[string]json.RawMessage
	Query  map[string]json.RawMessage
}

// Match returns an error for corrupt grant snapshots. Such errors must fail
// closed in a caller; they are distinct from a valid grant refusing a call.
// now is supplied by the caller so the decision is deterministic.
func Match(g *Grant, c Call, now time.Time) (Decision, error) {
	if g == nil {
		return Decision{Code: GrantUnknown, Reason: "No grant matches this token."}, nil
	}
	refuse := func(code Code, reason string) (Decision, error) {
		return Decision{Code: code, Reason: reason, Grant: g.ID}, nil
	}
	if err := validateGrant(g); err != nil {
		return Decision{}, fmt.Errorf("invalid grant snapshot: %w", err)
	}
	if g.RevokedAt != nil {
		return refuse(GrantRevoked, fmt.Sprintf("Grant %s was revoked at %s.", g.ID, g.RevokedAt.UTC().Format(time.RFC3339Nano)))
	}
	if !now.Before(g.ExpiresAt) {
		return refuse(GrantExpired, fmt.Sprintf("Grant %s expired at %s.", g.ID, g.ExpiresAt.UTC().Format(time.RFC3339Nano)))
	}
	if c.Target != g.Template.Target {
		return refuse(ToolNotAllowed, "This grant does not allow that target.")
	}
	args := make(map[string]json.RawMessage, len(c.Args))
	for k, v := range c.Args {
		args[k] = v
	}
	if g.TargetKind == "http" {
		if c.Tool != "" || c.Method != g.Template.Method || !safePath(c.Path) {
			return refuse(ToolNotAllowed, "This grant does not allow that HTTP method or path.")
		}
		pathArgs, ok := extractPath(g.Template.Path, c.Path)
		if !ok {
			return refuse(ToolNotAllowed, "This grant does not allow that HTTP path.")
		}
		for _, name := range keys(pathArgs) {
			text := pathArgs[name]
			rule := g.Template.Args[name]
			raw, err := pathScalar(text, rule, g.Args[name])
			if err != nil {
				return refuse(ArgMismatch, "Path argument "+name+" does not match its binding.")
			}
			if prior, exists := args[name]; exists && !equal(prior, raw) {
				return refuse(ArgMismatch, "Path and body disagree about argument "+name+".")
			}
			args[name] = raw
		}
	} else if c.Tool != g.Template.Tool || c.Method != "" || c.Path != "" || len(c.Query) != 0 {
		return refuse(ToolNotAllowed, "This grant does not allow that tool or transport.")
	}
	for _, group := range []struct {
		name     string
		rules    map[string]policy.Constraint
		bindings map[string]Binding
		values   map[string]json.RawMessage
	}{
		{"argument", g.Template.Args, g.Args, args}, {"query parameter", g.Template.Query, g.Query, c.Query},
	} {
		code, reason := checkGroup(group.name, group.rules, group.bindings, group.values, g.Template.AdditionalArgs == "allow")
		if code != "" {
			return refuse(code, reason)
		}
	}
	// Check scope before exhaustion so the demo can explain attempts to edit a
	// different post or delete a post even after the valid edit spent the use.
	if g.UsesLeft == 0 {
		return refuse(GrantExhausted, fmt.Sprintf("Grant %s allowed %d use(s) and has none left.", g.ID, g.InitialUses))
	}
	return Decision{Allowed: true, Code: Allowed, Reason: "Call fits this grant. A use must be consumed before forwarding.", Grant: g.ID}, nil
}

func validateGrant(g *Grant) error {
	if g.ID == "" || g.InitialUses <= 0 || g.InitialUses > g.Template.MaxUses || g.UsesLeft < 0 || g.UsesLeft > g.InitialUses || g.ExpiresAt.IsZero() {
		return fmt.Errorf("invalid identity, counter or expiry")
	}
	if _, err := g.Template.Validate(g.TargetKind); err != nil {
		return err
	}
	for _, group := range []struct {
		rules    map[string]policy.Constraint
		bindings map[string]Binding
	}{{g.Template.Args, g.Args}, {g.Template.Query, g.Query}} {
		for _, name := range keys(group.bindings) {
			binding := group.bindings[name]
			rule, ok := group.rules[name]
			if !ok || rule.Bind == "" {
				return fmt.Errorf("unexpected binding %s", name)
			}
			if rule.SHA256 {
				digest, err := hex.DecodeString(binding.SHA256)
				if err != nil || len(digest) != sha256.Size || binding.SHA256 != strings.ToLower(binding.SHA256) || len(binding.Value) != 0 {
					return fmt.Errorf("invalid hash binding %s", name)
				}
			} else {
				if binding.SHA256 != "" || len(binding.Value) == 0 {
					return fmt.Errorf("invalid value binding %s", name)
				}
				if err := checkValue(rule, binding.Value); err != nil {
					return fmt.Errorf("binding %s: %w", name, err)
				}
			}
		}
		for _, name := range keys(group.rules) {
			rule := group.rules[name]
			if rule.Bind == "required" || rule.SHA256 {
				if _, ok := group.bindings[name]; !ok {
					return fmt.Errorf("missing binding %s", name)
				}
			}
		}
	}
	return nil
}

func checkGroup(label string, rules map[string]policy.Constraint, bindings map[string]Binding, values map[string]json.RawMessage, allowAdditional bool) (Code, string) {
	for _, name := range keys(bindings) {
		binding := bindings[name]
		raw, ok := values[name]
		if !ok {
			return ArgMismatch, fmt.Sprintf("Bound %s %s is missing.", label, name)
		}
		if binding.SHA256 != "" {
			value, err := scalar(raw)
			if err != nil || value.kind != "string" {
				return ArgLimit, fmt.Sprintf("%s %s must be a string.", label, name)
			}
			digest := sha256.Sum256([]byte(value.text))
			want, _ := hex.DecodeString(binding.SHA256)
			if subtle.ConstantTimeCompare(digest[:], want) != 1 {
				return ArgMismatch, fmt.Sprintf("%s %s does not match its bound hash.", label, name)
			}
		} else if !equal(raw, binding.Value) {
			return ArgMismatch, fmt.Sprintf("%s %s does not match its bound value.", label, name)
		}
	}
	for _, name := range keys(values) {
		rule, ok := rules[name]
		if !ok {
			if !allowAdditional {
				return ArgNotAllowed, fmt.Sprintf("This grant does not allow %s %s.", label, name)
			}
			if !json.Valid(values[name]) || !utf8.Valid(values[name]) {
				return ArgLimit, fmt.Sprintf("%s %s must be valid JSON.", label, name)
			}
			continue
		}
		if err := checkValue(rule, values[name]); err != nil {
			return ArgLimit, fmt.Sprintf("%s %s: %s", label, name, err)
		}
	}
	return "", ""
}

func checkValue(c policy.Constraint, raw json.RawMessage) error {
	v, err := scalar(raw)
	if err != nil {
		return err
	}
	switch c.Type {
	case "": // A required, exactly bound scalar may omit its type.
	case "number", "integer":
		if v.kind != "number" {
			return fmt.Errorf("must be a %s", c.Type)
		}
		n, err := number.Parse(v.text)
		if err != nil {
			return err
		}
		if c.Type == "integer" && !n.IsInt() {
			return fmt.Errorf("must be an integer")
		}
		if c.Min != nil {
			min, _ := number.Parse(string(*c.Min))
			if n.Cmp(min) < 0 {
				return fmt.Errorf("is below the minimum")
			}
		}
		if c.Max != nil {
			max, _ := number.Parse(string(*c.Max))
			if n.Cmp(max) > 0 {
				return fmt.Errorf("exceeds the maximum")
			}
		}
	default:
		if v.kind != c.Type {
			return fmt.Errorf("must be a %s", c.Type)
		}
	}
	if v.kind == "string" {
		if c.MaxLen != nil && utf8.RuneCountInString(v.text) > *c.MaxLen {
			return fmt.Errorf("exceeds the character limit")
		}
		if c.MaxBytes != nil && len(v.text) > *c.MaxBytes {
			return fmt.Errorf("exceeds the UTF-8 byte limit")
		}
		if c.Pattern != "" {
			pattern, err := regexp.Compile(`\A(?:` + c.Pattern + `)\z`)
			if err != nil || !pattern.MatchString(v.text) {
				return fmt.Errorf("does not match the pattern")
			}
		}
	}
	if c.Enum != nil {
		for _, allowed := range c.Enum {
			if equal(raw, allowed) {
				return nil
			}
		}
		return fmt.Errorf("is not one of the allowed values")
	}
	return nil
}

var placeholder = regexp.MustCompile(`\{([A-Za-z0-9][A-Za-z0-9._-]*)\}`)

func extractPath(template, path string) (map[string]string, bool) {
	matches := placeholder.FindAllStringSubmatchIndex(template, -1)
	var pattern strings.Builder
	pattern.WriteString(`\A`)
	at := 0
	names := []string{}
	for _, m := range matches {
		pattern.WriteString(regexp.QuoteMeta(template[at:m[0]]))
		pattern.WriteString(`([^/]+)`)
		names = append(names, template[m[2]:m[3]])
		at = m[1]
	}
	pattern.WriteString(regexp.QuoteMeta(template[at:]))
	pattern.WriteString(`\z`)
	re, err := regexp.Compile(pattern.String())
	if err != nil {
		return nil, false
	}
	values := re.FindStringSubmatch(path)
	if values == nil {
		return nil, false
	}
	out := map[string]string{}
	for i, name := range names {
		if prior, ok := out[name]; ok && prior != values[i+1] {
			return nil, false
		}
		out[name] = values[i+1]
	}
	return out, true
}
func safePath(path string) bool {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "%?#\\") || strings.Contains(path, "//") || !utf8.ValidString(path) {
		return false
	}
	for _, r := range path {
		if unicode.IsControl(r) {
			return false
		}
	}
	for _, s := range strings.Split(path, "/") {
		if s == "." || s == ".." {
			return false
		}
	}
	return true
}
func pathScalar(text string, c policy.Constraint, b Binding) (json.RawMessage, error) {
	kind := c.Type
	if kind == "" {
		v, err := scalar(b.Value)
		if err != nil {
			return nil, err
		}
		kind = v.kind
	}
	if kind == "string" {
		return json.Marshal(text)
	}
	// A URL segment is a routing identifier, not a JSON number. Do not allow
	// alternate numeric spellings (2e0, 2.0) to match an ID bound as 2: an
	// upstream router could interpret those strings as different resources.
	if text != strings.TrimSpace(string(b.Value)) {
		return nil, fmt.Errorf("path spelling differs from binding")
	}
	raw := json.RawMessage(text)
	if err := checkValue(c, raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// UpstreamFailure records that forwarding failed after authorization. It never
// refunds a use. Status zero represents a transport failure.
func UpstreamFailure(grant string, status int) Decision {
	reason := "Call was authorized and forwarded, but the upstream request failed. The use remains consumed."
	if status >= 100 && status <= 599 {
		reason = fmt.Sprintf("Call was authorized and forwarded; the upstream returned HTTP %d. The use remains consumed.", status)
	}
	return Decision{Allowed: true, Code: UpstreamError, Reason: reason, Grant: grant}
}
func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
