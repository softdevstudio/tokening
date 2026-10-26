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
	"strconv"
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
	if err := ValidateGrant(g); err != nil {
		return Decision{}, fmt.Errorf("invalid grant snapshot: %w", err)
	}
	if g.RevokedAt != nil {
		return refuse(GrantRevoked, fmt.Sprintf("Grant %s was revoked at %s.", g.ID, g.RevokedAt.UTC().Format(time.RFC3339Nano)))
	}
	if !now.Before(g.ExpiresAt) {
		return refuse(GrantExpired, fmt.Sprintf("Grant %s expired at %s.", g.ID, g.ExpiresAt.UTC().Format(time.RFC3339Nano)))
	}
	if c.Target != g.Template.Target {
		return refuse(ToolNotAllowed, fmt.Sprintf("Grant is for target %s; call went to %s.", g.Template.Target, quoteShort(c.Target)))
	}
	args := make(map[string]json.RawMessage, len(c.Args))
	for k, v := range c.Args {
		args[k] = v
	}
	if g.TargetKind == "http" {
		if c.Tool != "" || c.Method != g.Template.Method || !safePath(c.Path) {
			if c.Method == "" {
				return refuse(ToolNotAllowed, fmt.Sprintf("Grant allows %s %s; call was not a REST request.", g.Template.Method, g.Template.Path))
			}
			return refuse(ToolNotAllowed, fmt.Sprintf("Grant allows %s %s; call used %s on another path.", g.Template.Method, g.Template.Path, quoteShort(c.Method)))
		}
		pathArgs, ok := extractPath(g.Template.Path, c.Path)
		if !ok {
			return refuse(ToolNotAllowed, fmt.Sprintf("Grant allows %s %s; call used another path.", g.Template.Method, g.Template.Path))
		}
		for _, name := range keys(pathArgs) {
			text := pathArgs[name]
			rule := g.Template.Args[name]
			raw, err := pathScalar(text, rule, g.Args[name])
			if err != nil {
				return refuse(ArgMismatch, mismatchReason("path argument", name, g.Args[name].Value, json.RawMessage(text)))
			}
			if prior, exists := args[name]; exists && !equal(prior, raw) {
				return refuse(ArgMismatch, "Path and body disagree about argument "+name+".")
			}
			args[name] = raw
		}
	} else if c.Tool != g.Template.Tool || c.Method != "" || c.Path != "" || len(c.Query) != 0 {
		if c.Tool != g.Template.Tool && c.Method == "" && c.Path == "" && len(c.Query) == 0 {
			return refuse(ToolNotAllowed, fmt.Sprintf("Grant allows %s; call asked for %s.", g.Template.Tool, quoteShort(c.Tool)))
		}
		return refuse(ToolNotAllowed, fmt.Sprintf("Grant allows MCP tool %s only; call used another transport.", g.Template.Tool))
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
		return refuse(GrantExhausted, fmt.Sprintf("Grant %s allowed %s and has none left.", g.ID, plural(g.InitialUses, "use")))
	}
	return Decision{Allowed: true, Code: Allowed, Reason: "Call fits this grant. A use must be consumed before forwarding.", Grant: g.ID}, nil
}

// ValidateGrant checks the saved permission shape and counters, without evaluating a call.
func ValidateGrant(g *Grant) error {
	if g == nil {
		return fmt.Errorf("missing grant snapshot")
	}
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
			return ArgMismatch, fmt.Sprintf("Grant is bound to %s %s; call did not send it.", label, name)
		}
		if binding.SHA256 != "" {
			value, err := scalar(raw)
			if err != nil || value.kind != "string" {
				return ArgLimit, fmt.Sprintf("%s %s must be a string.", capital(label), name)
			}
			digest := sha256.Sum256([]byte(value.text))
			want, _ := hex.DecodeString(binding.SHA256)
			if subtle.ConstantTimeCompare(digest[:], want) != 1 {
				return ArgMismatch, fmt.Sprintf("%s %s does not match the exact text approved for this grant.", capital(label), name)
			}
		} else if !equal(raw, binding.Value) {
			return ArgMismatch, mismatchReason(label, name, binding.Value, raw)
		}
	}
	for _, name := range keys(values) {
		rule, ok := rules[name]
		if !ok {
			if !allowAdditional {
				if len(rules) == 0 {
					return ArgNotAllowed, fmt.Sprintf("Grant does not allow any %s; call sent %s %s.", label, label, quoteShort(name))
				}
				return ArgNotAllowed, fmt.Sprintf("Grant does not allow %s %s. Allowed: %s.", label, quoteShort(name), strings.Join(keys(rules), ", "))
			}
			if !json.Valid(values[name]) || !utf8.Valid(values[name]) {
				return ArgLimit, fmt.Sprintf("%s %s must be valid JSON.", capital(label), quoteShort(name))
			}
			continue
		}
		if err := checkValue(rule, values[name]); err != nil {
			return ArgLimit, fmt.Sprintf("%s %s %s.", capital(label), name, err)
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
			return fmt.Errorf("is %d characters; grant allows up to %d", utf8.RuneCountInString(v.text), *c.MaxLen)
		}
		if c.MaxBytes != nil && len(v.text) > *c.MaxBytes {
			return fmt.Errorf("is %s; grant allows up to %s", plural(len(v.text), "byte"), plural(*c.MaxBytes, "byte"))
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

// quoteShort renders caller-supplied text for a reason, trimmed so a hostile
// call cannot flood the audit log through the reason field. Plain identifiers
// stay bare; anything else is quoted with control and bidi characters escaped.
func quoteShort(s string) string {
	const max = 64
	if r := []rune(s); len(r) > max {
		s = string(r[:max]) + "…"
	}
	if s != "" && plainName.MatchString(s) {
		return s
	}
	return strconv.QuoteToGraphic(s)
}

var plainName = regexp.MustCompile(`\A[A-Za-z0-9_./:{}-]+…?\z`)

// mismatchReason names both values only when both are JSON numbers or
// booleans, such as a post ID. Strings are never repeated: a bound or sent
// string can hold private text, and reasons are stored in the audit log.
func mismatchReason(label, name string, bound, sent json.RawMessage) string {
	b, errB := scalar(bound)
	v, errV := scalar(sent)
	if errB == nil && errV == nil && b.kind != "string" && v.kind != "string" && len(b.text) <= 32 && len(v.text) <= 32 {
		return fmt.Sprintf("Grant is bound to %s %s; call sent %s %s.", name, b.text, name, v.text)
	}
	return fmt.Sprintf("%s %s does not match the value bound to this grant.", capital(label), name)
}

func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func capital(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
