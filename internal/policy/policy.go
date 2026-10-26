// Package policy loads permission templates without contacting their targets.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/softdevstudio/tokening/internal/number"
)

const MaxFileBytes = 1 << 20

type Policy struct {
	Targets   map[string]Target   `json:"targets"`
	Templates map[string]Template `json:"templates"`
}
type Target struct {
	Kind       string     `json:"kind"`
	URL        string     `json:"url,omitempty"`
	Command    []string   `json:"command,omitempty"`
	Credential Credential `json:"credential"`
}
type Credential struct {
	Type string `json:"type"`
	Ref  string `json:"ref"`
}
type Template struct {
	Target         string                `json:"target"`
	Tool           string                `json:"tool,omitempty"`
	Method         string                `json:"method,omitempty"`
	Path           string                `json:"path,omitempty"`
	Args           map[string]Constraint `json:"args,omitempty"`
	Query          map[string]Constraint `json:"query,omitempty"`
	AdditionalArgs string                `json:"additional_args,omitempty"`
	MaxUses        int                   `json:"max_uses"`
	MaxTTL         string                `json:"max_ttl"`
}
type Constraint struct {
	Bind     string            `json:"bind,omitempty"`
	Type     string            `json:"type,omitempty"`
	Enum     []json.RawMessage `json:"enum,omitempty"`
	MaxLen   *int              `json:"max_len,omitempty"`
	MaxBytes *int              `json:"max_bytes,omitempty"`
	Min      *number.Number    `json:"min,omitempty"`
	Max      *number.Number    `json:"max,omitempty"`
	Pattern  string            `json:"pattern,omitempty"`
	SHA256   bool              `json:"sha256,omitempty"`
}

func Load(path string) (*Policy, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	return Decode(f)
}

// Decode rejects ambiguous JSON, unknown fields and oversized files.
func Decode(r io.Reader) (*Policy, []string, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxFileBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > MaxFileBytes {
		return nil, nil, fmt.Errorf("policy exceeds %d bytes", MaxFileBytes)
	}
	if !utf8.Valid(data) {
		return nil, nil, fmt.Errorf("policy JSON must be UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err = uniqueValue(d); err != nil {
		return nil, nil, fmt.Errorf("policy JSON: %w", err)
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, nil, fmt.Errorf("policy must contain one JSON object")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var p Policy
	if err = d.Decode(&p); err != nil {
		return nil, nil, fmt.Errorf("policy JSON: %w", err)
	}
	warnings, err := p.Validate()
	if err != nil {
		return nil, nil, err
	}
	return &p, warnings, nil
}

func uniqueValue(d *json.Decoder) error {
	t, err := d.Token()
	if err != nil {
		return err
	}
	if t == nil {
		return fmt.Errorf("null is not allowed; omit optional fields")
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			t, err = d.Token()
			if err != nil {
				return err
			}
			key, ok := t.(string)
			if !ok {
				return fmt.Errorf("expected object key")
			}
			if seen[key] {
				return fmt.Errorf("duplicate key %q", key)
			}
			seen[key] = true
			if err = uniqueValue(d); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err = uniqueValue(d); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected delimiter")
	}
	_, err = d.Token()
	return err
}

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
var placeholderPattern = regexp.MustCompile(`\{([A-Za-z0-9][A-Za-z0-9._-]*)\}`)

func (p Policy) Validate() ([]string, error) {
	var warnings []string
	if len(p.Targets) == 0 || len(p.Templates) == 0 {
		return nil, fmt.Errorf("policy needs targets and templates")
	}
	for _, name := range keys(p.Targets) {
		t := p.Targets[name]
		if !namePattern.MatchString(name) {
			return nil, fmt.Errorf("invalid target name %q", name)
		}
		switch t.Kind {
		case "mcp_http", "http":
			u, err := url.Parse(t.URL)
			if err != nil || u == nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || len(t.Command) != 0 {
				return nil, fmt.Errorf("target %s: needs an HTTP(S) URL without credentials, query or fragment, and no command", name)
			}
		case "mcp_stdio":
			if len(t.Command) == 0 || strings.TrimSpace(t.Command[0]) == "" || t.URL != "" {
				return nil, fmt.Errorf("target %s: stdio needs a command and no URL", name)
			}
		default:
			return nil, fmt.Errorf("target %s: unknown kind %q", name, t.Kind)
		}
		if t.Credential.Type != "basic" && t.Credential.Type != "bearer" && t.Credential.Type != "header" && t.Credential.Type != "env" {
			return nil, fmt.Errorf("target %s: invalid credential type", name)
		}
		if !strings.HasPrefix(t.Credential.Ref, "vault:") || !namePattern.MatchString(strings.TrimPrefix(t.Credential.Ref, "vault:")) {
			return nil, fmt.Errorf("target %s: credential ref must be vault:<name>", name)
		}
		if (t.Kind == "mcp_stdio") != (t.Credential.Type == "env") {
			return nil, fmt.Errorf("target %s: env credentials are only for stdio targets", name)
		}
	}
	for _, name := range keys(p.Templates) {
		t := p.Templates[name]
		fail := func(s string) ([]string, error) { return nil, fmt.Errorf("template %s: %s", name, s) }
		if !namePattern.MatchString(name) {
			return fail("invalid name")
		}
		target, ok := p.Targets[t.Target]
		if !ok {
			return fail("unknown target")
		}
		w, err := t.Validate(target.Kind)
		if err != nil {
			return fail(err.Error())
		}
		for _, warning := range w {
			warnings = append(warnings, "template "+name+": "+warning)
		}

	}
	return warnings, nil
}

func (c Constraint) validate() error { return c.Validate() }

// Validate checks a scalar constraint.
func (c Constraint) Validate() error {
	bad := func(s string) error { return fmt.Errorf("%s", s) }
	if c.Bind != "" && c.Bind != "required" && c.Bind != "optional" {
		return bad("bind must be required or optional")
	}
	if c.Type != "string" && c.Type != "integer" && c.Type != "number" && c.Type != "boolean" && !(c.Type == "" && c.Bind == "required") {
		return bad("needs a scalar type or required binding")
	}
	if (c.MaxLen != nil || c.MaxBytes != nil || c.Pattern != "" || c.SHA256) && c.Type != "string" {
		return bad("string constraints need type string")
	}
	if (c.MaxLen != nil && *c.MaxLen < 0) || (c.MaxBytes != nil && *c.MaxBytes < 0) {
		return bad("string limits cannot be negative")
	}
	if (c.Min != nil || c.Max != nil) && c.Type != "number" && c.Type != "integer" {
		return bad("numeric bounds need number or integer type")
	}
	var min, max *big.Rat
	if c.Min != nil {
		var err error
		min, err = number.Parse(string(*c.Min))
		if err != nil {
			return err
		}
	}
	if c.Max != nil {
		var err error
		max, err = number.Parse(string(*c.Max))
		if err != nil {
			return err
		}
	}
	if min != nil && max != nil && min.Cmp(max) > 0 {
		return bad("min exceeds max")
	}
	if c.Pattern != "" {
		if _, err := regexp.Compile(`\A(?:` + c.Pattern + `)\z`); err != nil {
			return bad("invalid RE2 pattern")
		}
	}
	if c.SHA256 && c.Bind == "" {
		return bad("sha256 needs an issue-time binding")
	}
	if c.Enum != nil {
		if len(c.Enum) == 0 {
			return bad("enum cannot be empty")
		}
		if c.Type != "string" && c.Type != "number" && c.Type != "integer" {
			return bad("enum needs string or numeric type")
		}
		for _, raw := range c.Enum {
			var value any
			d := json.NewDecoder(bytes.NewReader(raw))
			d.UseNumber()
			if err := d.Decode(&value); err != nil {
				return bad("invalid enum value")
			}
			switch c.Type {
			case "string":
				if _, ok := value.(string); !ok {
					return bad("enum value does not match type")
				}
			case "number", "integer":
				n, ok := value.(json.Number)
				if !ok {
					return bad("enum value does not match type")
				}
				value, err := number.Parse(string(n))
				if err != nil {
					return err
				}
				if c.Type == "integer" && !value.IsInt() {
					return bad("integer enum must contain integers")
				}
			}
		}
	}
	return nil
}
func validMethod(m string) bool {
	switch m {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		return true
	}
	return false
}
func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Validate checks a template snapshot against its target transport kind.
func (t Template) Validate(targetKind string) ([]string, error) {
	var warnings []string
	fail := func(s string) ([]string, error) { return nil, fmt.Errorf("%s", s) }
	if targetKind != "http" && targetKind != "mcp_http" && targetKind != "mcp_stdio" {
		return fail("unknown target kind")
	}
	if t.Target == "" {
		return fail("missing target")
	}
	ttl, err := time.ParseDuration(t.MaxTTL)
	if err != nil || ttl <= 0 || ttl%time.Second != 0 {
		return fail("max_ttl must be a positive whole-second duration")
	}
	if t.MaxUses <= 0 {
		return fail("max_uses must be positive")
	}
	if t.AdditionalArgs != "" && t.AdditionalArgs != "refuse" && t.AdditionalArgs != "allow" {
		return fail("additional_args must be refuse or allow")
	}
	if t.AdditionalArgs == "allow" {
		warnings = append(warnings, "additional_args allows unchecked fields")
	}
	if targetKind == "http" {
		if t.Tool != "" || !validMethod(t.Method) || !strings.HasPrefix(t.Path, "/") || strings.ContainsAny(t.Path, "?#\\") || strings.HasPrefix(t.Path, "//") {
			return fail("REST templates need method and absolute path, without tool, query or fragment")
		}
		stripped := placeholderPattern.ReplaceAllString(t.Path, "")
		if strings.ContainsAny(stripped, "{}%") {
			return fail("invalid path placeholder or encoded path")
		}
		for _, segment := range strings.Split(t.Path, "/") {
			if segment == "." || segment == ".." {
				return fail("path cannot contain dot segments")
			}
		}
		for _, m := range placeholderPattern.FindAllStringSubmatch(t.Path, -1) {
			if t.Args[m[1]].Bind != "required" {
				return fail("path placeholders must have bind: required in args")
			}
		}
	} else if t.Tool == "" || t.Method != "" || t.Path != "" || len(t.Query) > 0 {
		return fail("MCP templates need tool and cannot set method, path or query")
	}
	for _, group := range []struct {
		name  string
		rules map[string]Constraint
	}{{"args", t.Args}, {"query", t.Query}} {
		for _, arg := range keys(group.rules) {
			if strings.TrimSpace(arg) == "" {
				return fail("empty argument name")
			}
			c := group.rules[arg]
			if err := c.validate(); err != nil {
				return fail(group.name + "." + arg + ": " + err.Error())
			}
			if c.Type == "string" && c.Bind != "required" && c.MaxLen == nil && c.MaxBytes == nil && len(c.Enum) == 0 && !c.SHA256 {
				warnings = append(warnings, group.name+"."+arg+": string has no size limit")
			}
		}
	}
	return warnings, nil
}
