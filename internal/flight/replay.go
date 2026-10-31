package flight

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Body shapes written by internal/store. Fields are optional on decode so a
// replay of an unexpected body still prints something readable.
type GrantBody struct {
	Event           string   `json:"event"`
	Template        string   `json:"template,omitempty"`
	TemplateVersion int      `json:"template_version,omitempty"`
	Target          string   `json:"target,omitempty"`
	Action          string   `json:"action,omitempty"`
	Uses            int      `json:"uses,omitempty"`
	ExpiresAt       string   `json:"expires_at,omitempty"`
	IssuedBy        string   `json:"issued_by,omitempty"`
	Reason          string   `json:"reason,omitempty"`
	Bound           []string `json:"bound,omitempty"`
	BindingsDigest  string   `json:"bindings_digest,omitempty"`
	By              string   `json:"by,omitempty"`
}
type RequestBody struct {
	Target     string   `json:"target"`
	Action     string   `json:"action"`
	ArgsDigest string   `json:"args_digest"`
	Args       []string `json:"args"`
	Query      []string `json:"query,omitempty"`
	// ArgsOmitted and QueryOmitted count names left out because the agent sent
	// more than MaxNames. The digest still covers the whole call.
	ArgsOmitted  int `json:"args_omitted,omitempty"`
	QueryOmitted int `json:"query_omitted,omitempty"`
}

// Limits for agent-chosen text in a request entry. They keep every entry far
// below MaxLine, even when each character doubles in size as a JSON escape.
const (
	MaxActionBytes = 256
	MaxNameBytes   = 128
	MaxNames       = 100
)

// Clip shortens s to at most n bytes on a character boundary, marking the cut
// with "…".
func Clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n - len("…")
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// BoundNames returns the first MaxNames names, each clipped to MaxNameBytes,
// and how many were left out.
func BoundNames(names []string) ([]string, int) {
	omitted := 0
	if len(names) > MaxNames {
		omitted = len(names) - MaxNames
		names = names[:MaxNames]
	}
	out := make([]string, len(names))
	for i, name := range names {
		out[i] = Clip(name, MaxNameBytes)
	}
	return out, omitted
}

type DecisionBody struct {
	DecisionID int64  `json:"decision_id"`
	Outcome    string `json:"outcome"`
	Code       string `json:"code"`
	Reason     string `json:"reason"`
	UsesLeft   *int   `json:"uses_left,omitempty"`
}
type ResultBody struct {
	DecisionID      int64  `json:"decision_id"`
	AuthorizationID int64  `json:"authorization_id"`
	Code            string `json:"code"`
	UpstreamStatus  *int   `json:"upstream_status"`
	LatencyMS       int64  `json:"latency_ms"`
}

// NewBody encodes a body as compact JSON, the form that is hashed.
func NewBody(v any) (json.RawMessage, error) {
	var data bytes.Buffer
	enc := json.NewEncoder(&data)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := json.Compact(&out, data.Bytes()); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// SortedNames returns map keys in order, for argument name lists.
func SortedNames[V any](m map[string]V) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// FormatEntry renders one entry as a line of a replay timeline.
func FormatEntry(e Entry) string {
	head := fmt.Sprintf("#%d  %s  %-8s", e.Seq, e.Time().Format(TimeLayout), e.Kind)
	grant := quoteIfNeeded(e.Grant)
	if e.Grant == "" {
		grant = "(no grant)"
	}
	who := ""
	if e.Agent != "" {
		who = " " + quoteIfNeeded(e.Agent)
	}
	var text string
	switch e.Kind {
	case KindGrant:
		var b GrantBody
		if json.Unmarshal(e.Body, &b) == nil {
			switch b.Event {
			case "issued":
				text = fmt.Sprintf("%s issued to%s by %s: %s on %s, %s, expires %s", grant, who, quoteIfNeeded(b.IssuedBy), safe(b.Template), safe(b.Action), uses(b.Uses), safe(b.ExpiresAt))
				if len(b.Bound) > 0 {
					text += ", bound " + safeList(b.Bound)
				}
				if b.Reason != "" {
					text += ", reason " + quote(b.Reason)
				}
			case "revoked":
				text = fmt.Sprintf("%s revoked by %s", grant, quoteIfNeeded(b.By))
			}
		}
	case KindRequest:
		var b RequestBody
		if json.Unmarshal(e.Body, &b) == nil {
			names := "no arguments"
			if len(b.Args) > 0 {
				names = "arguments " + safeList(b.Args)
			}
			if b.ArgsOmitted > 0 {
				names += fmt.Sprintf(" and %d more", b.ArgsOmitted)
			}
			if len(b.Query) > 0 {
				names += ", query " + safeList(b.Query)
			}
			if b.QueryOmitted > 0 {
				names += fmt.Sprintf(" and %d more", b.QueryOmitted)
			}
			digest := safe(b.ArgsDigest)
			if len(digest) > 12 {
				digest = digest[:12]
			}
			text = fmt.Sprintf("%s%s asked for %s on %s with %s (digest %s)", grant, who, action(b.Action), quoteIfNeeded(b.Target), names, digest)
		}
	case KindDecision:
		var b DecisionBody
		if json.Unmarshal(e.Body, &b) == nil {
			text = fmt.Sprintf("%s %s", grant, safe(b.Outcome))
			if b.Code != "allowed" {
				text += " (" + safe(b.Code) + ")"
			}
			text += ": " + safe(b.Reason)
			if b.UsesLeft != nil {
				text += fmt.Sprintf(" %s left.", uses(*b.UsesLeft))
			}
		}
	case KindResult:
		var b ResultBody
		if json.Unmarshal(e.Body, &b) == nil {
			if b.UpstreamStatus != nil {
				text = fmt.Sprintf("%s upstream answered HTTP %d in %d ms", grant, *b.UpstreamStatus, b.LatencyMS)
			} else {
				text = fmt.Sprintf("%s upstream gave no HTTP answer after %d ms", grant, b.LatencyMS)
			}
			if b.Code != "allowed" {
				text += " (" + safe(b.Code) + ")"
			}
		}
	}
	if text == "" {
		text = grant + " " + safe(string(e.Body))
	}
	return head + "  " + text
}

func uses(n int) string {
	if n == 1 {
		return "1 use"
	}
	return fmt.Sprintf("%d uses", n)
}

func quote(s string) string { return strconv.QuoteToGraphic(s) }

// quoteIfNeeded keeps plain names bare and quotes anything with spaces of any
// kind, quotes or non-printing characters, so a name cannot fake a replay line.
func quoteIfNeeded(s string) string {
	if s != "" && !strings.ContainsRune(s, '"') && graphic(s) && !strings.ContainsFunc(s, unicode.IsSpace) && !strings.ContainsFunc(s, func(r rune) bool { return unicode.Is(unicode.Zs, r) }) {
		return s
	}
	return quote(s)
}

var (
	plainTool = regexp.MustCompile(`\A[A-Za-z0-9_./:{}-]+\z`)
	plainREST = regexp.MustCompile(`\A[A-Z]+ /[A-Za-z0-9_./:{}~%-]*\z`)
)

// action keeps an ordinary MCP tool name or "METHOD /path" bare. Anything
// else came from the agent in an unusual form and is quoted, so it cannot pass
// as the rest of the sentence.
func action(s string) string {
	if plainTool.MatchString(s) || plainREST.MatchString(s) {
		return s
	}
	return quote(s)
}

// safe leaves readable text as it is and quotes text holding control
// characters such as newlines or terminal escapes.
func safe(s string) string {
	if graphic(s) {
		return s
	}
	return quote(s)
}

func graphic(s string) bool {
	for _, r := range s {
		if !unicode.IsGraphic(r) {
			return false
		}
	}
	return true
}

func safeList(names []string) string {
	out := make([]string, len(names))
	for i, name := range names {
		out[i] = quoteIfNeeded(name)
	}
	return strings.Join(out, ", ")
}
