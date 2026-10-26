package matcher

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/softdevstudio/tokening/internal/policy"
)

// Reasons may name numbers and template names, never string values or hashes.
func TestReasonsNameNumbersButNeverStrings(t *testing.T) {
	g := grant(t)
	c := call()
	c.Args["id"] = raw(`3`)
	if d := check(t, g, c, ArgMismatch); d.Reason != "Grant is bound to id 2; call sent id 3." {
		t.Fatalf("reason %q", d.Reason)
	}
	long := strings.Repeat("9", 40)
	g.Args["id"] = Binding{Value: raw(long)}
	c.Args["id"] = raw(`3`)
	if d := check(t, g, c, ArgMismatch); strings.Contains(d.Reason, long) {
		t.Fatal("long number echoed")
	}

	// A string bound through a REST path never appears either.
	h := &Grant{ID: "g_rest", TargetKind: "http", Template: policy.Template{Target: "api", Method: "PATCH", Path: "/records/{slug}", MaxTTL: "15m", MaxUses: 1,
		Args: rules(t, `{"slug":{"type":"string","bind":"required"}}`)}, Args: map[string]Binding{"slug": {Value: raw(`"private-slug"`)}}, InitialUses: 1, UsesLeft: 1, ExpiresAt: now.Add(time.Minute)}
	d := check(t, h, Call{Target: "api", Method: "PATCH", Path: "/records/other-secret"}, ArgMismatch)
	if strings.Contains(d.Reason, "private-slug") || strings.Contains(d.Reason, "other-secret") {
		t.Fatalf("string leaked: %q", d.Reason)
	}
	if d := check(t, h, Call{Target: "api", Tool: "x"}, ToolNotAllowed); !strings.Contains(d.Reason, "not a REST request") {
		t.Fatalf("reason %q", d.Reason)
	}
}

func TestCallerNamesAreCutAndQuoted(t *testing.T) {
	g := grant(t)
	c := call()
	c.Tool = strings.Repeat("x", 200)
	d := check(t, g, c, ToolNotAllowed)
	if strings.Count(d.Reason, "x") > 64 {
		t.Fatalf("tool name not cut: %d", len(d.Reason))
	}
	c = call()
	c.Tool = "evil‮\x1b[0m"
	if d := check(t, g, c, ToolNotAllowed); strings.ContainsAny(d.Reason, "‮\x1b") {
		t.Fatalf("control characters kept: %q", d.Reason)
	}
	c = call()
	c.Args["status"] = json.RawMessage(`"publish"`)
	if d := check(t, g, c, ArgNotAllowed); d.Reason != "Grant does not allow argument status. Allowed: content, id, title." || strings.Contains(d.Reason, "publish") {
		t.Fatalf("reason %q", d.Reason)
	}
	c = call()
	c.Query = map[string]json.RawMessage{"q": raw(`1`)}
	if d, _ := Match(g, c, now); strings.Contains(d.Reason, "Allowed: .") {
		t.Fatalf("empty allowed list: %q", d.Reason)
	}
}
