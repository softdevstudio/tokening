package matcher

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/softdevstudio/tokening/internal/policy"
)

var now = time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)

func raw(s string) json.RawMessage { return json.RawMessage(s) }
func rules(t *testing.T, s string) map[string]policy.Constraint {
	t.Helper()
	var out map[string]policy.Constraint
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func grant(t *testing.T) *Grant {
	t.Helper()
	return &Grant{ID: "g_demo", TargetKind: "mcp_http", Template: policy.Template{Target: "wp", Tool: "wp_update_post", MaxTTL: "15m", MaxUses: 3, Args: rules(t, `{"id":{"bind":"required"},"title":{"type":"string","max_len":200},"content":{"type":"string","max_bytes":32768}}`)}, Args: map[string]Binding{"id": {Value: raw(`2`)}}, InitialUses: 1, UsesLeft: 1, ExpiresAt: now.Add(15 * time.Minute)}
}
func call() Call {
	return Call{Target: "wp", Tool: "wp_update_post", Args: map[string]json.RawMessage{"id": raw(`2`), "title": raw(`"Fixed title"`)}}
}
func check(t *testing.T, g *Grant, c Call, want Code) Decision {
	t.Helper()
	d, err := Match(g, c, now)
	if err != nil {
		t.Fatal(err)
	}
	if d.Code != want || d.Allowed != (want == Allowed) {
		t.Fatalf("want %s, got %+v", want, d)
	}
	if d.Reason == "" {
		t.Fatal("empty decision reason")
	}
	return d
}
func TestDemoScopeAndLifecycle(t *testing.T) {
	g := grant(t)
	c := call()
	check(t, g, c, Allowed)
	if g.UsesLeft != 1 {
		t.Fatal("matcher consumed a use")
	}
	g.UsesLeft = 0
	check(t, g, c, GrantExhausted)
	c.Args["id"] = raw(`3`)
	check(t, g, c, ArgMismatch)
	c.Tool = "wp_delete_post"
	check(t, g, c, ToolNotAllowed)
	check(t, nil, call(), GrantUnknown)
	g = grant(t)
	g.ExpiresAt = now
	check(t, g, call(), GrantExpired)
	g.ExpiresAt = now.Add(-time.Second)
	check(t, g, call(), GrantExpired)
	revoked := now.Add(-time.Minute)
	g.RevokedAt = &revoked
	check(t, g, call(), GrantRevoked)
	g = grant(t)
	g.ExpiresAt = now.Add(time.Nanosecond)
	check(t, g, call(), Allowed)
}
func TestTransportAndFields(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*Call)
		want   Code
	}{
		{"wrong target", func(c *Call) { c.Target = "other" }, ToolNotAllowed},
		{"wrong tool", func(c *Call) { c.Tool = "wp_delete_post" }, ToolNotAllowed},
		{"REST on MCP", func(c *Call) { c.Method = "POST" }, ToolNotAllowed},
		{"MCP path", func(c *Call) { c.Path = "/posts" }, ToolNotAllowed},
		{"MCP query", func(c *Call) { c.Query = map[string]json.RawMessage{"id": raw(`2`)} }, ToolNotAllowed},
		{"missing bound", func(c *Call) { delete(c.Args, "id") }, ArgMismatch},
		{"bound type mismatch", func(c *Call) { c.Args["id"] = raw(`"2"`) }, ArgMismatch},
		{"null bound", func(c *Call) { c.Args["id"] = raw(`null`) }, ArgMismatch},
		{"extra field", func(c *Call) { c.Args["status"] = raw(`"publish"`) }, ArgNotAllowed},
		{"missing optional field", func(c *Call) { delete(c.Args, "title") }, Allowed},
		{"wrong title type", func(c *Call) { c.Args["title"] = raw(`3`) }, ArgLimit},
		{"nested title", func(c *Call) { c.Args["title"] = raw(`{"x":1}`) }, ArgLimit},
		{"array title", func(c *Call) { c.Args["title"] = raw(`[1]`) }, ArgLimit},
		{"null title", func(c *Call) { c.Args["title"] = raw(`null`) }, ArgLimit},
		{"trailing JSON", func(c *Call) { c.Args["title"] = raw(`"ok" "bad"`) }, ArgLimit},
		{"invalid UTF8", func(c *Call) { c.Args["title"] = raw(string([]byte{'"', 0xff, '"'})) }, ArgLimit},
		{"lone high surrogate", func(c *Call) { c.Args["title"] = raw(`"\ud800"`) }, ArgLimit},
		{"lone low surrogate", func(c *Call) { c.Args["title"] = raw(`"\udc00"`) }, ArgLimit},
		{"surrogate pair", func(c *Call) { c.Args["title"] = raw(`"\ud83d\ude00"`) }, Allowed},
	} {
		t.Run(tt.name, func(t *testing.T) { c := call(); tt.change(&c); check(t, grant(t), c, tt.want) })
	}
}
func TestConstraintRules(t *testing.T) {
	for _, tt := range []struct {
		name, rule, input string
		want              Code
	}{
		{"characters boundary", `{"type":"string","max_len":2}`, `"é猫"`, Allowed},
		{"characters overflow", `{"type":"string","max_len":1}`, `"é猫"`, ArgLimit},
		{"bytes boundary", `{"type":"string","max_bytes":5}`, `"é猫"`, Allowed},
		{"bytes overflow", `{"type":"string","max_bytes":4}`, `"é猫"`, ArgLimit},
		{"zero chars empty", `{"type":"string","max_len":0}`, `""`, Allowed},
		{"zero chars nonempty", `{"type":"string","max_len":0}`, `"a"`, ArgLimit},
		{"zero bytes empty", `{"type":"string","max_bytes":0}`, `""`, Allowed},
		{"pattern match", `{"type":"string","pattern":"[a-z]+"}`, `"hello"`, Allowed},
		{"pattern anchored", `{"type":"string","pattern":"[a-z]+"}`, `"hello1"`, ArgLimit},
		{"pattern multiline anchored", `{"type":"string","pattern":"(?m)ok"}`, `"ok\nno"`, ArgLimit},
		{"integer boundary", `{"type":"integer","min":-2,"max":2}`, `2`, Allowed},
		{"integer below", `{"type":"integer","min":-2}`, `-3`, ArgLimit},
		{"integer above", `{"type":"integer","max":2}`, `3`, ArgLimit},
		{"integer fraction", `{"type":"integer"}`, `1.5`, ArgLimit},
		{"integer exponent", `{"type":"integer"}`, `1e2`, Allowed},
		{"integer decimal", `{"type":"integer"}`, `1.0`, Allowed},
		{"number decimal", `{"type":"number","min":0.1,"max":0.3}`, `0.3`, Allowed},
		{"number exact overflow", `{"type":"number","max":0.3}`, `0.30000000000000000001`, ArgLimit},
		{"number exact minimum", `{"type":"number","min":9007199254740993}`, `9007199254740992`, ArgLimit},
		{"number exact maximum", `{"type":"number","max":9007199254740992}`, `9007199254740993`, ArgLimit},
		{"number string", `{"type":"number"}`, `"1"`, ArgLimit},
		{"number huge exponent", `{"type":"number"}`, `1e999999999`, ArgLimit},
		{"number huge negative exponent", `{"type":"number"}`, `1e-999999999`, ArgLimit},
		{"boolean true", `{"type":"boolean"}`, `true`, Allowed},
		{"boolean false", `{"type":"boolean"}`, `false`, Allowed},
		{"boolean string", `{"type":"boolean"}`, `"true"`, ArgLimit},
		{"enum string", `{"type":"string","enum":["a","b"]}`, `"b"`, Allowed},
		{"enum refusal", `{"type":"string","enum":["a","b"]}`, `"c"`, ArgLimit},
		{"enum exact number", `{"type":"number","enum":[9007199254740992]}`, `9007199254740993`, ArgLimit},
		{"enum equivalent number", `{"type":"integer","enum":[1.0]}`, `1e0`, Allowed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := grant(t)
			g.Template.Args = rules(t, `{"value":`+tt.rule+`}`)
			g.Args = nil
			c := call()
			c.Args = map[string]json.RawMessage{"value": raw(tt.input)}
			check(t, g, c, tt.want)
		})
	}
}
func TestBindingsAndHashes(t *testing.T) {
	for _, tt := range []struct {
		bound, input string
		want         Code
	}{
		{`9007199254740993`, `9007199254740992`, ArgMismatch},
		{`1`, `1.0`, Allowed}, {`1`, `1e0`, Allowed}, {`false`, `false`, Allowed},
		{`"secret-text"`, `"different-secret"`, ArgMismatch},
	} {
		g := grant(t)
		g.Args["id"] = Binding{Value: raw(tt.bound)}
		c := call()
		c.Args["id"] = raw(tt.input)
		d := check(t, g, c, tt.want)
		if strings.Contains(d.Reason, "secret-text") || strings.Contains(d.Reason, "different-secret") {
			t.Fatal("reason leaked a value")
		}
	}
	g := grant(t)
	g.Template.Args = rules(t, `{"value":{"type":"string","bind":"optional","sha256":true,"max_bytes":10}}`)
	digest := sha256.Sum256([]byte("é猫"))
	g.Args = map[string]Binding{"value": {SHA256: hex.EncodeToString(digest[:])}}
	c := call()
	c.Args = map[string]json.RawMessage{"value": raw(`"é猫"`)}
	check(t, g, c, Allowed)
	c.Args["value"] = raw(`"\u00e9\u732b"`)
	check(t, g, c, Allowed)
	c.Args["value"] = raw(`"other"`)
	check(t, g, c, ArgMismatch)
	c.Args["value"] = raw(`1`)
	check(t, g, c, ArgLimit)
	delete(c.Args, "value")
	check(t, g, c, ArgMismatch)
	g = grant(t)
	g.Template.Args = rules(t, `{"value":{"type":"boolean","bind":"optional"}}`)
	g.Args = map[string]Binding{"value": {Value: raw(`false`)}}
	c.Args = map[string]json.RawMessage{"value": raw(`false`)}
	check(t, g, c, Allowed)
	c.Args = nil
	check(t, g, c, ArgMismatch)
	g.Args = nil
	check(t, g, c, Allowed)
}
func TestAdditionalArgs(t *testing.T) {
	g := grant(t)
	g.Template.AdditionalArgs = "allow"
	c := call()
	c.Args["status"] = raw(`{"nested":true}`)
	check(t, g, c, Allowed)
	c.Args["status"] = raw(`{"nested":`)
	check(t, g, c, ArgLimit)
}
func TestCorruptSnapshotsFailClosed(t *testing.T) {
	for _, change := range []func(*Grant){
		func(g *Grant) { g.ID = "" }, func(g *Grant) { g.UsesLeft = -1 }, func(g *Grant) { g.UsesLeft = 2 },
		func(g *Grant) { g.InitialUses = 4 }, func(g *Grant) { g.ExpiresAt = time.Time{} },
		func(g *Grant) { g.Template.Tool = "" }, func(g *Grant) { g.TargetKind = "other" },
		func(g *Grant) { delete(g.Args, "id") }, func(g *Grant) { g.Args["other"] = Binding{Value: raw(`1`)} },
		func(g *Grant) { g.Args["id"] = Binding{Value: raw(`{}`)} },
		func(g *Grant) { g.Args["id"] = Binding{SHA256: strings.Repeat("a", 64)} },
		func(g *Grant) { g.Template.Args["title"] = policy.Constraint{Type: "bad"} },
		func(g *Grant) { g.Template.Args["title"] = policy.Constraint{Type: "string", Pattern: "["} },
	} {
		g := grant(t)
		change(g)
		if d, err := Match(g, call(), now); err == nil || d.Allowed {
			t.Fatalf("corrupt grant allowed: %+v %v", d, err)
		}
	}
}
func TestNoMutationAndStableReasons(t *testing.T) {
	g := grant(t)
	c := call()
	beforeG, _ := json.Marshal(g)
	beforeC, _ := json.Marshal(c)
	c.Args["z"] = raw(`true`)
	c.Args["a"] = raw(`true`)
	first := check(t, g, c, ArgNotAllowed)
	for i := 0; i < 20; i++ {
		if got := check(t, g, c, ArgNotAllowed); !reflect.DeepEqual(got, first) {
			t.Fatal("unstable refusal")
		}
	}
	delete(c.Args, "a")
	delete(c.Args, "z")
	check(t, g, c, Allowed)
	afterG, _ := json.Marshal(g)
	afterC, _ := json.Marshal(c)
	if string(beforeG) != string(afterG) || string(beforeC) != string(afterC) {
		t.Fatal("matcher mutated inputs")
	}
}
func TestUpstreamFailure(t *testing.T) {
	for _, status := range []int{0, 403, 500} {
		d := UpstreamFailure("g_demo", status)
		if d.Code != UpstreamError || !d.Allowed || !strings.Contains(d.Reason, "consumed") {
			t.Fatalf("bad forwarded failure: %+v", d)
		}
	}
}

func TestHashSnapshotValidation(t *testing.T) {
	for _, binding := range []Binding{
		{}, {SHA256: "abc"}, {SHA256: strings.Repeat("z", 64)},
		{SHA256: strings.Repeat("A", 64)},
		{SHA256: strings.Repeat("a", 64), Value: raw(`"plaintext"`)},
	} {
		g := grant(t)
		g.Template.Args = rules(t, `{"value":{"type":"string","bind":"required","sha256":true}}`)
		g.Args = map[string]Binding{"value": binding}
		if d, err := Match(g, call(), now); err == nil || d.Allowed {
			t.Fatalf("corrupt hash binding accepted: %+v %v", d, err)
		}
	}
	g := grant(t)
	g.Template.Args = rules(t, `{"value":{"type":"string","bind":"optional","sha256":true}}`)
	g.Args = nil
	if d, err := Match(g, call(), now); err == nil || d.Allowed {
		t.Fatal("unbound hash rule accepted")
	}
}
