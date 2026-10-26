package matcher

import (
	"encoding/json"
	"testing"
)

func restGrant(t *testing.T) *Grant {
	g := grant(t)
	g.TargetKind = "http"
	g.Template.Tool = ""
	g.Template.Method = "PATCH"
	g.Template.Path = "/posts/{id}"
	g.Template.Query = rules(t, `{"context":{"type":"string","bind":"required"}}`)
	g.Query = map[string]Binding{"context": {Value: raw(`"edit"`)}}
	return g
}
func restCall() Call {
	return Call{Target: "wp", Method: "PATCH", Path: "/posts/2", Args: map[string]json.RawMessage{"title": raw(`"new"`)}, Query: map[string]json.RawMessage{"context": raw(`"edit"`)}}
}
func TestREST(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*Call)
		want   Code
	}{
		{"valid", func(c *Call) {}, Allowed},
		{"wrong method", func(c *Call) { c.Method = "DELETE" }, ToolNotAllowed},
		{"MCP tool", func(c *Call) { c.Tool = "wp_update_post" }, ToolNotAllowed},
		{"numeric exponent alias", func(c *Call) { c.Path = "/posts/2e0" }, ArgMismatch},
		{"numeric decimal alias", func(c *Call) { c.Path = "/posts/2.0" }, ArgMismatch},
		{"wrong post", func(c *Call) { c.Path = "/posts/3" }, ArgMismatch},
		{"wrong route", func(c *Call) { c.Path = "/users/2" }, ToolNotAllowed},
		{"extra segment", func(c *Call) { c.Path = "/posts/2/delete" }, ToolNotAllowed},
		{"encoded traversal", func(c *Call) { c.Path = "/posts/%2e%2e" }, ToolNotAllowed},
		{"dot traversal", func(c *Call) { c.Path = "/posts/../2" }, ToolNotAllowed},
		{"double slash", func(c *Call) { c.Path = "/posts//2" }, ToolNotAllowed},
		{"query in path", func(c *Call) { c.Path = "/posts/2?id=3" }, ToolNotAllowed},
		{"backslash", func(c *Call) { c.Path = "/posts/2\\delete" }, ToolNotAllowed},
		{"control", func(c *Call) { c.Path = "/posts/2\n" }, ToolNotAllowed},
		{"body conflicts with path", func(c *Call) { c.Args["id"] = raw(`3`) }, ArgMismatch},
		{"body agrees with path", func(c *Call) { c.Args["id"] = raw(`2`) }, Allowed},
		{"query mismatch", func(c *Call) { c.Query["context"] = raw(`"view"`) }, ArgMismatch},
		{"query missing", func(c *Call) { c.Query = nil }, ArgMismatch},
		{"query extra", func(c *Call) { c.Query["force"] = raw(`true`) }, ArgNotAllowed},
	} {
		t.Run(tt.name, func(t *testing.T) { c := restCall(); tt.change(&c); check(t, restGrant(t), c, tt.want) })
	}
}
func TestRESTStringPathAndRepeatedBindings(t *testing.T) {
	g := restGrant(t)
	g.Template.Args = rules(t, `{"id":{"type":"string","bind":"required"}}`)
	g.Args = map[string]Binding{"id": {Value: raw(`"hello"`)}}
	g.Template.Path = "/posts/{id}.json"
	c := restCall()
	c.Args = nil
	c.Path = "/posts/hello.json"
	check(t, g, c, Allowed)
	c.Path = "/posts/other.json"
	check(t, g, c, ArgMismatch)
	g.Template.Path = "/posts/{id}/copy/{id}"
	c.Path = "/posts/hello/copy/other"
	check(t, g, c, ToolNotAllowed)
	c.Path = "/posts/hello/copy/hello"
	check(t, g, c, Allowed)
}

func TestRESTDoesNotModifyCall(t *testing.T) {
	g := restGrant(t)
	c := restCall()
	before, _ := json.Marshal(c)
	check(t, g, c, Allowed)
	after, _ := json.Marshal(c)
	if string(before) != string(after) {
		t.Fatal("path extraction changed the caller's body")
	}
}
