package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

const validPolicy = `{"targets":{"wp":{"kind":"mcp_http","url":"https://example.com/mcp","credential":{"type":"basic","ref":"vault:wp"}}},"templates":{"edit":{"target":"wp","tool":"wp_update_post","args":{"id":{"bind":"required"},"title":{"type":"string","max_len":200}},"max_uses":1,"max_ttl":"15m"}}}`

func TestDecodeAmbiguousOrMalformed(t *testing.T) {
	tests := map[string]string{
		"null constraint":    strings.Replace(validPolicy, `"max_len":200`, `"max_len":null`, 1),
		"null template":      strings.Replace(validPolicy, `"id":{"bind":"required"}`, `"id":null`, 1),
		"invalid UTF8":       strings.Replace(validPolicy, "wp_update_post", string([]byte{0xff}), 1),
		"duplicate root":     strings.Replace(validPolicy, `"targets":`, `"targets":{},"targets":`, 1),
		"duplicate nested":   strings.Replace(validPolicy, `"max_uses":1`, `"max_uses":2,"max_uses":1`, 1),
		"escaped duplicate":  strings.Replace(validPolicy, `"max_uses":1`, `"max_uses":2,"max_\u0075ses":1`, 1),
		"unknown field":      strings.Replace(validPolicy, `"max_uses":1`, `"max_use":1`, 1),
		"unknown constraint": strings.Replace(validPolicy, `"max_len":200`, `"max_length":200`, 1),
		"trailing JSON":      validPolicy + ` {}`,
		"truncated":          validPolicy[:len(validPolicy)-1],
		"array root":         "[]", "null root": "null", "empty object": "{}",
		"oversized": strings.Repeat(" ", MaxFileBytes) + validPolicy,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Decode(strings.NewReader(input)); err == nil {
				t.Fatal("accepted invalid policy")
			}
		})
	}
}

func TestValidation(t *testing.T) {
	tests := []struct{ name, old, replacement string }{
		{"missing target", `"target":"wp"`, `"target":"missing"`},
		{"zero uses", `"max_uses":1`, `"max_uses":0`},
		{"negative uses", `"max_uses":1`, `"max_uses":-1`},
		{"fractional uses", `"max_uses":1`, `"max_uses":1.5`},
		{"invalid ttl", `"15m"`, `"tomorrow"`},
		{"negative ttl", `"15m"`, `"-1s"`},
		{"subsecond ttl", `"15m"`, `"1ms"`},
		{"unknown kind", `"mcp_http"`, `"ftp"`},
		{"credential in url", `https://example.com/mcp`, `https://user:pass@example.com/mcp`},
		{"wrong scheme", `https://example.com/mcp`, `file:///tmp/api`},
		{"query in url", `https://example.com/mcp`, `https://example.com/mcp?key=secret`},
		{"literal secret", `vault:wp`, `secret`},
		{"http env credential", `"basic"`, `"env"`},
		{"unknown credential", `"basic"`, `"magic"`},
		{"mixed transport", `"tool":"wp_update_post"`, `"tool":"wp_update_post","method":"POST","path":"/posts"`},
		{"invalid additional", `"max_uses":1`, `"additional_args":"ignore","max_uses":1`},
		{"invalid binding", `"required"`, `"sometimes"`},
		{"untyped optional", `"required"`, `"optional"`},
		{"unknown type", `"type":"string"`, `"type":"array"`},
		{"negative length", `"max_len":200`, `"max_len":-1`},
		{"wrong limit type", `"type":"string"`, `"type":"boolean"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := strings.Replace(validPolicy, tt.old, tt.replacement, 1)
			if input == validPolicy {
				t.Fatal("test did not mutate policy")
			}
			if _, _, err := Decode(strings.NewReader(input)); err == nil {
				t.Fatal("accepted invalid policy")
			}
		})
	}
}

func TestConstraints(t *testing.T) {
	for _, tt := range []struct {
		input string
		valid bool
	}{
		{`{"type":"string","max_len":0,"max_bytes":0,"pattern":"[a-z]+"}`, true},
		{`{"type":"string","pattern":"["}`, false},
		{`{"type":"string","pattern":"(?=x)"}`, false},
		{`{"type":"integer","min":0,"max":10,"enum":[1,2]}`, true},
		{`{"type":"number","min":10,"max":0}`, false},
		{`{"type":"string","min":0}`, false},
		{`{"type":"number","max_bytes":1}`, false},
		{`{"type":"string","enum":[]}`, false},
		{`{"type":"string","enum":[1]}`, false},
		{`{"type":"number","enum":["1"]}`, false},
		{`{"type":"integer","enum":[1.5]}`, false},
		{`{"type":"boolean","enum":[true]}`, false},
		{`{"type":"string","bind":"required","sha256":true}`, true},
		{`{"type":"string","sha256":true}`, false},
		{`{"bind":"required"}`, true},
		{`{"bind":"optional","type":"string"}`, true},
	} {
		t.Run(tt.input, func(t *testing.T) {
			var c Constraint
			if err := json.Unmarshal([]byte(tt.input), &c); err != nil {
				t.Fatal(err)
			}
			if err := c.validate(); (err == nil) != tt.valid {
				t.Fatalf("valid=%v error=%v", tt.valid, err)
			}
		})
	}
}

func TestRESTAndStdio(t *testing.T) {
	rest := strings.Replace(validPolicy, `"kind":"mcp_http"`, `"kind":"http"`, 1)
	rest = strings.Replace(rest, `"tool":"wp_update_post"`, `"method":"PATCH","path":"/posts/{id}","query":{"context":{"type":"string","enum":["edit"]}}`, 1)
	if _, _, err := Decode(strings.NewReader(rest)); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"//other.example/posts", "/posts/{other}", "/posts/{id", "/posts/{id}?x=1", "/../posts", "/posts/%2e%2e"} {
		t.Run(path, func(t *testing.T) {
			input := strings.Replace(rest, `/posts/{id}`, path, 1)
			if _, _, err := Decode(strings.NewReader(input)); err == nil {
				t.Fatal("accepted invalid REST path")
			}
		})
	}
	stdio := strings.Replace(validPolicy, `"kind":"mcp_http","url":"https://example.com/mcp"`, `"kind":"mcp_stdio","command":["adapter","--stdio"]`, 1)
	stdio = strings.Replace(stdio, `"type":"basic"`, `"type":"env"`, 1)
	if _, _, err := Decode(strings.NewReader(stdio)); err != nil {
		t.Fatal(err)
	}
}

func TestWarningsAndDefaults(t *testing.T) {
	p, w, err := Decode(strings.NewReader(validPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if len(w) != 0 || p.Templates["edit"].AdditionalArgs != "" {
		t.Fatalf("unexpected defaults or warnings: %v", w)
	}
	input := strings.Replace(validPolicy, `,"max_len":200`, "", 1)
	input = strings.Replace(input, `"max_uses":1`, `"additional_args":"allow","max_uses":1`, 1)
	_, w, err = Decode(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(w) != 2 {
		t.Fatalf("got warnings: %v", w)
	}
}

func TestExample(t *testing.T) {
	if _, _, err := Load("../../examples/wordpress.json"); err != nil {
		t.Fatal(err)
	}
}
