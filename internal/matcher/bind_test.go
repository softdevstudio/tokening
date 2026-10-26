package matcher

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBindValidatesAndCopiesValues(t *testing.T) {
	r := rules(t, `{"id":{"bind":"required","type":"integer","min":1,"max":10},"content":{"bind":"optional","type":"string","sha256":true,"max_bytes":5}}`)
	values := map[string]json.RawMessage{"id": raw(`2`), "content": raw(`"é猫"`)}
	bindings, err := Bind(r, values)
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings["content"].Value) != 0 || len(bindings["content"].SHA256) != 64 {
		t.Fatal("hash binding retained plaintext")
	}
	values["id"][0] = '3'
	if string(bindings["id"].Value) != "2" {
		t.Fatal("binding aliases caller input")
	}
	values["id"] = raw(`20`)
	if _, err = Bind(r, values); err == nil {
		t.Fatal("out-of-range bound value accepted")
	}
	values["id"] = raw(`2`)
	values["content"] = raw(`"long-secret-text"`)
	if _, err = Bind(r, values); err == nil || strings.Contains(err.Error(), "long-secret-text") {
		t.Fatal("invalid hash value accepted or leaked")
	}
	delete(values, "content")
	if _, err = Bind(r, values); err == nil {
		t.Fatal("optional hash binding omitted")
	}
}
