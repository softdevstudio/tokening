package number

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExactNumbers(t *testing.T) {
	for _, s := range []string{"0", "-0", "1.0", "1e2", "1e-1024", "1e1024", "9007199254740993"} {
		if _, err := Parse(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	for _, s := range []string{"", "null", "true", `"1"`, "01", "NaN", "1e1025", "1e-1025", strings.Repeat("9", 257)} {
		if _, err := Parse(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
	var n Number
	if err := json.Unmarshal([]byte("9007199254740993"), &n); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(n)
	if err != nil || string(out) != "9007199254740993" {
		t.Fatalf("rounded number: %s %v", out, err)
	}
	if err := json.Unmarshal([]byte(`"1"`), &n); err == nil {
		t.Fatal("accepted quoted number bound")
	}
}
