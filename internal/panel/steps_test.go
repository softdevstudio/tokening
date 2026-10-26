package panel

import (
	"encoding/json"
	"strings"
	"testing"
)

// Recorded agent steps keep only short scalars; long or nested values are dropped.
func TestDecodeKeepsShortStepArguments(t *testing.T) {
	var source map[string]any
	if err := json.Unmarshal([]byte(fixture(t)), &source); err != nil {
		t.Fatal(err)
	}
	source["wordpress"].(map[string]any)["before"] = []any{map[string]any{"id": 2, "title": "Seed post 2", "content": "Original", "status": "publish"}}
	source["agent"].(map[string]any)["steps"] = []any{
		map[string]any{"step": "edit post 2", "tool": "wp_update_post", "code": "allowed", "reason": "never-export-reason",
			"arguments": map[string]any{"id": 2, "title": "Scoped edit", "content": strings.Repeat("x", 61), "nested": map[string]any{"a": 1}, "ok": true}},
	}
	data, _ := json.Marshal(source)
	replay, err := Decode(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	args := replay.Agent.Steps[0].Arguments
	if len(args) != 3 || args["title"] != "Scoped edit" || args["ok"] != true || args["id"] == nil {
		t.Fatalf("arguments %v", args)
	}
	if len(replay.WordPress.Before) != 1 || replay.WordPress.Before[0].Title != "Seed post 2" {
		t.Fatal("before posts missing")
	}
	out, _ := json.Marshal(replay)
	if strings.Contains(string(out), "never-export-reason") || strings.Contains(string(out), strings.Repeat("x", 61)) {
		t.Fatal("unprojected step data exported")
	}
}
