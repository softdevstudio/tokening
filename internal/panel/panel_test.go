package panel

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("testdata/replay.json")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
func TestExportProjectsAndEscapesUntrustedText(t *testing.T) {
	input := strings.Replace(fixture(t), "Edited", `</script><img src=x onerror=alert(1)>`, 1)
	var output bytes.Buffer
	if err := Export(strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	page := output.String()
	for _, forbidden := range []string{"never-export-secret", "never-export-binding", "never-export-credential", `<img src=x`, `src="/admin/panel.js"`, `href="/admin/panel.css"`} {
		if strings.Contains(page, forbidden) {
			t.Fatalf("unexpected page content: %s", forbidden)
		}
	}
	if !strings.Contains(page, `\u003c/script\u003e`) || !strings.Contains(page, "connect-src 'none'") || !strings.Contains(page, "script-src 'sha256-") {
		t.Fatal("missing escaping or offline policy")
	}
	prefix := `id="replay-data">`
	start := strings.Index(page, prefix) + len(prefix)
	end := strings.Index(page[start:], "</script>") + start
	var projected map[string]any
	if err := json.Unmarshal([]byte(page[start:end]), &projected); err != nil {
		t.Fatal(err)
	}
	if len(projected["audit"].([]any)) != 2 {
		t.Fatal("missing actual records")
	}
}
func TestDecodeRefusesCorruptAndIncoherentReplays(t *testing.T) {
	for _, input := range []string{
		`{"schema":1,"schema":1}`, `[]`, strings.Repeat(" ", MaxReplayBytes+1),
		strings.Replace(fixture(t), `"passed": true`, `"passed": false`, 1),
		strings.Replace(fixture(t), `"authorization_id": 1`, `"authorization_id": 99`, 1),
		strings.Replace(fixture(t), `"uses_left": 0`, `"uses_left": 1`, 1),
		strings.Replace(fixture(t), `"writes": 1`, `"writes": 2`, 1),
		strings.Replace(fixture(t), `"id": 2,`, `"id": 1,`, 1),
	} {
		if _, err := Decode(strings.NewReader(input)); err == nil {
			t.Fatal("accepted invalid replay")
		}
	}
}
