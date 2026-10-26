package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckCLI(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"check", "../../examples/wordpress.json"}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "valid") {
		t.Fatalf("code=%d out=%s err=%s", code, &out, &errOut)
	}
	path := filepath.Join(t.TempDir(), "invalid.json")
	if err := os.WriteFile(path, []byte(`{"targets":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"check", path}, &out, &errOut); code != 1 || out.Len() != 0 || errOut.Len() == 0 {
		t.Fatalf("code=%d out=%s err=%s", code, &out, &errOut)
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"check", path + ".missing"}, &out, &errOut); code != 1 {
		t.Fatalf("missing file exit=%d", code)
	}
}
