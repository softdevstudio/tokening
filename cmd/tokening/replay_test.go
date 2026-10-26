package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestReplayCLIRejectsInvalidDataWithoutCreatingOutput(t *testing.T) {
	dir := t.TempDir()
	input, output := filepath.Join(dir, "in.json"), filepath.Join(dir, "out.html")
	if err := os.WriteFile(input, []byte(`{"schema":1,"passed":false}`), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"replay", "--input", input, "--output", output}, &out, &errOut); code != 1 {
		t.Fatal(code)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("invalid replay created output")
	}
}

func TestReplayCLIUsesNewFilesAndProtectsExistingOutput(t *testing.T) {
	output := filepath.Join(t.TempDir(), "replay.html")
	var out, errOut bytes.Buffer
	args := []string{"replay", "--input", "../../internal/panel/testdata/replay.json", "--output", output}
	if code := run(args, &out, &errOut); code != 0 {
		t.Fatal(code, errOut.String())
	}
	before, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(before, []byte("connect-src 'none'")) || bytes.Contains(before, []byte("never-export-secret")) {
		t.Fatal("invalid replay output")
	}
	if code := run(args, &out, &errOut); code != 1 {
		t.Fatal("overwrote existing file", code)
	}
	after, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("existing output changed", err)
	}
}
