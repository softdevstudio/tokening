package store

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This helper is launched only by TestConsumeCrashRecovery, in the same test
// executable. It pauses at a known transaction boundary until its parent kills
// it. No timing guess or production-only hook is needed.
func TestConsumeCrashHelper(t *testing.T) {
	mode := os.Getenv("TOKENING_CRASH_HELPER")
	if mode == "" {
		return
	}
	ctx := context.Background()
	s, err := Open(ctx, os.Getenv("TOKENING_CRASH_DB"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if mode == "before-commit" {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		d, err := consumeInTx(ctx, tx, sha256.Sum256([]byte("test-secret-0")), consumerCall(), time.Now)
		if err != nil || !d.Allowed {
			t.Fatalf("prepare consume: %+v %v", d, err)
		}
	} else if mode == "after-commit" {
		d, err := s.Consume(ctx, "test-secret-0", consumerCall())
		if err != nil || !d.Allowed {
			t.Fatalf("commit consume: %+v %v", d, err)
		}
	} else {
		t.Fatal("unknown crash helper mode")
	}
	fmt.Fprintln(os.Stdout, "ready")
	// In before-commit mode the deferred rollback has not run: tx still owns the
	// write lock and contains both the decrement and the new audit row.
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		t.Fatal(err)
	}
	t.Fatal("parent closed stdin instead of killing the helper")
}
func TestConsumeCrashRecovery(t *testing.T) {
	for _, mode := range []string{"before-commit", "after-commit"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "db")
			s := openTest(t, path)
			seedConsumer(t, s, 1)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestConsumeCrashHelper$")
			cmd.Env = append(os.Environ(), "TOKENING_CRASH_HELPER="+mode, "TOKENING_CRASH_DB="+path)
			input, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			output, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			reaped := false
			defer func() {
				if !reaped {
					cmd.Process.Kill()
					cmd.Wait()
				}
			}()
			line, readErr := bufio.NewReader(output).ReadString('\n')
			if readErr != nil || strings.TrimSpace(line) != "ready" {
				cmd.Process.Kill()
				cmd.Wait()
				reaped = true
				t.Fatalf("helper did not reach crash boundary: %q %v stderr=%s", line, readErr, &stderr)
			}
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err = cmd.Wait(); err == nil {
				t.Fatal("helper exited normally instead of being killed")
			}
			reaped = true
			reopened := openTest(t, path)
			wantUses, wantDecisions := 1, 0
			if mode == "after-commit" {
				wantUses, wantDecisions = 0, 1
			}
			if n := remaining(t, reopened, "g_0"); n != wantUses {
				t.Fatalf("uses=%d want=%d", n, wantUses)
			}
			var decisions int
			if err = reopened.db.QueryRow(`SELECT count(*) FROM decisions`).Scan(&decisions); err != nil {
				t.Fatal(err)
			}
			if decisions != wantDecisions {
				t.Fatalf("decisions=%d want=%d", decisions, wantDecisions)
			}
		})
	}
}
