package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/nacl/secretbox"
)

func testVault(t *testing.T) *Vault {
	t.Helper()
	v, err := New(bytes.Repeat([]byte{17}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func TestRoundTripNonceAndInputOwnership(t *testing.T) {
	v := testVault(t)
	plain := []byte("test-only-upstream-credential")
	first, err := v.Seal("wp", plain)
	if err != nil {
		t.Fatal(err)
	}
	second, err := v.Seal("wp", plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("encryption reused a nonce")
	}
	if bytes.Contains(first, plain) {
		t.Fatal("plaintext found in ciphertext")
	}
	for _, box := range [][]byte{first, second} {
		got, err := v.Open("wp", box)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatal("round trip failed")
		}
		clear(got)
	}
	if string(plain) != "test-only-upstream-credential" {
		t.Fatal("caller plaintext was changed")
	}
	key := bytes.Repeat([]byte{17}, 32)
	copied, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	clear(key)
	if _, err = copied.Open("wp", first); err != nil {
		t.Fatal("vault retained caller key slice")
	}
}
func TestAuthenticationAndMalformedBoxes(t *testing.T) {
	v := testVault(t)
	box, err := v.Seal("wp", []byte("credential"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range box {
		damaged := append([]byte(nil), box...)
		damaged[i] ^= 1
		if got, err := v.Open("wp", damaged); !errors.Is(err, ErrOpen) || got != nil {
			t.Fatalf("tamper at byte %d released plaintext", i)
		}
	}
	for n := 0; n < len(box); n++ {
		if got, err := v.Open("wp", box[:n]); !errors.Is(err, ErrOpen) || got != nil {
			t.Fatalf("truncation at %d released plaintext", n)
		}
	}
	other, _ := New(bytes.Repeat([]byte{18}, 32))
	if got, err := other.Open("wp", box); !errors.Is(err, ErrOpen) || got != nil {
		t.Fatal("wrong key released plaintext")
	}
	if got, err := v.Open("another-target", box); !errors.Is(err, ErrOpen) || got != nil {
		t.Fatal("cross-target ciphertext swap succeeded")
	}
	oversized := make([]byte, headerBytes+secretbox.Overhead+4+maxTargetBytes+MaxCredentialBytes+1)
	if _, err := v.Open("wp", oversized); !errors.Is(err, ErrOpen) {
		t.Fatal("oversized envelope accepted")
	}
}
func TestLimitsAndUninitializedVault(t *testing.T) {
	v := testVault(t)
	for _, tt := range []struct {
		target string
		plain  []byte
	}{{"", []byte("x")}, {strings.Repeat("a", maxTargetBytes+1), []byte("x")}, {string([]byte{0xff}), []byte("x")}, {"wp", nil}, {"wp", make([]byte, MaxCredentialBytes+1)}} {
		if _, err := v.Seal(tt.target, tt.plain); err == nil {
			t.Fatal("invalid encryption input accepted")
		}
	}
	box, err := v.Seal(strings.Repeat("a", maxTargetBytes), make([]byte, MaxCredentialBytes))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := v.Open(strings.Repeat("a", maxTargetBytes), box); err != nil || len(got) != MaxCredentialBytes {
		t.Fatal("maximum size credential failed")
	}
	for _, v := range []*Vault{nil, {}} {
		if _, err := v.Seal("wp", []byte("x")); !errors.Is(err, ErrUnavailable) {
			t.Fatal("uninitialized vault encrypted")
		}
		if _, err := v.Open("wp", nil); !errors.Is(err, ErrUnavailable) {
			t.Fatal("uninitialized vault decrypted")
		}
	}
	for _, n := range []int{0, 31, 33} {
		if _, err := New(make([]byte, n)); err == nil {
			t.Fatal("invalid key length accepted")
		}
	}
}
func unsetKey(t *testing.T) {
	t.Helper()
	t.Setenv(KeyEnv, "")
	if err := os.Unsetenv(KeyEnv); err != nil {
		t.Fatal(err)
	}
}
func TestLoadEnvironment(t *testing.T) {
	unsetKey(t)
	if _, err := Load(""); err == nil {
		t.Fatal("missing key accepted")
	}
	good := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32))
	for _, bad := range []string{"", "not-a-key", base64.StdEncoding.EncodeToString([]byte("short")), good[:10] + "\n" + good[10:], strings.Repeat("a", 257)} {
		t.Setenv(KeyEnv, bad)
		if _, err := Load(""); err == nil || strings.Contains(err.Error(), bad) && bad != "" {
			t.Fatal("bad key accepted or echoed")
		}
	}
	t.Setenv(KeyEnv, good)
	if _, err := Load(""); err != nil {
		t.Fatal(err)
	}
	if _, err := Load("unused-file"); err == nil {
		t.Fatal("ambiguous sources accepted")
	}
	t.Setenv(KeyEnv, "")
	if _, err := Load("unused-file"); err == nil {
		t.Fatal("empty configured env silently fell back to file")
	}
}
func TestLoadKeyFile(t *testing.T) {
	unsetKey(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.key")
	good := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32))
	if err := os.WriteFile(path, []byte(good+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("directory key accepted")
	}
	if _, err := Load(path + ".missing"); err == nil {
		t.Fatal("missing file accepted")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatal("public key file accepted")
		}
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "link")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(link); err == nil {
			t.Fatal("symlink key accepted")
		}
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte{'a'}, 257), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("oversized key file accepted")
	}
}
func TestKeyGenerationAndRedaction(t *testing.T) {
	a, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(a)
	if err != nil || len(decoded) != 32 || a == b {
		t.Fatal("key generation failed")
	}
	v := testVault(t)
	for _, value := range []any{v, *v} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if got := fmt.Sprintf(format, value); got != "<credential vault>" {
				t.Fatalf("vault formatting was not redacted: %s", format)
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("vault serialized")
		}
	}
}
func TestConcurrentEncryption(t *testing.T) {
	v := testVault(t)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			box, err := v.Seal("wp", []byte("credential"))
			if err != nil {
				t.Error(err)
				return
			}
			plain, err := v.Open("wp", box)
			if err != nil || string(plain) != "credential" {
				t.Error("concurrent encryption failed")
			}
			clear(plain)
		}()
	}
	wg.Wait()
}
