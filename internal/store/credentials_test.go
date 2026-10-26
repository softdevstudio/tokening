package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/softdevstudio/tokening/internal/vault"
)

func TestEncryptedCredentialPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "db")
	s := openTest(t, path)
	seed(t, s)
	v, err := vault.New(bytes.Repeat([]byte{17}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	plain := []byte("test-only-unique-upstream-secret-734911")
	if _, err = s.Credential(ctx, "wp", v); !errors.Is(err, ErrCredentialMissing) {
		t.Fatal("missing credential not reported")
	}
	if err = s.SetCredential(ctx, "wp", v, plain); err != nil {
		t.Fatal(err)
	}
	var box []byte
	if err = s.db.QueryRow(`SELECT cred_ciphertext FROM targets WHERE id='wp'`).Scan(&box); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(box, plain) {
		t.Fatal("database column contains plaintext")
	}
	// Check the main file and any live WAL/SHM sidecars, not just a SQL result.
	files, err := filepath.Glob(path + "*")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, plain) {
			t.Fatalf("plaintext persisted in %s", filepath.Base(file))
		}
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openTest(t, path)
	got, err := s.Credential(ctx, "wp", v)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal("stored credential failed after reopen")
	}
	clear(got)
	if err = s.SetCredential(ctx, "wp", v, []byte("replacement")); err != nil {
		t.Fatal(err)
	}
	got, err = s.Credential(ctx, "wp", v)
	if err != nil || string(got) != "replacement" {
		t.Fatal("credential replacement failed")
	}
	clear(got)
}
func TestCredentialErrorsAndTargetBinding(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "db"))
	seed(t, s)
	v, _ := vault.New(bytes.Repeat([]byte{17}, 32))
	other, _ := vault.New(bytes.Repeat([]byte{18}, 32))
	ctx := context.Background()
	if err := s.SetCredential(ctx, "missing", v, []byte("secret")); !errors.Is(err, ErrTargetUnknown) {
		t.Fatal(err)
	}
	if _, err := s.Credential(ctx, "missing", v); !errors.Is(err, ErrTargetUnknown) {
		t.Fatal(err)
	}
	if err := s.SetCredential(ctx, "wp", nil, []byte("secret")); !errors.Is(err, vault.ErrUnavailable) {
		t.Fatal(err)
	}
	if err := s.SetCredential(ctx, "wp", v, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Credential(ctx, "wp", other); !errors.Is(err, vault.ErrOpen) || got != nil {
		t.Fatal("wrong key released a credential")
	}
	mustExec(t, s, `INSERT INTO targets (id,kind,url_or_cmd,credential_type,credential_ref,cred_ciphertext,created_at) SELECT 'other',kind,url_or_cmd,credential_type,credential_ref,cred_ciphertext,created_at FROM targets WHERE id='wp'`)
	if got, err := s.Credential(ctx, "other", v); !errors.Is(err, vault.ErrOpen) || got != nil {
		t.Fatal("cross-target credential swap succeeded")
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.SetCredential(ctx, "wp", v, []byte("changed")); err == nil {
		t.Fatal("canceled credential write succeeded")
	}
	got, err := s.Credential(context.Background(), "wp", v)
	if err != nil || string(got) != "secret" {
		t.Fatal("failed write changed credential")
	}
	clear(got)
}
