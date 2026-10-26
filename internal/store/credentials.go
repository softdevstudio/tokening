package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/softdevstudio/tokening/internal/vault"
)

var ErrTargetUnknown = errors.New("credential target does not exist")
var ErrCredentialMissing = errors.New("target has no stored credential")

// SetCredential encrypts before passing any bytes to SQLite. This is an
// internal admin operation; no caller should expose it on an agent listener.
func (s *Store) SetCredential(ctx context.Context, target string, v *vault.Vault, plaintext []byte) error {
	box, err := v.Seal(target, plaintext)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE targets SET cred_ciphertext=? WHERE id=?`, box, target)
	if err != nil {
		return fmt.Errorf("store encrypted credential: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return ErrTargetUnknown
	}
	return nil
}

// Credential decrypts only for the internal forwarder, after authorization.
// It must never be returned by inspection, admin or agent-facing endpoints.
func (s *Store) Credential(ctx context.Context, target string, v *vault.Vault) ([]byte, error) {
	var box []byte
	err := s.db.QueryRowContext(ctx, `SELECT cred_ciphertext FROM targets WHERE id=?`, target).Scan(&box)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTargetUnknown
	}
	if err != nil {
		return nil, fmt.Errorf("read encrypted credential: %w", err)
	}
	if len(box) == 0 {
		return nil, ErrCredentialMissing
	}
	return v.Open(target, box)
}
