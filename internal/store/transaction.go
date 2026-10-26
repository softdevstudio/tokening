package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
)

// writeTx reserves a connection through commit. SQLite can leave a transaction
// open on a COMMIT error, so discard that connection before it can be reused.
func (s *Store) writeTx(ctx context.Context, fn func(*sql.Tx) error) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire database connection: %w", err)
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()
	if err = fn(tx); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}
