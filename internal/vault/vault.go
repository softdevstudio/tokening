// Package vault encrypts upstream credentials with NaCl secretbox.
package vault

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/nacl/secretbox"
)

const KeyEnv = "TOKENING_VAULT_KEY"
const MaxCredentialBytes = 64 << 10
const maxTargetBytes = 256
const prefix = "TKNV\x01"
const headerBytes = len(prefix) + 24

var ErrOpen = errors.New("credential could not be authenticated for this target")
var ErrUnavailable = errors.New("credential vault is not initialized")

// Vault is immutable after construction. Never copy its key into logs or JSON.
type Vault struct {
	key   [32]byte
	ready bool
}

func (Vault) String() string   { return "<credential vault>" }
func (Vault) GoString() string { return "<credential vault>" }
func (Vault) MarshalJSON() ([]byte, error) {
	return nil, errors.New("credential vault cannot be serialized")
}

// GenerateKey returns a random, base64-encoded 32-byte key. The caller must
// save it outside the database and outside any agent environment.
func GenerateKey() (string, error) {
	var key [32]byte
	defer clear(key[:])
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return "", errors.New("generate vault key failed")
	}
	return base64.StdEncoding.EncodeToString(key[:]), nil
}

func New(key []byte) (*Vault, error) {
	if len(key) != 32 {
		return nil, errors.New("vault key must decode to 32 bytes")
	}
	v := &Vault{ready: true}
	copy(v.key[:], key)
	return v, nil
}

// Load accepts exactly one source: KeyEnv or keyFile. Empty configured values
// are errors, never a reason to silently fall back to a different source.
func Load(keyFile string) (*Vault, error) {
	env, set := os.LookupEnv(KeyEnv)
	if set && keyFile != "" {
		return nil, errors.New("configure either TOKENING_VAULT_KEY or a key file, not both")
	}
	var encoded []byte
	if set {
		encoded = []byte(env)
	} else if keyFile != "" {
		info, err := os.Lstat(keyFile)
		if err != nil {
			return nil, errors.New("cannot inspect vault key file")
		}
		if !info.Mode().IsRegular() {
			return nil, errors.New("vault key file must be a regular file, not a symlink")
		}
		if runtime.GOOS != "windows" && (info.Mode().Perm()&0077 != 0 || info.Mode().Perm()&0400 == 0) {
			return nil, errors.New("vault key file must be owner-readable with no group or other permissions")
		}
		f, err := os.Open(keyFile)
		if err != nil {
			return nil, errors.New("cannot open vault key file")
		}
		defer f.Close()
		opened, err := f.Stat()
		if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
			return nil, errors.New("vault key file changed while opening")
		}
		if runtime.GOOS != "windows" && (opened.Mode().Perm()&0077 != 0 || opened.Mode().Perm()&0400 == 0) {
			return nil, errors.New("vault key file permissions changed while opening")
		}
		encoded, err = io.ReadAll(io.LimitReader(f, 257))
		if err != nil {
			return nil, errors.New("cannot read vault key file")
		}
	} else {
		return nil, errors.New("configure TOKENING_VAULT_KEY or a vault key file")
	}
	defer clear(encoded)
	if len(encoded) > 256 {
		return nil, errors.New("invalid vault key encoding")
	}
	text := strings.TrimSpace(string(encoded))
	key, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil {
		return nil, errors.New("vault key must be canonical base64 encoding of 32 random bytes")
	}
	defer clear(key)
	if base64.StdEncoding.EncodeToString(key) != text {
		return nil, errors.New("vault key must use canonical base64 encoding")
	}
	return New(key)
}

// Seal binds an encrypted credential to its target ID. Only ciphertext is
// returned to storage; caller-owned plaintext is not modified.
func (v *Vault) Seal(target string, credential []byte) ([]byte, error) {
	if v == nil || !v.ready {
		return nil, ErrUnavailable
	}
	if !validTarget(target) {
		return nil, errors.New("invalid credential target")
	}
	if len(credential) == 0 || len(credential) > MaxCredentialBytes {
		return nil, fmt.Errorf("credential must contain 1 to %d bytes", MaxCredentialBytes)
	}
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, errors.New("generate credential nonce failed")
	}
	message := make([]byte, 4+len(target)+len(credential))
	defer clear(message)
	binary.BigEndian.PutUint32(message, uint32(len(target)))
	copy(message[4:], target)
	copy(message[4+len(target):], credential)
	out := make([]byte, headerBytes, headerBytes+secretbox.Overhead+len(message))
	copy(out, prefix)
	copy(out[len(prefix):], nonce[:])
	return secretbox.Seal(out, message, &nonce, &v.key), nil
}

// Open authenticates before returning plaintext. The caller must clear the
// returned bytes after injecting the credential into the upstream request.
func (v *Vault) Open(target string, box []byte) ([]byte, error) {
	if v == nil || !v.ready {
		return nil, ErrUnavailable
	}
	if !validTarget(target) || len(box) < headerBytes+secretbox.Overhead+6 || len(box) > headerBytes+secretbox.Overhead+4+maxTargetBytes+MaxCredentialBytes || string(box[:len(prefix)]) != prefix {
		return nil, ErrOpen
	}
	var nonce [24]byte
	copy(nonce[:], box[len(prefix):headerBytes])
	message, ok := secretbox.Open(nil, box[headerBytes:], &nonce, &v.key)
	if !ok {
		return nil, ErrOpen
	}
	defer clear(message)
	if len(message) < 4 {
		return nil, ErrOpen
	}
	n := int(binary.BigEndian.Uint32(message[:4]))
	if n <= 0 || n > maxTargetBytes || n >= len(message)-4 {
		return nil, ErrOpen
	}
	if subtle.ConstantTimeCompare(message[4:4+n], []byte(target)) != 1 {
		return nil, ErrOpen
	}
	credential := message[4+n:]
	if len(credential) > MaxCredentialBytes {
		return nil, ErrOpen
	}
	return append([]byte(nil), credential...), nil
}
func validTarget(target string) bool {
	return target != "" && len(target) <= maxTargetBytes && utf8.ValidString(target)
}
