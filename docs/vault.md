# Credential vault

The internal vault encrypts upstream credentials before they reach SQLite. It
uses NaCl secretbox from `golang.org/x/crypto`, with a 32-byte random key and a
fresh 24-byte random nonce for every encryption. A target ID is authenticated
inside the encrypted payload. A credential encrypted for one target cannot be
opened as a credential for another target, even with the same vault key.

`vault.Load(keyFile)` accepts exactly one configured key source: the environment
variable `TOKENING_VAULT_KEY`, or a key file. A configured but empty environment
variable is an error. Setting both sources is also an error. There is no fallback
key, password-derived key or automatic replacement for a missing key.

The key is canonical standard base64 encoding of 32 random bytes. Surrounding
whitespace is ignored; embedded newlines and noncanonical encodings are refused.
`vault.GenerateKey()` generates this encoding from the operating system's random
source. These are internal Go functions. A key-generation CLI and server flags
have not been wired yet.

Key files must be regular files, not symlinks, and contain at most 256 bytes.
On Unix they must be owner-readable and grant no group or other permissions;
0400 or 0600 works. Windows protection depends on directory and file ACLs. Keep
the file in a private directory controlled by the operator, outside the database
and outside an agent workspace. Keep a protected backup: losing the key makes
the stored credentials unreadable. The vault key is not stored in SQLite.

The binary envelope starts with `TKNV`, format version 1, and the nonce. Secretbox
then authenticates and encrypts a length-prefixed target ID followed by the
credential bytes. The target ID is limited to 256 UTF-8 bytes and the credential
to 64 KiB. Empty credentials are refused. Unknown versions, truncation, tampering,
wrong keys and wrong targets return no plaintext.

The store's `SetCredential` method writes only ciphertext to `cred_ciphertext`.
Its `Credential` method returns plaintext for the internal forwarder after a
successful authorization. This method must never be exposed as an inspection or
agent endpoint. Replacing a credential changes its encrypted value; vault key
rotation is still a later hardening task.

Plaintext is copied out only after authentication. Callers should clear returned
byte buffers after use. Temporary byte buffers are cleared where possible, but
Go does not guarantee erasure of all key or plaintext copies from memory. Vault
values redact normal diagnostic formatting and refuse JSON serialization.
Errors do not include keys or credential values. Any future stdio launcher must
exclude the vault key from child environments rather than inherit the server's
whole environment.

Tests check round trips, fresh nonces, every-byte tampering and every truncation,
wrong keys, cross-target swapping, input limits and key-source validation.
Persistence tests inspect the SQLite column, main file and live WAL/SHM files for
the known test plaintext, then reopen and decrypt the credential. The [REST gateway](gateway.md) now injects credentials after committed authorization. MCP forwarding and running listeners remain separate tasks.
