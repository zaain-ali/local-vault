package sync

// keywrap.go provides the shared-vault-key primitives.
//
// A vault has one Data Encryption Key (DEK). The snapshot is encrypted
// symmetrically with the DEK. The DEK is delivered to a new joiner by
// wrapping it with a key derived from the invite token's secret, so the
// server only ever stores opaque blobs (see the design spec).

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Domain-separation prefix for the wrap key derived from the invite secret.
const wrapKeyPrefix = "lv-wrap-v1"

// deriveWrapKey returns the 32-byte AES key used to wrap the DEK.
func deriveWrapKey(secret []byte) [32]byte {
	return sha256.Sum256(append([]byte(wrapKeyPrefix), secret...))
}

// WrapKey encrypts the DEK with a key derived from the token secret.
// Output layout: nonce || AES-256-GCM ciphertext.
func WrapKey(dek, secret []byte) ([]byte, error) {
	key := deriveWrapKey(secret)
	gcm, err := newGCM(key[:])
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	return gcm.Seal(nonce, nonce, dek, nil), nil
}

// UnwrapKey reverses WrapKey. Fails if the secret is wrong or the blob
// was tampered with.
func UnwrapKey(blob, secret []byte) ([]byte, error) {
	key := deriveWrapKey(secret)
	gcm, err := newGCM(key[:])
	if err != nil {
		return nil, err
	}

	if len(blob) < gcm.NonceSize() {
		return nil, fmt.Errorf("wrapped key too short")
	}
	nonce, ciphertext := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]

	dek, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("could not unwrap vault key — wrong secret or corrupted token")
	}
	return dek, nil
}

// EncryptSnapshot encrypts all secrets with the vault DEK. No peer needed,
// so a solo owner can push. Reuses the VaultPayload envelope.
func EncryptSnapshot(secrets []SecretEntry, dek []byte) ([]byte, error) {
	secretsJSON, err := json.Marshal(secrets)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize secrets: %w", err)
	}

	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	payload := VaultPayload{
		Version: "2.0.0",
		Secrets: gcm.Seal(nil, nonce, secretsJSON, nil),
		Nonce:   nonce,
		SentAt:  time.Now(),
	}
	return json.Marshal(payload)
}

// DecryptSnapshot reverses EncryptSnapshot using the vault DEK.
func DecryptSnapshot(blob, dek []byte) ([]SecretEntry, error) {
	var payload VaultPayload
	if err := json.Unmarshal(blob, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse snapshot: %w", err)
	}

	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}

	secretsJSON, err := gcm.Open(nil, payload.Nonce, payload.Secrets, nil)
	if err != nil {
		return nil, fmt.Errorf("snapshot decryption failed — vault key mismatch")
	}

	var secrets []SecretEntry
	if err := json.Unmarshal(secretsJSON, &secrets); err != nil {
		return nil, fmt.Errorf("failed to parse decrypted snapshot: %w", err)
	}
	return secrets, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	return gcm, nil
}
