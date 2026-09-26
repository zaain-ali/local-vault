// Package lvcrypto implements the LocalVault protocol v4 crypto formats
// defined in spec/protocol.md. Every format here must stay byte-compatible
// with the server and the web app.
package lvcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"strconv"

	"golang.org/x/crypto/hkdf"
)

const (
	KeySize   = 32
	NonceSize = 12
	TagSize   = 16
)

// ErrDecrypt is returned when an AEAD open fails (wrong key, AAD or tampered data).
var ErrDecrypt = errors.New("lvcrypto: decryption failed")

// NewDEK returns a random 32-byte environment Data Encryption Key.
func NewDEK() ([]byte, error) {
	return randBytes(rand.Reader, KeySize)
}

func randBytes(r io.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("lvcrypto: key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// seal returns nonce(12) || AES-256-GCM(key, nonce, plaintext, aad), reading the nonce from r.
func seal(r io.Reader, key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce, err := randBytes(r, NonceSize)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func open(key, data, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(data) < NonceSize+TagSize {
		return nil, ErrDecrypt
	}
	pt, err := gcm.Open(nil, data[:NonceSize], data[NonceSize:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

func hkdf32(ikm, salt []byte, info string) ([]byte, error) {
	out := make([]byte, KeySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, salt, []byte(info)), out); err != nil {
		return nil, err
	}
	return out, nil
}

func itoa(n int) string { return strconv.Itoa(n) }
