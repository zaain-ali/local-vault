package lvcrypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/curve25519"
)

const (
	BundleVersion = 1
	accountAADPfx = "lv-account-keys-v1|"
	fingerprintPf = "lv-fp-v1"
)

// AccountKeys is a user's unlocked account key pair.
type AccountKeys struct {
	X25519Private []byte
	X25519Public  []byte
	Ed25519       ed25519.PrivateKey
}

// Ed25519Public returns the signing public key.
func (k *AccountKeys) Ed25519Public() ed25519.PublicKey {
	return k.Ed25519.Public().(ed25519.PublicKey)
}

// Fingerprint returns the account fingerprint.
func (k *AccountKeys) Fingerprint() string {
	return Fingerprint(k.X25519Public, k.Ed25519Public())
}

// Bundle is the AccountKeyBundle stored on the server.
type Bundle struct {
	Version              int       `json:"version"`
	KDF                  KDFParams `json:"kdf"`
	X25519PublicKey      []byte    `json:"x25519_public_key"`
	Ed25519PublicKey     []byte    `json:"ed25519_public_key"`
	EncryptedPrivateKeys []byte    `json:"encrypted_private_keys"`
	Fingerprint          string    `json:"fingerprint"`
}

type bundlePlaintext struct {
	X25519PrivateKey []byte `json:"x25519_private_key"`
	Ed25519Seed      []byte `json:"ed25519_seed"`
}

// GenerateAccountKeys creates a new random account key pair.
func GenerateAccountKeys() (*AccountKeys, error) {
	return generateAccountKeys(rand.Reader)
}

// generateAccountKeys reads the X25519 private key, then the Ed25519 seed, from r.
func generateAccountKeys(r io.Reader) (*AccountKeys, error) {
	xpriv, err := randBytes(r, KeySize)
	if err != nil {
		return nil, err
	}
	seed, err := randBytes(r, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return accountKeysFrom(xpriv, seed)
}

func accountKeysFrom(x25519Priv, seed []byte) (*AccountKeys, error) {
	if len(x25519Priv) != KeySize || len(seed) != ed25519.SeedSize {
		return nil, errors.New("lvcrypto: invalid account key length")
	}
	xpriv := clamp(x25519Priv)
	xpub, err := curve25519.X25519(xpriv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	return &AccountKeys{X25519Private: xpriv, X25519Public: xpub, Ed25519: ed25519.NewKeyFromSeed(seed)}, nil
}

func clamp(k []byte) []byte {
	c := append([]byte(nil), k...)
	c[0] &= 248
	c[31] &= 127
	c[31] |= 64
	return c
}

// X25519Public derives the public key for a 32-byte X25519 private key.
func X25519Public(priv []byte) ([]byte, error) {
	if len(priv) != KeySize {
		return nil, errors.New("lvcrypto: x25519 private key must be 32 bytes")
	}
	return curve25519.X25519(priv, curve25519.Basepoint)
}

func accountAAD(userID string) []byte { return []byte(accountAADPfx + userID) }

// SealBundle encrypts keys under a KEK derived from passphrase with fresh
// default KDF params. It returns the bundle and the KEK (for caching).
func SealBundle(userID, passphrase string, keys *AccountKeys) (*Bundle, []byte, error) {
	kdf, err := DefaultKDF()
	if err != nil {
		return nil, nil, err
	}
	kek, err := DeriveKEK(passphrase, kdf)
	if err != nil {
		return nil, nil, err
	}
	b, err := sealBundle(rand.Reader, userID, kdf, kek, keys)
	if err != nil {
		return nil, nil, err
	}
	return b, kek, nil
}

func sealBundle(r io.Reader, userID string, kdf KDFParams, kek []byte, keys *AccountKeys) (*Bundle, error) {
	pt, err := json.Marshal(bundlePlaintext{X25519PrivateKey: keys.X25519Private, Ed25519Seed: keys.Ed25519.Seed()})
	if err != nil {
		return nil, err
	}
	enc, err := seal(r, kek, pt, accountAAD(userID))
	if err != nil {
		return nil, err
	}
	epub := keys.Ed25519Public()
	return &Bundle{
		Version:              BundleVersion,
		KDF:                  kdf,
		X25519PublicKey:      append([]byte(nil), keys.X25519Public...),
		Ed25519PublicKey:     append([]byte(nil), epub...),
		EncryptedPrivateKeys: enc,
		Fingerprint:          Fingerprint(keys.X25519Public, epub),
	}, nil
}

// BundleKEK derives the KEK for b from the passphrase.
func BundleKEK(b *Bundle, passphrase string) ([]byte, error) {
	return DeriveKEK(passphrase, b.KDF)
}

// OpenBundle decrypts the private keys and checks they match the bundle's
// public keys and fingerprint.
func OpenBundle(userID string, b *Bundle, kek []byte) (*AccountKeys, error) {
	if b.Version != BundleVersion {
		return nil, errors.New("lvcrypto: unsupported bundle version")
	}
	pt, err := open(kek, b.EncryptedPrivateKeys, accountAAD(userID))
	if err != nil {
		return nil, err
	}
	var p bundlePlaintext
	if err := json.Unmarshal(pt, &p); err != nil {
		return nil, errors.New("lvcrypto: malformed bundle plaintext")
	}
	keys, err := accountKeysFrom(p.X25519PrivateKey, p.Ed25519Seed)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(keys.X25519Public, b.X25519PublicKey) != 1 ||
		subtle.ConstantTimeCompare(keys.Ed25519Public(), b.Ed25519PublicKey) != 1 {
		return nil, errors.New("lvcrypto: bundle public keys do not match private keys")
	}
	if b.Fingerprint != keys.Fingerprint() {
		return nil, errors.New("lvcrypto: bundle fingerprint mismatch")
	}
	return keys, nil
}

// Fingerprint returns the account fingerprint for the two public keys.
func Fingerprint(x25519Pub, ed25519Pub []byte) string {
	h := sha256.New()
	h.Write([]byte(fingerprintPf))
	h.Write(x25519Pub)
	h.Write(ed25519Pub)
	return formatFingerprint(h.Sum(nil))
}

// FingerprintSPKI returns the fingerprint of an RSA machine key (SPKI DER).
func FingerprintSPKI(der []byte) string {
	h := sha256.New()
	h.Write([]byte(fingerprintPf))
	h.Write(der)
	return formatFingerprint(h.Sum(nil))
}

func formatFingerprint(digest []byte) string {
	s := strings.ToUpper(hex.EncodeToString(digest[:16]))
	groups := make([]string, 0, 8)
	for i := 0; i < len(s); i += 4 {
		groups = append(groups, s[i:i+4])
	}
	return strings.Join(groups, "-")
}
