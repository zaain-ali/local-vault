package vault

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"

	"github.com/zain-23/local-vault/apps/server/internal/common/apperror"
)

// Wire limits.
const (
	MaxCiphertextBytes = 4 << 20 // 4 MiB
	minCiphertextBytes = 12 + 16 // nonce + GCM tag
	SignatureBytes     = ed25519.SignatureSize
	MaxWrappedKeyBytes = 1024
	maxEnvironments    = 32
	maxIdempotencyKey  = 128
	maxNoteLen         = 2000
)

// Wrapped-key scheme tags (first byte of wrapped_key).
const (
	SchemeX25519 byte = 0x01
	SchemeRSA    byte = 0x02
	SchemeToken  byte = 0x03
)

// Exact lengths for a 32-byte DEK.
const (
	x25519WrappedLen = 1 + 32 + 12 + 32 + 16 // tag || eph_pub || nonce || ct || gcm tag
	tokenWrappedLen  = 1 + 12 + 32 + 16
	minRSAWrappedLen = 1 + 128 // RSA-1024 modulus is the smallest we accept
)

var envNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// ValidEnvName reports whether name matches ^[a-z][a-z0-9-]{0,31}$.
func ValidEnvName(name string) bool { return envNamePattern.MatchString(name) }

// RevisionSigMessage builds the exact bytes an author signs for a revision.
func RevisionSigMessage(vaultID, env string, revision, parent, keyVersion int, ciphertext []byte) []byte {
	sum := sha256.Sum256(ciphertext)
	msg := "lv-rev-sig-v1\n" + vaultID + "\n" + env + "\n" +
		strconv.Itoa(revision) + "\n" + strconv.Itoa(parent) + "\n" +
		strconv.Itoa(keyVersion) + "\n" + hex.EncodeToString(sum[:])
	return []byte(msg)
}

// VerifyRevisionSignature checks sig against the author's Ed25519 public key.
func VerifyRevisionSignature(pub []byte, vaultID, env string, revision, parent, keyVersion int, ciphertext, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), RevisionSigMessage(vaultID, env, revision, parent, keyVersion, ciphertext), sig)
}

// validateCiphertext checks sizes of a revision payload.
func validateCiphertext(ciphertext, signature []byte) *apperror.Error {
	if len(ciphertext) < minCiphertextBytes {
		return apperror.New(400, "ciphertext is too short")
	}
	if len(ciphertext) > MaxCiphertextBytes {
		return apperror.WithCode(413, "too_large", "ciphertext exceeds 4 MiB")
	}
	if len(signature) != SignatureBytes {
		return apperror.New(400, "signature must be 64 bytes")
	}
	return nil
}

// validateWrappedKey checks the scheme tag and length expected for a recipient
// (recipientType user, or a machine's key_type).
func validateWrappedKey(recipientType, machineKeyType string, wk []byte) *apperror.Error {
	if len(wk) == 0 || len(wk) > MaxWrappedKeyBytes {
		return apperror.WithCode(400, "bad_wrapped_key", "wrapped_key has an invalid length")
	}
	want := SchemeX25519
	if recipientType == RecipientMachine {
		switch machineKeyType {
		case KeyTypeRSA:
			want = SchemeRSA
		case KeyTypeToken:
			want = SchemeToken
		}
	}
	if wk[0] != want {
		return apperror.WithCode(400, "bad_wrapped_key", "wrapped_key scheme does not match the recipient key type")
	}
	ok := false
	switch want {
	case SchemeX25519:
		ok = len(wk) == x25519WrappedLen
	case SchemeToken:
		ok = len(wk) == tokenWrappedLen
	case SchemeRSA:
		ok = len(wk) >= minRSAWrappedLen
	}
	if !ok {
		return apperror.WithCode(400, "bad_wrapped_key", "wrapped_key has an invalid length for its scheme")
	}
	return nil
}
