package lvcrypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"
)

const (
	ServiceTokenPrefix = "lv_st_"
	MachineIDPrefix    = "mi_"
	machineSuffixLen   = 16
	machineSuffixBytes = 10
	verifierPfx        = "lv-st-auth-v1"
)

var (
	machineB32      = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
	errServiceToken = errors.New("lvcrypto: malformed service token")
)

// NewServiceToken creates a machine id, its service token and the 32-byte secret.
func NewServiceToken() (machineID, token string, secret []byte, err error) {
	return newServiceToken(rand.Reader)
}

// newServiceToken reads the 10 suffix bytes, then the 32-byte secret, from r.
func newServiceToken(r io.Reader) (string, string, []byte, error) {
	raw, err := randBytes(r, machineSuffixBytes)
	if err != nil {
		return "", "", nil, err
	}
	secret, err := randBytes(r, KeySize)
	if err != nil {
		return "", "", nil, err
	}
	suffix := machineB32.EncodeToString(raw)
	token := ServiceTokenPrefix + suffix + "." + base64.RawURLEncoding.EncodeToString(secret)
	return MachineIDPrefix + suffix, token, secret, nil
}

// ParseServiceToken splits a service token into machine id and secret.
func ParseServiceToken(token string) (machineID string, secret []byte, err error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(token), ServiceTokenPrefix)
	if !ok {
		return "", nil, errServiceToken
	}
	suffix, enc, ok := strings.Cut(rest, ".")
	if !ok || !ValidMachineSuffix(suffix) {
		return "", nil, errServiceToken
	}
	secret, err = base64.RawURLEncoding.Strict().DecodeString(enc)
	if err != nil || len(secret) != KeySize {
		return "", nil, errServiceToken
	}
	return MachineIDPrefix + suffix, secret, nil
}

// ValidMachineSuffix reports whether s is 16 lowercase RFC 4648 base32 chars.
func ValidMachineSuffix(s string) bool {
	if len(s) != machineSuffixLen {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}

// TokenVerifier returns lower-hex(SHA-256("lv-st-auth-v1" || secret)), sent at login.
func TokenVerifier(secret []byte) string {
	h := sha256.New()
	h.Write([]byte(verifierPfx))
	h.Write(secret)
	return hex.EncodeToString(h.Sum(nil))
}

// VerifierHash returns lower-hex(SHA-256(verifier)) over the verifier's ASCII hex string.
func VerifierHash(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return hex.EncodeToString(sum[:])
}
