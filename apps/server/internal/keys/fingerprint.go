package keys

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const fingerprintPrefix = "lv-fp-v1"

// Fingerprint computes the account-key fingerprint from protocol v4:
// upper-hex(SHA-256("lv-fp-v1" || x25519_pub || ed25519_pub)[0:16]) in 8 groups of 4.
func Fingerprint(x25519Pub, ed25519Pub []byte) string {
	h := sha256.New()
	h.Write([]byte(fingerprintPrefix))
	h.Write(x25519Pub)
	h.Write(ed25519Pub)
	return format(h.Sum(nil))
}

// FingerprintKey computes a machine-identity fingerprint over a single public
// key (RSA SPKI DER or a raw 32-byte X25519 key), same formatting.
func FingerprintKey(pub []byte) string {
	h := sha256.New()
	h.Write([]byte(fingerprintPrefix))
	h.Write(pub)
	return format(h.Sum(nil))
}

func format(digest []byte) string {
	hexed := strings.ToUpper(hex.EncodeToString(digest[:16]))
	groups := make([]string, 0, 8)
	for i := 0; i < len(hexed); i += 4 {
		groups = append(groups, hexed[i:i+4])
	}
	return strings.Join(groups, "-")
}
