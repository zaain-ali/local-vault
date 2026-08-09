package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

var joinCodePattern = regexp.MustCompile(`^[2-9A-HJ-NP-Z]{4}-[2-9A-HJ-NP-Z]{4}$`)

func normalizeJoinCode(s string) string {
	s = strings.TrimSpace(strings.ToUpper(s))
	s = strings.ReplaceAll(s, " ", "")
	return s
}

func validJoinCode(s string) bool {
	return joinCodePattern.MatchString(normalizeJoinCode(s))
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func normalizeEmail(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
