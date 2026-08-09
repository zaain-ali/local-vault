package vault

import (
	"crypto/subtle"
	"time"
)

// verifierMatches compares the join verifier in constant time so an attacker
// can't learn the correct prefix from response timing.
func verifierMatches(stored, provided string) bool {
	return subtle.ConstantTimeCompare([]byte(stored), []byte(provided)) == 1
}

// hasPeer reports whether a P2P device id is already an authorized peer.
func hasPeer(v *Vault, deviceID string) bool {
	for _, p := range v.Peers {
		if p.DeviceID == deviceID {
			return true
		}
	}
	return false
}

// tokenActive = not revoked and not past its (optional) expiry.
func tokenActive(t Token, now time.Time) bool {
	if t.Revoked {
		return false
	}
	if t.ExpiresAt != nil && now.After(*t.ExpiresAt) {
		return false
	}
	return true
}
