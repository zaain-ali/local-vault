package keys

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"
)

func TestFingerprintMatchesSpecFormula(t *testing.T) {
	x := bytes.Repeat([]byte{0x01}, 32)
	ed := bytes.Repeat([]byte{0x02}, 32)

	sum := sha256.Sum256(append(append([]byte("lv-fp-v1"), x...), ed...))
	hexed := strings.ToUpper(hex.EncodeToString(sum[:16]))
	var groups []string
	for i := 0; i < 32; i += 4 {
		groups = append(groups, hexed[i:i+4])
	}
	want := strings.Join(groups, "-")

	got := Fingerprint(x, ed)
	if got != want {
		t.Fatalf("Fingerprint = %s, want %s", got, want)
	}
	if !regexp.MustCompile(`^([0-9A-F]{4}-){7}[0-9A-F]{4}$`).MatchString(got) {
		t.Fatalf("bad format %s", got)
	}
	if Fingerprint(ed, x) == got {
		t.Fatal("key order must matter")
	}
	if FingerprintKey(append(append([]byte{}, x...), ed...)) != got {
		t.Fatal("FingerprintKey over the concatenation should equal Fingerprint")
	}
}

func validReq() PutKeysRequest {
	x := bytes.Repeat([]byte{0xAA}, 32)
	ed := bytes.Repeat([]byte{0xBB}, 32)
	return PutKeysRequest{
		Version:              1,
		KDF:                  KDF{Alg: "argon2id", Salt: make([]byte, 16), Time: 3, MemoryKiB: 65536, Threads: 4},
		X25519PublicKey:      x,
		Ed25519PublicKey:     ed,
		EncryptedPrivateKeys: make([]byte, 120),
		Fingerprint:          strings.ToLower(Fingerprint(x, ed)), // case-insensitive
	}
}

func TestValidateBundle(t *testing.T) {
	if err := ValidateBundle(validReq()); err != nil {
		t.Fatalf("valid bundle rejected: %v", err)
	}
	cases := map[string]func(*PutKeysRequest){
		"version":      func(r *PutKeysRequest) { r.Version = 2 },
		"short x25519": func(r *PutKeysRequest) { r.X25519PublicKey = r.X25519PublicKey[:31] },
		"long ed25519": func(r *PutKeysRequest) { r.Ed25519PublicKey = append(r.Ed25519PublicKey, 0) },
		"alg":          func(r *PutKeysRequest) { r.KDF.Alg = "scrypt" },
		"memory low":   func(r *PutKeysRequest) { r.KDF.MemoryKiB = 8191 },
		"memory high":  func(r *PutKeysRequest) { r.KDF.MemoryKiB = 1024*1024 + 1 },
		"time zero":    func(r *PutKeysRequest) { r.KDF.Time = 0 },
		"time high":    func(r *PutKeysRequest) { r.KDF.Time = 11 },
		"threads":      func(r *PutKeysRequest) { r.KDF.Threads = 17 },
		"salt":         func(r *PutKeysRequest) { r.KDF.Salt = make([]byte, 8) },
		"empty ct":     func(r *PutKeysRequest) { r.EncryptedPrivateKeys = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := validReq()
			mutate(&r)
			if ValidateBundle(r) == nil {
				t.Fatal("expected rejection")
			}
		})
	}

	r := validReq()
	r.Fingerprint = Fingerprint(r.Ed25519PublicKey, r.X25519PublicKey)
	err := ValidateBundle(r)
	if err == nil || err.Code != "bad_fingerprint" || err.Status != 400 {
		t.Fatalf("want 400 bad_fingerprint, got %v", err)
	}
}
