package lvcrypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

var fpRe = regexp.MustCompile(`^([0-9A-F]{4}-){7}[0-9A-F]{4}$`)

func fastKDF(t *testing.T) KDFParams {
	t.Helper()
	p, err := DefaultKDF()
	if err != nil {
		t.Fatal(err)
	}
	p.Time, p.MemoryKiB, p.Threads = 1, kdfMinMemoryKiB, 1
	return p
}

func flip(b []byte, i int) []byte {
	c := append([]byte(nil), b...)
	c[i] ^= 0x01
	return c
}

func mustDEK(t *testing.T) []byte {
	t.Helper()
	dek, err := NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	return dek
}

func sampleSnapshot() *Snapshot {
	ts := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	return &Snapshot{Version: 1, Secrets: []Secret{
		{Key: "DATABASE_URL", Value: "postgres://db", UpdatedAt: ts, UpdatedBy: "usr_x"},
		{Key: "API_KEY", Value: "k1", UpdatedAt: ts, UpdatedBy: "usr_x"},
		{Key: "OLD", Value: "leak", UpdatedAt: ts, UpdatedBy: "usr_x", Deleted: true},
	}}
}

func TestKDFValidate(t *testing.T) {
	good := fastKDF(t)
	if _, err := DeriveKEK("pw", good); err != nil {
		t.Fatal(err)
	}
	bad := []func(p *KDFParams){
		func(p *KDFParams) { p.Alg = "scrypt" },
		func(p *KDFParams) { p.Salt = p.Salt[:8] },
		func(p *KDFParams) { p.MemoryKiB = 1024 },
		func(p *KDFParams) { p.MemoryKiB = 2 * 1024 * 1024 },
		func(p *KDFParams) { p.Time = 0 },
		func(p *KDFParams) { p.Time = 11 },
		func(p *KDFParams) { p.Threads = 0 },
		func(p *KDFParams) { p.Threads = 17 },
	}
	for i, mut := range bad {
		p := good
		mut(&p)
		if _, err := DeriveKEK("pw", p); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
	d, _ := DefaultKDF()
	if d.Validate() != nil || len(d.Salt) != 16 || d.Time != 3 || d.MemoryKiB != 65536 || d.Threads != 4 {
		t.Fatalf("bad defaults: %+v", d)
	}
}

func TestBundleRoundTrip(t *testing.T) {
	keys, err := GenerateAccountKeys()
	if err != nil {
		t.Fatal(err)
	}
	b, kek, err := SealBundle("usr_1", "pass phrase", keys)
	if err != nil {
		t.Fatal(err)
	}
	if !fpRe.MatchString(b.Fingerprint) || b.Fingerprint != keys.Fingerprint() {
		t.Fatalf("bad fingerprint %q", b.Fingerprint)
	}
	kek2, err := BundleKEK(b, "pass phrase")
	if err != nil || !bytes.Equal(kek, kek2) {
		t.Fatal("BundleKEK mismatch")
	}
	got, err := OpenBundle("usr_1", b, kek)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.X25519Private, keys.X25519Private) || !bytes.Equal(got.Ed25519, keys.Ed25519) {
		t.Fatal("keys differ after round trip")
	}

	if _, err := OpenBundle("usr_2", b, kek); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong user id: %v", err)
	}
	wrongKEK, _ := BundleKEK(b, "wrong")
	if _, err := OpenBundle("usr_1", b, wrongKEK); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	for _, i := range []int{0, NonceSize, len(b.EncryptedPrivateKeys) - 1} {
		t2 := *b
		t2.EncryptedPrivateKeys = flip(b.EncryptedPrivateKeys, i)
		if _, err := OpenBundle("usr_1", &t2, kek); err == nil {
			t.Fatalf("tamper at %d not detected", i)
		}
	}
	other, _ := GenerateAccountKeys()
	swapped := *b
	swapped.X25519PublicKey = other.X25519Public
	if _, err := OpenBundle("usr_1", &swapped, kek); err == nil {
		t.Fatal("swapped public key not detected")
	}
	badFP := *b
	badFP.Fingerprint = other.Fingerprint()
	if _, err := OpenBundle("usr_1", &badFP, kek); err == nil {
		t.Fatal("wrong fingerprint not detected")
	}
}

func TestAccountKeysClamped(t *testing.T) {
	keys, _ := GenerateAccountKeys()
	p := keys.X25519Private
	if p[0]&7 != 0 || p[31]&128 != 0 || p[31]&64 == 0 {
		t.Fatal("x25519 private key not clamped")
	}
}

func TestFingerprint(t *testing.T) {
	a := Fingerprint(make([]byte, 32), make([]byte, 32))
	b := Fingerprint(make([]byte, 32), bytes.Repeat([]byte{1}, 32))
	if !fpRe.MatchString(a) || !fpRe.MatchString(b) || a == b {
		t.Fatalf("bad fingerprints %q %q", a, b)
	}
	if s := FingerprintSPKI([]byte("der")); !fpRe.MatchString(s) {
		t.Fatalf("bad spki fingerprint %q", s)
	}
}

func TestGrantInfo(t *testing.T) {
	if got := GrantInfo("vlt_1", "production", 3); got != "lv-grant-v1|vlt_1|production|3" {
		t.Fatal(got)
	}
}

func TestX25519Grant(t *testing.T) {
	keys, _ := GenerateAccountKeys()
	dek := mustDEK(t)
	info := GrantInfo("vlt_1", "production", 1)
	w, err := WrapX25519(dek, keys.X25519Public, info)
	if err != nil {
		t.Fatal(err)
	}
	if SchemeOf(w) != SchemeX25519 || len(w) != 1+32+12+32+16 {
		t.Fatalf("bad wrapped layout len=%d", len(w))
	}
	got, err := UnwrapX25519(w, keys.X25519Private, info)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap: %v", err)
	}
	if _, err := UnwrapX25519(w, keys.X25519Private, GrantInfo("vlt_1", "production", 2)); err == nil {
		t.Fatal("wrong info accepted")
	}
	other, _ := GenerateAccountKeys()
	if _, err := UnwrapX25519(w, other.X25519Private, info); err == nil {
		t.Fatal("wrong recipient accepted")
	}
	for i := 1; i < len(w); i += 7 {
		if _, err := UnwrapX25519(flip(w, i), keys.X25519Private, info); err == nil {
			t.Fatalf("tamper at %d not detected", i)
		}
	}
	if _, err := UnwrapX25519(flip(w, 0), keys.X25519Private, info); err == nil {
		t.Fatal("wrong scheme accepted")
	}
	if _, err := WrapX25519(dek, make([]byte, 32), info); err == nil {
		t.Fatal("low-order public key accepted")
	}
	if _, err := WrapX25519(dek[:16], keys.X25519Public, info); err == nil {
		t.Fatal("short DEK accepted")
	}
}

func TestRSAGrant(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pub, err := ParseRSASPKI(der)
	if err != nil {
		t.Fatal(err)
	}
	dek := mustDEK(t)
	w, err := WrapRSA(dek, pub)
	if err != nil {
		t.Fatal(err)
	}
	if SchemeOf(w) != SchemeRSA {
		t.Fatal("bad scheme")
	}
	got, err := UnwrapRSALocal(w, priv)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap: %v", err)
	}
	if _, err := UnwrapRSALocal(flip(w, 20), priv); err == nil {
		t.Fatal("tamper not detected")
	}
	var seen []byte
	got, err = UnwrapRSAWith(w, func(ct []byte) ([]byte, error) { seen = ct; return dek, nil })
	if err != nil || !bytes.Equal(seen, w[1:]) || !bytes.Equal(got, dek) {
		t.Fatal("UnwrapRSAWith did not pass raw ciphertext")
	}
	if _, err := UnwrapRSAWith(w, func([]byte) ([]byte, error) { return []byte("short"), nil }); err == nil {
		t.Fatal("short DEK accepted")
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	sder, _ := x509.MarshalPKIXPublicKey(&small.PublicKey)
	if _, err := ParseRSASPKI(sder); err == nil {
		t.Fatal("1024-bit key accepted")
	}
}

func TestTokenGrant(t *testing.T) {
	_, _, secret, err := NewServiceToken()
	if err != nil {
		t.Fatal(err)
	}
	dek := mustDEK(t)
	info := GrantInfo("vlt_1", "staging", 4)
	w, err := WrapToken(dek, secret, info)
	if err != nil {
		t.Fatal(err)
	}
	if SchemeOf(w) != SchemeToken || len(w) != 1+12+32+16 {
		t.Fatal("bad wrapped layout")
	}
	got, err := UnwrapToken(w, secret, info)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap: %v", err)
	}
	if _, err := UnwrapToken(w, secret, GrantInfo("vlt_1", "production", 4)); err == nil {
		t.Fatal("wrong info accepted")
	}
	if _, err := UnwrapToken(w, flip(secret, 0), info); err == nil {
		t.Fatal("wrong secret accepted")
	}
	if _, err := UnwrapToken(flip(w, len(w)-1), secret, info); err == nil {
		t.Fatal("tamper not detected")
	}
	if SchemeOf(nil) != 0 {
		t.Fatal("SchemeOf(nil) != 0")
	}
}

func TestSnapshotNormalize(t *testing.T) {
	s := &Snapshot{Secrets: []Secret{
		{Key: "B", Value: "1"},
		{Key: "A", Value: "x"},
		{Key: "B", Value: "2"},
		{Key: "C", Value: "gone", Deleted: true},
	}}
	s.Normalize()
	if s.Version != 1 || len(s.Secrets) != 3 {
		t.Fatalf("%+v", s)
	}
	if s.Secrets[0].Key != "A" || s.Secrets[1].Value != "2" || s.Secrets[2].Value != "" {
		t.Fatalf("%+v", s.Secrets)
	}
	data, err := MarshalSnapshot(&Snapshot{})
	if err != nil || string(data) != `{"version":1,"secrets":[]}` {
		t.Fatalf("empty snapshot: %s %v", data, err)
	}
	if _, err := MarshalSnapshot(&Snapshot{Version: 2}); err == nil {
		t.Fatal("version 2 accepted")
	}

	old := time.Now().Add(-100 * 24 * time.Hour)
	p := &Snapshot{Secrets: []Secret{
		{Key: "A", Deleted: true, UpdatedAt: old},
		{Key: "B", Deleted: true, UpdatedAt: time.Now()},
		{Key: "C", Value: "v", UpdatedAt: old},
	}}
	p.PruneTombstones(time.Now().Add(-90 * 24 * time.Hour))
	if len(p.Secrets) != 2 || p.Secrets[0].Key != "B" {
		t.Fatalf("prune: %+v", p.Secrets)
	}
}

func TestRevisionRoundTrip(t *testing.T) {
	dek := mustDEK(t)
	keys, _ := GenerateAccountKeys()
	snap := sampleSnapshot()
	ct, err := EncryptRevision(dek, "vlt_1", "production", 5, 2, snap)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptRevision(dek, "vlt_1", "production", 5, 2, ct)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Secrets) != 3 || got.Secrets[0].Key != "API_KEY" {
		t.Fatalf("%+v", got.Secrets)
	}
	if s, _ := got.Get("OLD"); !s.Deleted || s.Value != "" {
		t.Fatal("tombstone not preserved/cleared")
	}
	wrongAAD := []struct {
		vault, env string
		rev, kv    int
	}{{"vlt_2", "production", 5, 2}, {"vlt_1", "staging", 5, 2}, {"vlt_1", "production", 4, 2}, {"vlt_1", "production", 5, 3}}
	for _, w := range wrongAAD {
		if _, err := DecryptRevision(dek, w.vault, w.env, w.rev, w.kv, ct); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("wrong aad %+v accepted", w)
		}
	}
	if _, err := DecryptRevision(dek, "vlt_1", "production", 5, 2, flip(ct, 30)); err == nil {
		t.Fatal("tamper not detected")
	}

	msg := string(SignatureMessage("vlt_1", "production", 5, 4, 2, ct))
	if !strings.HasPrefix(msg, "lv-rev-sig-v1\nvlt_1\nproduction\n5\n4\n2\n") || len(msg) != len("lv-rev-sig-v1\nvlt_1\nproduction\n5\n4\n2\n")+64 {
		t.Fatalf("bad sig msg %q", msg)
	}
	sig := SignRevision(keys.Ed25519, "vlt_1", "production", 5, 4, 2, ct)
	pub := keys.Ed25519Public()
	if !VerifyRevision(pub, sig, "vlt_1", "production", 5, 4, 2, ct) {
		t.Fatal("valid signature rejected")
	}
	if VerifyRevision(pub, sig, "vlt_1", "production", 5, 4, 2, flip(ct, 0)) ||
		VerifyRevision(pub, sig, "vlt_1", "production", 5, 3, 2, ct) ||
		VerifyRevision(pub, sig, "vlt_1", "staging", 5, 4, 2, ct) ||
		VerifyRevision(pub, flip(sig, 0), "vlt_1", "production", 5, 4, 2, ct) ||
		VerifyRevision(pub[:10], sig, "vlt_1", "production", 5, 4, 2, ct) {
		t.Fatal("invalid signature accepted")
	}
	sig2 := SignRevision(keys.Ed25519, "vlt_1", "production", 7, 4, 2, ct)
	if VerifyRevision(pub, sig2, "vlt_1", "production", 7, 4, 2, ct) {
		t.Fatal("revision != parent+1 accepted")
	}
}

func TestLocalRoundTrip(t *testing.T) {
	dek := mustDEK(t)
	w, err := EncryptLocal(dek, "vlt_1", "development", sampleSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptLocal(dek, "vlt_1", "development", w); err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptLocal(dek, "vlt_1", "staging", w); err == nil {
		t.Fatal("wrong env accepted")
	}
	if _, err := DecryptRevision(dek, "vlt_1", "development", 1, 1, w); err == nil {
		t.Fatal("working copy accepted as revision")
	}
	if _, err := DecryptLocal(dek, "vlt_1", "development", flip(w, 15)); err == nil {
		t.Fatal("tamper not detected")
	}
	if _, err := DecryptLocal(dek, "vlt_1", "development", w[:10]); err == nil {
		t.Fatal("short input accepted")
	}
}

func TestServiceToken(t *testing.T) {
	mid, token, secret, err := NewServiceToken()
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^mi_[a-z2-7]{16}$`).MatchString(mid) {
		t.Fatalf("bad machine id %q", mid)
	}
	if !regexp.MustCompile(`^lv_st_[a-z2-7]{16}\.[A-Za-z0-9_-]{43}$`).MatchString(token) {
		t.Fatalf("bad token %q", token)
	}
	gotMID, gotSecret, err := ParseServiceToken(token)
	if err != nil || gotMID != mid || !bytes.Equal(gotSecret, secret) {
		t.Fatalf("parse: %v", err)
	}
	for _, bad := range []string{
		"", "lv_xx_" + token[6:], strings.Replace(token, ".", "", 1),
		token[:len(token)-1], token + "A", "lv_st_ABCDEFGHIJKLMNOP." + token[23:],
	} {
		if _, _, err := ParseServiceToken(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	v := TokenVerifier(secret)
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(v) || VerifierHash(v) == v || len(VerifierHash(v)) != 64 {
		t.Fatal("bad verifier")
	}
}
