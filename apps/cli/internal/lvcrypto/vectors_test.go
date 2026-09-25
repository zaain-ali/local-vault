package lvcrypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

// detReader is a deterministic stream: SHA-256(seed || uint64be(counter)) blocks.
type detReader struct {
	seed    []byte
	counter uint64
	buf     []byte
}

func (d *detReader) Read(p []byte) (int, error) {
	for len(d.buf) < len(p) {
		var c [8]byte
		binary.BigEndian.PutUint64(c[:], d.counter)
		d.counter++
		sum := sha256.Sum256(append(append([]byte(nil), d.seed...), c[:]...))
		d.buf = append(d.buf, sum[:]...)
	}
	n := copy(p, d.buf)
	d.buf = d.buf[n:]
	return n, nil
}

func (d *detReader) take(t *testing.T, n int) []byte {
	t.Helper()
	b, err := randBytes(d, n)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type kdfVector struct {
	Passphrase string    `json:"passphrase"`
	KDF        KDFParams `json:"kdf"`
	KEK        []byte    `json:"kek"`
}

type bundleVector struct {
	UserID           string  `json:"user_id"`
	Passphrase       string  `json:"passphrase"`
	KEK              []byte  `json:"kek"`
	X25519PrivateKey []byte  `json:"x25519_private_key"`
	Ed25519Seed      []byte  `json:"ed25519_seed"`
	Nonce            []byte  `json:"nonce"`
	AAD              string  `json:"aad"`
	Plaintext        []byte  `json:"plaintext"`
	Bundle           *Bundle `json:"bundle"`
}

type x25519GrantVector struct {
	VaultID             string `json:"vault_id"`
	Env                 string `json:"env"`
	KeyVersion          int    `json:"key_version"`
	Info                string `json:"info"`
	DEK                 []byte `json:"dek"`
	RecipientPrivateKey []byte `json:"recipient_private_key"`
	RecipientPublicKey  []byte `json:"recipient_public_key"`
	EphemeralPrivateKey []byte `json:"ephemeral_private_key"`
	EphemeralPublicKey  []byte `json:"ephemeral_public_key"`
	SharedSecret        []byte `json:"shared_secret"`
	WrapKey             []byte `json:"wrap_key"`
	Nonce               []byte `json:"nonce"`
	WrappedKey          []byte `json:"wrapped_key"`
}

type tokenGrantVector struct {
	VaultID     string `json:"vault_id"`
	Env         string `json:"env"`
	KeyVersion  int    `json:"key_version"`
	Info        string `json:"info"`
	HKDFInfo    string `json:"hkdf_info"`
	DEK         []byte `json:"dek"`
	TokenSecret []byte `json:"token_secret"`
	WrapKey     []byte `json:"wrap_key"`
	Nonce       []byte `json:"nonce"`
	WrappedKey  []byte `json:"wrapped_key"`
}

type revisionVector struct {
	VaultID           string `json:"vault_id"`
	Env               string `json:"env"`
	Revision          int    `json:"revision"`
	ParentRevision    int    `json:"parent_revision"`
	KeyVersion        int    `json:"key_version"`
	DEK               []byte `json:"dek"`
	Nonce             []byte `json:"nonce"`
	AAD               string `json:"aad"`
	SnapshotJSON      []byte `json:"snapshot_json"`
	Ciphertext        []byte `json:"ciphertext"`
	CiphertextSHA256  string `json:"ciphertext_sha256_hex"`
	SignatureMessage  string `json:"signature_message"`
	AuthorEd25519Seed []byte `json:"author_ed25519_seed"`
	AuthorEd25519Pub  []byte `json:"author_ed25519_public_key"`
	Signature         []byte `json:"signature"`
}

type localVector struct {
	VaultID      string `json:"vault_id"`
	Env          string `json:"env"`
	DEK          []byte `json:"dek"`
	Nonce        []byte `json:"nonce"`
	AAD          string `json:"aad"`
	SnapshotJSON []byte `json:"snapshot_json"`
	Working      []byte `json:"working"`
}

type serviceTokenVector struct {
	MachineIDRandom []byte `json:"machine_id_random"`
	MachineID       string `json:"machine_id"`
	TokenSecret     []byte `json:"token_secret"`
	Token           string `json:"token"`
	Verifier        string `json:"verifier"`
	VerifierHash    string `json:"verifier_hash"`
}

type vectorFile struct {
	Description  string             `json:"description"`
	KDF          kdfVector          `json:"kdf"`
	Bundle       bundleVector       `json:"bundle"`
	X25519Grant  x25519GrantVector  `json:"grant_x25519"`
	TokenGrant   tokenGrantVector   `json:"grant_token"`
	Revision     revisionVector     `json:"revision"`
	Local        localVector        `json:"local"`
	ServiceToken serviceTokenVector `json:"service_token"`
}

func vectorSnapshot() *Snapshot {
	ts := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	return &Snapshot{Version: 1, Secrets: []Secret{
		{Key: "DATABASE_URL", Value: "postgres://app:p%40ss@db:5432/app", UpdatedAt: ts, UpdatedBy: "usr_test"},
		{Key: "GREETING", Value: "héllo ✓", UpdatedAt: ts.Add(time.Minute), UpdatedBy: "usr_test"},
		{Key: "OLD_TOKEN", UpdatedAt: ts.Add(2 * time.Minute), UpdatedBy: "usr_test", Deleted: true},
	}}
}

// must panics on error; the test binary reports the panic as a failure.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func readers(parts ...[]byte) io.Reader {
	rs := make([]io.Reader, len(parts))
	for i, p := range parts {
		rs[i] = bytes.NewReader(p)
	}
	return io.MultiReader(rs...)
}

func buildVectors(t *testing.T) *vectorFile {
	d := &detReader{seed: []byte("lv-protocol-test-vectors-v1")}
	v := &vectorFile{Description: "LocalVault protocol v4 in-memory test vectors."}

	// 1. Argon2id KEK.
	kdf := KDFParams{Alg: KDFAlg, Salt: d.take(t, KDFSaltSize), Time: 3, MemoryKiB: 65536, Threads: 4}
	pass := "correct horse battery staple"
	kek := must(DeriveKEK(pass, kdf))
	v.KDF = kdfVector{Passphrase: pass, KDF: kdf, KEK: kek}

	// 2. Account key bundle.
	keys := must(generateAccountKeys(d))
	nonce := d.take(t, NonceSize)
	b := must(sealBundle(bytes.NewReader(nonce), "usr_test", kdf, kek, keys))
	pt := must(open(kek, b.EncryptedPrivateKeys, accountAAD("usr_test")))
	v.Bundle = bundleVector{
		UserID: "usr_test", Passphrase: pass, KEK: kek,
		X25519PrivateKey: keys.X25519Private, Ed25519Seed: keys.Ed25519.Seed(),
		Nonce: nonce, AAD: string(accountAAD("usr_test")), Plaintext: pt, Bundle: b,
	}

	// 3. X25519 grant to the bundle's account key.
	info := GrantInfo("vlt_test", "production", 1)
	dek := d.take(t, KeySize)
	eph := clamp(d.take(t, KeySize))
	ephPub := must(curve25519.X25519(eph, curve25519.Basepoint))
	nonce = d.take(t, NonceSize)
	shared := must(curve25519.X25519(eph, keys.X25519Public))
	wrapKey := must(x25519WrapKey(eph, keys.X25519Public, ephPub, keys.X25519Public, info))
	v.X25519Grant = x25519GrantVector{
		VaultID: "vlt_test", Env: "production", KeyVersion: 1, Info: info, DEK: dek,
		RecipientPrivateKey: keys.X25519Private, RecipientPublicKey: keys.X25519Public,
		EphemeralPrivateKey: eph, EphemeralPublicKey: ephPub, SharedSecret: shared, WrapKey: wrapKey,
		Nonce: nonce, WrappedKey: must(wrapX25519(readers(eph, nonce), dek, keys.X25519Public, info)),
	}

	// 4. Service-token grant of the same DEK.
	secret := d.take(t, KeySize)
	nonce = d.take(t, NonceSize)
	v.TokenGrant = tokenGrantVector{
		VaultID: "vlt_test", Env: "production", KeyVersion: 1, Info: info, HKDFInfo: tokenWrapPfx + info,
		DEK: dek, TokenSecret: secret, WrapKey: must(tokenWrapKey(secret, info)), Nonce: nonce,
		WrappedKey: must(wrapToken(bytes.NewReader(nonce), dek, secret, info)),
	}

	// 5. Revision 1 signed by the bundle's Ed25519 key.
	snapJSON := must(MarshalSnapshot(vectorSnapshot()))
	nonce = d.take(t, NonceSize)
	ct := must(encryptSnapshot(bytes.NewReader(nonce), dek, vectorSnapshot(), RevisionAAD("vlt_test", "production", 1, 1)))
	sum := sha256.Sum256(ct)
	v.Revision = revisionVector{
		VaultID: "vlt_test", Env: "production", Revision: 1, ParentRevision: 0, KeyVersion: 1,
		DEK: dek, Nonce: nonce, AAD: string(RevisionAAD("vlt_test", "production", 1, 1)),
		SnapshotJSON: snapJSON, Ciphertext: ct, CiphertextSHA256: hex.EncodeToString(sum[:]),
		SignatureMessage:  string(SignatureMessage("vlt_test", "production", 1, 0, 1, ct)),
		AuthorEd25519Seed: keys.Ed25519.Seed(), AuthorEd25519Pub: keys.Ed25519Public(),
		Signature: SignRevision(keys.Ed25519, "vlt_test", "production", 1, 0, 1, ct),
	}

	// 6. Local working copy.
	nonce = d.take(t, NonceSize)
	v.Local = localVector{
		VaultID: "vlt_test", Env: "production", DEK: dek, Nonce: nonce,
		AAD: string(localAAD("vlt_test", "production")), SnapshotJSON: snapJSON,
		Working: must(encryptSnapshot(bytes.NewReader(nonce), dek, vectorSnapshot(), localAAD("vlt_test", "production"))),
	}

	// 7. Service token.
	raw := d.take(t, machineSuffixBytes)
	mid, token, _ := must3(t)(newServiceToken(readers(raw, secret)))
	verifier := TokenVerifier(secret)
	v.ServiceToken = serviceTokenVector{
		MachineIDRandom: raw, MachineID: mid, TokenSecret: secret, Token: token,
		Verifier: verifier, VerifierHash: VerifierHash(verifier),
	}
	return v
}

func must3(t *testing.T) func(a, b string, c []byte, err error) (string, string, []byte) {
	return func(a, b string, c []byte, err error) (string, string, []byte) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return a, b, c
	}
}

func TestVectors(t *testing.T) {
	v := buildVectors(t)
	eq := func(name string, got, want []byte) {
		t.Helper()
		if !bytes.Equal(got, want) {
			t.Errorf("%s mismatch", name)
		}
	}

	t.Run("kdf", func(t *testing.T) {
		eq("kek", must(DeriveKEK(v.KDF.Passphrase, v.KDF.KDF)), v.KDF.KEK)
	})

	t.Run("bundle", func(t *testing.T) {
		bv := v.Bundle
		eq("kek", must(BundleKEK(bv.Bundle, bv.Passphrase)), bv.KEK)
		keys := must(OpenBundle(bv.UserID, bv.Bundle, bv.KEK))
		eq("x25519 priv", keys.X25519Private, bv.X25519PrivateKey)
		eq("ed25519 seed", keys.Ed25519.Seed(), bv.Ed25519Seed)
		eq("plaintext", must(open(bv.KEK, bv.Bundle.EncryptedPrivateKeys, []byte(bv.AAD))), bv.Plaintext)
		eq("nonce", bv.Bundle.EncryptedPrivateKeys[:NonceSize], bv.Nonce)
		if bv.AAD != string(accountAAD(bv.UserID)) || bv.Bundle.Fingerprint != Fingerprint(bv.Bundle.X25519PublicKey, bv.Bundle.Ed25519PublicKey) || !fpRe.MatchString(bv.Bundle.Fingerprint) {
			t.Error("aad/fingerprint mismatch")
		}
		re := must(sealBundle(bytes.NewReader(bv.Nonce), bv.UserID, bv.Bundle.KDF, bv.KEK, keys))
		eq("encrypted_private_keys", re.EncryptedPrivateKeys, bv.Bundle.EncryptedPrivateKeys)
	})

	t.Run("grant_x25519", func(t *testing.T) {
		g := v.X25519Grant
		if g.Info != GrantInfo(g.VaultID, g.Env, g.KeyVersion) {
			t.Error("info mismatch")
		}
		eq("dek", must(UnwrapX25519(g.WrappedKey, g.RecipientPrivateKey, g.Info)), g.DEK)
		eq("shared", must(curve25519.X25519(g.RecipientPrivateKey, g.EphemeralPublicKey)), g.SharedSecret)
		eq("wrap_key", must(x25519WrapKey(g.RecipientPrivateKey, g.EphemeralPublicKey, g.EphemeralPublicKey, g.RecipientPublicKey, g.Info)), g.WrapKey)
		eq("wrapped_key", must(wrapX25519(readers(g.EphemeralPrivateKey, g.Nonce), g.DEK, g.RecipientPublicKey, g.Info)), g.WrappedKey)
	})

	t.Run("grant_token", func(t *testing.T) {
		g := v.TokenGrant
		if g.HKDFInfo != tokenWrapPfx+g.Info || g.Info != GrantInfo(g.VaultID, g.Env, g.KeyVersion) {
			t.Error("info mismatch")
		}
		eq("dek", must(UnwrapToken(g.WrappedKey, g.TokenSecret, g.Info)), g.DEK)
		eq("wrap_key", must(tokenWrapKey(g.TokenSecret, g.Info)), g.WrapKey)
		eq("wrapped_key", must(wrapToken(bytes.NewReader(g.Nonce), g.DEK, g.TokenSecret, g.Info)), g.WrappedKey)
	})

	t.Run("revision", func(t *testing.T) {
		r := v.Revision
		if r.AAD != string(RevisionAAD(r.VaultID, r.Env, r.Revision, r.KeyVersion)) {
			t.Error("aad mismatch")
		}
		eq("snapshot_json", must(open(r.DEK, r.Ciphertext, []byte(r.AAD))), r.SnapshotJSON)
		s := must(DecryptRevision(r.DEK, r.VaultID, r.Env, r.Revision, r.KeyVersion, r.Ciphertext))
		if tomb, _ := s.Get("OLD_TOKEN"); len(s.Secrets) != 3 || !tomb.Deleted {
			t.Error("unexpected snapshot content")
		}
		eq("ciphertext", must(encryptSnapshot(bytes.NewReader(r.Nonce), r.DEK, s, []byte(r.AAD))), r.Ciphertext)
		sum := sha256.Sum256(r.Ciphertext)
		if r.CiphertextSHA256 != hex.EncodeToString(sum[:]) {
			t.Error("ciphertext hash mismatch")
		}
		if string(SignatureMessage(r.VaultID, r.Env, r.Revision, r.ParentRevision, r.KeyVersion, r.Ciphertext)) != r.SignatureMessage {
			t.Error("signature message mismatch")
		}
		priv := ed25519.NewKeyFromSeed(r.AuthorEd25519Seed)
		eq("pub", priv.Public().(ed25519.PublicKey), r.AuthorEd25519Pub)
		eq("signature", SignRevision(priv, r.VaultID, r.Env, r.Revision, r.ParentRevision, r.KeyVersion, r.Ciphertext), r.Signature)
		if !VerifyRevision(r.AuthorEd25519Pub, r.Signature, r.VaultID, r.Env, r.Revision, r.ParentRevision, r.KeyVersion, r.Ciphertext) {
			t.Error("signature does not verify")
		}
	})

	t.Run("local", func(t *testing.T) {
		l := v.Local
		if l.AAD != string(localAAD(l.VaultID, l.Env)) {
			t.Error("aad mismatch")
		}
		s := must(DecryptLocal(l.DEK, l.VaultID, l.Env, l.Working))
		eq("snapshot_json", must(MarshalSnapshot(s)), l.SnapshotJSON)
		eq("working", must(encryptSnapshot(bytes.NewReader(l.Nonce), l.DEK, s, []byte(l.AAD))), l.Working)
	})

	t.Run("service_token", func(t *testing.T) {
		st := v.ServiceToken
		mid, secret := must2(t)(ParseServiceToken(st.Token))
		if mid != st.MachineID {
			t.Error("machine id mismatch")
		}
		eq("secret", secret, st.TokenSecret)
		mid2, token, _ := must3(t)(newServiceToken(readers(st.MachineIDRandom, st.TokenSecret)))
		if mid2 != st.MachineID || token != st.Token {
			t.Error("token regeneration mismatch")
		}
		if TokenVerifier(st.TokenSecret) != st.Verifier || VerifierHash(st.Verifier) != st.VerifierHash {
			t.Error("verifier mismatch")
		}
	})
}

func must2(t *testing.T) func(a string, b []byte, err error) (string, []byte) {
	return func(a string, b []byte, err error) (string, []byte) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return a, b
	}
}
