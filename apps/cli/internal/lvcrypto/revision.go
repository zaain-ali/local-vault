package lvcrypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
)

const (
	revisionAADPfx = "lv-rev-v1|"
	revisionSigPfx = "lv-rev-sig-v1\n"
	localAADPfx    = "lv-local-v1|"
)

// RevisionAAD returns the AEAD associated data of a revision ciphertext.
func RevisionAAD(vaultID, env string, revision, keyVersion int) []byte {
	return []byte(revisionAADPfx + vaultID + "|" + env + "|" + itoa(revision) + "|" + itoa(keyVersion))
}

// EncryptRevision encrypts snap as the ciphertext of a revision.
func EncryptRevision(dek []byte, vaultID, env string, revision, keyVersion int, snap *Snapshot) ([]byte, error) {
	return encryptSnapshot(rand.Reader, dek, snap, RevisionAAD(vaultID, env, revision, keyVersion))
}

// DecryptRevision decrypts a revision ciphertext.
func DecryptRevision(dek []byte, vaultID, env string, revision, keyVersion int, ciphertext []byte) (*Snapshot, error) {
	return decryptSnapshot(dek, ciphertext, RevisionAAD(vaultID, env, revision, keyVersion))
}

// SignatureMessage returns the exact bytes signed for a revision.
func SignatureMessage(vaultID, env string, revision, parentRevision, keyVersion int, ciphertext []byte) []byte {
	sum := sha256.Sum256(ciphertext)
	return []byte(revisionSigPfx + vaultID + "\n" + env + "\n" + itoa(revision) + "\n" +
		itoa(parentRevision) + "\n" + itoa(keyVersion) + "\n" + hex.EncodeToString(sum[:]))
}

// SignRevision signs a revision with the author's Ed25519 key.
func SignRevision(priv ed25519.PrivateKey, vaultID, env string, revision, parentRevision, keyVersion int, ciphertext []byte) []byte {
	return ed25519.Sign(priv, SignatureMessage(vaultID, env, revision, parentRevision, keyVersion, ciphertext))
}

// VerifyRevision checks a revision signature and that revision = parent + 1.
func VerifyRevision(pub ed25519.PublicKey, sig []byte, vaultID, env string, revision, parentRevision, keyVersion int, ciphertext []byte) bool {
	if len(pub) != ed25519.PublicKeySize || revision != parentRevision+1 {
		return false
	}
	return ed25519.Verify(pub, SignatureMessage(vaultID, env, revision, parentRevision, keyVersion, ciphertext), sig)
}

func localAAD(vaultID, env string) []byte {
	return []byte(localAADPfx + vaultID + "|" + env)
}

// EncryptLocal encrypts the CLI working copy of an environment.
func EncryptLocal(dek []byte, vaultID, env string, snap *Snapshot) ([]byte, error) {
	return encryptSnapshot(rand.Reader, dek, snap, localAAD(vaultID, env))
}

// DecryptLocal decrypts the CLI working copy of an environment.
func DecryptLocal(dek []byte, vaultID, env string, working []byte) (*Snapshot, error) {
	return decryptSnapshot(dek, working, localAAD(vaultID, env))
}

func encryptSnapshot(r io.Reader, dek []byte, snap *Snapshot, aad []byte) ([]byte, error) {
	pt, err := MarshalSnapshot(snap)
	if err != nil {
		return nil, err
	}
	return seal(r, dek, pt, aad)
}

func decryptSnapshot(dek, data, aad []byte) (*Snapshot, error) {
	pt, err := open(dek, data, aad)
	if err != nil {
		return nil, err
	}
	return UnmarshalSnapshot(pt)
}
