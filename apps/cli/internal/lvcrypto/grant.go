package lvcrypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
)

// Wrapped key scheme tags.
const (
	SchemeX25519 byte = 0x01
	SchemeRSA    byte = 0x02
	SchemeToken  byte = 0x03
)

const (
	grantInfoPfx = "lv-grant-v1|"
	tokenWrapPfx = "lv-st-wrap-v1|"
	minRSABits   = 2048
)

var errBadWrapped = errors.New("lvcrypto: malformed wrapped key")

// GrantInfo returns the HKDF info / AAD binding a grant to (vault, env, key_version).
func GrantInfo(vaultID, env string, keyVersion int) string {
	return grantInfoPfx + vaultID + "|" + env + "|" + itoa(keyVersion)
}

// SchemeOf returns the scheme tag of a wrapped key, or 0 if empty.
func SchemeOf(wrapped []byte) byte {
	if len(wrapped) == 0 {
		return 0
	}
	return wrapped[0]
}

func checkDEK(dek []byte) error {
	if len(dek) != KeySize {
		return errors.New("lvcrypto: DEK must be 32 bytes")
	}
	return nil
}

// WrapX25519 seals dek to an X25519 public key (scheme 0x01).
func WrapX25519(dek, recipientPub []byte, info string) ([]byte, error) {
	return wrapX25519(rand.Reader, dek, recipientPub, info)
}

// wrapX25519 reads the ephemeral private key, then the nonce, from r.
func wrapX25519(r io.Reader, dek, recipientPub []byte, info string) ([]byte, error) {
	if err := checkDEK(dek); err != nil {
		return nil, err
	}
	if len(recipientPub) != KeySize {
		return nil, errors.New("lvcrypto: x25519 public key must be 32 bytes")
	}
	ephRaw, err := randBytes(r, KeySize)
	if err != nil {
		return nil, err
	}
	ephPriv := clamp(ephRaw)
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	key, err := x25519WrapKey(ephPriv, recipientPub, ephPub, recipientPub, info)
	if err != nil {
		return nil, err
	}
	ct, err := seal(r, key, dek, []byte(info))
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+KeySize+len(ct))
	out = append(out, SchemeX25519)
	out = append(out, ephPub...)
	return append(out, ct...), nil
}

// x25519WrapKey derives the scheme 0x01 AEAD key from X25519(priv, peer).
// curve25519.X25519 rejects low-order peers (all-zero shared secret).
func x25519WrapKey(priv, peer, ephPub, recipientPub []byte, info string) ([]byte, error) {
	shared, err := curve25519.X25519(priv, peer)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 0, 2*KeySize)
	salt = append(salt, ephPub...)
	salt = append(salt, recipientPub...)
	return hkdf32(shared, salt, info)
}

// UnwrapX25519 opens a scheme 0x01 wrapped key with the recipient's private key.
func UnwrapX25519(wrapped, recipientPriv []byte, info string) ([]byte, error) {
	if len(wrapped) < 1+KeySize+NonceSize+TagSize || wrapped[0] != SchemeX25519 {
		return nil, errBadWrapped
	}
	if len(recipientPriv) != KeySize {
		return nil, errors.New("lvcrypto: x25519 private key must be 32 bytes")
	}
	ephPub := wrapped[1 : 1+KeySize]
	recipientPub, err := X25519Public(recipientPriv)
	if err != nil {
		return nil, err
	}
	key, err := x25519WrapKey(recipientPriv, ephPub, ephPub, recipientPub, info)
	if err != nil {
		return nil, ErrDecrypt
	}
	dek, err := open(key, wrapped[1+KeySize:], []byte(info))
	if err != nil {
		return nil, err
	}
	return dek, checkDEK(dek)
}

// ParseRSASPKI parses an RSA public key from SPKI DER.
func ParseRSASPKI(der []byte) (*rsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("lvcrypto: not an RSA public key")
	}
	if pub.N.BitLen() < minRSABits {
		return nil, errors.New("lvcrypto: RSA key too small")
	}
	return pub, nil
}

// WrapRSA wraps dek with RSA-OAEP-SHA256, empty label (scheme 0x02).
func WrapRSA(dek []byte, pub *rsa.PublicKey) ([]byte, error) {
	if err := checkDEK(dek); err != nil {
		return nil, err
	}
	if pub.N.BitLen() < minRSABits {
		return nil, errors.New("lvcrypto: RSA key too small")
	}
	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, dek, nil)
	if err != nil {
		return nil, err
	}
	return append([]byte{SchemeRSA}, ct...), nil
}

// UnwrapRSAWith unwraps a scheme 0x02 key using decrypt (e.g. a KMS call
// performing RSA-OAEP-SHA256 on the raw ciphertext).
func UnwrapRSAWith(wrapped []byte, decrypt func(ciphertext []byte) ([]byte, error)) ([]byte, error) {
	if len(wrapped) < 2 || wrapped[0] != SchemeRSA {
		return nil, errBadWrapped
	}
	dek, err := decrypt(wrapped[1:])
	if err != nil {
		return nil, err
	}
	return dek, checkDEK(dek)
}

// UnwrapRSALocal unwraps a scheme 0x02 key with a local RSA private key.
func UnwrapRSALocal(wrapped []byte, priv *rsa.PrivateKey) ([]byte, error) {
	return UnwrapRSAWith(wrapped, func(ct []byte) ([]byte, error) {
		pt, err := rsa.DecryptOAEP(sha256.New(), nil, priv, ct, nil)
		if err != nil {
			return nil, ErrDecrypt
		}
		return pt, nil
	})
}

func tokenWrapKey(secret []byte, info string) ([]byte, error) {
	if len(secret) != KeySize {
		return nil, errors.New("lvcrypto: token secret must be 32 bytes")
	}
	return hkdf32(secret, nil, tokenWrapPfx+info)
}

// WrapToken wraps dek to a service-token secret (scheme 0x03).
func WrapToken(dek, secret []byte, info string) ([]byte, error) {
	return wrapToken(rand.Reader, dek, secret, info)
}

func wrapToken(r io.Reader, dek, secret []byte, info string) ([]byte, error) {
	if err := checkDEK(dek); err != nil {
		return nil, err
	}
	key, err := tokenWrapKey(secret, info)
	if err != nil {
		return nil, err
	}
	ct, err := seal(r, key, dek, []byte(info))
	if err != nil {
		return nil, err
	}
	return append([]byte{SchemeToken}, ct...), nil
}

// UnwrapToken opens a scheme 0x03 wrapped key.
func UnwrapToken(wrapped, secret []byte, info string) ([]byte, error) {
	if len(wrapped) < 1+NonceSize+TagSize || wrapped[0] != SchemeToken {
		return nil, errBadWrapped
	}
	key, err := tokenWrapKey(secret, info)
	if err != nil {
		return nil, err
	}
	dek, err := open(key, wrapped[1:], []byte(info))
	if err != nil {
		return nil, err
	}
	return dek, checkDEK(dek)
}
