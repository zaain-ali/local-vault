package lvcrypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// Default Argon2id parameters from the spec.
const (
	KDFAlg          = "argon2id"
	KDFTime         = 3
	KDFMemoryKiB    = 64 * 1024
	KDFThreads      = 4
	KDFSaltSize     = 16
	kdfMinMemoryKiB = 8 * 1024
	kdfMaxMemoryKiB = 1024 * 1024
	kdfMaxTime      = 10
	kdfMaxThreads   = 16
)

// KDFParams describes how the account KEK is derived from the passphrase.
type KDFParams struct {
	Alg       string `json:"alg"`
	Salt      []byte `json:"salt"`
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
}

// DefaultKDF returns the spec defaults with a fresh random salt.
func DefaultKDF() (KDFParams, error) {
	return defaultKDF(rand.Reader)
}

func defaultKDF(r io.Reader) (KDFParams, error) {
	salt, err := randBytes(r, KDFSaltSize)
	if err != nil {
		return KDFParams{}, err
	}
	return KDFParams{Alg: KDFAlg, Salt: salt, Time: KDFTime, MemoryKiB: KDFMemoryKiB, Threads: KDFThreads}, nil
}

// Validate rejects unknown algorithms and out-of-range parameters
// (a hostile server could otherwise make clients burn CPU/RAM).
func (p KDFParams) Validate() error {
	switch {
	case p.Alg != KDFAlg:
		return fmt.Errorf("lvcrypto: unsupported kdf %q", p.Alg)
	case len(p.Salt) < KDFSaltSize:
		return errors.New("lvcrypto: kdf salt too short")
	case p.MemoryKiB < kdfMinMemoryKiB || p.MemoryKiB > kdfMaxMemoryKiB:
		return errors.New("lvcrypto: kdf memory out of range")
	case p.Time < 1 || p.Time > kdfMaxTime:
		return errors.New("lvcrypto: kdf time out of range")
	case p.Threads < 1 || p.Threads > kdfMaxThreads:
		return errors.New("lvcrypto: kdf threads out of range")
	}
	return nil
}

// DeriveKEK derives the 32-byte key-encryption key from the passphrase.
func DeriveKEK(passphrase string, p KDFParams) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return argon2.IDKey([]byte(passphrase), p.Salt, p.Time, p.MemoryKiB, p.Threads, KeySize), nil
}
