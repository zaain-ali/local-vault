package keys

import "time"

// KDF describes how the passphrase was stretched into the bundle's wrap key.
type KDF struct {
	Alg       string `bson:"alg" json:"alg"` // "argon2id"
	Salt      []byte `bson:"salt" json:"salt"`
	Time      int    `bson:"time" json:"time"`
	MemoryKiB int    `bson:"memory_kib" json:"memory_kib"`
	Threads   int    `bson:"threads" json:"threads"`
}

// Bundle is one user's account key bundle ("user_keys" collection, _id = user id).
// The private keys are only ever stored encrypted under the passphrase.
type Bundle struct {
	UserID               string    `bson:"_id" json:"user_id"`
	Version              int       `bson:"version" json:"version"`
	KDF                  KDF       `bson:"kdf" json:"kdf"`
	X25519PublicKey      []byte    `bson:"x25519_public_key" json:"x25519_public_key"`
	Ed25519PublicKey     []byte    `bson:"ed25519_public_key" json:"ed25519_public_key"`
	EncryptedPrivateKeys []byte    `bson:"encrypted_private_keys" json:"encrypted_private_keys"`
	Fingerprint          string    `bson:"fingerprint" json:"fingerprint"`
	CreatedAt            time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt            time.Time `bson:"updated_at" json:"updated_at"`
}

// Bundle limits enforced on upload.
const (
	BundleVersion    = 1
	KDFAlg           = "argon2id"
	KeyLen           = 32
	minMemoryKiB     = 8 * 1024        // 8 MiB
	maxMemoryKiB     = 1024 * 1024     // 1 GiB
	minTime, maxTime = 1, 10
	minThreads       = 1
	maxThreads       = 16
	minSaltLen       = 16
	maxSaltLen       = 64
	minEncryptedLen  = 12 + 16 + 2 // nonce + tag + "{}"
	maxEncryptedLen  = 4096
)
