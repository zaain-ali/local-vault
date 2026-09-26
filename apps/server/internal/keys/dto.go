package keys

// PutKeysRequest is the AccountKeyBundle a client uploads (PUT /keys/me).
type PutKeysRequest struct {
	Version              int    `json:"version"`
	KDF                  KDF    `json:"kdf"`
	X25519PublicKey      []byte `json:"x25519_public_key"`
	Ed25519PublicKey     []byte `json:"ed25519_public_key"`
	EncryptedPrivateKeys []byte `json:"encrypted_private_keys"`
	Fingerprint          string `json:"fingerprint"`
}

// PublicKeyResponse is one row of GET /workspaces/:wid/keys.
type PublicKeyResponse struct {
	UserID           string `json:"user_id"`
	Email            string `json:"email"`
	Name             string `json:"name"`
	X25519PublicKey  []byte `json:"x25519_public_key"`
	Ed25519PublicKey []byte `json:"ed25519_public_key"`
	Fingerprint      string `json:"fingerprint"`
}
