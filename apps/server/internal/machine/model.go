package machine

import "time"

type Identity struct {
	ID                 string     `bson:"_id" json:"id"`
	WorkspaceID        string     `bson:"workspace_id" json:"workspace_id"`
	VaultID            string     `bson:"vault_id" json:"vault_id"`
	Env                string     `bson:"env" json:"env"`
	Name               string     `bson:"name" json:"name"`
	Kind               string     `bson:"kind" json:"kind"`
	KeyType            string     `bson:"key_type" json:"key_type"`
	PublicKey          []byte     `bson:"public_key,omitempty" json:"public_key,omitempty"`
	TokenVerifierHash  string     `bson:"token_verifier_hash,omitempty" json:"-"`
	OIDC               *OIDCSpec  `bson:"oidc,omitempty" json:"oidc,omitempty"`
	CreatedBy          string     `bson:"created_by" json:"created_by"`
	CreatedAt          time.Time  `bson:"created_at" json:"created_at"`
	ExpiresAt          *time.Time `bson:"expires_at,omitempty" json:"expires_at,omitempty"`
	Revoked            bool       `bson:"revoked" json:"revoked"`
	RevokedReason      string     `bson:"revoked_reason,omitempty" json:"revoked_reason,omitempty"`
	LastUsedAt         *time.Time `bson:"last_used_at,omitempty" json:"last_used_at,omitempty"`
}

// usable reports whether m may still act for (vaultID, env) at now: it exists,
// is not revoked or expired, and is bound to that vault and environment.
func (m *Identity) usable(now time.Time, vaultID, env string) bool {
	if m == nil || m.Revoked || m.VaultID != vaultID || m.Env != env {
		return false
	}
	return m.ExpiresAt == nil || now.Before(*m.ExpiresAt)
}

type OIDCSpec struct {
	Issuer   string            `bson:"issuer" json:"issuer"`
	Audience string            `bson:"audience" json:"audience"`
	Subject  string            `bson:"subject" json:"subject"`
	Claims   map[string]string `bson:"claims,omitempty" json:"claims,omitempty"`
}

const (
	KindToken = "token"
	KindOIDC  = "oidc"

	KeyTypeToken  = "token"
	KeyTypeX25519 = "x25519"

	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
)
