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
	KeyRef             string     `bson:"key_ref,omitempty" json:"key_ref,omitempty"`
	TokenVerifierHash  string     `bson:"token_verifier_hash,omitempty" json:"-"`
	OIDC               *OIDCSpec  `bson:"oidc,omitempty" json:"oidc,omitempty"`
	AWS                *AWSSpec   `bson:"aws,omitempty" json:"aws,omitempty"`
	CreatedBy          string     `bson:"created_by" json:"created_by"`
	CreatedAt          time.Time  `bson:"created_at" json:"created_at"`
	ExpiresAt          *time.Time `bson:"expires_at,omitempty" json:"expires_at,omitempty"`
	Revoked            bool       `bson:"revoked" json:"revoked"`
	RevokedReason      string     `bson:"revoked_reason,omitempty" json:"revoked_reason,omitempty"`
	LastUsedAt         *time.Time `bson:"last_used_at,omitempty" json:"last_used_at,omitempty"`
}

type OIDCSpec struct {
	Issuer   string            `bson:"issuer" json:"issuer"`
	Audience string            `bson:"audience" json:"audience"`
	Subject  string            `bson:"subject" json:"subject"`
	Claims   map[string]string `bson:"claims,omitempty" json:"claims,omitempty"`
}

type AWSSpec struct {
	RoleARN string `bson:"role_arn" json:"role_arn"`
}

const (
	KindToken = "token"
	KindOIDC  = "oidc"
	KindAWS   = "aws"

	KeyTypeToken  = "token"
	KeyTypeX25519 = "x25519"
	KeyTypeRSA    = "rsa-oaep-256"

	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
)
