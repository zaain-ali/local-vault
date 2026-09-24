package vault

import "time"

// Vault = one project's secrets container ("vaults" collection).
type Vault struct {
	ID           string        `bson:"_id" json:"id"` // prefix "vlt_"
	WorkspaceID  string        `bson:"workspace_id" json:"workspace_id"`
	Name         string        `bson:"name" json:"name"`
	CreatedBy    string        `bson:"created_by" json:"created_by"`
	Environments []Environment `bson:"environments" json:"environments"`
	CreatedAt    time.Time     `bson:"created_at" json:"created_at"`
	UpdatedAt    time.Time     `bson:"updated_at" json:"updated_at"`
}

// Environment has its own DEK (key_version) and revision chain.
type Environment struct {
	Name          string    `bson:"name" json:"name"`
	KeyVersion    int       `bson:"key_version" json:"key_version"`
	HeadRevision  int       `bson:"head_revision" json:"head_revision"`
	Protected     bool      `bson:"protected" json:"protected"`
	RekeyRequired bool      `bson:"rekey_required" json:"rekey_required"`
	UpdatedAt     time.Time `bson:"updated_at" json:"updated_at"`
}

// Env returns a pointer to the named environment, or nil.
func (v *Vault) Env(name string) *Environment {
	return v.env(name)
}

// env returns a pointer to the named environment, or nil.
func (v *Vault) env(name string) *Environment {
	for i := range v.Environments {
		if v.Environments[i].Name == name {
			return &v.Environments[i]
		}
	}
	return nil
}

// EnvAccess is one environment a member may read (or read+write).
type EnvAccess struct {
	Env        string `bson:"env" json:"env"`
	Permission string `bson:"permission" json:"permission"` // read | write
}

// Member = a user's access to one vault ("vault_members").
type Member struct {
	ID          string      `bson:"_id" json:"id"` // prefix "vm_"
	VaultID     string      `bson:"vault_id" json:"vault_id"`
	WorkspaceID string      `bson:"workspace_id" json:"workspace_id"`
	UserID      string      `bson:"user_id" json:"user_id"`
	Role        string      `bson:"role" json:"role"` // admin | member
	EnvAccess   []EnvAccess `bson:"env_access" json:"env_access"`
	AddedBy     string      `bson:"added_by" json:"added_by"`
	CreatedAt   time.Time   `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time   `bson:"updated_at" json:"updated_at"`
}

// permission returns "", "read" or "write" for env.
func (m *Member) permission(env string) string {
	if m == nil {
		return ""
	}
	for _, a := range m.EnvAccess {
		if a.Env == env {
			return a.Permission
		}
	}
	return ""
}

// Grant delivers one (vault, env, key_version) DEK to one recipient ("vault_key_grants").
type Grant struct {
	ID            string    `bson:"_id" json:"-"` // prefix "gr_"
	VaultID       string    `bson:"vault_id" json:"vault_id"`
	Env           string    `bson:"env" json:"env"`
	KeyVersion    int       `bson:"key_version" json:"key_version"`
	RecipientType string    `bson:"recipient_type" json:"recipient_type"` // user | machine
	RecipientID   string    `bson:"recipient_id" json:"recipient_id"`
	WrappedKey    []byte    `bson:"wrapped_key" json:"wrapped_key"`
	GrantedBy     string    `bson:"granted_by" json:"granted_by"`
	CreatedAt     time.Time `bson:"created_at" json:"created_at"`
}

// RevisionDoc is one committed, signed ciphertext ("vault_revisions").
// The author's public key is captured at commit time so history stays
// verifiable after the author resets their account keys.
type RevisionDoc struct {
	ID                     string    `bson:"_id"` // prefix "rev_"
	VaultID                string    `bson:"vault_id"`
	Env                    string    `bson:"env"`
	Revision               int       `bson:"revision"`
	ParentRevision         int       `bson:"parent_revision"`
	KeyVersion             int       `bson:"key_version"`
	Ciphertext             []byte    `bson:"ciphertext"`
	Signature              []byte    `bson:"signature"`
	AuthorUserID           string    `bson:"author_user_id"`
	AuthorEd25519PublicKey []byte    `bson:"author_ed25519_public_key"`
	AuthorFingerprint      string    `bson:"author_fingerprint"`
	IdempotencyKey         string    `bson:"idempotency_key,omitempty"`
	ChangeRequestID        string    `bson:"change_request_id,omitempty"`
	CreatedAt              time.Time `bson:"created_at"`
}

// ChangeRequest is a proposed revision for a protected environment ("vault_change_requests").
type ChangeRequest struct {
	ID                     string    `bson:"_id" json:"id"` // prefix "cr_"
	VaultID                string    `bson:"vault_id" json:"vault_id"`
	Env                    string    `bson:"env" json:"env"`
	BaseRevision           int       `bson:"base_revision" json:"base_revision"`
	KeyVersion             int       `bson:"key_version" json:"key_version"`
	Ciphertext             []byte    `bson:"ciphertext" json:"ciphertext"`
	Signature              []byte    `bson:"signature" json:"signature"`
	AuthorUserID           string    `bson:"author_user_id" json:"author_user_id"`
	AuthorEd25519PublicKey []byte    `bson:"author_ed25519_public_key" json:"author_ed25519_public_key"`
	AuthorFingerprint      string    `bson:"author_fingerprint" json:"author_fingerprint"`
	Note                   string    `bson:"note" json:"note"`
	Status                 string    `bson:"status" json:"status"` // pending | approved | rejected | stale
	ReviewedBy             string    `bson:"reviewed_by,omitempty" json:"reviewed_by,omitempty"`
	CreatedAt              time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt              time.Time `bson:"updated_at" json:"updated_at"`
}

// Machine is the subset of a "machine_identities" document the vault domain
// needs for entitlement, pending grants and rekey. The collection and its
// routes are owned by the machine domain.
type Machine struct {
	ID            string     `bson:"_id"` // prefix "mi_"
	WorkspaceID   string     `bson:"workspace_id"`
	VaultID       string     `bson:"vault_id"`
	Env           string     `bson:"env"`
	Name          string     `bson:"name"`
	Kind          string     `bson:"kind"`     // token | oidc | aws
	KeyType       string     `bson:"key_type"` // token | x25519 | rsa-oaep-256
	PublicKey     []byte     `bson:"public_key,omitempty"`
	KeyRef        string     `bson:"key_ref,omitempty"`
	ExpiresAt     *time.Time `bson:"expires_at,omitempty"`
	Revoked       bool       `bson:"revoked"`
	RevokedReason string     `bson:"revoked_reason,omitempty"`
}

// active reports whether a machine may still receive keys.
func (m *Machine) active(now time.Time) bool {
	return !m.Revoked && (m.ExpiresAt == nil || now.Before(*m.ExpiresAt))
}

// Vault roles.
const (
	VaultRoleAdmin  = "admin"
	VaultRoleMember = "member"
)

// Env permissions.
const (
	PermRead  = "read"
	PermWrite = "write"
)

// Grant recipient types.
const (
	RecipientUser    = "user"
	RecipientMachine = "machine"
)

// Machine key types.
const (
	KeyTypeToken  = "token"
	KeyTypeX25519 = "x25519"
	KeyTypeRSA    = "rsa-oaep-256"
)

// Change request statuses.
const (
	CRPending  = "pending"
	CRApproved = "approved"
	CRRejected = "rejected"
	CRStale    = "stale"
)

// Workspace roles (mirrors member.Role* — duplicated to avoid importing member).
const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
)

// DefaultEnvironments are created when a vault is created without a list.
var DefaultEnvironments = []string{"development", "staging", "production"}
