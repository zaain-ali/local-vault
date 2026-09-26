package vault

import "time"

// GrantInput is a wrapped DEK the client already sealed for a recipient.
type GrantInput struct {
	Env           string `json:"env"`
	KeyVersion    int    `json:"key_version"`
	RecipientType string `json:"recipient_type,omitempty"`
	RecipientID   string `json:"recipient_id,omitempty"`
	WrappedKey    []byte `json:"wrapped_key"`
}

type CreateVaultRequest struct {
	ID           string      `json:"id"` // optional client-chosen vlt_ id (needed so grants bind GrantInfo)
	Name         string      `json:"name" validate:"required,max=100"`
	Environments []string    `json:"environments"`
	Grants       []GrantInput `json:"grants" validate:"required"`
}

type EnvAccessInput struct {
	Env        string `json:"env" validate:"required"`
	Permission string `json:"permission" validate:"required"`
}

type AddMemberRequest struct {
	Email     string           `json:"email" validate:"required,email"`
	Role      string           `json:"role"`
	EnvAccess []EnvAccessInput `json:"env_access" validate:"required"`
}

type UpdateMemberRequest struct {
	Role      *string          `json:"role"`
	EnvAccess []EnvAccessInput `json:"env_access"`
}

type AddEnvironmentRequest struct {
	Name      string     `json:"name" validate:"required"`
	Protected bool       `json:"protected"`
	Grant     GrantInput `json:"grant"`
}

type PatchEnvironmentRequest struct {
	Protected *bool `json:"protected"`
}

type CreateGrantsRequest struct {
	Grants []GrantInput `json:"grants" validate:"required"`
}

type PushRevisionRequest struct {
	BaseRevision int    `json:"base_revision"`
	KeyVersion   int    `json:"key_version"`
	Ciphertext   []byte `json:"ciphertext" validate:"required"`
	Signature    []byte `json:"signature" validate:"required"`
}

type CreateChangeRequestBody struct {
	BaseRevision int    `json:"base_revision"`
	KeyVersion   int    `json:"key_version"`
	Ciphertext   []byte `json:"ciphertext" validate:"required"`
	Signature    []byte `json:"signature" validate:"required"`
	Note         string `json:"note"`
}

type RekeyRequest struct {
	NewKeyVersion int                 `json:"new_key_version" validate:"required"`
	Revision      *PushRevisionRequest `json:"revision"`
	Grants        []GrantInput        `json:"grants" validate:"required"`
}

type EnvAccessResponse struct {
	Env        string `json:"env"`
	Permission string `json:"permission"`
}

type EnvironmentResponse struct {
	Name          string    `json:"name"`
	KeyVersion    int       `json:"key_version"`
	HeadRevision  int       `json:"head_revision"`
	Protected     bool      `json:"protected"`
	RekeyRequired bool      `json:"rekey_required"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type MemberResponse struct {
	UserID      string              `json:"user_id"`
	Name        string              `json:"name"`
	Email       string              `json:"email"`
	Role        string              `json:"role"`
	EnvAccess   []EnvAccessResponse `json:"env_access"`
	Fingerprint string              `json:"fingerprint,omitempty"`
	HasKeys     bool                `json:"has_keys"`
}

type VaultSummary struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Environments []EnvironmentResponse `json:"environments"`
	MemberCount int                    `json:"member_count"`
	MyRole      string                 `json:"my_role,omitempty"`
	MyEnvAccess []EnvAccessResponse    `json:"my_env_access,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

type VaultDetail struct {
	ID           string                 `json:"id"`
	WorkspaceID  string                 `json:"workspace_id"`
	Name         string                 `json:"name"`
	CreatedBy    string                 `json:"created_by"`
	Environments []EnvironmentResponse  `json:"environments"`
	Members      []MemberResponse       `json:"members"`
	MyRole       string                 `json:"my_role,omitempty"`
	MyEnvAccess  []EnvAccessResponse    `json:"my_env_access,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
}

type GrantResponse struct {
	Env        string `json:"env"`
	KeyVersion int    `json:"key_version"`
	WrappedKey []byte `json:"wrapped_key"`
}

type PendingGrant struct {
	Env           string `json:"env"`
	KeyVersion    int    `json:"key_version"`
	RecipientType string `json:"recipient_type"`
	RecipientID   string `json:"recipient_id"`
	Label         string `json:"label"`
	Email         string `json:"email,omitempty"`
	KeyType       string `json:"key_type"`
	PublicKey     []byte `json:"public_key"`
	Fingerprint   string `json:"fingerprint"`
}

type RevisionResponse struct {
	VaultID                string    `json:"vault_id"`
	Env                    string    `json:"env"`
	Revision               int       `json:"revision"`
	ParentRevision         int       `json:"parent_revision"`
	KeyVersion             int       `json:"key_version"`
	Ciphertext             []byte    `json:"ciphertext,omitempty"`
	Signature              []byte    `json:"signature,omitempty"`
	AuthorUserID           string    `json:"author_user_id,omitempty"`
	AuthorEd25519PublicKey []byte    `json:"author_ed25519_public_key,omitempty"`
	AuthorFingerprint      string    `json:"author_fingerprint,omitempty"`
	CreatedAt              time.Time `json:"created_at,omitempty"`
}

type RevisionMeta struct {
	Revision       int       `json:"revision"`
	ParentRevision int       `json:"parent_revision"`
	KeyVersion     int       `json:"key_version"`
	AuthorUserID   string    `json:"author_user_id"`
	AuthorEmail    string    `json:"author_email,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

func envResponses(envs []Environment) []EnvironmentResponse {
	out := make([]EnvironmentResponse, 0, len(envs))
	for _, e := range envs {
		out = append(out, EnvironmentResponse{
			Name: e.Name, KeyVersion: e.KeyVersion, HeadRevision: e.HeadRevision,
			Protected: e.Protected, RekeyRequired: e.RekeyRequired, UpdatedAt: e.UpdatedAt,
		})
	}
	return out
}

func accessResponses(a []EnvAccess) []EnvAccessResponse {
	out := make([]EnvAccessResponse, 0, len(a))
	for _, x := range a {
		out = append(out, EnvAccessResponse{Env: x.Env, Permission: x.Permission})
	}
	return out
}

func EmptyHead(vaultID, env string, keyVersion int) *RevisionResponse {
	return &RevisionResponse{VaultID: vaultID, Env: env, Revision: 0, KeyVersion: keyVersion}
}

func RevisionAsResponse(r *RevisionDoc) *RevisionResponse {
	return revisionResponse(r, true)
}

func revisionResponse(r *RevisionDoc, includeBlob bool) *RevisionResponse {
	if r == nil {
		return &RevisionResponse{}
	}
	out := &RevisionResponse{
		VaultID: r.VaultID, Env: r.Env, Revision: r.Revision, ParentRevision: r.ParentRevision,
		KeyVersion: r.KeyVersion, AuthorUserID: r.AuthorUserID,
		AuthorEd25519PublicKey: r.AuthorEd25519PublicKey, AuthorFingerprint: r.AuthorFingerprint,
		CreatedAt: r.CreatedAt,
	}
	if includeBlob {
		out.Ciphertext = r.Ciphertext
		out.Signature = r.Signature
	}
	return out
}
