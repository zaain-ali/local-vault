package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/zain-23/local-vault/apps/cli/internal/authstore"
	"github.com/zain-23/local-vault/apps/cli/internal/lvcrypto"
)

type KeyBundle = lvcrypto.Bundle

type PublicKey struct {
	UserID           string `json:"user_id"`
	Email            string `json:"email"`
	Name             string `json:"name"`
	X25519PublicKey  []byte `json:"x25519_public_key"`
	Ed25519PublicKey []byte `json:"ed25519_public_key"`
	Fingerprint      string `json:"fingerprint"`
}

type EnvAccess struct {
	Env        string `json:"env"`
	Permission string `json:"permission"`
}

type Environment struct {
	Name          string    `json:"name"`
	KeyVersion    int       `json:"key_version"`
	HeadRevision  int       `json:"head_revision"`
	Protected     bool      `json:"protected"`
	RekeyRequired bool      `json:"rekey_required"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type VaultMember struct {
	UserID      string      `json:"user_id"`
	Name        string      `json:"name"`
	Email       string      `json:"email"`
	Role        string      `json:"role"`
	EnvAccess   []EnvAccess `json:"env_access"`
	Fingerprint string      `json:"fingerprint"`
	HasKeys     bool        `json:"has_keys"`
}

type VaultSummary struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	Environments []Environment `json:"environments"`
	MemberCount  int           `json:"member_count"`
	MyRole       string        `json:"my_role"`
	MyEnvAccess  []EnvAccess   `json:"my_env_access"`
	CreatedAt    time.Time     `json:"created_at"`
	UpdatedAt    time.Time     `json:"updated_at"`
}

type VaultDetail struct {
	ID           string        `json:"id"`
	WorkspaceID  string        `json:"workspace_id"`
	Name         string        `json:"name"`
	CreatedBy    string        `json:"created_by"`
	Environments []Environment `json:"environments"`
	Members      []VaultMember `json:"members"`
	MyRole       string        `json:"my_role"`
	MyEnvAccess  []EnvAccess   `json:"my_env_access"`
	CreatedAt    time.Time     `json:"created_at"`
	UpdatedAt    time.Time     `json:"updated_at"`
}

type GrantIn struct {
	Env           string `json:"env"`
	KeyVersion    int    `json:"key_version"`
	RecipientType string `json:"recipient_type,omitempty"`
	RecipientID   string `json:"recipient_id,omitempty"`
	WrappedKey    []byte `json:"wrapped_key"`
}

type GrantOut struct {
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
	Email         string `json:"email"`
	KeyType       string `json:"key_type"`
	PublicKey     []byte `json:"public_key"`
	Fingerprint   string `json:"fingerprint"`
}

type Revision struct {
	VaultID                string    `json:"vault_id"`
	Env                    string    `json:"env"`
	Revision               int       `json:"revision"`
	ParentRevision         int       `json:"parent_revision"`
	KeyVersion             int       `json:"key_version"`
	Ciphertext             []byte    `json:"ciphertext"`
	Signature              []byte    `json:"signature"`
	AuthorUserID           string    `json:"author_user_id"`
	AuthorEd25519PublicKey []byte    `json:"author_ed25519_public_key"`
	AuthorFingerprint      string    `json:"author_fingerprint"`
	CreatedAt              time.Time `json:"created_at"`
}

func (c *Client) GetKeys() (*KeyBundle, error) {
	var out KeyBundle
	if err := c.do(http.MethodGet, "/api/v1/keys/me", nil, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) PutKeys(b *KeyBundle) error {
	return c.do(http.MethodPut, "/api/v1/keys/me", b, nil, true)
}

func (c *Client) WorkspaceKeys(workspaceID string, userIDs string) ([]PublicKey, error) {
	var out []PublicKey
	path := fmt.Sprintf("/api/v1/workspaces/%s/keys", workspaceID)
	if userIDs != "" {
		path += "?user_ids=" + userIDs
	}
	if err := c.do(http.MethodGet, path, nil, &out, true); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) CreateVaultV4(workspaceID string, body map[string]any) (*VaultDetail, error) {
	var out VaultDetail
	path := fmt.Sprintf("/api/v1/workspaces/%s/vaults", workspaceID)
	if err := c.do(http.MethodPost, path, body, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ListVaults(workspaceID string) ([]VaultSummary, error) {
	var out []VaultSummary
	path := fmt.Sprintf("/api/v1/workspaces/%s/vaults", workspaceID)
	if err := c.do(http.MethodGet, path, nil, &out, true); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) GetVaultV4(workspaceID, vaultID string) (*VaultDetail, error) {
	var out VaultDetail
	path := fmt.Sprintf("/api/v1/workspaces/%s/vaults/%s", workspaceID, vaultID)
	if err := c.do(http.MethodGet, path, nil, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) AddVaultMember(workspaceID, vaultID, email, role string, access []EnvAccess) (*VaultMember, error) {
	var out VaultMember
	path := fmt.Sprintf("/api/v1/workspaces/%s/vaults/%s/members", workspaceID, vaultID)
	if err := c.do(http.MethodPost, path, map[string]any{"email": email, "role": role, "env_access": access}, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) RemoveVaultMember(workspaceID, vaultID, userID string) error {
	path := fmt.Sprintf("/api/v1/workspaces/%s/vaults/%s/members/%s", workspaceID, vaultID, userID)
	return c.do(http.MethodDelete, path, nil, nil, true)
}

func (c *Client) MyGrants(workspaceID, vaultID string) ([]GrantOut, error) {
	var out []GrantOut
	path := fmt.Sprintf("/api/v1/workspaces/%s/vaults/%s/grants/mine", workspaceID, vaultID)
	if err := c.do(http.MethodGet, path, nil, &out, true); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) PendingGrants(workspaceID, vaultID string) ([]PendingGrant, error) {
	var out []PendingGrant
	path := fmt.Sprintf("/api/v1/workspaces/%s/vaults/%s/grants/pending", workspaceID, vaultID)
	if err := c.do(http.MethodGet, path, nil, &out, true); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) PostGrants(workspaceID, vaultID string, grants []GrantIn) error {
	path := fmt.Sprintf("/api/v1/workspaces/%s/vaults/%s/grants", workspaceID, vaultID)
	return c.do(http.MethodPost, path, map[string]any{"grants": grants}, nil, true)
}

func (c *Client) HeadRevision(workspaceID, vaultID, env, etag string) (*Revision, error) {
	var out Revision
	path := fmt.Sprintf("/api/v1/workspaces/%s/vaults/%s/environments/%s/head", workspaceID, vaultID, env)
	headers := map[string]string{}
	if etag != "" {
		headers["If-None-Match"] = etag
	}
	err := c.doWithHeaders(http.MethodGet, path, nil, &out, true, headers)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) PushRevision(workspaceID, vaultID, env string, body map[string]any) (*Revision, error) {
	var out Revision
	path := fmt.Sprintf("/api/v1/workspaces/%s/vaults/%s/environments/%s/revisions", workspaceID, vaultID, env)
	if err := c.do(http.MethodPost, path, body, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) CreateChangeRequest(workspaceID, vaultID, env string, body map[string]any) error {
	path := fmt.Sprintf("/api/v1/workspaces/%s/vaults/%s/environments/%s/change-requests", workspaceID, vaultID, env)
	return c.do(http.MethodPost, path, body, nil, true)
}

func (c *Client) Rekey(workspaceID, vaultID, env string, body map[string]any) error {
	path := fmt.Sprintf("/api/v1/workspaces/%s/vaults/%s/environments/%s/rekey", workspaceID, vaultID, env)
	return c.do(http.MethodPost, path, body, nil, true)
}

type MachineLoginResult struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
	WorkspaceID string    `json:"workspace_id"`
	VaultID     string    `json:"vault_id"`
	Env         string    `json:"env"`
}

type MachineSecrets struct {
	WorkspaceID string    `json:"workspace_id"`
	VaultID     string    `json:"vault_id"`
	Env         string    `json:"env"`
	KeyVersion  int       `json:"key_version"`
	KeyType     string    `json:"key_type"`
	WrappedKey  []byte    `json:"wrapped_key"`
	KeyRef      string    `json:"key_ref,omitempty"`
	Revision    *Revision `json:"revision"`
}

type MachineIdentity struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Env       string    `json:"env"`
	Kind      string    `json:"kind"`
	KeyType   string    `json:"key_type"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
}

func (c *Client) UseAccessToken(tok string) {
	c.UseTokens(&authstore.Tokens{AccessToken: tok})
}

func (c *Client) MachineLogin(machineID, method, verifier string) (*MachineLoginResult, error) {
	var out MachineLoginResult
	if err := c.do(http.MethodPost, "/api/v1/machine/login", map[string]any{
		"machine_id": machineID, "method": method, "token_verifier": verifier,
	}, &out, false); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) MachineOIDCLogin(machineID, jwt string) (*MachineLoginResult, error) {
	var out MachineLoginResult
	if err := c.do(http.MethodPost, "/api/v1/machine/login", map[string]any{
		"machine_id": machineID, "method": "oidc", "jwt": jwt,
	}, &out, false); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) MachineSecrets() (*MachineSecrets, error) {
	var out MachineSecrets
	if err := c.do(http.MethodGet, "/api/v1/machine/secrets", nil, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) CreateMachine(workspaceID, vaultID string, body map[string]any) (*MachineIdentity, error) {
	var out MachineIdentity
	path := fmt.Sprintf("/api/v1/workspaces/%s/vaults/%s/machines", workspaceID, vaultID)
	if err := c.do(http.MethodPost, path, body, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ListMachines(workspaceID, vaultID string) ([]MachineIdentity, error) {
	var out []MachineIdentity
	path := fmt.Sprintf("/api/v1/workspaces/%s/vaults/%s/machines", workspaceID, vaultID)
	if err := c.do(http.MethodGet, path, nil, &out, true); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) RevokeMachine(workspaceID, vaultID, machineID string) error {
	path := fmt.Sprintf("/api/v1/workspaces/%s/vaults/%s/machines/%s", workspaceID, vaultID, machineID)
	return c.do(http.MethodDelete, path, nil, nil, true)
}
