package api

import (
	"fmt"
	"net/http"
	"time"
)

type CreateVaultRequest struct {
	Name            string `json:"name"`
	OwnerDeviceID   string `json:"owner_id"`
	OwnerName       string `json:"owner_name"`
	PublicKey       []byte `json:"public_key"`
	X25519PublicKey []byte `json:"x25519_public_key"`
}

type CreateVaultResponse struct {
	VaultID   string    `json:"vault_id"`
	CreatedAt time.Time `json:"created_at"`
}

type Peer struct {
	DeviceID        string    `json:"device_id"`
	DeviceName      string    `json:"device_name"`
	PublicKey       []byte    `json:"public_key"`
	X25519PublicKey []byte    `json:"x25519_public_key"`
	UserID          string    `json:"user_id,omitempty"`
	Name            string    `json:"name,omitempty"`
	Email           string    `json:"email,omitempty"`
	JoinedAt        time.Time `json:"joined_at"`
}

type VaultResponse struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	WorkspaceID   string    `json:"workspace_id"`
	OwnerDeviceID string    `json:"owner_device_id"`
	Peers         []Peer    `json:"peers"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type SnapshotResponse struct {
	Snapshot  []byte    `json:"snapshot"`
	UpdatedAt time.Time `json:"updated_at"`
}

type CreateTokenRequest struct {
	DeviceID   string     `json:"device_id"`
	Name       string     `json:"name"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	WrappedDEK []byte     `json:"wrapped_dek"`
	Verifier   string     `json:"verifier"`
}

type TokenResponse struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at"`
}

type listTokensData struct {
	Tokens []TokenResponse `json:"tokens"`
}

func (c *Client) CreateVault(workspaceID string, req CreateVaultRequest) (*CreateVaultResponse, error) {
	var out CreateVaultResponse
	path := fmt.Sprintf("/api/v1/workspaces/%s/vaults", workspaceID)
	if err := c.do(http.MethodPost, path, req, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) GetVault(workspaceID, vaultID string) (*VaultResponse, error) {
	var out VaultResponse
	path := fmt.Sprintf("/api/v1/workspaces/%s/vaults/%s", workspaceID, vaultID)
	if err := c.do(http.MethodGet, path, nil, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) PushSnapshot(workspaceID, vaultID, deviceID string, snapshot []byte) error {
	path := fmt.Sprintf("/api/v1/workspaces/%s/vaults/%s/snapshot", workspaceID, vaultID)
	body := map[string]any{"device_id": deviceID, "snapshot": snapshot}
	return c.do(http.MethodPut, path, body, nil, true)
}

func (c *Client) PullSnapshot(workspaceID, vaultID, deviceID string) (*SnapshotResponse, error) {
	var out SnapshotResponse
	path := fmt.Sprintf("/api/v1/workspaces/%s/vaults/%s/snapshot", workspaceID, vaultID)
	if err := c.doWithHeaders(http.MethodGet, path, nil, &out, true, map[string]string{
		"X-Device-ID": deviceID,
	}); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) CreateToken(workspaceID, vaultID string, req CreateTokenRequest) (*TokenResponse, error) {
	var out TokenResponse
	path := fmt.Sprintf("/api/v1/workspaces/%s/vaults/%s/tokens", workspaceID, vaultID)
	if err := c.do(http.MethodPost, path, req, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ListTokens(workspaceID, vaultID string) ([]TokenResponse, error) {
	var out listTokensData
	path := fmt.Sprintf("/api/v1/workspaces/%s/vaults/%s/tokens", workspaceID, vaultID)
	if err := c.do(http.MethodGet, path, nil, &out, true); err != nil {
		return nil, err
	}
	return out.Tokens, nil
}

func (c *Client) RevokeToken(workspaceID, vaultID, tokenID string) error {
	path := fmt.Sprintf("/api/v1/workspaces/%s/vaults/%s/tokens/%s", workspaceID, vaultID, tokenID)
	return c.do(http.MethodDelete, path, nil, nil, true)
}

func (c *Client) RemovePeer(workspaceID, vaultID, deviceID string) error {
	path := fmt.Sprintf("/api/v1/workspaces/%s/vaults/%s/peers/%s", workspaceID, vaultID, deviceID)
	return c.do(http.MethodDelete, path, nil, nil, true)
}
