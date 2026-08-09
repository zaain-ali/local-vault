package vault

import "time"

// --- create ---

// CreateVaultRequest — the CLI sends its owner peer material; "name" is new.
// json:"owner_id" preserves the old wire name for the P2P device id.
type CreateVaultRequest struct {
	Name            string `json:"name" validate:"required,max=100"`
	OwnerDeviceID   string `json:"owner_id" validate:"required"`
	OwnerName       string `json:"owner_name" validate:"required"`
	PublicKey       []byte `json:"public_key" validate:"required"`
	X25519PublicKey []byte `json:"x25519_public_key" validate:"required"`
}

// CreateVaultResponse keeps the old relay shape so the CLI's init flow is unchanged.
type CreateVaultResponse struct {
	VaultID   string    `json:"vault_id"`
	CreatedAt time.Time `json:"created_at"`
}


// --- read (web dashboard) ---
// VaultSummary is one row of the list endpoint (no peers, just a count).
type VaultSummary struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	OwnerDeviceID string    `json:"owner_device_id"`
	PeerCount     int       `json:"peer_count"`
	HasSnapshot   bool      `json:"has_snapshot"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// VaultResponse is the detail view — includes peers, excludes snapshot/tokens.
type VaultResponse struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	WorkspaceID   string         `json:"workspace_id"`
	CreatedBy     string         `json:"created_by"`
	OwnerDeviceID string         `json:"owner_device_id"`
	Peers         []PeerResponse `json:"peers"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

// PeerResponse is a peer for API responses (optional account enrichment).
type PeerResponse struct {
	DeviceID        string    `json:"device_id"`
	DeviceName      string    `json:"device_name"`
	PublicKey       []byte    `json:"public_key"`
	X25519PublicKey []byte    `json:"x25519_public_key"`
	UserID          string    `json:"user_id,omitempty"`
	Name            string    `json:"name,omitempty"`
	Email           string    `json:"email,omitempty"`
	JoinedAt        time.Time `json:"joined_at"`
}

// --- collaborators ---

type InviteCollaboratorRequest struct {
	Email      string `json:"email" validate:"required,email"`
	DeviceID   string `json:"device_id" validate:"required"`
	Code       string `json:"code" validate:"required"`        // short ABCD-1234; emailed; stored hashed
	WrappedDEK []byte `json:"wrapped_dek" validate:"required"` // DEK wrapped with the code
}

type CollaboratorResponse struct {
	ID        string    `json:"id"`
	VaultID   string    `json:"vault_id"`
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	InvitedBy string    `json:"invited_by"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// JoinByCodeRequest — authenticated short-code join (email invite).
type JoinByCodeRequest struct {
	Code            string `json:"code" validate:"required"`
	DeviceID        string `json:"device_id" validate:"required"`
	DeviceName      string `json:"device_name" validate:"required"`
	PublicKey       []byte `json:"public_key" validate:"required"`
	X25519PublicKey []byte `json:"x25519_public_key" validate:"required"`
}


// --- snapshot ---
// PushSnapshotRequest — device_id is the P2P peer id (must already be a peer).
type PushSnapshotRequest struct {
	DeviceID string `json:"device_id" validate:"required"`
	Snapshot []byte `json:"snapshot" validate:"required"`
}

// SnapshotResponse is what "lv sync" downloads.
type SnapshotResponse struct {
	Snapshot  []byte    `json:"snapshot"`
	UpdatedAt time.Time `json:"updated_at"`
}


// --- tokens ---
// CreateTokenRequest mirrors the old relay body (device_id + wrapped_dek + verifier).
type CreateTokenRequest struct {
	DeviceID   string     `json:"device_id" validate:"required"`
	Name       string     `json:"name" validate:"required,max=100"`
	ExpiresAt  *time.Time `json:"expires_at"`               // optional — nil means never
	WrappedDEK []byte     `json:"wrapped_dek" validate:"required"`
	Verifier   string     `json:"verifier" validate:"required"`
}

// TokenResponse is the public token view — never wrapped_dek or verifier.
type TokenResponse struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// ListTokensResponse keeps the old {"tokens":[...]} envelope inside .data.
type ListTokensResponse struct {
	Tokens []TokenResponse `json:"tokens"`
}


// --- join (public) ---
// JoinRequest — token is the public token id; verifier proves knowledge of the secret.
type JoinRequest struct {
	Token           string `json:"token" validate:"required"`
	Verifier        string `json:"verifier" validate:"required"`
	DeviceID        string `json:"device_id" validate:"required"`
	DeviceName      string `json:"device_name" validate:"required"`
	PublicKey       []byte `json:"public_key" validate:"required"`
	X25519PublicKey []byte `json:"x25519_public_key" validate:"required"`
}

// JoinResponse gives the joiner the snapshot, current peers, and its sealed DEK.
type JoinResponse struct {
	VaultID     string `json:"vault_id"`
	WorkspaceID string `json:"workspace_id"`
	Snapshot    []byte `json:"snapshot"`
	Peers       []Peer `json:"peers"`
	WrappedDEK  []byte `json:"wrapped_dek"`
	Message     string `json:"message,omitempty"` // "already a peer" when re-joining
}


// --- offline messages ---
type SendMessageRequest struct {
	ForDeviceID   string `json:"for_device_id" validate:"required"`
	FromDeviceID  string `json:"from_device_id" validate:"required"`
	FromPublicKey []byte `json:"from_public_key" validate:"required"`
	Payload       []byte `json:"payload" validate:"required"`
}

type SendMessageResponse struct {
	ID      string `json:"id"`
	Success bool   `json:"success"`
}

type MessagesResponse struct {
	Messages []PendingMessage `json:"messages"`
	Count    int              `json:"count"`
}