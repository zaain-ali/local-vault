package vault

import "time"

type Vault struct {
	ID				string 		`bson:"_id" json:"id"`
	WorkspaceID		string		`bson:"workspace_id" json:"workspace_id"`
	Name			string		`bson:"name" json:"name"`
	OwnerDeviceID	string		`bson:"owner_device_id" json:"owner_device_id"`
	CreatedBy		string		`bson:"created_by" json:"created_by"`
	Snapshot		[]byte		`bson:"snapshot" json:"snapshot"`
	Peers			[]Peer		`bson:"peers" json:"peers"`
	Tokens			[]Token		`bson:"tokens" json:"-"`
	CreatedAt		time.Time	`bson:"created_at" json:"created_at"`	
	UpdatedAt		time.Time	`bson:"updated_at" json:"updated_at"`	
}


// Peer = one authorized device in a vault. device_id here is the CLI's *P2P*
type Peer struct {
	DeviceID        string    `bson:"device_id" json:"device_id"`
	DeviceName      string    `bson:"device_name" json:"device_name"`
	PublicKey       []byte    `bson:"public_key" json:"public_key"`
	X25519PublicKey []byte    `bson:"x25519_public_key" json:"x25519_public_key"`
	UserID          string    `bson:"user_id,omitempty" json:"user_id,omitempty"` // account that owns this device
	JoinedAt        time.Time `bson:"joined_at" json:"joined_at"`
}

// Collaborator invite lifecycle (collection: vault_collaborators).
const (
	CollabPending = "pending"
	CollabActive  = "active"
	CollabRevoked = "revoked"
)

// Collaborator = emailed short-code invite; join via CLI adds a Peer.
type Collaborator struct {
	ID          string    `bson:"_id" json:"id"`
	VaultID     string    `bson:"vault_id" json:"vault_id"`
	WorkspaceID string    `bson:"workspace_id" json:"workspace_id"`
	UserID      string    `bson:"user_id" json:"user_id"`
	Email       string    `bson:"email" json:"email"`
	InvitedBy   string    `bson:"invited_by" json:"invited_by"`
	Status      string    `bson:"status" json:"status"`
	CodeHash    string    `bson:"code_hash,omitempty" json:"-"` // sha256 of join code
	WrappedDEK  []byte    `bson:"wrapped_dek,omitempty" json:"-"`
	CreatedAt   time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time `bson:"updated_at" json:"updated_at"`
	ExpiresAt   time.Time `bson:"expires_at" json:"expires_at"`
}

// Token = a join token. wrapped_dek + verifier are secrets (json:"-"): the CLI
// gets id/name/created_at/expires_at only.
type Token struct {
	ID         string     `bson:"id" json:"id"`                    // prefix "lv_join_"
	Name       string     `bson:"name" json:"name"`
	WrappedDEK []byte     `bson:"wrapped_dek" json:"-"`            // DEK sealed for the joiner
	Verifier   string     `bson:"verifier" json:"-"`               // hash the joiner must reproduce
	CreatedAt  time.Time  `bson:"created_at" json:"created_at"`
	ExpiresAt  *time.Time `bson:"expires_at" json:"expires_at"`    // pointer = nullable ("never expires")
	Revoked    bool       `bson:"revoked" json:"revoked"`
}


// PendingMessage = one queued offline message ("pending_messages" collection).
type PendingMessage struct {
	ID            string    `bson:"_id" json:"id"`                           // prefix "msg_"
	ForDeviceID   string    `bson:"for_device_id" json:"for_device_id"`
	FromDeviceID  string    `bson:"from_device_id" json:"from_device_id"`
	FromPublicKey []byte    `bson:"from_public_key" json:"from_public_key"`
	Payload       []byte    `bson:"payload" json:"payload"`
	CreatedAt     time.Time `bson:"created_at" json:"created_at"`
	ExpiresAt     time.Time `bson:"expires_at" json:"expires_at"`            // TTL index deletes past this
}

// Workspace roles (mirrors member.Role* — duplicated to avoid importing member).
const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
)

// MessageTTL — how long an undelivered offline message lives.
const MessageTTL = 48 * time.Hour
