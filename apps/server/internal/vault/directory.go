package vault

import "context"

// DirectoryUser is display + identity for account enrichment and invites.
type DirectoryUser struct {
	ID    string
	Name  string
	Email string
}

// Directory looks up users, workspace roles, and membership without importing member.
type Directory interface {
	FindUserByEmail(ctx context.Context, email string) (*DirectoryUser, error)
	MembershipExists(ctx context.Context, workspaceID, userID string) (bool, error)
	FindUsersByIDs(ctx context.Context, ids []string) ([]DirectoryUser, error)
	FindWorkspaceName(ctx context.Context, workspaceID string) (string, error)
	RoleOf(ctx context.Context, workspaceID, userID string) (string, error)
	WorkspaceMemberIDs(ctx context.Context, workspaceID string, ids []string) ([]string, error)
}

// AccountPub is the public half of a user's account key bundle.
type AccountPub struct {
	UserID           string
	X25519PublicKey  []byte
	Ed25519PublicKey []byte
	Fingerprint      string
}

// KeyLookup reads account public keys without importing the keys package.
type KeyLookup interface {
	Public(ctx context.Context, userID string) (*AccountPub, error)
	PublicMany(ctx context.Context, ids []string) (map[string]AccountPub, error)
}
