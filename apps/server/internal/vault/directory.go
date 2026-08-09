package vault

import "context"

// DirectoryUser is display + identity for account enrichment and invites.
type DirectoryUser struct {
	ID    string
	Name  string
	Email string
}

// Directory looks up users and membership without importing the member package.
type Directory interface {
	FindUserByEmail(ctx context.Context, email string) (*DirectoryUser, error)
	MembershipExists(ctx context.Context, workspaceID, userID string) (bool, error)
	FindUsersByIDs(ctx context.Context, ids []string) ([]DirectoryUser, error)
	FindWorkspaceName(ctx context.Context, workspaceID string) (string, error)
}
