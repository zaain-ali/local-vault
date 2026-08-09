package app

import (
	"context"

	"github.com/zain-23/local-vault/apps/server/internal/member"
	"github.com/zain-23/local-vault/apps/server/internal/vault"
)

// memberDirectory adapts member.Store to vault.Directory.
type memberDirectory struct {
	store *member.Store
}

func (d memberDirectory) FindUserByEmail(ctx context.Context, email string) (*vault.DirectoryUser, error) {
	u, err := d.store.FindUserByEmail(ctx, email)
	if err != nil || u == nil {
		return nil, err
	}
	return &vault.DirectoryUser{ID: u.ID, Name: u.Name, Email: u.Email}, nil
}

func (d memberDirectory) MembershipExists(ctx context.Context, workspaceID, userID string) (bool, error) {
	return d.store.MembershipExists(ctx, workspaceID, userID)
}

func (d memberDirectory) FindUsersByIDs(ctx context.Context, ids []string) ([]vault.DirectoryUser, error) {
	users, err := d.store.FindUsersByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make([]vault.DirectoryUser, 0, len(users))
	for _, u := range users {
		out = append(out, vault.DirectoryUser{ID: u.ID, Name: u.Name, Email: u.Email})
	}
	return out, nil
}

func (d memberDirectory) FindWorkspaceName(ctx context.Context, workspaceID string) (string, error) {
	return d.store.FindWorkspaceName(ctx, workspaceID)
}
