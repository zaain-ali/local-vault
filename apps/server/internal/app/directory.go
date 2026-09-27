package app

import (
	"context"

	"github.com/zain-23/local-vault/apps/server/internal/keys"
	"github.com/zain-23/local-vault/apps/server/internal/member"
	"github.com/zain-23/local-vault/apps/server/internal/vault"
)

// memberDirectory adapts member.Store to vault.Directory and keys.Directory.
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

func (d memberDirectory) RoleOf(ctx context.Context, workspaceID, userID string) (string, error) {
	return d.store.RoleOf(ctx, workspaceID, userID)
}

func (d memberDirectory) WorkspaceMemberIDs(ctx context.Context, workspaceID string, ids []string) ([]string, error) {
	return d.store.WorkspaceMemberIDs(ctx, workspaceID, ids)
}

type keysDirectory struct {
	store *member.Store
}

func (d keysDirectory) WorkspaceMemberIDs(ctx context.Context, workspaceID string, ids []string) ([]string, error) {
	return d.store.WorkspaceMemberIDs(ctx, workspaceID, ids)
}

func (d keysDirectory) FindUsersByIDs(ctx context.Context, ids []string) ([]keys.DirectoryUser, error) {
	users, err := d.store.FindUsersByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make([]keys.DirectoryUser, 0, len(users))
	for _, u := range users {
		out = append(out, keys.DirectoryUser{ID: u.ID, Name: u.Name, Email: u.Email})
	}
	return out, nil
}

type keyLookup struct {
	store *keys.Store
}

func (k keyLookup) Public(ctx context.Context, userID string) (*vault.AccountPub, error) {
	b, err := k.store.Get(ctx, userID)
	if err != nil || b == nil {
		return nil, err
	}
	return &vault.AccountPub{
		UserID: b.UserID, X25519PublicKey: b.X25519PublicKey,
		Ed25519PublicKey: b.Ed25519PublicKey, Fingerprint: b.Fingerprint,
	}, nil
}

func (k keyLookup) PublicMany(ctx context.Context, ids []string) (map[string]vault.AccountPub, error) {
	bundles, err := k.store.FindByUserIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make(map[string]vault.AccountPub, len(bundles))
	for id, b := range bundles {
		out[id] = vault.AccountPub{
			UserID: b.UserID, X25519PublicKey: b.X25519PublicKey,
			Ed25519PublicKey: b.Ed25519PublicKey, Fingerprint: b.Fingerprint,
		}
	}
	return out, nil
}
