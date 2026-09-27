package vault

import (
	"context"
	"strings"

	"github.com/zain-23/local-vault/apps/server/internal/common/apperror"
	"github.com/zain-23/local-vault/apps/server/internal/common/middleware"
)

type actor struct {
	UserID  string
	Email   string
	WSRole  string
	Vault   *Vault
	Member  *Member
}

func (a actor) canManage() bool {
	return a.WSRole == RoleOwner || a.WSRole == RoleAdmin || a.isVaultAdmin()
}

func (a actor) isVaultAdmin() bool {
	return a.Member != nil && a.Member.Role == VaultRoleAdmin
}

func (a actor) canSee() bool {
	return a.canManage() || a.Member != nil
}

func (a actor) perm(env string) string {
	if a.Member == nil {
		return ""
	}
	return a.Member.permission(env)
}

func (a actor) canRead(env string) bool {
	p := a.perm(env)
	return p == PermRead || p == PermWrite
}

func (a actor) canWrite(env string) bool {
	return a.perm(env) == PermWrite
}

func (a actor) requireSee() error {
	if !a.canSee() {
		return apperror.New(404, "vault not found")
	}
	return nil
}

func (a actor) requireManage() error {
	if err := a.requireSee(); err != nil {
		return err
	}
	if !a.canManage() {
		return apperror.WithCode(403, "no_access", "vault admin required")
	}
	return nil
}

func (a actor) requireRead(env string) error {
	if err := a.requireSee(); err != nil {
		return err
	}
	if a.Vault.env(env) == nil {
		return apperror.New(404, "environment not found")
	}
	if !a.canRead(env) {
		return apperror.WithCode(403, "no_access", "no access to this environment")
	}
	return nil
}

func (a actor) requireWrite(env string) error {
	if err := a.requireRead(env); err != nil {
		return err
	}
	if !a.canWrite(env) {
		return apperror.WithCode(403, "no_access", "write access required")
	}
	return nil
}

func (s *Service) resolve(ctx context.Context, workspaceID, vaultID, userID, email string) (*actor, error) {
	v, err := s.Store.FindVault(ctx, vaultID)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	if v == nil || v.WorkspaceID != workspaceID {
		return nil, apperror.New(404, "vault not found")
	}
	wsRole := ""
	if s.dir != nil {
		wsRole, err = s.dir.RoleOf(ctx, workspaceID, userID)
		if err != nil {
			return nil, apperror.ErrInternal
		}
	}
	mem, err := s.Store.FindMember(ctx, vaultID, userID)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	a := &actor{UserID: userID, Email: email, WSRole: wsRole, Vault: v, Member: mem}
	if !a.canSee() {
		return nil, apperror.New(404, "vault not found")
	}
	return a, nil
}

func (s *Service) resolveFromUser(ctx context.Context, workspaceID, vaultID string, user middleware.AuthUser) (*actor, error) {
	return s.resolve(ctx, workspaceID, vaultID, user.ID, user.Email)
}

// Access is the exported view the machine domain uses for authorization.
type Access struct {
	Vault *Vault
	admin bool
}

func (a *Access) IsVaultAdmin() bool { return a.admin }

// ResolveForMachine is resolve() for the machine domain (same package-level checks).
func (s *Service) ResolveForMachine(ctx context.Context, workspaceID, vaultID, userID, email string) (*Access, error) {
	a, err := s.resolve(ctx, workspaceID, vaultID, userID, email)
	if err != nil {
		return nil, err
	}
	return &Access{Vault: a.Vault, admin: a.isVaultAdmin()}, nil
}

func normalizeRole(role string) (string, error) {
	role = strings.TrimSpace(strings.ToLower(role))
	if role == "" {
		role = VaultRoleMember
	}
	if role != VaultRoleAdmin && role != VaultRoleMember {
		return "", apperror.New(400, "role must be admin or member")
	}
	return role, nil
}

func parseEnvAccess(in []EnvAccessInput, vault *Vault) ([]EnvAccess, error) {
	if len(in) == 0 {
		return nil, apperror.New(400, "env_access is required")
	}
	seen := map[string]bool{}
	out := make([]EnvAccess, 0, len(in))
	for _, a := range in {
		env := strings.TrimSpace(a.Env)
		perm := strings.TrimSpace(strings.ToLower(a.Permission))
		if vault.env(env) == nil {
			return nil, apperror.New(400, "unknown environment: "+env)
		}
		if perm != PermRead && perm != PermWrite {
			return nil, apperror.New(400, "permission must be read or write")
		}
		if seen[env] {
			continue
		}
		seen[env] = true
		out = append(out, EnvAccess{Env: env, Permission: perm})
	}
	return out, nil
}
