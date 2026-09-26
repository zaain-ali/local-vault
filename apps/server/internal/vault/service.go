package vault

import (
	"context"
	"encoding/json"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/zain-23/local-vault/apps/server/internal/audit"
	"github.com/zain-23/local-vault/apps/server/internal/common/apperror"
	"github.com/zain-23/local-vault/apps/server/internal/common/id"
	"github.com/zain-23/local-vault/apps/server/internal/config"
	"github.com/zain-23/local-vault/apps/server/internal/email"
	"github.com/zain-23/local-vault/apps/server/internal/events"
	"github.com/zain-23/local-vault/apps/server/internal/keys"
)

var vaultIDPattern = regexp.MustCompile(`^vlt_[a-zA-Z0-9]{8,32}$`)

type Service struct {
	Store     *Store
	audit     audit.Recorder
	dir       Directory
	keys      KeyLookup
	publisher *email.Publisher
	bus       events.Publisher
	cfg       config.Config
}

func NewService(store *Store, recorder audit.Recorder, dir Directory, keys KeyLookup, pub *email.Publisher, bus events.Publisher, cfg config.Config) *Service {
	return &Service{Store: store, audit: recorder, dir: dir, keys: keys, publisher: pub, bus: bus, cfg: cfg}
}

func (s *Service) emit(ctx context.Context, vaultID, event string, data any) {
	if s.bus != nil {
		s.bus.Publish(ctx, vaultID, event, data)
	}
}

// KeysUploaded implements keys.Hooks — emit grants_pending for every vault the user is in.
func (s *Service) KeysUploaded(ctx context.Context, userID string) {
	list, err := s.Store.ListMembershipsOfUser(ctx, userID, "")
	if err != nil {
		log.Printf("⚠️ keys uploaded: list memberships: %v", err)
		return
	}
	for _, m := range list {
		for _, a := range m.EnvAccess {
			s.emit(ctx, m.VaultID, events.GrantsPending, map[string]any{"env": a.Env})
		}
	}
}

// KeysReset implements keys.Hooks.
func (s *Service) KeysReset(ctx context.Context, userID string) error {
	return s.Store.DeleteAllUserGrants(ctx, userID)
}

func (s *Service) Create(ctx context.Context, workspaceID, createdBy string, req CreateVaultRequest) (*VaultDetail, error) {
	envs := req.Environments
	if len(envs) == 0 {
		envs = append([]string{}, DefaultEnvironments...)
	}
	if len(envs) > maxEnvironments {
		return nil, apperror.New(400, "too many environments")
	}
	seen := map[string]bool{}
	now := time.Now()
	list := make([]Environment, 0, len(envs))
	for _, name := range envs {
		name = strings.TrimSpace(name)
		if !ValidEnvName(name) {
			return nil, apperror.New(400, "invalid environment name: "+name)
		}
		if seen[name] {
			return nil, apperror.New(400, "duplicate environment: "+name)
		}
		seen[name] = true
		list = append(list, Environment{
			Name: name, KeyVersion: 1, HeadRevision: 0,
			Protected: name == "production", RekeyRequired: false, UpdatedAt: now,
		})
	}
	if len(req.Grants) != len(list) {
		return nil, apperror.New(400, "grants must cover every environment exactly once")
	}
	vid := strings.TrimSpace(req.ID)
	if vid == "" {
		vid = id.Generate("vlt_", 12)
	} else if !vaultIDPattern.MatchString(vid) {
		return nil, apperror.New(400, "invalid vault id")
	}

	grants := make([]Grant, 0, len(req.Grants))
	covered := map[string]bool{}
	for _, g := range req.Grants {
		if !seen[g.Env] || g.KeyVersion != 1 || covered[g.Env] {
			return nil, apperror.New(400, "grants must cover every environment at key_version 1")
		}
		if err := validateWrappedKey(RecipientUser, "", g.WrappedKey); err != nil {
			return nil, err
		}
		covered[g.Env] = true
		grants = append(grants, Grant{
			ID: id.Generate("gr_", 12), VaultID: vid, Env: g.Env, KeyVersion: 1,
			RecipientType: RecipientUser, RecipientID: createdBy, WrappedKey: g.WrappedKey,
			GrantedBy: createdBy, CreatedAt: now,
		})
	}

	access := make([]EnvAccess, 0, len(list))
	for _, e := range list {
		access = append(access, EnvAccess{Env: e.Name, Permission: PermWrite})
	}
	v := &Vault{
		ID: vid, WorkspaceID: workspaceID, Name: strings.TrimSpace(req.Name),
		CreatedBy: createdBy, Environments: list, CreatedAt: now, UpdatedAt: now,
	}
	mem := &Member{
		ID: id.Generate("vm_", 12), VaultID: vid, WorkspaceID: workspaceID,
		UserID: createdBy, Role: VaultRoleAdmin, EnvAccess: access,
		AddedBy: createdBy, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.Store.InsertVault(ctx, v); err != nil {
		if strings.Contains(err.Error(), "duplicate") {
			return nil, apperror.New(409, "vault id already exists")
		}
		return nil, apperror.ErrInternal
	}
	if err := s.Store.InsertMember(ctx, mem); err != nil {
		_ = s.Store.DeleteVaultCascade(ctx, vid)
		return nil, apperror.ErrInternal
	}
	if err := s.Store.InsertGrants(ctx, grants); err != nil {
		_ = s.Store.DeleteVaultCascade(ctx, vid)
		return nil, apperror.ErrInternal
	}
	s.audit.Record(ctx, audit.Entry{
		WorkspaceID: workspaceID, Action: "vault.created",
		TargetType: "vault", TargetID: vid, TargetName: v.Name,
	})
	return s.Get(ctx, workspaceID, vid, createdBy, "")
}

func (s *Service) List(ctx context.Context, workspaceID, userID string) ([]VaultSummary, error) {
	wsRole := ""
	if s.dir != nil {
		var err error
		wsRole, err = s.dir.RoleOf(ctx, workspaceID, userID)
		if err != nil {
			return nil, apperror.ErrInternal
		}
	}
	var ids []string
	if wsRole != RoleOwner && wsRole != RoleAdmin {
		mems, err := s.Store.ListMembershipsOfUser(ctx, userID, workspaceID)
		if err != nil {
			return nil, apperror.ErrInternal
		}
		ids = make([]string, 0, len(mems))
		for _, m := range mems {
			ids = append(ids, m.VaultID)
		}
		if len(ids) == 0 {
			return []VaultSummary{}, nil
		}
	}
	vaults, err := s.Store.ListVaults(ctx, workspaceID, ids)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	vIDs := make([]string, 0, len(vaults))
	for _, v := range vaults {
		vIDs = append(vIDs, v.ID)
	}
	counts, err := s.Store.CountMembers(ctx, vIDs)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	out := make([]VaultSummary, 0, len(vaults))
	for _, v := range vaults {
		mem, _ := s.Store.FindMember(ctx, v.ID, userID)
		sum := VaultSummary{
			ID: v.ID, Name: v.Name, Environments: envResponses(v.Environments),
			MemberCount: counts[v.ID], CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt,
		}
		if mem != nil {
			sum.MyRole = mem.Role
			sum.MyEnvAccess = accessResponses(mem.EnvAccess)
		}
		out = append(out, sum)
	}
	return out, nil
}

func (s *Service) Get(ctx context.Context, workspaceID, vaultID, userID, email string) (*VaultDetail, error) {
	a, err := s.resolve(ctx, workspaceID, vaultID, userID, email)
	if err != nil {
		return nil, err
	}
	members, err := s.Store.ListMembers(ctx, vaultID)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	ids := make([]string, 0, len(members))
	for _, m := range members {
		ids = append(ids, m.UserID)
	}
	users := map[string]DirectoryUser{}
	if s.dir != nil && len(ids) > 0 {
		list, err := s.dir.FindUsersByIDs(ctx, ids)
		if err != nil {
			return nil, apperror.ErrInternal
		}
		for _, u := range list {
			users[u.ID] = u
		}
	}
	pubs := map[string]AccountPub{}
	if s.keys != nil && len(ids) > 0 {
		pubs, err = s.keys.PublicMany(ctx, ids)
		if err != nil {
			return nil, apperror.ErrInternal
		}
	}
	outMem := make([]MemberResponse, 0, len(members))
	for _, m := range members {
		u := users[m.UserID]
		p, ok := pubs[m.UserID]
		outMem = append(outMem, MemberResponse{
			UserID: m.UserID, Name: u.Name, Email: u.Email, Role: m.Role,
			EnvAccess: accessResponses(m.EnvAccess), HasKeys: ok, Fingerprint: p.Fingerprint,
		})
	}
	detail := &VaultDetail{
		ID: a.Vault.ID, WorkspaceID: a.Vault.WorkspaceID, Name: a.Vault.Name,
		CreatedBy: a.Vault.CreatedBy, Environments: envResponses(a.Vault.Environments),
		Members: outMem, CreatedAt: a.Vault.CreatedAt, UpdatedAt: a.Vault.UpdatedAt,
	}
	if a.Member != nil {
		detail.MyRole = a.Member.Role
		detail.MyEnvAccess = accessResponses(a.Member.EnvAccess)
	}
	return detail, nil
}

func (s *Service) Delete(ctx context.Context, workspaceID, vaultID, userID, email string) error {
	a, err := s.resolve(ctx, workspaceID, vaultID, userID, email)
	if err != nil {
		return err
	}
	if err := a.requireManage(); err != nil {
		return err
	}
	if err := s.Store.DeleteVaultCascade(ctx, vaultID); err != nil {
		return apperror.ErrInternal
	}
	s.audit.Record(ctx, audit.Entry{
		WorkspaceID: workspaceID, Action: "vault.deleted",
		TargetType: "vault", TargetID: vaultID,
	})
	return nil
}

func (s *Service) AddEnvironment(ctx context.Context, workspaceID, vaultID, userID, email string, req AddEnvironmentRequest) error {
	a, err := s.resolve(ctx, workspaceID, vaultID, userID, email)
	if err != nil {
		return err
	}
	if err := a.requireManage(); err != nil {
		return err
	}
	name := strings.TrimSpace(req.Name)
	if !ValidEnvName(name) {
		return apperror.New(400, "invalid environment name")
	}
	if a.Vault.env(name) != nil {
		return apperror.New(409, "environment already exists")
	}
	if req.Grant.KeyVersion != 1 || (req.Grant.Env != "" && req.Grant.Env != name) {
		return apperror.New(400, "grant must be for this environment at key_version 1")
	}
	if err := validateWrappedKey(RecipientUser, "", req.Grant.WrappedKey); err != nil {
		return err
	}
	now := time.Now()
	ok, err := s.Store.AddEnvironment(ctx, vaultID, Environment{
		Name: name, KeyVersion: 1, HeadRevision: 0, Protected: req.Protected, UpdatedAt: now,
	})
	if err != nil {
		return apperror.ErrInternal
	}
	if !ok {
		return apperror.New(409, "environment already exists")
	}
	_ = s.Store.AddEnvAccess(ctx, vaultID, userID, EnvAccess{Env: name, Permission: PermWrite})
	if err := s.Store.InsertGrants(ctx, []Grant{{
		ID: id.Generate("gr_", 12), VaultID: vaultID, Env: name, KeyVersion: 1,
		RecipientType: RecipientUser, RecipientID: userID, WrappedKey: req.Grant.WrappedKey,
		GrantedBy: userID, CreatedAt: now,
	}}); err != nil {
		return apperror.ErrInternal
	}
	s.audit.Record(ctx, audit.Entry{
		WorkspaceID: workspaceID, Action: "vault.env.added",
		TargetType: "vault", TargetID: vaultID, Details: map[string]any{"env": name},
	})
	s.emit(ctx, vaultID, events.Members, map[string]any{"env": name})
	return nil
}

func (s *Service) PatchEnvironment(ctx context.Context, workspaceID, vaultID, env, userID, email string, req PatchEnvironmentRequest) error {
	a, err := s.resolve(ctx, workspaceID, vaultID, userID, email)
	if err != nil {
		return err
	}
	if err := a.requireManage(); err != nil {
		return err
	}
	if a.Vault.env(env) == nil {
		return apperror.New(404, "environment not found")
	}
	if req.Protected == nil {
		return apperror.New(400, "protected is required")
	}
	if err := s.Store.SetEnvProtected(ctx, vaultID, env, *req.Protected); err != nil {
		return apperror.ErrInternal
	}
	return nil
}

func (s *Service) AddMember(ctx context.Context, workspaceID, vaultID, invitedBy, inviterEmail string, req AddMemberRequest) (*MemberResponse, error) {
	a, err := s.resolve(ctx, workspaceID, vaultID, invitedBy, inviterEmail)
	if err != nil {
		return nil, err
	}
	if err := a.requireManage(); err != nil {
		return nil, err
	}
	role, err := normalizeRole(req.Role)
	if err != nil {
		return nil, err
	}
	access, err := parseEnvAccess(req.EnvAccess, a.Vault)
	if err != nil {
		return nil, err
	}
	if s.dir == nil {
		return nil, apperror.ErrInternal
	}
	user, err := s.dir.FindUserByEmail(ctx, strings.ToLower(strings.TrimSpace(req.Email)))
	if err != nil {
		return nil, apperror.ErrInternal
	}
	if user == nil {
		return nil, apperror.WithCode(404, "not_workspace_member", "no account with this email — invite them to the workspace first")
	}
	ok, err := s.dir.MembershipExists(ctx, workspaceID, user.ID)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	if !ok {
		return nil, apperror.WithCode(404, "not_workspace_member", "user must be a workspace member before vault access")
	}
	if existing, _ := s.Store.FindMember(ctx, vaultID, user.ID); existing != nil {
		return nil, apperror.New(409, "user is already a vault member")
	}
	now := time.Now()
	mem := &Member{
		ID: id.Generate("vm_", 12), VaultID: vaultID, WorkspaceID: workspaceID,
		UserID: user.ID, Role: role, EnvAccess: access, AddedBy: invitedBy,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := s.Store.InsertMember(ctx, mem); err != nil {
		return nil, apperror.ErrInternal
	}
	inviter := inviterEmail
	if users, _ := s.dir.FindUsersByIDs(ctx, []string{invitedBy}); len(users) > 0 && users[0].Name != "" {
		inviter = users[0].Name
	}
	envs := make([]string, 0, len(access))
	for _, x := range access {
		envs = append(envs, x.Env)
		s.emit(ctx, vaultID, events.GrantsPending, map[string]any{"env": x.Env})
	}
	if s.publisher != nil {
		if err := s.publisher.Publish(ctx, email.EmailJob{
			Kind: email.KindVaultCollaboratorInvite, To: user.Email,
			Name: a.Vault.Name, Inviter: inviter, Envs: strings.Join(envs, ", "),
		}); err != nil {
			log.Printf("⚠️ vault access email for %s: %v", user.Email, err)
		}
	}
	s.audit.Record(ctx, audit.Entry{
		WorkspaceID: workspaceID, Action: "vault.member.added",
		TargetType: "vault", TargetID: vaultID, TargetName: user.Email,
		Details: map[string]any{"user_id": user.ID, "role": role},
	})
	s.emit(ctx, vaultID, events.Members, map[string]any{})
	pub, _ := s.publicOf(ctx, user.ID)
	return &MemberResponse{
		UserID: user.ID, Name: user.Name, Email: user.Email, Role: role,
		EnvAccess: accessResponses(access), HasKeys: pub != nil,
		Fingerprint: fingerprintOf(pub),
	}, nil
}

func (s *Service) UpdateMember(ctx context.Context, workspaceID, vaultID, targetID, userID, email string, req UpdateMemberRequest) (*MemberResponse, error) {
	a, err := s.resolve(ctx, workspaceID, vaultID, userID, email)
	if err != nil {
		return nil, err
	}
	if err := a.requireManage(); err != nil {
		return nil, err
	}
	mem, err := s.Store.FindMember(ctx, vaultID, targetID)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	if mem == nil {
		return nil, apperror.New(404, "member not found")
	}
	role := mem.Role
	if req.Role != nil {
		role, err = normalizeRole(*req.Role)
		if err != nil {
			return nil, err
		}
	}
	access := mem.EnvAccess
	if req.EnvAccess != nil {
		access, err = parseEnvAccess(req.EnvAccess, a.Vault)
		if err != nil {
			return nil, err
		}
	}
	lost := lostEnvs(mem.EnvAccess, access)
	if err := s.Store.UpdateMember(ctx, vaultID, targetID, role, access); err != nil {
		return nil, apperror.ErrInternal
	}
	if len(lost) > 0 {
		_ = s.Store.DeleteRecipientGrants(ctx, vaultID, RecipientUser, targetID, lost)
		_ = s.Store.SetRekeyRequired(ctx, vaultID, lost)
		for _, env := range lost {
			s.emit(ctx, vaultID, events.RekeyRequired, map[string]any{"env": env})
		}
	}
	for _, x := range access {
		if mem.permission(x.Env) == "" {
			s.emit(ctx, vaultID, events.GrantsPending, map[string]any{"env": x.Env})
		}
	}
	s.audit.Record(ctx, audit.Entry{
		WorkspaceID: workspaceID, Action: "vault.member.updated",
		TargetType: "vault", TargetID: vaultID, Details: map[string]any{"user_id": targetID},
	})
	s.emit(ctx, vaultID, events.Members, map[string]any{})
	return s.memberResponse(ctx, vaultID, targetID)
}

func (s *Service) RemoveMember(ctx context.Context, workspaceID, vaultID, targetID, userID, email string) error {
	a, err := s.resolve(ctx, workspaceID, vaultID, userID, email)
	if err != nil {
		return err
	}
	if err := a.requireManage(); err != nil {
		return err
	}
	if targetID == a.Vault.CreatedBy {
		return apperror.New(400, "cannot remove the vault creator")
	}
	mem, err := s.Store.FindMember(ctx, vaultID, targetID)
	if err != nil {
		return apperror.ErrInternal
	}
	if mem == nil {
		return apperror.New(404, "member not found")
	}
	envs := make([]string, 0, len(mem.EnvAccess))
	for _, x := range mem.EnvAccess {
		envs = append(envs, x.Env)
	}
	if err := s.Store.DeleteMember(ctx, vaultID, targetID); err != nil {
		return apperror.ErrInternal
	}
	_ = s.Store.DeleteRecipientGrants(ctx, vaultID, RecipientUser, targetID, nil)
	_ = s.Store.SetRekeyRequired(ctx, vaultID, envs)
	for _, env := range envs {
		s.emit(ctx, vaultID, events.RekeyRequired, map[string]any{"env": env})
	}
	s.audit.Record(ctx, audit.Entry{
		WorkspaceID: workspaceID, Action: "vault.member.removed",
		TargetType: "vault", TargetID: vaultID, Details: map[string]any{"user_id": targetID},
	})
	s.emit(ctx, vaultID, events.Members, map[string]any{})
	return nil
}

func (s *Service) MyGrants(ctx context.Context, workspaceID, vaultID, userID, email string) ([]GrantResponse, error) {
	a, err := s.resolve(ctx, workspaceID, vaultID, userID, email)
	if err != nil {
		return nil, err
	}
	if a.Member == nil {
		return []GrantResponse{}, nil
	}
	list, err := s.Store.ListRecipientGrants(ctx, vaultID, RecipientUser, userID)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	out := make([]GrantResponse, 0, len(list))
	for _, g := range list {
		out = append(out, GrantResponse{Env: g.Env, KeyVersion: g.KeyVersion, WrappedKey: g.WrappedKey})
	}
	return out, nil
}

func (s *Service) PendingGrants(ctx context.Context, workspaceID, vaultID, userID, email string) ([]PendingGrant, error) {
	a, err := s.resolve(ctx, workspaceID, vaultID, userID, email)
	if err != nil {
		return nil, err
	}
	pairs := make([]EnvVersion, 0)
	for _, e := range a.Vault.Environments {
		ok, err := s.Store.HasGrant(ctx, vaultID, e.Name, e.KeyVersion, RecipientUser, userID)
		if err != nil {
			return nil, apperror.ErrInternal
		}
		if ok {
			pairs = append(pairs, EnvVersion{Env: e.Name, KeyVersion: e.KeyVersion})
		}
	}
	if len(pairs) == 0 {
		return []PendingGrant{}, nil
	}
	have, err := s.Store.ListGrantRecipients(ctx, vaultID, pairs)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	held := map[string]bool{}
	for _, g := range have {
		held[g.Env+"|"+g.RecipientType+"|"+g.RecipientID+"|"+itoa(g.KeyVersion)] = true
	}
	members, err := s.Store.ListMembers(ctx, vaultID)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	ids := make([]string, 0, len(members))
	for _, m := range members {
		ids = append(ids, m.UserID)
	}
	pubs := map[string]AccountPub{}
	if s.keys != nil {
		pubs, err = s.keys.PublicMany(ctx, ids)
		if err != nil {
			return nil, apperror.ErrInternal
		}
	}
	users := map[string]DirectoryUser{}
	if s.dir != nil && len(ids) > 0 {
		list, err := s.dir.FindUsersByIDs(ctx, ids)
		if err != nil {
			return nil, apperror.ErrInternal
		}
		for _, u := range list {
			users[u.ID] = u
		}
	}
	out := []PendingGrant{}
	for _, p := range pairs {
		for _, m := range members {
			if m.permission(p.Env) == "" {
				continue
			}
			pub, ok := pubs[m.UserID]
			if !ok {
				continue
			}
			if held[p.Env+"|"+RecipientUser+"|"+m.UserID+"|"+itoa(p.KeyVersion)] {
				continue
			}
			u := users[m.UserID]
			label := u.Name
			if label == "" {
				label = u.Email
			}
			out = append(out, PendingGrant{
				Env: p.Env, KeyVersion: p.KeyVersion, RecipientType: RecipientUser,
				RecipientID: m.UserID, Label: label, Email: u.Email,
				KeyType: KeyTypeX25519, PublicKey: pub.X25519PublicKey, Fingerprint: pub.Fingerprint,
			})
		}
		machines, err := s.Store.ListMachines(ctx, vaultID, p.Env)
		if err != nil {
			return nil, apperror.ErrInternal
		}
		now := time.Now()
		for _, mach := range machines {
			if !mach.active(now) || mach.KeyType == KeyTypeToken {
				continue
			}
			if held[p.Env+"|"+RecipientMachine+"|"+mach.ID+"|"+itoa(p.KeyVersion)] {
				continue
			}
			out = append(out, PendingGrant{
				Env: p.Env, KeyVersion: p.KeyVersion, RecipientType: RecipientMachine,
				RecipientID: mach.ID, Label: mach.Name, KeyType: mach.KeyType,
				PublicKey: mach.PublicKey, Fingerprint: machineFingerprint(mach),
			})
		}
	}
	return out, nil
}

func (s *Service) CreateGrants(ctx context.Context, workspaceID, vaultID, userID, email string, req CreateGrantsRequest) error {
	a, err := s.resolve(ctx, workspaceID, vaultID, userID, email)
	if err != nil {
		return err
	}
	if len(req.Grants) == 0 {
		return apperror.New(400, "grants is required")
	}
	now := time.Now()
	docs := make([]Grant, 0, len(req.Grants))
	for _, g := range req.Grants {
		env := a.Vault.env(g.Env)
		if env == nil {
			return apperror.New(400, "unknown environment: "+g.Env)
		}
		if g.KeyVersion < 1 || g.KeyVersion > env.KeyVersion {
			return apperror.New(400, "invalid key_version")
		}
		ok, err := s.Store.HasGrant(ctx, vaultID, g.Env, g.KeyVersion, RecipientUser, userID)
		if err != nil {
			return apperror.ErrInternal
		}
		if !ok {
			return apperror.WithCode(403, "no_access", "you do not hold this key version")
		}
		rt := g.RecipientType
		if rt == "" {
			rt = RecipientUser
		}
		if rt != RecipientUser && rt != RecipientMachine {
			return apperror.New(400, "recipient_type must be user or machine")
		}
		keyType := KeyTypeX25519
		if rt == RecipientUser {
			mem, err := s.Store.FindMember(ctx, vaultID, g.RecipientID)
			if err != nil {
				return apperror.ErrInternal
			}
			if mem == nil || mem.permission(g.Env) == "" {
				return apperror.New(400, "recipient is not entitled to this environment")
			}
		} else {
			mach, err := s.Store.FindMachine(ctx, g.RecipientID)
			if err != nil {
				return apperror.ErrInternal
			}
			if mach == nil || mach.VaultID != vaultID || mach.Env != g.Env || !mach.active(now) {
				return apperror.New(400, "recipient machine is not entitled")
			}
			keyType = mach.KeyType
		}
		if err := validateWrappedKey(rt, keyType, g.WrappedKey); err != nil {
			return err
		}
		docs = append(docs, Grant{
			ID: id.Generate("gr_", 12), VaultID: vaultID, Env: g.Env, KeyVersion: g.KeyVersion,
			RecipientType: rt, RecipientID: g.RecipientID, WrappedKey: g.WrappedKey,
			GrantedBy: userID, CreatedAt: now,
		})
	}
	if err := s.Store.InsertGrants(ctx, docs); err != nil {
		return apperror.ErrInternal
	}
	s.audit.Record(ctx, audit.Entry{
		WorkspaceID: workspaceID, Action: "vault.grant.created",
		TargetType: "vault", TargetID: vaultID, Details: map[string]any{"count": len(docs)},
	})
	return nil
}

func (s *Service) Head(ctx context.Context, workspaceID, vaultID, env, userID, email string) (*RevisionResponse, error) {
	a, err := s.resolve(ctx, workspaceID, vaultID, userID, email)
	if err != nil {
		return nil, err
	}
	if err := a.requireRead(env); err != nil {
		return nil, err
	}
	e := a.Vault.env(env)
	if e.HeadRevision == 0 {
		return &RevisionResponse{VaultID: vaultID, Env: env, Revision: 0, KeyVersion: e.KeyVersion}, nil
	}
	r, err := s.Store.FindRevision(ctx, vaultID, env, e.HeadRevision)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	if r == nil {
		return &RevisionResponse{VaultID: vaultID, Env: env, Revision: 0, KeyVersion: e.KeyVersion}, nil
	}
	return revisionResponse(r, true), nil
}

func (s *Service) ListRevisions(ctx context.Context, workspaceID, vaultID, env, userID, email string, before, limit int) ([]RevisionMeta, error) {
	a, err := s.resolve(ctx, workspaceID, vaultID, userID, email)
	if err != nil {
		return nil, err
	}
	if err := a.requireRead(env); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	list, err := s.Store.ListRevisionMeta(ctx, vaultID, env, before, limit)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	ids := make([]string, 0, len(list))
	for _, r := range list {
		ids = append(ids, r.AuthorUserID)
	}
	users := map[string]DirectoryUser{}
	if s.dir != nil && len(ids) > 0 {
		ulist, err := s.dir.FindUsersByIDs(ctx, ids)
		if err != nil {
			return nil, apperror.ErrInternal
		}
		for _, u := range ulist {
			users[u.ID] = u
		}
	}
	out := make([]RevisionMeta, 0, len(list))
	for _, r := range list {
		out = append(out, RevisionMeta{
			Revision: r.Revision, ParentRevision: r.ParentRevision, KeyVersion: r.KeyVersion,
			AuthorUserID: r.AuthorUserID, AuthorEmail: users[r.AuthorUserID].Email, CreatedAt: r.CreatedAt,
		})
	}
	return out, nil
}

func (s *Service) GetRevision(ctx context.Context, workspaceID, vaultID, env string, rev int, userID, email string) (*RevisionResponse, error) {
	a, err := s.resolve(ctx, workspaceID, vaultID, userID, email)
	if err != nil {
		return nil, err
	}
	if err := a.requireRead(env); err != nil {
		return nil, err
	}
	r, err := s.Store.FindRevision(ctx, vaultID, env, rev)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	if r == nil {
		return nil, apperror.New(404, "revision not found")
	}
	return revisionResponse(r, true), nil
}

func (s *Service) PushRevision(ctx context.Context, workspaceID, vaultID, env, userID, email, idem string, req PushRevisionRequest) (*RevisionResponse, error) {
	a, err := s.resolve(ctx, workspaceID, vaultID, userID, email)
	if err != nil {
		return nil, err
	}
	if err := a.requireWrite(env); err != nil {
		return nil, err
	}
	e := a.Vault.env(env)
	if e.Protected && !a.isVaultAdmin() {
		return nil, apperror.WithCode(403, "protected_env", "submit a change request instead")
	}
	if e.RekeyRequired {
		return nil, apperror.WithCode(409, "rekey_required", "environment must be rekeyed before new writes")
	}
	if req.KeyVersion != e.KeyVersion {
		return nil, apperror.WithCode(409, "stale_key_version", "key_version is not current")
	}
	if req.BaseRevision != e.HeadRevision {
		return nil, apperror.WithCode(409, "conflict", "base_revision is not the head").With("head_revision", e.HeadRevision)
	}
	if err := validateCiphertext(req.Ciphertext, req.Signature); err != nil {
		return nil, err
	}
	if idem != "" {
		if len(idem) > maxIdempotencyKey {
			return nil, apperror.New(400, "idempotency key too long")
		}
		if existing, _ := s.Store.FindByIdempotencyKey(ctx, vaultID, env, userID, idem); existing != nil {
			return revisionResponse(existing, true), nil
		}
	}
	pub, err := s.publicOf(ctx, userID)
	if err != nil {
		return nil, err
	}
	if pub == nil {
		return nil, apperror.WithCode(400, "no_keys", "upload account keys before pushing")
	}
	rev := req.BaseRevision + 1
	if !VerifyRevisionSignature(pub.Ed25519PublicKey, vaultID, env, rev, req.BaseRevision, req.KeyVersion, req.Ciphertext, req.Signature) {
		return nil, apperror.WithCode(400, "bad_signature", "revision signature is invalid")
	}
	doc := &RevisionDoc{
		ID: id.Generate("rev_", 12), VaultID: vaultID, Env: env, Revision: rev,
		ParentRevision: req.BaseRevision, KeyVersion: req.KeyVersion,
		Ciphertext: req.Ciphertext, Signature: req.Signature,
		AuthorUserID: userID, AuthorEd25519PublicKey: pub.Ed25519PublicKey,
		AuthorFingerprint: pub.Fingerprint, IdempotencyKey: idem, CreatedAt: time.Now(),
	}
	if err := s.Store.InsertRevision(ctx, doc); err != nil {
		if err == ErrRevisionExists {
			head, _ := s.Store.FindVault(ctx, vaultID)
			hr := req.BaseRevision
			if head != nil {
				if e := head.env(env); e != nil {
					hr = e.HeadRevision
				}
			}
			return nil, apperror.WithCode(409, "conflict", "base_revision is not the head").With("head_revision", hr)
		}
		return nil, apperror.ErrInternal
	}
	_ = s.Store.BumpHead(ctx, vaultID, env, rev)
	s.audit.Record(ctx, audit.Entry{
		WorkspaceID: workspaceID, Action: "vault.revision.pushed",
		TargetType: "vault", TargetID: vaultID, Details: map[string]any{"env": env, "revision": rev},
	})
	s.emit(ctx, vaultID, events.Revision, map[string]any{"env": env, "revision": rev})
	return revisionResponse(doc, true), nil
}

func (s *Service) CreateChangeRequest(ctx context.Context, workspaceID, vaultID, env, userID, email string, req CreateChangeRequestBody) (*ChangeRequest, error) {
	a, err := s.resolve(ctx, workspaceID, vaultID, userID, email)
	if err != nil {
		return nil, err
	}
	if err := a.requireWrite(env); err != nil {
		return nil, err
	}
	e := a.Vault.env(env)
	if !e.Protected {
		return nil, apperror.New(400, "change requests are only for protected environments")
	}
	if e.RekeyRequired {
		return nil, apperror.WithCode(409, "rekey_required", "environment must be rekeyed before new writes")
	}
	if req.KeyVersion != e.KeyVersion {
		return nil, apperror.WithCode(409, "stale_key_version", "key_version is not current")
	}
	if req.BaseRevision != e.HeadRevision {
		return nil, apperror.WithCode(409, "conflict", "base_revision is not the head").With("head_revision", e.HeadRevision)
	}
	if err := validateCiphertext(req.Ciphertext, req.Signature); err != nil {
		return nil, err
	}
	if len(req.Note) > maxNoteLen {
		return nil, apperror.New(400, "note is too long")
	}
	pub, err := s.publicOf(ctx, userID)
	if err != nil {
		return nil, err
	}
	if pub == nil {
		return nil, apperror.WithCode(400, "no_keys", "upload account keys first")
	}
	if !VerifyRevisionSignature(pub.Ed25519PublicKey, vaultID, env, req.BaseRevision+1, req.BaseRevision, req.KeyVersion, req.Ciphertext, req.Signature) {
		return nil, apperror.WithCode(400, "bad_signature", "revision signature is invalid")
	}
	now := time.Now()
	cr := &ChangeRequest{
		ID: id.Generate("cr_", 12), VaultID: vaultID, Env: env,
		BaseRevision: req.BaseRevision, KeyVersion: req.KeyVersion,
		Ciphertext: req.Ciphertext, Signature: req.Signature,
		AuthorUserID: userID, AuthorEd25519PublicKey: pub.Ed25519PublicKey,
		AuthorFingerprint: pub.Fingerprint, Note: req.Note, Status: CRPending,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := s.Store.InsertChangeRequest(ctx, cr); err != nil {
		return nil, apperror.ErrInternal
	}
	s.audit.Record(ctx, audit.Entry{
		WorkspaceID: workspaceID, Action: "vault.change_request.created",
		TargetType: "vault", TargetID: vaultID, Details: map[string]any{"id": cr.ID, "env": env},
	})
	s.emit(ctx, vaultID, events.ChangeRequest, map[string]any{"env": env, "id": cr.ID, "status": CRPending})
	return cr, nil
}

func (s *Service) ListChangeRequests(ctx context.Context, workspaceID, vaultID, env, status, userID, email string) ([]ChangeRequest, error) {
	a, err := s.resolve(ctx, workspaceID, vaultID, userID, email)
	if err != nil {
		return nil, err
	}
	if err := a.requireRead(env); err != nil {
		return nil, err
	}
	list, err := s.Store.ListChangeRequests(ctx, vaultID, env, status, 100)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	return list, nil
}

func (s *Service) ApproveChangeRequest(ctx context.Context, workspaceID, vaultID, env, crID, userID, email string) (*RevisionResponse, error) {
	a, err := s.resolve(ctx, workspaceID, vaultID, userID, email)
	if err != nil {
		return nil, err
	}
	if err := a.requireManage(); err != nil {
		return nil, err
	}
	if !a.isVaultAdmin() {
		return nil, apperror.WithCode(403, "no_access", "vault admin required")
	}
	cr, err := s.Store.FindChangeRequest(ctx, crID)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	if cr == nil || cr.VaultID != vaultID || cr.Env != env {
		return nil, apperror.New(404, "change request not found")
	}
	if cr.AuthorUserID == userID {
		return nil, apperror.New(400, "cannot approve your own change request")
	}
	if cr.Status != CRPending {
		return nil, apperror.New(400, "change request is not pending")
	}
	e := a.Vault.env(env)
	if e == nil {
		return nil, apperror.New(404, "environment not found")
	}
	if cr.BaseRevision != e.HeadRevision {
		_, _ = s.Store.TransitionChangeRequest(ctx, crID, CRPending, CRStale, userID)
		s.emit(ctx, vaultID, events.ChangeRequest, map[string]any{"env": env, "id": crID, "status": CRStale})
		return nil, apperror.WithCode(409, "stale", "head moved; change request is stale")
	}
	ok, err := s.Store.TransitionChangeRequest(ctx, crID, CRPending, CRApproved, userID)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	if !ok {
		return nil, apperror.New(409, "change request is no longer pending")
	}
	rev := cr.BaseRevision + 1
	doc := &RevisionDoc{
		ID: id.Generate("rev_", 12), VaultID: vaultID, Env: env, Revision: rev,
		ParentRevision: cr.BaseRevision, KeyVersion: cr.KeyVersion,
		Ciphertext: cr.Ciphertext, Signature: cr.Signature,
		AuthorUserID: cr.AuthorUserID, AuthorEd25519PublicKey: cr.AuthorEd25519PublicKey,
		AuthorFingerprint: cr.AuthorFingerprint, ChangeRequestID: cr.ID, CreatedAt: time.Now(),
	}
	if err := s.Store.InsertRevision(ctx, doc); err != nil {
		if err == ErrRevisionExists {
			_, _ = s.Store.TransitionChangeRequest(ctx, crID, CRApproved, CRStale, userID)
			return nil, apperror.WithCode(409, "stale", "head moved; change request is stale")
		}
		return nil, apperror.ErrInternal
	}
	_ = s.Store.BumpHead(ctx, vaultID, env, rev)
	s.audit.Record(ctx, audit.Entry{
		WorkspaceID: workspaceID, Action: "vault.change_request.approved",
		TargetType: "vault", TargetID: vaultID, Details: map[string]any{"id": crID, "revision": rev},
	})
	s.emit(ctx, vaultID, events.Revision, map[string]any{"env": env, "revision": rev})
	s.emit(ctx, vaultID, events.ChangeRequest, map[string]any{"env": env, "id": crID, "status": CRApproved})
	return revisionResponse(doc, true), nil
}

func (s *Service) RejectChangeRequest(ctx context.Context, workspaceID, vaultID, env, crID, userID, email string) error {
	a, err := s.resolve(ctx, workspaceID, vaultID, userID, email)
	if err != nil {
		return err
	}
	if !a.isVaultAdmin() {
		return apperror.WithCode(403, "no_access", "vault admin required")
	}
	cr, err := s.Store.FindChangeRequest(ctx, crID)
	if err != nil {
		return apperror.ErrInternal
	}
	if cr == nil || cr.VaultID != vaultID || cr.Env != env {
		return apperror.New(404, "change request not found")
	}
	ok, err := s.Store.TransitionChangeRequest(ctx, crID, CRPending, CRRejected, userID)
	if err != nil {
		return apperror.ErrInternal
	}
	if !ok {
		return apperror.New(400, "change request is not pending")
	}
	s.audit.Record(ctx, audit.Entry{
		WorkspaceID: workspaceID, Action: "vault.change_request.rejected",
		TargetType: "vault", TargetID: vaultID, Details: map[string]any{"id": crID},
	})
	s.emit(ctx, vaultID, events.ChangeRequest, map[string]any{"env": env, "id": crID, "status": CRRejected})
	return nil
}

func (s *Service) Rekey(ctx context.Context, workspaceID, vaultID, env, userID, email string, req RekeyRequest) (*RevisionResponse, error) {
	a, err := s.resolve(ctx, workspaceID, vaultID, userID, email)
	if err != nil {
		return nil, err
	}
	if !a.isVaultAdmin() {
		return nil, apperror.WithCode(403, "no_access", "vault admin required")
	}
	if err := a.requireRead(env); err != nil {
		return nil, err
	}
	e := a.Vault.env(env)
	if req.NewKeyVersion != e.KeyVersion+1 {
		return nil, apperror.New(400, "new_key_version must be current + 1")
	}
	ok, err := s.Store.HasGrant(ctx, vaultID, env, e.KeyVersion, RecipientUser, userID)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	if !ok {
		return nil, apperror.WithCode(403, "no_access", "you do not hold the current key")
	}

	entitled, missing, err := s.entitledRecipients(ctx, a.Vault, env)
	if err != nil {
		return nil, err
	}
	covered := map[string]GrantInput{}
	for _, g := range req.Grants {
		if g.Env != "" && g.Env != env {
			return nil, apperror.New(400, "grant env mismatch")
		}
		rt := g.RecipientType
		if rt == "" {
			rt = RecipientUser
		}
		covered[rt+"|"+g.RecipientID] = g
	}
	var miss []map[string]string
	for _, rec := range entitled {
		if rec.keyType == KeyTypeToken {
			continue
		}
		g, ok := covered[rec.typ+"|"+rec.id]
		if !ok {
			miss = append(miss, map[string]string{"recipient_type": rec.typ, "recipient_id": rec.id, "key_type": rec.keyType})
			continue
		}
		if err := validateWrappedKey(rec.typ, rec.keyType, g.WrappedKey); err != nil {
			return nil, err
		}
	}
	if len(miss) > 0 {
		return nil, apperror.WithCode(400, "missing_grants", "grants must cover every entitled recipient").With("missing", miss)
	}
	_ = missing

	now := time.Now()
	docs := make([]Grant, 0, len(req.Grants))
	ids := make([]string, 0, len(req.Grants))
	for _, g := range req.Grants {
		rt := g.RecipientType
		if rt == "" {
			rt = RecipientUser
		}
		gid := id.Generate("gr_", 12)
		ids = append(ids, gid)
		docs = append(docs, Grant{
			ID: gid, VaultID: vaultID, Env: env, KeyVersion: req.NewKeyVersion,
			RecipientType: rt, RecipientID: g.RecipientID, WrappedKey: g.WrappedKey,
			GrantedBy: userID, CreatedAt: now,
		})
	}

	var revDoc *RevisionDoc
	if e.HeadRevision > 0 {
		if req.Revision == nil {
			return nil, apperror.New(400, "revision is required when the environment has a head")
		}
		if req.Revision.BaseRevision != e.HeadRevision {
			return nil, apperror.WithCode(409, "conflict", "base_revision is not the head").With("head_revision", e.HeadRevision)
		}
		if err := validateCiphertext(req.Revision.Ciphertext, req.Revision.Signature); err != nil {
			return nil, err
		}
		pub, err := s.publicOf(ctx, userID)
		if err != nil {
			return nil, err
		}
		if pub == nil {
			return nil, apperror.WithCode(400, "no_keys", "upload account keys first")
		}
		rev := e.HeadRevision + 1
		if !VerifyRevisionSignature(pub.Ed25519PublicKey, vaultID, env, rev, e.HeadRevision, req.NewKeyVersion, req.Revision.Ciphertext, req.Revision.Signature) {
			return nil, apperror.WithCode(400, "bad_signature", "revision signature is invalid")
		}
		revDoc = &RevisionDoc{
			ID: id.Generate("rev_", 12), VaultID: vaultID, Env: env, Revision: rev,
			ParentRevision: e.HeadRevision, KeyVersion: req.NewKeyVersion,
			Ciphertext: req.Revision.Ciphertext, Signature: req.Revision.Signature,
			AuthorUserID: userID, AuthorEd25519PublicKey: pub.Ed25519PublicKey,
			AuthorFingerprint: pub.Fingerprint, CreatedAt: now,
		}
	}

	var tokenIDs []string
	machines, _ := s.Store.ListMachines(ctx, vaultID, env)
	for _, m := range machines {
		if m.KeyType == KeyTypeToken && m.active(now) {
			tokenIDs = append(tokenIDs, m.ID)
		}
	}

	err = s.Store.withTx(ctx, func(ctx context.Context) error {
		if err := s.Store.InsertGrants(ctx, docs); err != nil {
			return err
		}
		if revDoc != nil {
			if err := s.Store.InsertRevision(ctx, revDoc); err != nil {
				return err
			}
		}
		head := e.HeadRevision
		if revDoc != nil {
			head = revDoc.Revision
		}
		ok, err := s.Store.CommitRekey(ctx, vaultID, env, e.KeyVersion, req.NewKeyVersion, head)
		if err != nil {
			return err
		}
		if !ok {
			return apperror.New(409, "environment key_version changed")
		}
		if len(tokenIDs) > 0 {
			_ = s.Store.RevokeMachines(ctx, tokenIDs, "rekey")
			_ = s.Store.DeleteMachineGrants(ctx, vaultID, tokenIDs)
		}
		return nil
	})
	if err != nil {
		if _, ok := err.(*apperror.Error); ok {
			_ = s.Store.DeleteGrantsByID(ctx, ids)
			return nil, err
		}
		_ = s.Store.DeleteGrantsByID(ctx, ids)
		return nil, apperror.ErrInternal
	}
	s.audit.Record(ctx, audit.Entry{
		WorkspaceID: workspaceID, Action: "vault.rekeyed",
		TargetType: "vault", TargetID: vaultID,
		Details: map[string]any{"env": env, "key_version": req.NewKeyVersion},
	})
	s.emit(ctx, vaultID, events.Members, map[string]any{"env": env})
	if revDoc != nil {
		s.emit(ctx, vaultID, events.Revision, map[string]any{"env": env, "revision": revDoc.Revision})
		return revisionResponse(revDoc, true), nil
	}
	return &RevisionResponse{VaultID: vaultID, Env: env, KeyVersion: req.NewKeyVersion, Revision: e.HeadRevision}, nil
}

type entitled struct {
	typ, id, keyType string
}

func (s *Service) entitledRecipients(ctx context.Context, v *Vault, env string) ([]entitled, []entitled, error) {
	members, err := s.Store.ListMembers(ctx, v.ID)
	if err != nil {
		return nil, nil, apperror.ErrInternal
	}
	ids := make([]string, 0, len(members))
	for _, m := range members {
		if m.permission(env) != "" {
			ids = append(ids, m.UserID)
		}
	}
	pubs := map[string]AccountPub{}
	if s.keys != nil {
		pubs, err = s.keys.PublicMany(ctx, ids)
		if err != nil {
			return nil, nil, apperror.ErrInternal
		}
	}
	var have, missing []entitled
	for _, id := range ids {
		if _, ok := pubs[id]; ok {
			have = append(have, entitled{typ: RecipientUser, id: id, keyType: KeyTypeX25519})
		} else {
			missing = append(missing, entitled{typ: RecipientUser, id: id, keyType: KeyTypeX25519})
		}
	}
	machines, err := s.Store.ListMachines(ctx, v.ID, env)
	if err != nil {
		return nil, nil, apperror.ErrInternal
	}
	now := time.Now()
	for _, m := range machines {
		if !m.active(now) {
			continue
		}
		have = append(have, entitled{typ: RecipientMachine, id: m.ID, keyType: m.KeyType})
	}
	return have, missing, nil
}

func (s *Service) publicOf(ctx context.Context, userID string) (*AccountPub, error) {
	if s.keys == nil {
		return nil, nil
	}
	return s.keys.Public(ctx, userID)
}

func (s *Service) memberResponse(ctx context.Context, vaultID, userID string) (*MemberResponse, error) {
	mem, err := s.Store.FindMember(ctx, vaultID, userID)
	if err != nil || mem == nil {
		return nil, apperror.ErrInternal
	}
	var u DirectoryUser
	if s.dir != nil {
		list, _ := s.dir.FindUsersByIDs(ctx, []string{userID})
		if len(list) > 0 {
			u = list[0]
		}
	}
	pub, _ := s.publicOf(ctx, userID)
	return &MemberResponse{
		UserID: userID, Name: u.Name, Email: u.Email, Role: mem.Role,
		EnvAccess: accessResponses(mem.EnvAccess), HasKeys: pub != nil, Fingerprint: fingerprintOf(pub),
	}, nil
}

func fingerprintOf(p *AccountPub) string {
	if p == nil {
		return ""
	}
	return p.Fingerprint
}

func machineFingerprint(m Machine) string {
	if len(m.PublicKey) == 0 {
		return ""
	}
	return keys.FingerprintKey(m.PublicKey)
}

func lostEnvs(old, neu []EnvAccess) []string {
	keep := map[string]bool{}
	for _, a := range neu {
		keep[a.Env] = true
	}
	var lost []string
	for _, a := range old {
		if !keep[a.Env] {
			lost = append(lost, a.Env)
		}
	}
	return lost
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
