package vault

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/zain-23/local-vault/apps/server/internal/audit"
	"github.com/zain-23/local-vault/apps/server/internal/common/apperror"
	"github.com/zain-23/local-vault/apps/server/internal/common/id"
	"github.com/zain-23/local-vault/apps/server/internal/config"
	"github.com/zain-23/local-vault/apps/server/internal/email"
)

// Service holds the vault domain's business logic.
type Service struct {
	Store     *Store
	audit     audit.Recorder
	dir       Directory
	publisher *email.Publisher
	cfg       config.Config
}

func NewService(store *Store, recorder audit.Recorder, dir Directory, pub *email.Publisher, cfg config.Config) *Service {
	return &Service{Store: store, audit: recorder, dir: dir, publisher: pub, cfg: cfg}
}

// getScoped loads a vault and enforces it belongs to workspaceID, else 404.
func (s *Service) getScoped(ctx context.Context, workspaceID, vaultID string) (*Vault, error) {
	v, err := s.Store.FindVaultByID(ctx, vaultID)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	if v == nil || v.WorkspaceID != workspaceID {
		return nil, apperror.New(404, "vault not found")
	}
	return v, nil
}

// Create registers a vault with the caller's device as the first peer.
func (s *Service) Create(ctx context.Context, workspaceID, createdBy string, req CreateVaultRequest) (*CreateVaultResponse, error) {
	now := time.Now()
	v := &Vault{
		ID:            id.Generate("vlt_", 12),
		WorkspaceID:   workspaceID,
		Name:          req.Name,
		CreatedBy:     createdBy,
		OwnerDeviceID: req.OwnerDeviceID,
		Peers: []Peer{{
			DeviceID:        req.OwnerDeviceID,
			DeviceName:      req.OwnerName,
			PublicKey:       req.PublicKey,
			X25519PublicKey: req.X25519PublicKey,
			UserID:          createdBy,
			JoinedAt:        now,
		}},
		Tokens:    []Token{},
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.Store.CreateVault(ctx, v); err != nil {
		return nil, apperror.ErrInternal
	}

	s.audit.Record(ctx, audit.Entry{
		WorkspaceID: workspaceID,
		Action:      "vault.created",
		TargetType:  "vault",
		TargetID:    v.ID,
		TargetName:  v.Name,
	})

	return &CreateVaultResponse{VaultID: v.ID, CreatedAt: v.CreatedAt}, nil
}

// List returns every vault in the workspace as lightweight summaries.
func (s *Service) List(ctx context.Context, workspaceID string) ([]VaultSummary, error) {
	vaults, err := s.Store.ListVaultsByWorkspace(ctx, workspaceID)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	out := make([]VaultSummary, 0, len(vaults))
	for _, v := range vaults {
		out = append(out, VaultSummary{
			ID:            v.ID,
			Name:          v.Name,
			OwnerDeviceID: v.OwnerDeviceID,
			PeerCount:     len(v.Peers),
			HasSnapshot:   len(v.Snapshot) > 0,
			CreatedAt:     v.CreatedAt,
			UpdatedAt:     v.UpdatedAt,
		})
	}
	return out, nil
}

// Get returns the detail view (with peers) for one vault.
func (s *Service) Get(ctx context.Context, workspaceID, vaultID string) (*VaultResponse, error) {
	v, err := s.getScoped(ctx, workspaceID, vaultID)
	if err != nil {
		return nil, err
	}
	peers, err := s.enrichPeers(ctx, v.Peers)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	return &VaultResponse{
		ID:            v.ID,
		Name:          v.Name,
		WorkspaceID:   v.WorkspaceID,
		CreatedBy:     v.CreatedBy,
		OwnerDeviceID: v.OwnerDeviceID,
		Peers:         peers,
		CreatedAt:     v.CreatedAt,
		UpdatedAt:     v.UpdatedAt,
	}, nil
}

func (s *Service) enrichPeers(ctx context.Context, peers []Peer) ([]PeerResponse, error) {
	ids := make([]string, 0, len(peers))
	seen := map[string]struct{}{}
	for _, p := range peers {
		if p.UserID == "" {
			continue
		}
		if _, ok := seen[p.UserID]; ok {
			continue
		}
		seen[p.UserID] = struct{}{}
		ids = append(ids, p.UserID)
	}
	byID := map[string]DirectoryUser{}
	if len(ids) > 0 && s.dir != nil {
		users, err := s.dir.FindUsersByIDs(ctx, ids)
		if err != nil {
			return nil, err
		}
		for _, u := range users {
			byID[u.ID] = u
		}
	}
	out := make([]PeerResponse, 0, len(peers))
	for _, p := range peers {
		pr := PeerResponse{
			DeviceID:        p.DeviceID,
			DeviceName:      p.DeviceName,
			PublicKey:       p.PublicKey,
			X25519PublicKey: p.X25519PublicKey,
			UserID:          p.UserID,
			JoinedAt:        p.JoinedAt,
		}
		if u, ok := byID[p.UserID]; ok {
			pr.Name = u.Name
			pr.Email = u.Email
		}
		out = append(out, pr)
	}
	return out, nil
}

// Delete removes a vault (route restricts this to owner/admin).
func (s *Service) Delete(ctx context.Context, workspaceID, vaultID string) error {
	v, err := s.getScoped(ctx, workspaceID, vaultID)
	if err != nil {
		return err
	}
	if err := s.Store.DeleteVault(ctx, vaultID); err != nil {
		return apperror.ErrInternal
	}

	s.audit.Record(ctx, audit.Entry{
		WorkspaceID: workspaceID,
		Action:      "vault.deleted",
		TargetType:  "vault",
		TargetID:    vaultID,
		TargetName:  v.Name,
	})

	return nil
}

// PushSnapshot stores a new encrypted snapshot. deviceID is the caller's P2P id;
// only an existing peer may push.
func (s *Service) PushSnapshot(ctx context.Context, workspaceID, vaultID, deviceID string, snapshot []byte) (*SnapshotResponse, error) {
	v, err := s.getScoped(ctx, workspaceID, vaultID)
	if err != nil {
		return nil, err
	}
	if !hasPeer(v, deviceID) {
		return nil, apperror.New(403, "device is not a vault peer")
	}
	if err := s.Store.SetSnapshot(ctx, vaultID, snapshot); err != nil {
		return nil, apperror.ErrInternal
	}

	s.audit.Record(ctx, audit.Entry{
		WorkspaceID: workspaceID,
		Action:      "vault.push",
		TargetType:  "vault",
		TargetID:    vaultID,
		TargetName:  v.Name,
		Details:     map[string]any{"device_id": deviceID, "bytes": len(snapshot)},
	})

	return &SnapshotResponse{Snapshot: snapshot, UpdatedAt: time.Now()}, nil
}

// PullSnapshot returns the encrypted snapshot. If a P2P device id is supplied it
// must still be a peer — a removed device gets 403, not stale data.
func (s *Service) PullSnapshot(ctx context.Context, workspaceID, vaultID, deviceID string) (*SnapshotResponse, error) {
	v, err := s.getScoped(ctx, workspaceID, vaultID)
	if err != nil {
		return nil, err
	}
	if deviceID != "" && !hasPeer(v, deviceID) {
		return nil, apperror.New(403, "access revoked")
	}
	if len(v.Snapshot) == 0 {
		return nil, apperror.New(404, "no snapshot yet")
	}
	return &SnapshotResponse{Snapshot: v.Snapshot, UpdatedAt: v.UpdatedAt}, nil
}

// RemovePeer deauthorizes a peer (route restricts this to owner/admin).
func (s *Service) RemovePeer(ctx context.Context, workspaceID, vaultID, deviceID string) error {
	v, err := s.getScoped(ctx, workspaceID, vaultID)
	if err != nil {
		return err
	}
	ok, err := s.Store.RemovePeer(ctx, vaultID, deviceID)
	if err != nil {
		return apperror.ErrInternal
	}
	if !ok {
		return apperror.New(404, "peer not found")
	}

	s.audit.Record(ctx, audit.Entry{
		WorkspaceID: workspaceID,
		Action:      "vault.peer.removed",
		TargetType:  "vault",
		TargetID:    vaultID,
		TargetName:  v.Name,
		Details:     map[string]any{"device_id": deviceID},
	})

	return nil
}

// CreateToken adds a join token to a vault and returns its public view.
func (s *Service) CreateToken(ctx context.Context, workspaceID, vaultID string, req CreateTokenRequest) (*TokenResponse, error) {
	if _, err := s.getScoped(ctx, workspaceID, vaultID); err != nil {
		return nil, err
	}
	tok := Token{
		ID:         id.Generate("lv_join_", 12),
		Name:       req.Name,
		WrappedDEK: req.WrappedDEK,
		Verifier:   req.Verifier,
		CreatedAt:  time.Now(),
		ExpiresAt:  req.ExpiresAt,
		Revoked:    false,
	}
	if err := s.Store.AddToken(ctx, vaultID, tok); err != nil {
		return nil, apperror.ErrInternal
	}

	s.audit.Record(ctx, audit.Entry{
		WorkspaceID: workspaceID,
		Action:      "vault.token.created",
		TargetType:  "vault",
		TargetID:    vaultID,
		TargetName:  tok.Name,
	})

	return &TokenResponse{ID: tok.ID, Name: tok.Name, CreatedAt: tok.CreatedAt, ExpiresAt: tok.ExpiresAt}, nil
}

// ListTokens returns only active (non-revoked, non-expired) tokens, public fields only.
func (s *Service) ListTokens(ctx context.Context, workspaceID, vaultID string) (*ListTokensResponse, error) {
	v, err := s.getScoped(ctx, workspaceID, vaultID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := make([]TokenResponse, 0, len(v.Tokens))
	for _, t := range v.Tokens {
		if !tokenActive(t, now) {
			continue
		}
		out = append(out, TokenResponse{ID: t.ID, Name: t.Name, CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt})
	}
	return &ListTokensResponse{Tokens: out}, nil
}

// RevokeToken marks a token revoked so it can no longer be used to join.
func (s *Service) RevokeToken(ctx context.Context, workspaceID, vaultID, tokenID string) error {
	v, err := s.getScoped(ctx, workspaceID, vaultID)
	if err != nil {
		return err
	}
	var tokenName string
	for _, t := range v.Tokens {
		if t.ID == tokenID {
			tokenName = t.Name
			break
		}
	}
	ok, err := s.Store.RevokeToken(ctx, vaultID, tokenID)
	if err != nil {
		return apperror.ErrInternal
	}
	if !ok {
		return apperror.New(404, "token not found")
	}

	s.audit.Record(ctx, audit.Entry{
		WorkspaceID: workspaceID,
		Action:      "vault.token.revoked",
		TargetName:  tokenName,
		TargetType:  "vault",
		TargetID:    vaultID,
	})

	return nil
}

// InviteCollaborator creates a pending short-code invite and emails the code.
// The CLI wraps the DEK with the code before calling this.
func (s *Service) InviteCollaborator(ctx context.Context, workspaceID, vaultID, invitedBy string, req InviteCollaboratorRequest) (*CollaboratorResponse, error) {
	v, err := s.getScoped(ctx, workspaceID, vaultID)
	if err != nil {
		return nil, err
	}
	if !hasPeer(v, req.DeviceID) {
		return nil, apperror.New(403, "device is not a vault peer")
	}
	if s.dir == nil {
		return nil, apperror.ErrInternal
	}

	code := normalizeJoinCode(req.Code)
	if !validJoinCode(code) {
		return nil, apperror.New(400, "invalid join code format")
	}
	if len(req.WrappedDEK) == 0 {
		return nil, apperror.New(400, "wrapped_dek is required")
	}

	addr := normalizeEmail(req.Email)
	user, err := s.dir.FindUserByEmail(ctx, addr)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	if user == nil {
		return nil, apperror.New(404, "no account with this email — invite them to the workspace first")
	}
	ok, err := s.dir.MembershipExists(ctx, workspaceID, user.ID)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	if !ok {
		return nil, apperror.New(400, "user must be a workspace member before vault invite")
	}

	for _, p := range v.Peers {
		if p.UserID == user.ID {
			return nil, apperror.New(409, "user already has a device in this vault")
		}
	}
	existing, err := s.Store.FindOpenCollaborator(ctx, vaultID, addr)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	if existing != nil {
		return nil, apperror.New(409, "an invite is already pending for this email")
	}

	codeHash := sha256Hex(code)
	if clash, err := s.Store.FindCollaboratorByCodeHash(ctx, codeHash); err != nil {
		return nil, apperror.ErrInternal
	} else if clash != nil {
		return nil, apperror.New(409, "join code collision — try again")
	}

	now := time.Now()
	c := &Collaborator{
		ID:          id.Generate("vc_", 12),
		VaultID:     vaultID,
		WorkspaceID: workspaceID,
		UserID:      user.ID,
		Email:       addr,
		InvitedBy:   invitedBy,
		Status:      CollabPending,
		CodeHash:    codeHash,
		WrappedDEK:  req.WrappedDEK,
		CreatedAt:   now,
		UpdatedAt:   now,
		ExpiresAt:   now.Add(7 * 24 * time.Hour),
	}
	if err := s.Store.CreateCollaborator(ctx, c); err != nil {
		return nil, apperror.ErrInternal
	}

	job := email.EmailJob{
		Kind: email.KindVaultCollaboratorInvite,
		To:   addr,
		Name: v.Name,
		Code: code,
	}
	if s.publisher != nil {
		if err := s.publisher.Publish(ctx, job); err != nil {
			log.Printf("⚠️ failed to enqueue vault collaborator email for %s: %v", addr, err)
		}
	}

	s.audit.Record(ctx, audit.Entry{
		WorkspaceID: workspaceID,
		Action:      "vault.collaborator.invited",
		TargetType:  "vault",
		TargetID:    vaultID,
		TargetName:  addr,
		Details:     map[string]any{"collaborator_id": c.ID, "user_id": user.ID},
	})

	return toCollaboratorResponse(c), nil
}

func (s *Service) ListCollaborators(ctx context.Context, workspaceID, vaultID string) ([]CollaboratorResponse, error) {
	if _, err := s.getScoped(ctx, workspaceID, vaultID); err != nil {
		return nil, err
	}
	list, err := s.Store.ListCollaboratorsByVault(ctx, vaultID)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	out := make([]CollaboratorResponse, 0, len(list))
	for i := range list {
		out = append(out, *toCollaboratorResponse(&list[i]))
	}
	return out, nil
}

func (s *Service) RevokeCollaborator(ctx context.Context, workspaceID, vaultID, collabID string) error {
	if _, err := s.getScoped(ctx, workspaceID, vaultID); err != nil {
		return err
	}
	c, err := s.Store.FindCollaboratorByID(ctx, collabID)
	if err != nil {
		return apperror.ErrInternal
	}
	if c == nil || c.VaultID != vaultID {
		return apperror.New(404, "invite not found")
	}
	if c.Status == CollabActive || c.Status == CollabRevoked {
		return apperror.New(400, "cannot revoke this invite")
	}
	if err := s.Store.UpdateCollaborator(ctx, collabID, bson.M{"status": CollabRevoked}); err != nil {
		return apperror.ErrInternal
	}
	s.audit.Record(ctx, audit.Entry{
		WorkspaceID: workspaceID,
		Action:      "vault.collaborator.revoked",
		TargetType:  "vault",
		TargetID:    vaultID,
		TargetName:  c.Email,
		Details:     map[string]any{"collaborator_id": collabID},
	})
	return nil
}

// JoinByCode completes an emailed short-code invite: add peer + return wrapped DEK.
func (s *Service) JoinByCode(ctx context.Context, userID, userEmail string, req JoinByCodeRequest) (*JoinResponse, error) {
	code := normalizeJoinCode(req.Code)
	if !validJoinCode(code) {
		return nil, apperror.New(404, "invalid or expired invite code")
	}
	c, err := s.Store.FindCollaboratorByCodeHash(ctx, sha256Hex(code))
	if err != nil {
		return nil, apperror.ErrInternal
	}
	if c == nil || c.Status != CollabPending {
		return nil, apperror.New(404, "invalid or expired invite code")
	}
	if time.Now().After(c.ExpiresAt) {
		return nil, apperror.New(404, "invalid or expired invite code")
	}
	if c.UserID != userID && normalizeEmail(userEmail) != c.Email {
		return nil, apperror.New(403, "invite was sent to a different account")
	}
	if s.dir != nil {
		ok, err := s.dir.MembershipExists(ctx, c.WorkspaceID, userID)
		if err != nil {
			return nil, apperror.ErrInternal
		}
		if !ok {
			return nil, apperror.New(403, "join the workspace before joining this vault")
		}
	}

	v, err := s.getScoped(ctx, c.WorkspaceID, c.VaultID)
	if err != nil {
		return nil, err
	}
	if hasPeer(v, req.DeviceID) {
		return &JoinResponse{
			VaultID:     v.ID,
			WorkspaceID: v.WorkspaceID,
			Snapshot:    v.Snapshot,
			Peers:       v.Peers,
			WrappedDEK:  c.WrappedDEK,
			Message:     "already a peer",
		}, nil
	}

	peer := Peer{
		DeviceID:        req.DeviceID,
		DeviceName:      req.DeviceName,
		PublicKey:       req.PublicKey,
		X25519PublicKey: req.X25519PublicKey,
		UserID:          userID,
		JoinedAt:        time.Now(),
	}
	if err := s.Store.AddPeer(ctx, v.ID, peer); err != nil {
		return nil, apperror.ErrInternal
	}
	if err := s.Store.UpdateCollaborator(ctx, c.ID, bson.M{"status": CollabActive}); err != nil {
		return nil, apperror.ErrInternal
	}

	s.audit.Record(ctx, audit.Entry{
		WorkspaceID: v.WorkspaceID,
		Action:      "vault.collaborator.joined",
		TargetType:  "vault",
		TargetID:    v.ID,
		TargetName:  v.Name,
		Details:     map[string]any{"collaborator_id": c.ID, "device_id": req.DeviceID},
	})

	return &JoinResponse{
		VaultID:     v.ID,
		WorkspaceID: v.WorkspaceID,
		Snapshot:    v.Snapshot,
		Peers:       append(v.Peers, peer),
		WrappedDEK:  c.WrappedDEK,
	}, nil
}

// Join adds the caller as a peer using a join token. Legacy path; prefer collaborators.
func (s *Service) Join(ctx context.Context, req JoinRequest, userID string) (*JoinResponse, error) {
	v, err := s.Store.FindVaultByTokenID(ctx, req.Token)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	if v == nil {
		return nil, apperror.New(404, "invalid or expired token")
	}

	if userID != "" && s.dir != nil {
		ok, err := s.dir.MembershipExists(ctx, v.WorkspaceID, userID)
		if err != nil {
			return nil, apperror.ErrInternal
		}
		if !ok {
			return nil, apperror.New(403, "join the workspace before joining this vault")
		}
	}

	var tok *Token
	for i := range v.Tokens {
		if v.Tokens[i].ID == req.Token {
			tok = &v.Tokens[i]
			break
		}
	}
	if tok == nil || !tokenActive(*tok, time.Now()) {
		return nil, apperror.New(404, "invalid or expired token")
	}
	if !verifierMatches(tok.Verifier, req.Verifier) {
		return nil, apperror.New(404, "invalid or expired token")
	}

	if hasPeer(v, req.DeviceID) {
		return &JoinResponse{
			VaultID:     v.ID,
			WorkspaceID: v.WorkspaceID,
			Snapshot:    v.Snapshot,
			Peers:       v.Peers,
			WrappedDEK:  tok.WrappedDEK,
			Message:     "already a peer",
		}, nil
	}

	peer := Peer{
		DeviceID:        req.DeviceID,
		DeviceName:      req.DeviceName,
		PublicKey:       req.PublicKey,
		X25519PublicKey: req.X25519PublicKey,
		UserID:          userID,
		JoinedAt:        time.Now(),
	}
	if err := s.Store.AddPeer(ctx, v.ID, peer); err != nil {
		return nil, apperror.ErrInternal
	}

	s.audit.Record(ctx, audit.Entry{
		WorkspaceID: v.WorkspaceID,
		Action:      "vault.peer.joined",
		TargetType:  "vault",
		TargetID:    v.ID,
		TargetName:  v.Name,
		Details:     map[string]any{"device_id": req.DeviceID, "device_name": req.DeviceName},
	})

	return &JoinResponse{
		VaultID:     v.ID,
		WorkspaceID: v.WorkspaceID,
		Snapshot:    v.Snapshot,
		Peers:       append(v.Peers, peer),
		WrappedDEK:  tok.WrappedDEK,
	}, nil
}

// SendMessage queues one offline message with a 48h TTL.
func (s *Service) SendMessage(ctx context.Context, req SendMessageRequest) (*SendMessageResponse, error) {
	now := time.Now()
	m := &PendingMessage{
		ID:            id.Generate("msg_", 12),
		ForDeviceID:   req.ForDeviceID,
		FromDeviceID:  req.FromDeviceID,
		FromPublicKey: req.FromPublicKey,
		Payload:       req.Payload,
		CreatedAt:     now,
		ExpiresAt:     now.Add(MessageTTL),
	}
	if err := s.Store.CreateMessage(ctx, m); err != nil {
		return nil, apperror.ErrInternal
	}
	return &SendMessageResponse{ID: m.ID, Success: true}, nil
}

// GetMessages drains the offline queue for a device.
func (s *Service) GetMessages(ctx context.Context, deviceID string) (*MessagesResponse, error) {
	msgs, err := s.Store.DrainMessages(ctx, deviceID)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	return &MessagesResponse{Messages: msgs, Count: len(msgs)}, nil
}

func toCollaboratorResponse(c *Collaborator) *CollaboratorResponse {
	return &CollaboratorResponse{
		ID:        c.ID,
		VaultID:   c.VaultID,
		UserID:    c.UserID,
		Email:     c.Email,
		InvitedBy: c.InvitedBy,
		Status:    c.Status,
		CreatedAt: c.CreatedAt,
		ExpiresAt: c.ExpiresAt,
	}
}
