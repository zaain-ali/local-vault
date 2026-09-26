package machine

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"github.com/zain-23/local-vault/apps/server/internal/audit"
	"github.com/zain-23/local-vault/apps/server/internal/common/apperror"
	"github.com/zain-23/local-vault/apps/server/internal/common/id"
	"github.com/zain-23/local-vault/apps/server/internal/common/jwt"
	"github.com/zain-23/local-vault/apps/server/internal/config"
	"github.com/zain-23/local-vault/apps/server/internal/events"
	"github.com/zain-23/local-vault/apps/server/internal/vault"
)

type Service struct {
	store *Store
	vault *vault.Service
	jwt   *jwt.Service
	audit audit.Recorder
	bus   events.Publisher
	cfg   config.Config
	http  *http.Client
}

func NewService(store *Store, vs *vault.Service, jwtSvc *jwt.Service, rec audit.Recorder, bus events.Publisher, cfg config.Config) *Service {
	return &Service{store: store, vault: vs, jwt: jwtSvc, audit: rec, bus: bus, cfg: cfg, http: &http.Client{Timeout: 10 * time.Second}}
}

type CreateRequest struct {
	ID            string     `json:"id"`
	Name          string     `json:"name" validate:"required"`
	Env           string     `json:"env" validate:"required"`
	Kind          string     `json:"kind" validate:"required"`
	KeyType       string     `json:"key_type" validate:"required"`
	PublicKey     []byte     `json:"public_key"`
	KeyRef        string     `json:"key_ref"`
	TokenVerifier string     `json:"token_verifier"`
	OIDC          *OIDCSpec  `json:"oidc"`
	AWS           *AWSSpec   `json:"aws"`
	ExpiresAt     *time.Time `json:"expires_at"`
	Grant         struct {
		KeyVersion int    `json:"key_version"`
		WrappedKey []byte `json:"wrapped_key"`
	} `json:"grant"`
}

func (s *Service) Create(ctx context.Context, workspaceID, vaultID, userID, email string, req CreateRequest) (*Identity, error) {
	a, err := s.vault.ResolveForMachine(ctx, workspaceID, vaultID, userID, email)
	if err != nil {
		return nil, err
	}
	if !a.IsVaultAdmin() {
		return nil, apperror.WithCode(403, "no_access", "vault admin required")
	}
	if a.Vault.Env(req.Env) == nil {
		return nil, apperror.New(400, "unknown environment")
	}
	kind := strings.ToLower(req.Kind)
	keyType := strings.ToLower(req.KeyType)
	mid := strings.TrimSpace(req.ID)
	if mid == "" {
		mid = id.Generate("mi_", 12)
	}
	if !strings.HasPrefix(mid, "mi_") {
		return nil, apperror.New(400, "machine id must start with mi_")
	}
	now := time.Now()
	m := &Identity{
		ID: mid, WorkspaceID: workspaceID, VaultID: vaultID, Env: req.Env,
		Name: req.Name, Kind: kind, KeyType: keyType, PublicKey: req.PublicKey,
		KeyRef: req.KeyRef, OIDC: req.OIDC, AWS: req.AWS, CreatedBy: userID,
		CreatedAt: now, ExpiresAt: req.ExpiresAt,
	}
	switch kind {
	case KindToken:
		if req.TokenVerifier == "" {
			return nil, apperror.New(400, "token_verifier is required")
		}
		m.TokenVerifierHash = HashVerifier(req.TokenVerifier)
		if keyType == "" {
			m.KeyType = KeyTypeToken
		}
	case KindOIDC:
		if req.OIDC == nil || req.OIDC.Issuer == "" || req.OIDC.Subject == "" {
			return nil, apperror.New(400, "oidc.issuer and oidc.subject are required")
		}
		if req.OIDC.Audience == "" {
			req.OIDC.Audience = "localvault"
			m.OIDC.Audience = "localvault"
		}
	case KindAWS:
		if req.AWS == nil || req.AWS.RoleARN == "" {
			return nil, apperror.New(400, "aws.role_arn is required")
		}
	default:
		return nil, apperror.New(400, "kind must be token, oidc, or aws")
	}
	if err := s.store.Insert(ctx, m); err != nil {
		if err == ErrExists {
			return nil, apperror.New(409, "machine id already exists")
		}
		return nil, apperror.ErrInternal
	}
	if len(req.Grant.WrappedKey) > 0 {
		kv := req.Grant.KeyVersion
		if kv == 0 {
			kv = a.Vault.Env(req.Env).KeyVersion
		}
		_ = s.vault.Store.InsertGrants(ctx, []vault.Grant{{
			ID: id.Generate("gr_", 12), VaultID: vaultID, Env: req.Env, KeyVersion: kv,
			RecipientType: vault.RecipientMachine, RecipientID: mid, WrappedKey: req.Grant.WrappedKey,
			GrantedBy: userID, CreatedAt: now,
		}})
	}
	s.audit.Record(ctx, audit.Entry{
		WorkspaceID: workspaceID, Action: "vault.machine.created",
		TargetType: "machine", TargetID: mid, TargetName: req.Name,
	})
	if s.bus != nil {
		s.bus.Publish(ctx, vaultID, events.GrantsPending, map[string]any{"env": req.Env})
	}
	m.TokenVerifierHash = ""
	return m, nil
}

func (s *Service) List(ctx context.Context, workspaceID, vaultID, userID, email string) ([]Identity, error) {
	if _, err := s.vault.ResolveForMachine(ctx, workspaceID, vaultID, userID, email); err != nil {
		return nil, err
	}
	return s.store.List(ctx, vaultID)
}

func (s *Service) Revoke(ctx context.Context, workspaceID, vaultID, machineID, userID, email string) error {
	a, err := s.vault.ResolveForMachine(ctx, workspaceID, vaultID, userID, email)
	if err != nil {
		return err
	}
	if !a.IsVaultAdmin() {
		return apperror.WithCode(403, "no_access", "vault admin required")
	}
	ok, err := s.store.Revoke(ctx, machineID, "revoked")
	if err != nil {
		return apperror.ErrInternal
	}
	if !ok {
		return apperror.New(404, "machine not found")
	}
	_ = s.store.DeleteGrants(ctx, vaultID, machineID)
	s.audit.Record(ctx, audit.Entry{
		WorkspaceID: workspaceID, Action: "vault.machine.revoked",
		TargetType: "machine", TargetID: machineID,
	})
	return nil
}

type LoginRequest struct {
	MachineID     string          `json:"machine_id" validate:"required"`
	Method        string          `json:"method" validate:"required"`
	TokenVerifier string          `json:"token_verifier"`
	JWT           string          `json:"jwt"`
	AWS           *AWSLoginProof  `json:"aws"`
}

type AWSLoginProof struct {
	Method  string              `json:"method"`
	URL     string              `json:"url"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
}

type LoginResponse struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
	WorkspaceID string    `json:"workspace_id"`
	VaultID     string    `json:"vault_id"`
	Env         string    `json:"env"`
}

func (s *Service) Login(ctx context.Context, req LoginRequest) (*LoginResponse, error) {
	m, err := s.store.Find(ctx, req.MachineID)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	if m == nil || m.Revoked || (m.ExpiresAt != nil && time.Now().After(*m.ExpiresAt)) {
		return nil, apperror.New(401, "invalid machine identity")
	}
	switch strings.ToLower(req.Method) {
	case KindToken:
		if m.Kind != KindToken || subtle.ConstantTimeCompare([]byte(HashVerifier(req.TokenVerifier)), []byte(m.TokenVerifierHash)) != 1 {
			return nil, apperror.New(401, "invalid machine identity")
		}
	case KindOIDC:
		if m.Kind != KindOIDC || !verifyOIDC(s.http, req.JWT, m.OIDC) {
			return nil, apperror.New(401, "invalid machine identity")
		}
	case KindAWS:
		if m.Kind != KindAWS || !verifyAWS(s.http, req.AWS, m.AWS, s.cfg.AWSServerID) {
			return nil, apperror.New(401, "invalid machine identity")
		}
	default:
		return nil, apperror.New(400, "method must be token, oidc, or aws")
	}
	tok, exp, err := s.jwt.GenerateMachineToken(m.ID, m.WorkspaceID, m.VaultID, m.Env)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	s.store.Touch(ctx, m.ID)
	return &LoginResponse{AccessToken: tok, ExpiresAt: exp, WorkspaceID: m.WorkspaceID, VaultID: m.VaultID, Env: m.Env}, nil
}

type SecretsResponse struct {
	WorkspaceID string                 `json:"workspace_id"`
	VaultID     string                 `json:"vault_id"`
	Env         string                 `json:"env"`
	KeyVersion  int                    `json:"key_version"`
	KeyType     string                 `json:"key_type"`
	WrappedKey  []byte                 `json:"wrapped_key"`
	KeyRef      string                 `json:"key_ref,omitempty"`
	Revision    *vault.RevisionResponse `json:"revision"`
}

func (s *Service) Secrets(ctx context.Context, mid, workspaceID, vaultID, env string) (*SecretsResponse, int, error) {
	m, err := s.store.Find(ctx, mid)
	if err != nil {
		return nil, 0, apperror.ErrInternal
	}
	if m == nil || m.Revoked || m.VaultID != vaultID || m.Env != env {
		return nil, 0, apperror.New(401, "invalid machine identity")
	}
	v, err := s.vault.Store.FindVault(ctx, vaultID)
	if err != nil || v == nil {
		return nil, 0, apperror.ErrInternal
	}
	e := v.Env(env)
	if e == nil {
		return nil, 0, apperror.New(404, "environment not found")
	}
	grants, err := s.vault.Store.ListRecipientGrants(ctx, vaultID, vault.RecipientMachine, mid)
	if err != nil {
		return nil, 0, apperror.ErrInternal
	}
	var wk []byte
	kv := e.KeyVersion
	for _, g := range grants {
		if g.Env == env && g.KeyVersion == e.KeyVersion {
			wk = g.WrappedKey
			kv = g.KeyVersion
			break
		}
	}
	if len(wk) == 0 {
		return nil, 0, apperror.WithCode(403, "no_access", "no grant for this environment")
	}
	head, err := s.vault.Store.FindRevision(ctx, vaultID, env, e.HeadRevision)
	if err != nil {
		return nil, 0, apperror.ErrInternal
	}
	rev := vault.EmptyHead(vaultID, env, e.KeyVersion)
	if head != nil {
		rev = vault.RevisionAsResponse(head)
	}
	return &SecretsResponse{
		WorkspaceID: workspaceID, VaultID: vaultID, Env: env, KeyVersion: kv,
		KeyType: m.KeyType, WrappedKey: wk, KeyRef: m.KeyRef, Revision: rev,
	}, e.HeadRevision, nil
}

// verifyAWS is implemented in aws.go; verifyOIDC in oidc.go.
