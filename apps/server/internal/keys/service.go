package keys

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/zain-23/local-vault/apps/server/internal/audit"
	"github.com/zain-23/local-vault/apps/server/internal/common/apperror"
)

// maxLookupIDs bounds GET /workspaces/:wid/keys?user_ids=.
const maxLookupIDs = 200

// DirectoryUser is display info for the public-key listing.
type DirectoryUser struct {
	ID    string
	Name  string
	Email string
}

// Directory resolves workspace membership and user display fields.
type Directory interface {
	// WorkspaceMemberIDs returns which of ids are members of the workspace
	// (every member when ids is empty).
	WorkspaceMemberIDs(ctx context.Context, workspaceID string, ids []string) ([]string, error)
	FindUsersByIDs(ctx context.Context, ids []string) ([]DirectoryUser, error)
}

// Hooks lets the vault domain react to key changes without an import cycle.
type Hooks interface {
	// KeysUploaded fires after a user uploads a bundle (vaults emit grants_pending).
	KeysUploaded(ctx context.Context, userID string)
	// KeysReset must delete every grant addressed to the user.
	KeysReset(ctx context.Context, userID string) error
}

type Service struct {
	store *Store
	dir   Directory
	hooks Hooks
	audit audit.Recorder
}

func NewService(store *Store, dir Directory, hooks Hooks, recorder audit.Recorder) *Service {
	return &Service{store: store, dir: dir, hooks: hooks, audit: recorder}
}

// Me returns the caller's bundle or 404 code=no_keys.
func (s *Service) Me(ctx context.Context, userID string) (*Bundle, error) {
	b, err := s.store.Get(ctx, userID)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	if b == nil {
		return nil, apperror.WithCode(404, "no_keys", "no account keys uploaded")
	}
	return b, nil
}

// Put stores the caller's first bundle; 409 code=keys_exist if one is set.
func (s *Service) Put(ctx context.Context, userID string, req PutKeysRequest) (*Bundle, error) {
	if err := ValidateBundle(req); err != nil {
		return nil, err
	}
	now := time.Now()
	b := &Bundle{
		UserID:               userID,
		Version:              req.Version,
		KDF:                  req.KDF,
		X25519PublicKey:      req.X25519PublicKey,
		Ed25519PublicKey:     req.Ed25519PublicKey,
		EncryptedPrivateKeys: req.EncryptedPrivateKeys,
		Fingerprint:          Fingerprint(req.X25519PublicKey, req.Ed25519PublicKey),
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := s.store.Insert(ctx, b); err != nil {
		if err == ErrExists {
			return nil, apperror.WithCode(409, "keys_exist", "account keys already exist; reset them first")
		}
		return nil, apperror.ErrInternal
	}
	s.audit.Record(ctx, audit.Entry{
		Action:     "keys.uploaded",
		TargetType: "user",
		TargetID:   userID,
		Details:    map[string]any{"fingerprint": b.Fingerprint},
	})
	if s.hooks != nil {
		s.hooks.KeysUploaded(ctx, userID)
	}
	return b, nil
}

// Reset deletes every grant addressed to the caller, then the bundle itself.
func (s *Service) Reset(ctx context.Context, userID string) error {
	if s.hooks != nil {
		if err := s.hooks.KeysReset(ctx, userID); err != nil {
			log.Printf("⚠️ keys reset: deleting grants for %s: %v", userID, err)
			return apperror.ErrInternal
		}
	}
	existed, err := s.store.Delete(ctx, userID)
	if err != nil {
		return apperror.ErrInternal
	}
	s.audit.Record(ctx, audit.Entry{
		Action:     "keys.reset",
		TargetType: "user",
		TargetID:   userID,
		Details:    map[string]any{"had_keys": existed},
	})
	return nil
}

// WorkspaceKeys lists public keys of workspace members (only those with keys).
func (s *Service) WorkspaceKeys(ctx context.Context, workspaceID, rawIDs string) ([]PublicKeyResponse, error) {
	var ids []string
	seen := map[string]bool{}
	for _, p := range strings.Split(rawIDs, ",") {
		p = strings.TrimSpace(p)
		if p != "" && !seen[p] {
			seen[p] = true
			ids = append(ids, p)
		}
	}
	if len(ids) > maxLookupIDs {
		return nil, apperror.New(400, "too many user_ids (max 200)")
	}
	memberIDs, err := s.dir.WorkspaceMemberIDs(ctx, workspaceID, ids)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	bundles, err := s.store.FindByUserIDs(ctx, memberIDs)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	withKeys := make([]string, 0, len(bundles))
	for _, id := range memberIDs {
		if _, ok := bundles[id]; ok {
			withKeys = append(withKeys, id)
		}
	}
	users := map[string]DirectoryUser{}
	if len(withKeys) > 0 {
		list, err := s.dir.FindUsersByIDs(ctx, withKeys)
		if err != nil {
			return nil, apperror.ErrInternal
		}
		for _, u := range list {
			users[u.ID] = u
		}
	}
	out := make([]PublicKeyResponse, 0, len(withKeys))
	for _, id := range withKeys {
		b := bundles[id]
		u := users[id]
		out = append(out, PublicKeyResponse{
			UserID:           id,
			Email:            u.Email,
			Name:             u.Name,
			X25519PublicKey:  b.X25519PublicKey,
			Ed25519PublicKey: b.Ed25519PublicKey,
			Fingerprint:      b.Fingerprint,
		})
	}
	return out, nil
}

// ValidateBundle enforces the protocol v4 bundle shape and KDF bounds and
// checks the client's fingerprint against the server's own computation.
func ValidateBundle(req PutKeysRequest) *apperror.Error {
	switch {
	case req.Version != BundleVersion:
		return apperror.New(400, "unsupported bundle version (want 1)")
	case len(req.X25519PublicKey) != KeyLen:
		return apperror.New(400, "x25519_public_key must be 32 bytes")
	case len(req.Ed25519PublicKey) != KeyLen:
		return apperror.New(400, "ed25519_public_key must be 32 bytes")
	case len(req.EncryptedPrivateKeys) < minEncryptedLen || len(req.EncryptedPrivateKeys) > maxEncryptedLen:
		return apperror.New(400, "encrypted_private_keys has an invalid length")
	case req.KDF.Alg != KDFAlg:
		return apperror.New(400, "kdf.alg must be argon2id")
	case len(req.KDF.Salt) < minSaltLen || len(req.KDF.Salt) > maxSaltLen:
		return apperror.New(400, "kdf.salt must be 16..64 bytes")
	case req.KDF.MemoryKiB < minMemoryKiB || req.KDF.MemoryKiB > maxMemoryKiB:
		return apperror.New(400, "kdf.memory_kib must be between 8192 and 1048576")
	case req.KDF.Time < minTime || req.KDF.Time > maxTime:
		return apperror.New(400, "kdf.time must be between 1 and 10")
	case req.KDF.Threads < minThreads || req.KDF.Threads > maxThreads:
		return apperror.New(400, "kdf.threads must be between 1 and 16")
	}
	if want := Fingerprint(req.X25519PublicKey, req.Ed25519PublicKey); strings.ToUpper(strings.TrimSpace(req.Fingerprint)) != want {
		return apperror.WithCode(400, "bad_fingerprint", "fingerprint does not match the public keys")
	}
	return nil
}
