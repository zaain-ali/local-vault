package vault

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type Store struct {
	vaults         *mongo.Collection
	messages       *mongo.Collection
	collaborators  *mongo.Collection
}

// NewStore create the store and its indexes
func NewStore(db *mongo.Database) *Store {
	s := &Store{
		vaults:        db.Collection("vaults"),
		messages:      db.Collection("pending_messages"),
		collaborators: db.Collection("vault_collaborators"),
	}

	ctx := context.TODO()

	// workspace_id - list a workspace's vaults quickly.
	s.vaults.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "workspace_id", Value: 1}},
	})

	s.vaults.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "tokens.id", Value: 1}},
	})

	// TTL — MongoDB auto-deletes a message once expires_at passes (no cleanup cron).
	s.messages.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "expires_at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(0),
	})
	// for_device_id — drain one device's queue quickly.
	s.messages.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "for_device_id", Value: 1}},
	})

	s.collaborators.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "vault_id", Value: 1}, {Key: "status", Value: 1}},
	})
	s.collaborators.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "vault_id", Value: 1}, {Key: "email", Value: 1}},
	})
	s.collaborators.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "code_hash", Value: 1}},
		Options: options.Index().SetUnique(true).SetSparse(true),
	})

	return s
}


// ------------------------ Vault CRUD -----------------
// CreateVault inserts a new vault (owner already embedded as the first peer)
func (s *Store) CreateVault(ctx context.Context, v *Vault) error {
	_, err := s.vaults.InsertOne(ctx, v)
	return err
}

// FindVaultByID returns one vault, or (nil, nil) if it does not exist.
func (s *Store) FindVaultByID(ctx context.Context, id string) (*Vault, error) {
	var v Vault
	err := s.vaults.FindOne(ctx, bson.M{"_id": id}).Decode(&v)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil // not found is not an error — the caller picks the status code
	}
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// ListVaultsByWorkspace returns every vault in a workspace, newest first.
func (s *Store) ListVaultsByWorkspace(ctx context.Context, workspaceID string) ([]Vault, error) {
	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}) // -1 = descending
	cur, err := s.vaults.Find(ctx, bson.M{"workspace_id": workspaceID}, opts)
	if err != nil {
		return nil, err
	}
	var vaults []Vault
	if err := cur.All(ctx, &vaults); err != nil { // All decodes + closes the cursor
		return nil, err
	}
	return vaults, nil
}


func (s *Store) DeleteVault(ctx context.Context, id string) error {
	_, err := s.vaults.DeleteOne(ctx, bson.M{"_id": id})
	return err
}

// FindVaultByTokenID finds the vault that embeds a token with this id (join lookup).
func (s *Store) FindVaultByTokenID(ctx context.Context, tokenID string) (*Vault, error) {
	var v Vault
	err := s.vaults.FindOne(ctx, bson.M{"tokens.id": tokenID}).Decode(&v)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &v, nil
}


// touch bumps updated_at — shared by the mutating helpers below.
func touch() bson.M { return bson.M{"updated_at": time.Now()} }


// ---------------- Snapshot ----------------
// SetSnapshot stores the encrypted blob and bumps updated_at.
func (s *Store) SetSnapshot(ctx context.Context, vaultID string, snapshot []byte) error {
	_, err := s.vaults.UpdateOne(ctx,
		bson.M{"_id": vaultID},
		bson.M{"$set": bson.M{"snapshot": snapshot, "updated_at": time.Now()}},
	)
	return err
}


// ---------------- Peers ----------------
// AddPeer appends a peer to the embedded array ($push) and bumps updated_at.
func (s *Store) AddPeer(ctx context.Context, vaultID string, p Peer) error {
	_, err := s.vaults.UpdateOne(ctx,
		bson.M{"_id": vaultID},
		bson.M{"$push": bson.M{"peers": p}, "$set": touch()},
	)
	return err
}

// RemovePeer pulls a peer by P2P device id. Returns whether a peer actually left.
func (s *Store) RemovePeer(ctx context.Context, vaultID, deviceID string) (bool, error) {
	res, err := s.vaults.UpdateOne(ctx,
		bson.M{"_id": vaultID},
		bson.M{"$pull": bson.M{"peers": bson.M{"device_id": deviceID}}, "$set": touch()},
	)
	if err != nil {
		return false, err
	}
	return res.ModifiedCount == 1, nil // false = that device wasn't a peer
}


// ---------------- Tokens ----------------
// AddToken appends a join token to the embedded array.
func (s *Store) AddToken(ctx context.Context, vaultID string, tok Token) error {
	_, err := s.vaults.UpdateOne(ctx,
		bson.M{"_id": vaultID},
		bson.M{"$push": bson.M{"tokens": tok}, "$set": touch()},
	)
	return err
}

// RevokeToken flips revoked=true on the matching embedded token via the positional
// operator ("tokens.$"). Returns whether a token matched.
func (s *Store) RevokeToken(ctx context.Context, vaultID, tokenID string) (bool, error) {
	res, err := s.vaults.UpdateOne(ctx,
		bson.M{"_id": vaultID, "tokens.id": tokenID}, // "tokens.$" refers to this matched element
		bson.M{"$set": bson.M{"tokens.$.revoked": true, "updated_at": time.Now()}},
	)
	if err != nil {
		return false, err
	}
	return res.MatchedCount == 1, nil
}

// ---------------- Collaborators ----------------

func (s *Store) CreateCollaborator(ctx context.Context, c *Collaborator) error {
	_, err := s.collaborators.InsertOne(ctx, c)
	return err
}

func (s *Store) FindCollaboratorByID(ctx context.Context, id string) (*Collaborator, error) {
	var c Collaborator
	err := s.collaborators.FindOne(ctx, bson.M{"_id": id}).Decode(&c)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) FindCollaboratorByCodeHash(ctx context.Context, codeHash string) (*Collaborator, error) {
	var c Collaborator
	err := s.collaborators.FindOne(ctx, bson.M{"code_hash": codeHash}).Decode(&c)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// FindOpenCollaborator returns a pending invite for vault+email.
func (s *Store) FindOpenCollaborator(ctx context.Context, vaultID, email string) (*Collaborator, error) {
	var c Collaborator
	err := s.collaborators.FindOne(ctx, bson.M{
		"vault_id": vaultID,
		"email":    email,
		"status":   CollabPending,
	}).Decode(&c)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) ListCollaboratorsByVault(ctx context.Context, vaultID string) ([]Collaborator, error) {
	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}})
	cur, err := s.collaborators.Find(ctx, bson.M{
		"vault_id": vaultID,
		"status":   bson.M{"$ne": CollabRevoked},
	}, opts)
	if err != nil {
		return nil, err
	}
	var out []Collaborator
	if err := cur.All(ctx, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []Collaborator{}
	}
	return out, nil
}

func (s *Store) UpdateCollaborator(ctx context.Context, id string, set bson.M) error {
	if set == nil {
		set = bson.M{}
	}
	set["updated_at"] = time.Now()
	_, err := s.collaborators.UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": set})
	return err
}

// ---------------- Offline messages ----------------

// CreateMessage queues one offline message.
func (s *Store) CreateMessage(ctx context.Context, m *PendingMessage) error {
	_, err := s.messages.InsertOne(ctx, m)
	return err
}

// DrainMessages returns a device's queued messages and deletes exactly those it
// returned (delete-by-id, not delete-by-device) so nothing that arrives between
// the read and the delete is lost.
func (s *Store) DrainMessages(ctx context.Context, deviceID string) ([]PendingMessage, error) {
	cur, err := s.messages.Find(ctx, bson.M{"for_device_id": deviceID})
	if err != nil {
		return nil, err
	}
	var msgs []PendingMessage
	if err := cur.All(ctx, &msgs); err != nil {
		return nil, err
	}
	if len(msgs) == 0 {
		return []PendingMessage{}, nil // never nil — the client expects an array
	}

	ids := make([]string, 0, len(msgs))
	for _, m := range msgs {
		ids = append(ids, m.ID)
	}
	if _, err := s.messages.DeleteMany(ctx, bson.M{"_id": bson.M{"$in": ids}}); err != nil {
		return nil, err
	}
	return msgs, nil
}