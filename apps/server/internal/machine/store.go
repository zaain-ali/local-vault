package machine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type Store struct {
	col    *mongo.Collection
	grants *mongo.Collection
}

func NewStore(db *mongo.Database) *Store {
	s := &Store{
		col:    db.Collection("machine_identities"),
		grants: db.Collection("vault_key_grants"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, _ = s.col.Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "vault_id", Value: 1}}})
	_, _ = s.col.Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "workspace_id", Value: 1}}})
	return s
}

func (s *Store) Insert(ctx context.Context, m *Identity) error {
	_, err := s.col.InsertOne(ctx, m)
	if mongo.IsDuplicateKeyError(err) {
		return ErrExists
	}
	return err
}

var ErrExists = errors.New("machine id already exists")

func (s *Store) Find(ctx context.Context, id string) (*Identity, error) {
	var m Identity
	err := s.col.FindOne(ctx, bson.M{"_id": id}).Decode(&m)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	return &m, err
}

func (s *Store) List(ctx context.Context, vaultID string) ([]Identity, error) {
	cur, err := s.col.Find(ctx, bson.M{"vault_id": vaultID}, options.Find().SetProjection(bson.M{"token_verifier_hash": 0}).SetSort(bson.D{{Key: "created_at", Value: -1}}))
	if err != nil {
		return nil, err
	}
	out := []Identity{}
	err = cur.All(ctx, &out)
	return out, err
}

func (s *Store) Revoke(ctx context.Context, id, reason string) (bool, error) {
	res, err := s.col.UpdateOne(ctx, bson.M{"_id": id, "revoked": bson.M{"$ne": true}}, bson.M{
		"$set": bson.M{"revoked": true, "revoked_reason": reason, "revoked_at": time.Now()},
	})
	if err != nil {
		return false, err
	}
	return res.MatchedCount == 1, nil
}

func (s *Store) Touch(ctx context.Context, id string) {
	now := time.Now()
	_, _ = s.col.UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": bson.M{"last_used_at": now}})
}

func (s *Store) DeleteGrants(ctx context.Context, vaultID, machineID string) error {
	_, err := s.grants.DeleteMany(ctx, bson.M{"vault_id": vaultID, "recipient_type": "machine", "recipient_id": machineID})
	return err
}

func HashVerifier(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return hex.EncodeToString(sum[:])
}
