package keys

import (
	"context"
	"errors"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// ErrExists is returned by Insert when the user already has a bundle.
var ErrExists = errors.New("keys already exist")

// Store owns the "user_keys" collection (_id = user id is the only index needed).
type Store struct {
	keys *mongo.Collection
}

func NewStore(db *mongo.Database) *Store {
	return &Store{keys: db.Collection("user_keys")}
}

// Get returns a user's bundle, or (nil, nil) if they have none.
func (s *Store) Get(ctx context.Context, userID string) (*Bundle, error) {
	var b Bundle
	err := s.keys.FindOne(ctx, bson.M{"_id": userID}).Decode(&b)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// Insert stores a new bundle; ErrExists if one is already set.
func (s *Store) Insert(ctx context.Context, b *Bundle) error {
	_, err := s.keys.InsertOne(ctx, b)
	if mongo.IsDuplicateKeyError(err) {
		return ErrExists
	}
	return err
}

// Delete removes a user's bundle. Returns whether one existed.
func (s *Store) Delete(ctx context.Context, userID string) (bool, error) {
	res, err := s.keys.DeleteOne(ctx, bson.M{"_id": userID})
	if err != nil {
		return false, err
	}
	return res.DeletedCount > 0, nil
}

// FindByUserIDs returns the bundles that exist for ids, keyed by user id.
func (s *Store) FindByUserIDs(ctx context.Context, ids []string) (map[string]Bundle, error) {
	out := map[string]Bundle{}
	if len(ids) == 0 {
		return out, nil
	}
	cur, err := s.keys.Find(ctx, bson.M{"_id": bson.M{"$in": ids}})
	if err != nil {
		return nil, err
	}
	var list []Bundle
	if err := cur.All(ctx, &list); err != nil {
		return nil, err
	}
	for _, b := range list {
		out[b.UserID] = b
	}
	return out, nil
}
