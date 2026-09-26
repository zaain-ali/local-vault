package dashboard

import (
	"context"
	"time"

	"github.com/zain-23/local-vault/apps/server/internal/audit"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type Store struct {
	vaults      *mongo.Collection
	memberships *mongo.Collection
	invites     *mongo.Collection
	vMembers    *mongo.Collection
	changes     *mongo.Collection
	events      *mongo.Collection
	users       *mongo.Collection
}

func NewStore(db *mongo.Database) *Store {
	return &Store{
		vaults:      db.Collection("vaults"),
		memberships: db.Collection("memberships"),
		invites:     db.Collection("workspace_invites"),
		vMembers:    db.Collection("vault_members"),
		changes:     db.Collection("vault_change_requests"),
		events:      db.Collection("audit_events"),
		users:       db.Collection("users"),
	}
}

// vaultAgg is the single-row result of the vaults summary aggregation.
type vaultAgg struct {
	Total        int64 `bson:"total"`
	WithSnapshot int64 `bson:"with_snapshot"`
	PeerTotal    int64 `bson:"peer_total"`
}

// SummaryCounts holds raw counts from Mongo for the summary endpoint.
type SummaryCounts struct {
	Vaults               vaultAgg
	MemberTotal          int64
	PendingInvites       int64
	PendingCollaborators int64
}

// GetSummaryCounts loads workspace overview counts.
func (s *Store) GetSummaryCounts(ctx context.Context, workspaceID string) (SummaryCounts, error) {
	var out SummaryCounts

	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{"workspace_id": workspaceID}}},
		{{Key: "$group", Value: bson.M{
			"_id":   nil,
			"total": bson.M{"$sum": 1},
			"with_snapshot": bson.M{"$sum": bson.M{
				"$cond": bson.A{
					bson.M{"$gt": bson.A{
						bson.M{"$size": bson.M{"$filter": bson.M{
							"input": bson.M{"$ifNull": bson.A{"$environments", bson.A{}}},
							"as":    "e",
							"cond":  bson.M{"$gt": bson.A{"$$e.head_revision", 0}},
						}}},
						0,
					}},
					1,
					0,
				},
			}},
			"peer_total": bson.M{"$sum": 0},
		}}},
	}
	cursor, err := s.vaults.Aggregate(ctx, pipeline)
	if err != nil {
		return out, err
	}
	var rows []vaultAgg
	if err := cursor.All(ctx, &rows); err != nil {
		return out, err
	}
	if len(rows) > 0 {
		out.Vaults = rows[0]
	}

	out.MemberTotal, err = s.memberships.CountDocuments(ctx, bson.M{"workspace_id": workspaceID})
	if err != nil {
		return out, err
	}

	out.PendingInvites, err = s.invites.CountDocuments(ctx, bson.M{
		"workspace_id": workspaceID,
		"status":       "pending",
	})
	if err != nil {
		return out, err
	}

	out.Vaults.PeerTotal, err = s.vMembers.CountDocuments(ctx, bson.M{"workspace_id": workspaceID})
	if err != nil {
		return out, err
	}

	var vaultIDs []string
	cur, err := s.vaults.Find(ctx, bson.M{"workspace_id": workspaceID}, options.Find().SetProjection(bson.M{"_id": 1}))
	if err != nil {
		return out, err
	}
	var idRows []struct {
		ID string `bson:"_id"`
	}
	if err := cur.All(ctx, &idRows); err != nil {
		return out, err
	}
	for _, r := range idRows {
		vaultIDs = append(vaultIDs, r.ID)
	}
	if len(vaultIDs) > 0 {
		out.PendingCollaborators, err = s.changes.CountDocuments(ctx, bson.M{
			"vault_id": bson.M{"$in": vaultIDs},
			"status":   "pending",
		})
	}
	if err != nil {
		return out, err
	}

	return out, nil
}

// actorLookup joins each event to its actor's display name (copied from audit store).
func actorLookup() mongo.Pipeline {
	return mongo.Pipeline{
		{{Key: "$lookup", Value: bson.M{
			"from":         "users",
			"localField":   "actor_id",
			"foreignField": "_id",
			"as":           "actor",
		}}},
		{{Key: "$unwind", Value: bson.M{"path": "$actor", "preserveNullAndEmptyArrays": true}}},
		{{Key: "$addFields", Value: bson.M{
			"actor_name":       "$actor.name",
			"actor_avatar_url": "$actor.avatar_url",
		}}},
		{{Key: "$project", Value: bson.M{"actor": 0}}},
	}
}

// ListRecentEvents returns up to limit newest audit events since from (inclusive).
func (s *Store) ListRecentEvents(ctx context.Context, workspaceID string, from time.Time, limit int64) ([]audit.EventResponse, error) {
	pipeline := append(mongo.Pipeline{
		{{Key: "$match", Value: bson.M{
			"workspace_id": workspaceID,
			"created_at":   bson.M{"$gte": from},
		}}},
		{{Key: "$sort", Value: bson.D{{Key: "created_at", Value: -1}}}},
		{{Key: "$limit", Value: limit}},
	}, actorLookup()...)

	cursor, err := s.events.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	var out []audit.EventResponse
	if err := cursor.All(ctx, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []audit.EventResponse{}
	}
	return out, nil
}

// seriesRow is one (day, prefix) group from the activity aggregation.
type seriesRow struct {
	ID struct {
		Date   time.Time `bson:"date"`
		Prefix string    `bson:"prefix"`
	} `bson:"_id"`
	Count int64 `bson:"count"`
}

// AggregateSeries returns per-day, per-action-prefix counts since from.
func (s *Store) AggregateSeries(ctx context.Context, workspaceID string, from time.Time) ([]seriesRow, error) {
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{
			"workspace_id": workspaceID,
			"created_at":   bson.M{"$gte": from},
		}}},
		{{Key: "$group", Value: bson.M{
			"_id": bson.M{
				"date": bson.M{
					"$dateTrunc": bson.M{
						"date":     "$created_at",
						"unit":     "day",
						"timezone": "UTC",
					},
				},
				"prefix": bson.M{
					"$arrayElemAt": bson.A{
						bson.M{"$split": bson.A{"$action", "."}},
						0,
					},
				},
			},
			"count": bson.M{"$sum": 1},
		}}},
		{{Key: "$sort", Value: bson.D{{Key: "_id.date", Value: 1}}}},
	}

	cursor, err := s.events.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	var rows []seriesRow
	if err := cursor.All(ctx, &rows); err != nil {
		return nil, err
	}
	if rows == nil {
		rows = []seriesRow{}
	}
	return rows, nil
}
