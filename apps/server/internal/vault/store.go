package vault

import (
	"context"
	"errors"
	"log"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Store owns vaults, vault_members, vault_key_grants, vault_revisions and
// vault_change_requests, and reads machine_identities (owned by the machine domain).
type Store struct {
	client    *mongo.Client
	vaults    *mongo.Collection
	members   *mongo.Collection
	grants    *mongo.Collection
	revisions *mongo.Collection
	changes   *mongo.Collection
	machines  *mongo.Collection

	noTx atomic.Bool // set once the deployment is known not to support transactions
}

// NewStore creates the store and its indexes.
func NewStore(db *mongo.Database) *Store {
	s := &Store{
		client:    db.Client(),
		vaults:    db.Collection("vaults"),
		members:   db.Collection("vault_members"),
		grants:    db.Collection("vault_key_grants"),
		revisions: db.Collection("vault_revisions"),
		changes:   db.Collection("vault_change_requests"),
		machines:  db.Collection("machine_identities"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	unique := options.Index().SetUnique(true)
	indexes := []struct {
		coll  *mongo.Collection
		model mongo.IndexModel
	}{
		{s.vaults, mongo.IndexModel{Keys: bson.D{{Key: "workspace_id", Value: 1}}}},
		{s.members, mongo.IndexModel{Keys: bson.D{{Key: "vault_id", Value: 1}, {Key: "user_id", Value: 1}}, Options: unique}},
		{s.members, mongo.IndexModel{Keys: bson.D{{Key: "user_id", Value: 1}}}},
		{s.grants, mongo.IndexModel{Keys: bson.D{
			{Key: "vault_id", Value: 1}, {Key: "env", Value: 1}, {Key: "key_version", Value: 1},
			{Key: "recipient_type", Value: 1}, {Key: "recipient_id", Value: 1},
		}, Options: unique}},
		// grants/mine and keys reset look grants up by recipient.
		{s.grants, mongo.IndexModel{Keys: bson.D{{Key: "recipient_type", Value: 1}, {Key: "recipient_id", Value: 1}, {Key: "vault_id", Value: 1}}}},
		// Optimistic concurrency: inserting base+1 twice fails with a duplicate key.
		{s.revisions, mongo.IndexModel{Keys: bson.D{{Key: "vault_id", Value: 1}, {Key: "env", Value: 1}, {Key: "revision", Value: 1}}, Options: unique}},
		{s.revisions, mongo.IndexModel{
			Keys: bson.D{{Key: "vault_id", Value: 1}, {Key: "env", Value: 1}, {Key: "author_user_id", Value: 1}, {Key: "idempotency_key", Value: 1}},
			Options: options.Index().SetPartialFilterExpression(bson.M{"idempotency_key": bson.M{"$exists": true}}),
		}},
		{s.changes, mongo.IndexModel{Keys: bson.D{{Key: "vault_id", Value: 1}, {Key: "env", Value: 1}, {Key: "status", Value: 1}}}},
		{s.machines, mongo.IndexModel{Keys: bson.D{{Key: "vault_id", Value: 1}}}},
		{s.machines, mongo.IndexModel{Keys: bson.D{{Key: "workspace_id", Value: 1}}}},
	}
	for _, ix := range indexes {
		if _, err := ix.coll.Indexes().CreateOne(ctx, ix.model); err != nil {
			log.Printf("⚠️ vault: create index on %s: %v", ix.coll.Name(), err)
		}
	}
	return s
}

// ---------------- Transactions ----------------

// withTx runs fn in a transaction when the deployment supports it (replica set
// / mongos). On a standalone mongod it runs fn directly, so fn must order its
// writes to leave a consistent state if interrupted.
func (s *Store) withTx(ctx context.Context, fn func(ctx context.Context) error) error {
	if s.noTx.Load() {
		return fn(ctx)
	}
	sess, err := s.client.StartSession()
	if err != nil {
		return err
	}
	defer sess.EndSession(ctx)
	_, err = sess.WithTransaction(ctx, func(ctx context.Context) (any, error) {
		return nil, fn(ctx)
	})
	if err != nil && isTxUnsupported(err) {
		s.noTx.Store(true)
		log.Printf("⚠️ vault: MongoDB deployment has no transactions — using ordered writes")
		return fn(ctx)
	}
	return err
}

// isTxUnsupported detects "Transaction numbers are only allowed on a replica set
// member or mongos" (code 20, IllegalOperation) from a standalone server.
func isTxUnsupported(err error) bool {
	var se mongo.ServerError
	if errors.As(err, &se) && se.HasErrorCode(20) {
		return true
	}
	return strings.Contains(err.Error(), "Transaction numbers are only allowed")
}

// ---------------- Vaults ----------------

func (s *Store) InsertVault(ctx context.Context, v *Vault) error {
	_, err := s.vaults.InsertOne(ctx, v)
	return err
}

// FindVault returns one vault, or (nil, nil) if it does not exist.
func (s *Store) FindVault(ctx context.Context, id string) (*Vault, error) {
	var v Vault
	err := s.vaults.FindOne(ctx, bson.M{"_id": id}).Decode(&v)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// ListVaults returns a workspace's vaults, newest first; ids == nil means all.
func (s *Store) ListVaults(ctx context.Context, workspaceID string, ids []string) ([]Vault, error) {
	filter := bson.M{"workspace_id": workspaceID}
	if ids != nil {
		filter["_id"] = bson.M{"$in": ids}
	}
	cur, err := s.vaults.Find(ctx, filter, options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}))
	if err != nil {
		return nil, err
	}
	out := []Vault{}
	if err := cur.All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteVaultCascade removes a vault and everything hanging off it.
// The vault doc goes first so a partial failure never leaves a live vault
// with missing members/grants.
func (s *Store) DeleteVaultCascade(ctx context.Context, vaultID string) error {
	return s.withTx(ctx, func(ctx context.Context) error {
		if _, err := s.vaults.DeleteOne(ctx, bson.M{"_id": vaultID}); err != nil {
			return err
		}
		for _, c := range []*mongo.Collection{s.members, s.grants, s.revisions, s.changes, s.machines} {
			if _, err := c.DeleteMany(ctx, bson.M{"vault_id": vaultID}); err != nil {
				return err
			}
		}
		return nil
	})
}

// AddEnvironment appends env unless one with the same name exists.
func (s *Store) AddEnvironment(ctx context.Context, vaultID string, env Environment) (bool, error) {
	res, err := s.vaults.UpdateOne(ctx,
		bson.M{"_id": vaultID, "environments.name": bson.M{"$ne": env.Name}},
		bson.M{"$push": bson.M{"environments": env}, "$set": bson.M{"updated_at": time.Now()}},
	)
	if err != nil {
		return false, err
	}
	return res.MatchedCount == 1, nil
}

// SetEnvProtected flips one environment's protected flag.
func (s *Store) SetEnvProtected(ctx context.Context, vaultID, env string, protected bool) error {
	now := time.Now()
	_, err := s.vaults.UpdateOne(ctx,
		bson.M{"_id": vaultID, "environments.name": env},
		bson.M{"$set": bson.M{"environments.$.protected": protected, "environments.$.updated_at": now, "updated_at": now}},
	)
	return err
}

// BumpHead raises environments.$.head_revision to at least rev ($max — never moves back).
func (s *Store) BumpHead(ctx context.Context, vaultID, env string, rev int) error {
	now := time.Now()
	_, err := s.vaults.UpdateOne(ctx,
		bson.M{"_id": vaultID, "environments.name": env},
		bson.M{
			"$max": bson.M{"environments.$.head_revision": rev},
			"$set": bson.M{"environments.$.updated_at": now, "updated_at": now},
		},
	)
	return err
}

// SetRekeyRequired flags the given environments as needing a DEK rotation.
func (s *Store) SetRekeyRequired(ctx context.Context, vaultID string, envs []string) error {
	if len(envs) == 0 {
		return nil
	}
	now := time.Now()
	_, err := s.vaults.UpdateOne(ctx,
		bson.M{"_id": vaultID},
		bson.M{"$set": bson.M{
			"environments.$[e].rekey_required": true,
			"environments.$[e].updated_at":     now,
			"updated_at":                       now,
		}},
		options.UpdateOne().SetArrayFilters([]any{bson.M{"e.name": bson.M{"$in": envs}}}),
	)
	return err
}

// CommitRekey moves env from oldKV to newKV (compare-and-set on key_version),
// raises head to at least head and clears rekey_required.
func (s *Store) CommitRekey(ctx context.Context, vaultID, env string, oldKV, newKV, head int) (bool, error) {
	now := time.Now()
	res, err := s.vaults.UpdateOne(ctx,
		bson.M{"_id": vaultID, "environments": bson.M{"$elemMatch": bson.M{"name": env, "key_version": oldKV}}},
		bson.M{
			"$set": bson.M{
				"environments.$.key_version":    newKV,
				"environments.$.rekey_required": false,
				"environments.$.updated_at":     now,
				"updated_at":                    now,
			},
			"$max": bson.M{"environments.$.head_revision": head},
		},
	)
	if err != nil {
		return false, err
	}
	return res.MatchedCount == 1, nil
}

// RepairKeyVersion raises key_version when a rekey revision was committed but
// the env update was lost (crash between writes without transactions).
func (s *Store) RepairKeyVersion(ctx context.Context, vaultID, env string, kv int) error {
	_, err := s.vaults.UpdateOne(ctx,
		bson.M{"_id": vaultID, "environments": bson.M{"$elemMatch": bson.M{"name": env, "key_version": bson.M{"$lt": kv}}}},
		bson.M{"$set": bson.M{"environments.$.key_version": kv, "environments.$.rekey_required": false}},
	)
	return err
}

// ---------------- Members ----------------

func (s *Store) InsertMember(ctx context.Context, m *Member) error {
	_, err := s.members.InsertOne(ctx, m)
	return err
}

// FindMember returns a user's membership of a vault, or (nil, nil).
func (s *Store) FindMember(ctx context.Context, vaultID, userID string) (*Member, error) {
	var m Member
	err := s.members.FindOne(ctx, bson.M{"vault_id": vaultID, "user_id": userID}).Decode(&m)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// ListMembers returns a vault's members, oldest first.
func (s *Store) ListMembers(ctx context.Context, vaultID string) ([]Member, error) {
	cur, err := s.members.Find(ctx, bson.M{"vault_id": vaultID}, options.Find().SetSort(bson.D{{Key: "created_at", Value: 1}}))
	if err != nil {
		return nil, err
	}
	out := []Member{}
	if err := cur.All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListMembershipsOfUser returns every vault membership of a user; workspaceID "" = all workspaces.
func (s *Store) ListMembershipsOfUser(ctx context.Context, userID, workspaceID string) ([]Member, error) {
	filter := bson.M{"user_id": userID}
	if workspaceID != "" {
		filter["workspace_id"] = workspaceID
	}
	cur, err := s.members.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	out := []Member{}
	if err := cur.All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CountMembers returns member counts per vault id.
func (s *Store) CountMembers(ctx context.Context, vaultIDs []string) (map[string]int, error) {
	out := map[string]int{}
	if len(vaultIDs) == 0 {
		return out, nil
	}
	cur, err := s.members.Aggregate(ctx, mongo.Pipeline{
		{{Key: "$match", Value: bson.M{"vault_id": bson.M{"$in": vaultIDs}}}},
		{{Key: "$group", Value: bson.M{"_id": "$vault_id", "n": bson.M{"$sum": 1}}}},
	})
	if err != nil {
		return nil, err
	}
	var rows []struct {
		ID string `bson:"_id"`
		N  int    `bson:"n"`
	}
	if err := cur.All(ctx, &rows); err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.ID] = r.N
	}
	return out, nil
}

// UpdateMember replaces role and env_access.
func (s *Store) UpdateMember(ctx context.Context, vaultID, userID, role string, access []EnvAccess) error {
	_, err := s.members.UpdateOne(ctx,
		bson.M{"vault_id": vaultID, "user_id": userID},
		bson.M{"$set": bson.M{"role": role, "env_access": access, "updated_at": time.Now()}},
	)
	return err
}

// AddEnvAccess gives a member access to one more environment (no-op if present).
func (s *Store) AddEnvAccess(ctx context.Context, vaultID, userID string, a EnvAccess) error {
	_, err := s.members.UpdateOne(ctx,
		bson.M{"vault_id": vaultID, "user_id": userID, "env_access.env": bson.M{"$ne": a.Env}},
		bson.M{"$push": bson.M{"env_access": a}, "$set": bson.M{"updated_at": time.Now()}},
	)
	return err
}

func (s *Store) DeleteMember(ctx context.Context, vaultID, userID string) error {
	_, err := s.members.DeleteOne(ctx, bson.M{"vault_id": vaultID, "user_id": userID})
	return err
}

// ---------------- Grants ----------------

// InsertGrants inserts grants, silently skipping ones whose
// (vault, env, key_version, recipient) already exists. Existing grants are
// filtered first so this is also safe inside a transaction, where a duplicate
// key error would abort it.
func (s *Store) InsertGrants(ctx context.Context, grants []Grant) error {
	if len(grants) == 0 {
		return nil
	}
	or := make(bson.A, 0, len(grants))
	for _, g := range grants {
		or = append(or, bson.M{
			"vault_id": g.VaultID, "env": g.Env, "key_version": g.KeyVersion,
			"recipient_type": g.RecipientType, "recipient_id": g.RecipientID,
		})
	}
	cur, err := s.grants.Find(ctx, bson.M{"$or": or}, options.Find().SetProjection(bson.M{"wrapped_key": 0}))
	if err != nil {
		return err
	}
	var existing []Grant
	if err := cur.All(ctx, &existing); err != nil {
		return err
	}
	have := map[string]bool{}
	for _, g := range existing {
		have[grantKey(g)] = true
	}
	docs := make([]any, 0, len(grants))
	for _, g := range grants {
		k := grantKey(g)
		if have[k] {
			continue
		}
		have[k] = true
		docs = append(docs, g)
	}
	if len(docs) == 0 {
		return nil
	}
	_, err = s.grants.InsertMany(ctx, docs, options.InsertMany().SetOrdered(false))
	if err != nil && mongo.IsDuplicateKeyError(err) && onlyDuplicateKeyErrors(err) {
		return nil // lost a race with a concurrent identical grant — fine
	}
	return err
}

func onlyDuplicateKeyErrors(err error) bool {
	var bwe mongo.BulkWriteException
	if !errors.As(err, &bwe) {
		return true
	}
	if bwe.WriteConcernError != nil {
		return false
	}
	for _, we := range bwe.WriteErrors {
		if we.Code != 11000 {
			return false
		}
	}
	return true
}

func grantKey(g Grant) string {
	return g.VaultID + "\x00" + g.Env + "\x00" + strconv.Itoa(g.KeyVersion) + "\x00" + g.RecipientType + "\x00" + g.RecipientID
}

// HasGrant reports whether a recipient holds (env, key_version).
func (s *Store) HasGrant(ctx context.Context, vaultID, env string, kv int, recipientType, recipientID string) (bool, error) {
	err := s.grants.FindOne(ctx, bson.M{
		"vault_id": vaultID, "env": env, "key_version": kv,
		"recipient_type": recipientType, "recipient_id": recipientID,
	}, options.FindOne().SetProjection(bson.M{"_id": 1})).Err()
	if errors.Is(err, mongo.ErrNoDocuments) {
		return false, nil
	}
	return err == nil, err
}

// ListRecipientGrants returns every grant one recipient holds in a vault.
func (s *Store) ListRecipientGrants(ctx context.Context, vaultID, recipientType, recipientID string) ([]Grant, error) {
	cur, err := s.grants.Find(ctx,
		bson.M{"vault_id": vaultID, "recipient_type": recipientType, "recipient_id": recipientID},
		options.Find().SetSort(bson.D{{Key: "env", Value: 1}, {Key: "key_version", Value: 1}}),
	)
	if err != nil {
		return nil, err
	}
	out := []Grant{}
	if err := cur.All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// EnvVersion names one (env, key_version) pair.
type EnvVersion struct {
	Env        string
	KeyVersion int
}

// ListGrantRecipients returns grant metadata (no wrapped keys) for the given (env, kv) pairs.
func (s *Store) ListGrantRecipients(ctx context.Context, vaultID string, pairs []EnvVersion) ([]Grant, error) {
	if len(pairs) == 0 {
		return []Grant{}, nil
	}
	or := make(bson.A, 0, len(pairs))
	for _, p := range pairs {
		or = append(or, bson.M{"env": p.Env, "key_version": p.KeyVersion})
	}
	cur, err := s.grants.Find(ctx, bson.M{"vault_id": vaultID, "$or": or}, options.Find().SetProjection(bson.M{"wrapped_key": 0}))
	if err != nil {
		return nil, err
	}
	out := []Grant{}
	if err := cur.All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteRecipientGrants removes a recipient's grants in a vault; envs == nil means every env.
func (s *Store) DeleteRecipientGrants(ctx context.Context, vaultID, recipientType, recipientID string, envs []string) error {
	filter := bson.M{"vault_id": vaultID, "recipient_type": recipientType, "recipient_id": recipientID}
	if envs != nil {
		if len(envs) == 0 {
			return nil
		}
		filter["env"] = bson.M{"$in": envs}
	}
	_, err := s.grants.DeleteMany(ctx, filter)
	return err
}

// DeleteAllUserGrants removes every grant addressed to a user, in every vault.
func (s *Store) DeleteAllUserGrants(ctx context.Context, userID string) error {
	_, err := s.grants.DeleteMany(ctx, bson.M{"recipient_type": RecipientUser, "recipient_id": userID})
	return err
}

// DeleteGrantsByID removes specific grants (rollback of a failed rekey).
func (s *Store) DeleteGrantsByID(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := s.grants.DeleteMany(ctx, bson.M{"_id": bson.M{"$in": ids}})
	return err
}

// ---------------- Revisions ----------------

// ErrRevisionExists means another writer already committed that revision number.
var ErrRevisionExists = errors.New("revision already exists")

// InsertRevision commits a revision; ErrRevisionExists on a lost race.
func (s *Store) InsertRevision(ctx context.Context, r *RevisionDoc) error {
	_, err := s.revisions.InsertOne(ctx, r)
	if mongo.IsDuplicateKeyError(err) {
		return ErrRevisionExists
	}
	return err
}

// LatestRevision returns the highest revision of an env, or (nil, nil) when empty.
func (s *Store) LatestRevision(ctx context.Context, vaultID, env string) (*RevisionDoc, error) {
	var r RevisionDoc
	err := s.revisions.FindOne(ctx,
		bson.M{"vault_id": vaultID, "env": env},
		options.FindOne().SetSort(bson.D{{Key: "revision", Value: -1}}),
	).Decode(&r)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// FindRevision returns one revision, or (nil, nil).
func (s *Store) FindRevision(ctx context.Context, vaultID, env string, rev int) (*RevisionDoc, error) {
	var r RevisionDoc
	err := s.revisions.FindOne(ctx, bson.M{"vault_id": vaultID, "env": env, "revision": rev}).Decode(&r)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// FindByIdempotencyKey returns the revision an author already committed with key, or (nil, nil).
func (s *Store) FindByIdempotencyKey(ctx context.Context, vaultID, env, authorID, key string) (*RevisionDoc, error) {
	var r RevisionDoc
	err := s.revisions.FindOne(ctx, bson.M{
		"vault_id": vaultID, "env": env, "author_user_id": authorID, "idempotency_key": key,
	}).Decode(&r)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ListRevisionMeta returns revision metadata (no ciphertext), newest first.
// before > 0 returns revisions strictly below it.
func (s *Store) ListRevisionMeta(ctx context.Context, vaultID, env string, before, limit int) ([]RevisionDoc, error) {
	filter := bson.M{"vault_id": vaultID, "env": env}
	if before > 0 {
		filter["revision"] = bson.M{"$lt": before}
	}
	cur, err := s.revisions.Find(ctx, filter, options.Find().
		SetSort(bson.D{{Key: "revision", Value: -1}}).
		SetLimit(int64(limit)).
		SetProjection(bson.M{"ciphertext": 0, "signature": 0}),
	)
	if err != nil {
		return nil, err
	}
	out := []RevisionDoc{}
	if err := cur.All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ---------------- Change requests ----------------

func (s *Store) InsertChangeRequest(ctx context.Context, cr *ChangeRequest) error {
	_, err := s.changes.InsertOne(ctx, cr)
	return err
}

// FindChangeRequest returns one change request, or (nil, nil).
func (s *Store) FindChangeRequest(ctx context.Context, id string) (*ChangeRequest, error) {
	var cr ChangeRequest
	err := s.changes.FindOne(ctx, bson.M{"_id": id}).Decode(&cr)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &cr, nil
}

// ListChangeRequests returns an env's change requests, newest first; status "" = any.
func (s *Store) ListChangeRequests(ctx context.Context, vaultID, env, status string, limit int) ([]ChangeRequest, error) {
	filter := bson.M{"vault_id": vaultID, "env": env}
	if status != "" {
		filter["status"] = status
	}
	cur, err := s.changes.Find(ctx, filter, options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}).SetLimit(int64(limit)))
	if err != nil {
		return nil, err
	}
	out := []ChangeRequest{}
	if err := cur.All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// TransitionChangeRequest moves a CR from one status to another (compare-and-set).
func (s *Store) TransitionChangeRequest(ctx context.Context, id, from, to, reviewer string) (bool, error) {
	set := bson.M{"status": to, "updated_at": time.Now()}
	if reviewer != "" {
		set["reviewed_by"] = reviewer
	}
	res, err := s.changes.UpdateOne(ctx, bson.M{"_id": id, "status": from}, bson.M{"$set": set})
	if err != nil {
		return false, err
	}
	return res.MatchedCount == 1, nil
}

// ---------------- Machine identities (read side + rekey revocation) ----------------

// ListMachines returns a vault's machine identities; env "" = every env.
func (s *Store) ListMachines(ctx context.Context, vaultID, env string) ([]Machine, error) {
	filter := bson.M{"vault_id": vaultID}
	if env != "" {
		filter["env"] = env
	}
	cur, err := s.machines.Find(ctx, filter, options.Find().SetProjection(bson.M{"token_verifier_hash": 0}))
	if err != nil {
		return nil, err
	}
	out := []Machine{}
	if err := cur.All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// FindMachine returns one machine identity, or (nil, nil).
func (s *Store) FindMachine(ctx context.Context, id string) (*Machine, error) {
	var m Machine
	err := s.machines.FindOne(ctx, bson.M{"_id": id}, options.FindOne().SetProjection(bson.M{"token_verifier_hash": 0})).Decode(&m)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// RevokeMachines marks machines revoked with a reason.
func (s *Store) RevokeMachines(ctx context.Context, ids []string, reason string) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := s.machines.UpdateMany(ctx,
		bson.M{"_id": bson.M{"$in": ids}, "revoked": bson.M{"$ne": true}},
		bson.M{"$set": bson.M{"revoked": true, "revoked_reason": reason, "revoked_at": time.Now()}},
	)
	return err
}

// DeleteMachineGrants removes every grant of the given machines in a vault.
func (s *Store) DeleteMachineGrants(ctx context.Context, vaultID string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := s.grants.DeleteMany(ctx, bson.M{"vault_id": vaultID, "recipient_type": RecipientMachine, "recipient_id": bson.M{"$in": ids}})
	return err
}
