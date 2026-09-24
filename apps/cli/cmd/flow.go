package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/zain-23/local-vault/apps/cli/internal/account"
	"github.com/zain-23/local-vault/apps/cli/internal/api"
	"github.com/zain-23/local-vault/apps/cli/internal/knownkeys"
	"github.com/zain-23/local-vault/apps/cli/internal/localstore"
	"github.com/zain-23/local-vault/apps/cli/internal/lvcrypto"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

func (v *vaultCtx) syncGrants() error {
	grants, err := v.Client.MyGrants(v.Project.Workspace, v.Project.Vault)
	if err != nil {
		return mapNotLoggedIn(err)
	}
	v.State.WorkspaceID = v.Project.Workspace
	v.State.VaultID = v.Project.Vault
	for _, g := range grants {
		v.State.PutGrant(g.Env, g.KeyVersion, g.WrappedKey)
	}
	return v.State.Save()
}

func (v *vaultCtx) pull(resolveRemote bool) (*lvcrypto.Snapshot, []string, error) {
	if err := v.syncGrants(); err != nil {
		return nil, nil, err
	}
	head, err := v.Client.HeadRevision(v.Project.Workspace, v.Project.Vault, v.Env, "")
	if err != nil {
		if errors.Is(err, api.ErrNotModified) {
			snap, werr := v.State.Working(v.Env)
			return snap, nil, werr
		}
		return nil, nil, mapNotLoggedIn(err)
	}
	if head.Revision == 0 || len(head.Ciphertext) == 0 {
		snap, werr := v.State.Working(v.Env)
		if werr != nil {
			snap = &lvcrypto.Snapshot{Version: lvcrypto.SnapshotVersion}
		}
		v.State.SetBase(v.Env, 0, max(head.KeyVersion, 1), nil)
		return snap, nil, v.State.Save()
	}
	if err := knownkeys.Check(head.AuthorUserID, head.AuthorFingerprint); err != nil {
		return nil, nil, err
	}
	if !lvcrypto.VerifyRevision(head.AuthorEd25519PublicKey, head.Signature, head.VaultID, head.Env, head.Revision, head.ParentRevision, head.KeyVersion, head.Ciphertext) {
		return nil, nil, fmt.Errorf("revision %d signature is invalid", head.Revision)
	}
	dek, err := v.State.DEK(v.Env, head.KeyVersion)
	if err != nil {
		return nil, nil, err
	}
	remote, err := lvcrypto.DecryptRevision(dek, head.VaultID, head.Env, head.Revision, head.KeyVersion, head.Ciphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("could not decrypt revision %d: %w", head.Revision, err)
	}
	local, err := v.State.Working(v.Env)
	if err != nil {
		local = &lvcrypto.Snapshot{Version: lvcrypto.SnapshotVersion}
	}
	base, err := v.State.Base(v.Env)
	if err != nil {
		base = &lvcrypto.Snapshot{Version: lvcrypto.SnapshotVersion}
	}
	merged, conflicts := lvcrypto.Merge(base, local, remote)
	if len(conflicts) > 0 && resolveRemote {
		merged = lvcrypto.Resolve(merged, remote, conflicts, true)
		conflicts = nil
	}
	st := v.State.Envs[v.Env]
	dirty := st.Dirty
	if len(conflicts) == 0 {
		dirty = st.Dirty && !sameSnap(local, remote)
	}
	v.State.SetBase(v.Env, head.Revision, head.KeyVersion, head.Ciphertext)
	if err := v.State.SetWorking(v.Env, merged, dirty || len(conflicts) > 0); err != nil {
		return nil, nil, err
	}
	return merged, conflicts, nil
}

func (v *vaultCtx) push(note string) error {
	keys, err := account.Keys()
	if err != nil {
		return err
	}
	if err := v.syncGrants(); err != nil {
		return err
	}
	snap, err := v.State.Working(v.Env)
	if err != nil {
		return err
	}
	st := v.State.Envs[v.Env]
	kv := st.KeyVersion
	if kv == 0 {
		kv = 1
	}
	dek, err := v.State.DEK(v.Env, kv)
	if err != nil {
		return err
	}
	base := st.BaseRevision
	rev := base + 1
	ct, err := lvcrypto.EncryptRevision(dek, v.Project.Vault, v.Env, rev, kv, snap)
	if err != nil {
		return err
	}
	sig := lvcrypto.SignRevision(keys.Ed25519, v.Project.Vault, v.Env, rev, base, kv, ct)
	body := map[string]any{
		"base_revision": base,
		"key_version":   kv,
		"ciphertext":    ct,
		"signature":     sig,
	}
	out, err := v.Client.PushRevision(v.Project.Workspace, v.Project.Vault, v.Env, body)
	if err != nil {
		if api.IsCode(err, "protected_env") {
			if note == "" {
				note = "change request from CLI"
			}
			body["note"] = note
			if cerr := v.Client.CreateChangeRequest(v.Project.Workspace, v.Project.Vault, v.Env, body); cerr != nil {
				return mapNotLoggedIn(cerr)
			}
			ui.Success("change request submitted for %s (protected)", v.Env)
			return nil
		}
		if api.IsCode(err, "conflict") {
			ui.Warn("remote moved — pulling and merging")
			if _, conflicts, perr := v.pull(false); perr != nil {
				return perr
			} else if len(conflicts) > 0 {
				return fmt.Errorf("merge conflicts: %v\n  resolve locally, then: lv push", conflicts)
			}
			return v.push(note)
		}
		return mapNotLoggedIn(err)
	}
	v.State.SetBase(v.Env, out.Revision, out.KeyVersion, out.Ciphertext)
	st = v.State.Envs[v.Env]
	st.Dirty = false
	v.State.Envs[v.Env] = st
	if err := v.State.Save(); err != nil {
		return err
	}
	ui.Success("pushed %s revision %d", v.Env, out.Revision)
	return nil
}

func (v *vaultCtx) wrapGrant(env string, kv int, recipientPub []byte) ([]byte, error) {
	dek, err := v.State.DEK(env, kv)
	if err != nil {
		return nil, err
	}
	return lvcrypto.WrapX25519(dek, recipientPub, lvcrypto.GrantInfo(v.Project.Vault, env, kv))
}

func (v *vaultCtx) grantPending(yes bool) error {
	if err := v.syncGrants(); err != nil {
		return err
	}
	pending, err := v.Client.PendingGrants(v.Project.Workspace, v.Project.Vault)
	if err != nil {
		return mapNotLoggedIn(err)
	}
	if len(pending) == 0 {
		ui.Success("no pending grants")
		return nil
	}
	var grants []api.GrantIn
	for _, p := range pending {
		if p.RecipientType == "user" && p.Fingerprint != "" {
			if err := knownkeys.Check(p.RecipientID, p.Fingerprint); err != nil {
				ui.Warn("%s", err)
				continue
			}
		}
		ui.Info("%s %s  %s", p.Env, p.Label, p.Fingerprint)
		if p.KeyType != "x25519" {
			ui.Warn("skipping %s — key type %s needs a KMS wrap", p.Label, p.KeyType)
			continue
		}
		wrapped, err := v.wrapGrant(p.Env, p.KeyVersion, p.PublicKey)
		if err != nil {
			ui.Warn("could not wrap %s/%s: %v", p.Label, p.Env, err)
			continue
		}
		grants = append(grants, api.GrantIn{
			Env: p.Env, KeyVersion: p.KeyVersion,
			RecipientType: p.RecipientType, RecipientID: p.RecipientID,
			WrappedKey: wrapped,
		})
	}
	if len(grants) == 0 {
		return nil
	}
	if !yes {
		ok, err := ui.Confirm(fmt.Sprintf("grant %d key(s)", len(grants)))
		if err != nil {
			return err
		}
		if !ok {
			ui.Info("cancelled")
			return nil
		}
	}
	if err := v.Client.PostGrants(v.Project.Workspace, v.Project.Vault, grants); err != nil {
		return mapNotLoggedIn(err)
	}
	ui.Success("granted %d key(s)", len(grants))
	return nil
}

func sameSnap(a, b *lvcrypto.Snapshot) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	am, bm := localstore.InjectMap(a), localstore.InjectMap(b)
	if len(am) != len(bm) {
		return false
	}
	for k, v := range am {
		if bm[k] != v {
			return false
		}
	}
	return true
}

func execWithSecrets(secrets map[string]string, args []string) error {
	if len(args) == 0 {
		if os.Getenv("GITHUB_ENV") != "" {
			f, err := os.OpenFile(os.Getenv("GITHUB_ENV"), os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			defer f.Close()
			for k, v := range secrets {
				fmt.Fprintf(f, "%s=%s\n", k, v)
			}
			return nil
		}
		for k, val := range secrets {
			fmt.Printf("export %s=%q\n", k, val)
		}
		return nil
	}
	return runCommand(secrets, args)
}
