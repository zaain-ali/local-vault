package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/zain-23/local-vault/apps/cli/internal/account"
	"github.com/zain-23/local-vault/apps/cli/internal/knownkeys"
	"github.com/zain-23/local-vault/apps/cli/internal/lvcrypto"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var rekeyCmd = &cobra.Command{
	Use:   "rekey",
	Short: "Rotate an environment DEK and re-grant remaining members",
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := requireVault(envFlag)
		if err != nil {
			return err
		}
		if err := v.syncGrants(); err != nil {
			return err
		}
		detail, err := v.Client.GetVaultV4(v.Project.Workspace, v.Project.Vault)
		if err != nil {
			return mapNotLoggedIn(err)
		}
		var envInfo *struct {
			kv, head int
		}
		for _, e := range detail.Environments {
			if e.Name == v.Env {
				envInfo = &struct{ kv, head int }{e.KeyVersion, e.HeadRevision}
				break
			}
		}
		if envInfo == nil {
			return fmt.Errorf("unknown environment %s", v.Env)
		}
		oldDEK, err := v.State.DEK(v.Env, envInfo.kv)
		if err != nil {
			return err
		}
		newDEK, err := lvcrypto.NewDEK()
		if err != nil {
			return err
		}
		newKV := envInfo.kv + 1
		keys, err := account.Keys()
		if err != nil {
			return err
		}

		var revBody map[string]any
		if envInfo.head > 0 {
			head, err := v.Client.HeadRevision(v.Project.Workspace, v.Project.Vault, v.Env, "")
			if err != nil {
				return mapNotLoggedIn(err)
			}
			snap, err := lvcrypto.DecryptRevision(oldDEK, v.Project.Vault, v.Env, head.Revision, head.KeyVersion, head.Ciphertext)
			if err != nil {
				return err
			}
			next := head.Revision + 1
			ct, err := lvcrypto.EncryptRevision(newDEK, v.Project.Vault, v.Env, next, newKV, snap)
			if err != nil {
				return err
			}
			sig := lvcrypto.SignRevision(keys.Ed25519, v.Project.Vault, v.Env, next, head.Revision, newKV, ct)
			revBody = map[string]any{
				"base_revision": head.Revision,
				"key_version":   newKV,
				"ciphertext":    ct,
				"signature":     sig,
			}
		}

		userIDs := make([]string, 0, len(detail.Members))
		for _, m := range detail.Members {
			if m.HasKeys {
				userIDs = append(userIDs, m.UserID)
			}
		}
		pubs, err := v.Client.WorkspaceKeys(v.Project.Workspace, joinIDs(userIDs))
		if err != nil {
			return mapNotLoggedIn(err)
		}
		info := lvcrypto.GrantInfo(v.Project.Vault, v.Env, newKV)
		var grants []map[string]any
		for _, p := range pubs {
			if err := knownkeys.Check(p.UserID, p.Fingerprint); err != nil {
				ui.Warn("%s", err)
				continue
			}
			wrapped, err := lvcrypto.WrapX25519(newDEK, p.X25519PublicKey, info)
			if err != nil {
				ui.Warn("could not wrap for %s: %v", p.Email, err)
				continue
			}
			grants = append(grants, map[string]any{
				"recipient_type": "user", "recipient_id": p.UserID, "wrapped_key": wrapped,
			})
		}
		pending, _ := v.Client.PendingGrants(v.Project.Workspace, v.Project.Vault)
		for _, p := range pending {
			if p.Env != v.Env || p.RecipientType != "machine" || p.KeyType != "x25519" {
				continue
			}
			wrapped, err := lvcrypto.WrapX25519(newDEK, p.PublicKey, info)
			if err != nil {
				continue
			}
			grants = append(grants, map[string]any{
				"recipient_type": "machine", "recipient_id": p.RecipientID, "wrapped_key": wrapped,
			})
		}

		body := map[string]any{"new_key_version": newKV, "grants": grants}
		if revBody != nil {
			body["revision"] = revBody
		}
		if err := v.Client.Rekey(v.Project.Workspace, v.Project.Vault, v.Env, body); err != nil {
			return mapNotLoggedIn(err)
		}
		selfWrap, err := lvcrypto.WrapX25519(newDEK, keys.X25519Public, info)
		if err != nil {
			return err
		}
		v.State.PutGrant(v.Env, newKV, selfWrap)
		if err := v.State.Save(); err != nil {
			return err
		}
		ui.Success("rekeyed %s to version %d", v.Env, newKV)
		ui.Hint("service tokens for this env were revoked — issue new ones: lv machine token")
		return nil
	},
}

func joinIDs(ids []string) string {
	out := ""
	for i, id := range ids {
		if i > 0 {
			out += ","
		}
		out += id
	}
	return out
}

func init() {
	rekeyCmd.Flags().StringVarP(&envFlag, "env", "e", "", "environment")
	rootCmd.AddCommand(rekeyCmd)
}
