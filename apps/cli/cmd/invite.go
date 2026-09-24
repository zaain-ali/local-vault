package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/zain-23/local-vault/apps/cli/internal/api"
	"github.com/zain-23/local-vault/apps/cli/internal/knownkeys"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var inviteCmd = &cobra.Command{
	Use:   "invite [email]",
	Short: "Add a workspace member to this vault",
	Example: `  lv invite sara@company.com
  lv invite --list
  lv invite --revoke usr_x`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := requireVault(envFlag)
		if err != nil {
			return err
		}
		listFlag, _ := cmd.Flags().GetBool("list")
		revokeArg, _ := cmd.Flags().GetString("revoke")
		role, _ := cmd.Flags().GetString("role")
		if role == "" {
			role = "member"
		}

		if listFlag {
			return listVaultMembers(v)
		}
		if revokeArg != "" {
			return revokeVaultMember(v, revokeArg)
		}
		if len(args) == 0 {
			return fmt.Errorf("provide an email\n  Example: lv invite sara@company.com")
		}
		email := strings.TrimSpace(args[0])
		detail, err := v.Client.GetVaultV4(v.Project.Workspace, v.Project.Vault)
		if err != nil {
			return mapNotLoggedIn(err)
		}
		access := defaultEnvAccess(envNames(detail), role)
		if err := v.syncGrants(); err != nil {
			return err
		}
		mem, err := v.Client.AddVaultMember(v.Project.Workspace, v.Project.Vault, email, role, access)
		if err != nil {
			return mapNotLoggedIn(err)
		}
		ui.Success("added %s as %s", mem.Email, mem.Role)
		if !mem.HasKeys {
			ui.Hint("they must run: lv login   then an admin: lv access grant")
			return nil
		}
		if err := knownkeys.Check(mem.UserID, mem.Fingerprint); err != nil {
			ui.Warn("%s", err)
			ui.Hint("grant later with: lv access grant")
			return nil
		}
		ui.KeyValue("Fingerprint", mem.Fingerprint)
		keys, err := v.Client.WorkspaceKeys(v.Project.Workspace, mem.UserID)
		if err != nil || len(keys) == 0 {
			ui.Hint("grant later with: lv access grant")
			return nil
		}
		var grants []api.GrantIn
		for _, e := range access {
			st := v.State.Envs[e.Env]
			kv := st.KeyVersion
			if kv == 0 {
				kv = 1
			}
			wrapped, err := v.wrapGrant(e.Env, kv, keys[0].X25519PublicKey)
			if err != nil {
				ui.Warn("could not wrap %s: %v", e.Env, err)
				continue
			}
			grants = append(grants, api.GrantIn{
				Env: e.Env, KeyVersion: kv, RecipientType: "user",
				RecipientID: mem.UserID, WrappedKey: wrapped,
			})
		}
		if len(grants) > 0 {
			if err := v.Client.PostGrants(v.Project.Workspace, v.Project.Vault, grants); err != nil {
				ui.Warn("member added but grant failed: %v", err)
				ui.Hint("run: lv access grant")
				return nil
			}
			ui.Success("granted keys for %d environment(s)", len(grants))
		}
		ui.Hint("they run: lv link --vault %s", v.Project.Vault)
		return nil
	},
}

func listVaultMembers(v *vaultCtx) error {
	detail, err := v.Client.GetVaultV4(v.Project.Workspace, v.Project.Vault)
	if err != nil {
		return mapNotLoggedIn(err)
	}
	if len(detail.Members) == 0 {
		ui.Info("no members")
		return nil
	}
	rows := make([][]string, 0, len(detail.Members))
	for _, m := range detail.Members {
		fp := m.Fingerprint
		if fp == "" {
			fp = "no keys"
		}
		rows = append(rows, []string{m.Email, m.Role, fp, m.UserID})
	}
	ui.Header("Vault Members")
	ui.Table([]string{"EMAIL", "ROLE", "FINGERPRINT", "ID"}, rows)
	return nil
}

func revokeVaultMember(v *vaultCtx, emailOrID string) error {
	detail, err := v.Client.GetVaultV4(v.Project.Workspace, v.Project.Vault)
	if err != nil {
		return mapNotLoggedIn(err)
	}
	var target *api.VaultMember
	for i := range detail.Members {
		m := &detail.Members[i]
		if m.UserID == emailOrID || strings.EqualFold(m.Email, emailOrID) {
			target = m
			break
		}
	}
	if target == nil {
		return fmt.Errorf("no member matching %q", emailOrID)
	}
	if err := v.Client.RemoveVaultMember(v.Project.Workspace, v.Project.Vault, target.UserID); err != nil {
		return mapNotLoggedIn(err)
	}
	ui.Success("removed %s", target.Email)
	ui.Hint("rotate the environment key: lv rekey --env <env>")
	return nil
}

func init() {
	inviteCmd.Flags().Bool("list", false, "list vault members")
	inviteCmd.Flags().String("revoke", "", "remove a member by email or id")
	inviteCmd.Flags().String("role", "member", "vault role: admin or member")
	inviteCmd.Flags().StringVarP(&envFlag, "env", "e", "", "unused (kept for compatibility)")
	rootCmd.AddCommand(inviteCmd)
}
