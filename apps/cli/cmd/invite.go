package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/zain-23/local-vault/apps/cli/internal/api"
	"github.com/zain-23/local-vault/apps/cli/internal/identity"
	"github.com/zain-23/local-vault/apps/cli/internal/joincode"
	internalsync "github.com/zain-23/local-vault/apps/cli/internal/sync"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var inviteCmd = &cobra.Command{
	Use:   "invite [email]",
	Short: "Invite a workspace member to this vault by email",
	Example: `  lv invite sara@company.com
  lv invite --list
  lv invite --revoke sara@company.com`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := os.Getwd()
		if err != nil {
			return err
		}
		lvDir := filepath.Join(dir, ".lv")

		id, err := identity.Load(lvDir)
		if err != nil {
			return err
		}
		cfg, err := requireLinkedConfig(lvDir)
		if err != nil {
			return err
		}
		client, err := requireAPI()
		if err != nil {
			return err
		}

		listFlag, _ := cmd.Flags().GetBool("list")
		revokeArg, _ := cmd.Flags().GetString("revoke")

		if listFlag {
			return listCollaborators(client, cfg.WorkspaceID, cfg.VaultID)
		}
		if revokeArg != "" {
			return revokeCollaborator(client, cfg.WorkspaceID, cfg.VaultID, revokeArg)
		}
		if len(args) == 0 {
			return fmt.Errorf("provide an email\n  Example: lv invite sara@company.com")
		}
		email := strings.TrimSpace(args[0])

		v, err := loadVault(dir)
		if err != nil {
			return err
		}
		dek, err := v.EnsureDataKey()
		if err != nil {
			return err
		}

		code, err := joincode.New()
		if err != nil {
			return fmt.Errorf("failed to generate join code: %w", err)
		}
		// Wrap with the same normalized form the invitee will type into `lv join`.
		code = normalizeJoinCode(code)
		wrappedDEK, err := internalsync.WrapKey(dek, []byte(code))
		if err != nil {
			return err
		}

		collab, err := client.InviteCollaborator(cfg.WorkspaceID, cfg.VaultID, api.InviteCollaboratorRequest{
			Email:      email,
			DeviceID:   id.DeviceID,
			Code:       code,
			WrappedDEK: wrappedDEK,
		})
		if err != nil {
			return mapNotLoggedIn(fmt.Errorf("failed to invite: %w", err))
		}

		ui.Header("Vault Invite")
		ui.KeyValue("Email", collab.Email)
		ui.KeyValue("Expires", collab.ExpiresAt.Format("2006-01-02"))
		ui.Success("invite email sent with join code")
		ui.Hint("they run: lv login && lv join <code-from-email>")
		return nil
	},
}

func listCollaborators(client *api.Client, workspaceID, vaultID string) error {
	list, err := client.ListCollaborators(workspaceID, vaultID)
	if err != nil {
		return mapNotLoggedIn(err)
	}
	if len(list) == 0 {
		ui.Info("no collaborators or pending invites")
		ui.Hint("invite one: lv invite sara@company.com")
		return nil
	}
	rows := make([][]string, 0, len(list))
	for _, c := range list {
		rows = append(rows, []string{c.Email, c.Status, c.ID, c.CreatedAt.Format("2006-01-02 15:04")})
	}
	ui.Header("Vault Collaborators")
	ui.Table([]string{"EMAIL", "STATUS", "ID", "CREATED"}, rows)
	return nil
}

func revokeCollaborator(client *api.Client, workspaceID, vaultID, emailOrID string) error {
	list, err := client.ListCollaborators(workspaceID, vaultID)
	if err != nil {
		return mapNotLoggedIn(err)
	}
	var target *api.Collaborator
	for i := range list {
		c := &list[i]
		if c.Status != "pending" {
			continue
		}
		if c.ID == emailOrID || strings.EqualFold(c.Email, emailOrID) {
			target = c
			break
		}
	}
	if target == nil {
		return fmt.Errorf("no pending invite matching %q", emailOrID)
	}
	if err := client.RevokeCollaborator(workspaceID, vaultID, target.ID); err != nil {
		return mapNotLoggedIn(err)
	}
	ui.Success("invite revoked")
	ui.KeyValue("Email", target.Email)
	return nil
}

func init() {
	inviteCmd.Flags().Bool("list", false, "list collaborators and pending invites")
	inviteCmd.Flags().String("revoke", "", "revoke a pending invite by email or id")
	rootCmd.AddCommand(inviteCmd)
}
