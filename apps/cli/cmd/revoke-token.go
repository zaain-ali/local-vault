package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var revokeTokenCmd = &cobra.Command{
	Use:   "revoke-token TOKEN",
	Short: "Revoke a legacy join token (prefer email invites)",
	Example: `  lv revoke-token lv_join_a3f9b2c1xxx

  Prefer: lv invite --revoke teammate@company.com`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		tokenID := args[0]
		dir, err := os.Getwd()
		if err != nil {
			return err
		}
		lvDir := filepath.Join(dir, ".lv")

		cfg, err := requireLinkedConfig(lvDir)
		if err != nil {
			return err
		}
		client, err := requireAPI()
		if err != nil {
			return err
		}

		ui.Warn("join tokens are legacy — prefer: lv invite --revoke <email>")
		if err := client.RevokeToken(cfg.WorkspaceID, cfg.VaultID, tokenID); err != nil {
			return mapNotLoggedIn(fmt.Errorf("failed to revoke token: %w", err))
		}

		ui.Success("token revoked")
		ui.KeyValue("Token", tokenID)
		ui.Hint("already joined peers keep their access")
		ui.Hint("to remove peer access: lv revoke <device-id>")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(revokeTokenCmd)
}
