package cmd

import (
	"github.com/spf13/cobra"

	"github.com/zain-23/local-vault/apps/cli/internal/account"
	"github.com/zain-23/local-vault/apps/cli/internal/authstore"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Log out of your LocalVault account",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := authstore.Load(); err != nil {
			ui.Info("already logged out")
			return nil
		}
		if err := authstore.Clear(); err != nil {
			return err
		}
		_ = account.Lock()
		ui.Success("logged out")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}
