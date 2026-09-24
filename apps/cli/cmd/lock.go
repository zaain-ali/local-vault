package cmd

import (
	"github.com/spf13/cobra"
	"github.com/zain-23/local-vault/apps/cli/internal/account"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var lockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Lock account keys and clear the session",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := account.Lock(); err != nil {
			return err
		}
		ui.Success("account locked")
		ui.Hint("run: lv unlock")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(lockCmd)
}
