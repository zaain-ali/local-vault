package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/zain-23/local-vault/apps/cli/internal/session"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var lockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Lock vault and clear session",
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := os.Getwd()
		if err != nil {
			return err
		}
		lvDir := filepath.Join(dir, ".lv")

		if !session.IsUnlocked(lvDir) {
			ui.Info("vault is already locked")
			return nil
		}
		if err := session.Delete(lvDir); err != nil {
			return fmt.Errorf("failed to lock vault: %w", err)
		}
		ui.Success("vault locked")
		ui.Hint("other project vaults remain unlocked")
		ui.Hint("run: lv unlock to unlock again")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(lockCmd)
}
