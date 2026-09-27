package cmd

import (
	"time"

	"github.com/spf13/cobra"
	"github.com/zain-23/local-vault/apps/cli/internal/account"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var unlockCmd = &cobra.Command{
	Use:   "unlock",
	Short: "Unlock account keys for this session (12 hours)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := account.Keys(); err == nil {
			ui.Success("already unlocked")
			ui.Hint("run: lv lock to lock now")
			return nil
		}
		pass, err := promptPassphrase()
		if err != nil {
			return err
		}
		keys, err := account.Unlock(pass)
		if err != nil {
			return err
		}
		ui.Success("account unlocked")
		ui.KeyValue("Fingerprint", keys.Fingerprint())
		ui.KeyValue("Valid until", time.Now().Add(12*time.Hour).Format("15:04:05 (Jan 02)"))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(unlockCmd)
}
