package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/zain-23/local-vault/apps/cli/internal/session"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
	"github.com/zain-23/local-vault/apps/cli/internal/vault"
)

var unlockCmd = &cobra.Command{
	Use:   "unlock",
	Short: "Unlock vault for this session (12 hours)",
	Long: `Unlocks the vault by asking your passphrase once.
The derived key is cached in your OS keychain.
All other commands work without prompting until session expires.

Session lasts 12 hours or until you run: lv lock`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := os.Getwd()
		if err != nil {
			return err
		}
		lvDir := filepath.Join(dir, ".lv")

		if session.IsUnlocked(lvDir) {
			remaining, _ := session.TimeRemaining(lvDir)
			hours := int(remaining.Hours())
			minutes := int(remaining.Minutes()) % 60
			ui.Success("already unlocked (%dh %dm remaining)", hours, minutes)
			ui.Hint("run: lv lock to lock now")
			return nil
		}

		ui.Title("Unlocking vault")
		passphrase, err := promptPassphrase()
		if err != nil {
			return err
		}

		v, err := vault.Load(dir, passphrase)
		if err != nil {
			return err
		}
		if err := session.Save(lvDir, v.GetKey()); err != nil {
			return fmt.Errorf("failed to save session: %w", err)
		}

		expiresAt := time.Now().Add(12 * time.Hour)
		ui.Success("vault unlocked")
		ui.KeyValue("Valid until", expiresAt.Format("15:04:05 (Jan 02)"))
		ui.Hint("run: lv lock   to lock immediately")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(unlockCmd)
}
