package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var joinCmd = &cobra.Command{
	Use:   "join",
	Short: "Deprecated — use lv link after an admin adds you",
	RunE: func(cmd *cobra.Command, args []string) error {
		ui.Warn("join codes are gone. invites no longer wrap the vault key.")
		ui.Hint("1. an admin adds you: lv invite you@company.com")
		ui.Hint("2. they grant your fingerprint: lv access grant")
		ui.Hint("3. you link the project: lv link --vault vlt_...")
		return fmt.Errorf("lv join is no longer supported")
	},
}

func init() {
	rootCmd.AddCommand(joinCmd)
}
