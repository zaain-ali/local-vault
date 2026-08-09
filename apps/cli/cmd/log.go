package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var logCmd = &cobra.Command{
	Use:   "log",
	Short: "Show audit trail of vault changes",
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := os.Getwd()
		if err != nil {
			return err
		}
		v, err := loadVault(dir)
		if err != nil {
			return err
		}

		entries := v.GetAuditLog()
		if len(entries) == 0 {
			ui.Info("no audit log entries yet")
			ui.Hint("entries are recorded when you add, update, or remove secrets")
			return nil
		}

		ui.Header("Vault Audit Log")
		rows := make([][]string, 0, len(entries))
		for _, entry := range entries {
			env := entry.Env
			if env == "" {
				env = "all"
			}
			rows = append(rows, []string{
				ui.AuditGlyph(entry.Action) + " " + entry.Action,
				entry.Key + " [" + env + "]",
				entry.Timestamp.Format("2006-01-02 15:04:05"),
				shortID(entry.DeviceID),
			})
		}
		ui.Table([]string{"ACTION", "KEY", "WHEN", "DEVICE"}, rows)
		ui.Info("%d entries total", len(entries))
		return nil
	},
}

func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8] + "..."
}

func init() {
	rootCmd.AddCommand(logCmd)
}
