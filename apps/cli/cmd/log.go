package cmd

import (
	"github.com/spf13/cobra"
	"github.com/zain-23/local-vault/apps/cli/internal/localstore"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var logCmd = &cobra.Command{
	Use:   "log",
	Short: "Show keys in the working copy with last-updated metadata",
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := requireVault(envFlag)
		if err != nil {
			return err
		}
		snap, err := v.State.Working(v.Env)
		if err != nil {
			return err
		}
		secrets := localstore.ActiveSecrets(snap)
		if len(secrets) == 0 {
			ui.Info("no secrets yet")
			return nil
		}
		ui.Header("Working copy")
		rows := make([][]string, 0, len(secrets))
		for _, s := range secrets {
			rows = append(rows, []string{
				s.Key,
				v.Env,
				s.UpdatedAt.Format("2006-01-02 15:04:05"),
				shortID(s.UpdatedBy),
			})
		}
		ui.Table([]string{"KEY", "ENV", "UPDATED", "BY"}, rows)
		return nil
	},
}

func init() {
	logCmd.Flags().StringVarP(&envFlag, "env", "e", "", "environment")
	rootCmd.AddCommand(logCmd)
}
