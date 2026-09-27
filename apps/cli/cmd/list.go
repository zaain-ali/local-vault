package cmd

import (
	"github.com/spf13/cobra"
	"github.com/zain-23/local-vault/apps/cli/internal/localstore"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List secrets (keys only, values hidden)",
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
			ui.Info("no secrets found")
			ui.Hint("add one with: lv add KEY=VALUE")
			return nil
		}
		rows := make([][]string, 0, len(secrets))
		for _, s := range secrets {
			val := s.Value
			if len(val) > 3 {
				val = val[:3] + "***"
			} else {
				val = "***"
			}
			rows = append(rows, []string{s.Key, v.Env, val})
		}
		ui.Header("LocalVault Secrets")
		ui.Table([]string{"KEY", "ENV", "VALUE"}, rows)
		ui.Info("%d secret(s) in %s", len(secrets), v.Env)
		return nil
	},
}

func init() {
	listCmd.Flags().StringVarP(&envFlag, "env", "e", "", "environment")
	rootCmd.AddCommand(listCmd)
}
