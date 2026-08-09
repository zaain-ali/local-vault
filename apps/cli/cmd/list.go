package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all secrets (keys only, values hidden)",
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, _ := os.Getwd()
		v, err := loadVault(dir)
		if err != nil {
			return err
		}

		secrets := v.List(envFlag)
		if len(secrets) == 0 {
			ui.Info("no secrets found")
			ui.Hint("add one with: lv add KEY=VALUE")
			return nil
		}

		rows := make([][]string, 0, len(secrets))
		for _, s := range secrets {
			env := s.Env
			if env == "" {
				env = "all"
			}
			rows = append(rows, []string{s.Key, env, s.Value})
		}
		ui.Header("LocalVault Secrets")
		ui.Table([]string{"KEY", "ENV", "VALUE"}, rows)
		ui.Info("%d secret(s) total", len(secrets))
		return nil
	},
}

func init() {
	listCmd.Flags().StringVarP(&envFlag, "env", "e", "", "filter by environment")
	rootCmd.AddCommand(listCmd)
}
