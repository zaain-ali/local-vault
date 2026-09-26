package cmd

import (
	"github.com/spf13/cobra"
	"github.com/zain-23/local-vault/apps/cli/internal/localstore"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var injectCmd = &cobra.Command{
	Use:   "inject [-- command]",
	Short: "Print export statements or run a command with secrets",
	Example: `  lv inject
  lv inject -- npm run dev`,
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := requireVault(envFlag)
		if err != nil {
			return err
		}
		snap, err := v.State.Working(v.Env)
		if err != nil {
			return err
		}
		secrets := localstore.InjectMap(snap)
		if len(secrets) == 0 {
			ui.Info("no secrets found for this environment")
			ui.Hint("add secrets with: lv add KEY=value")
			return nil
		}
		if len(args) > 0 {
			ui.Step("injected %d secrets, starting: %s", len(secrets), args[0])
		}
		return execWithSecrets(secrets, args)
	},
}

func init() {
	injectCmd.Flags().StringVarP(&envFlag, "env", "e", "", "environment")
	rootCmd.AddCommand(injectCmd)
}
