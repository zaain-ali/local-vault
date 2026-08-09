package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var removeCmd = &cobra.Command{
	Use:   "remove KEY",
	Short: "Remove a secret from the vault",
	Example: `  lv remove DATABASE_URL
  lv remove STRIPE_KEY --env production`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		key := args[0]
		force, _ := cmd.Flags().GetBool("force")
		if !force {
			ok, err := ui.Confirm("remove " + key + "?")
			if err != nil {
				return err
			}
			if !ok {
				ui.Info("cancelled")
				return nil
			}
		}

		dir, err := os.Getwd()
		if err != nil {
			return err
		}
		v, err := loadVault(dir)
		if err != nil {
			return err
		}
		if err := v.Remove(key, envFlag); err != nil {
			return err
		}

		env := envFlag
		if env == "" {
			env = "all environments"
		}
		ui.Success("removed %s (%s)", key, env)
		ui.Hint("run: lv push   to sync with peers")
		return nil
	},
}

func init() {
	removeCmd.Flags().StringVarP(&envFlag, "env", "e", "", "environment")
	removeCmd.Flags().BoolP("force", "f", false, "skip confirmation prompt")
	rootCmd.AddCommand(removeCmd)
}
