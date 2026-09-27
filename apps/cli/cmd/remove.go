package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/zain-23/local-vault/apps/cli/internal/account"
	"github.com/zain-23/local-vault/apps/cli/internal/localstore"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var removeCmd = &cobra.Command{
	Use:   "remove KEY",
	Short: "Remove a secret from the working copy",
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
		v, err := requireVault(envFlag)
		if err != nil {
			return err
		}
		snap, err := v.State.Working(v.Env)
		if err != nil {
			return err
		}
		found := false
		for i := range snap.Secrets {
			if snap.Secrets[i].Key == key {
				snap.Secrets[i].Deleted = true
				snap.Secrets[i].Value = ""
				localstore.Touch(&snap.Secrets[i], account.UserID())
				found = true
			}
		}
		if !found {
			return fmt.Errorf("secret %q not found", key)
		}
		if err := v.State.SetWorking(v.Env, snap, true); err != nil {
			return err
		}
		ui.Success("removed %s (%s)", key, v.Env)
		ui.Hint("run: lv push")
		return nil
	},
}

func init() {
	removeCmd.Flags().StringVarP(&envFlag, "env", "e", "", "environment")
	removeCmd.Flags().BoolP("force", "f", false, "skip confirmation prompt")
	rootCmd.AddCommand(removeCmd)
}
