package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/zain-23/local-vault/apps/cli/internal/account"
	"github.com/zain-23/local-vault/apps/cli/internal/localstore"
	"github.com/zain-23/local-vault/apps/cli/internal/lvcrypto"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var addCmd = &cobra.Command{
	Use:   "add KEY=VALUE",
	Short: "Add or update a secret in the working copy",
	Example: `  lv add DATABASE_URL=postgres://localhost/mydb
  lv add API_KEY=sk-xxx --env production`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		parts := strings.SplitN(args[0], "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid format. use: lv add KEY=VALUE")
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" {
			return fmt.Errorf("key cannot be empty")
		}
		v, err := requireVault(envFlag)
		if err != nil {
			return err
		}
		if err := v.syncGrants(); err != nil {
			return err
		}
		snap, err := v.State.Working(v.Env)
		if err != nil {
			return err
		}
		sec, ok := snap.Get(key)
		if !ok {
			sec = lvcrypto.Secret{Key: key}
			snap.Secrets = append(snap.Secrets, sec)
		}
		for i := range snap.Secrets {
			if snap.Secrets[i].Key == key {
				snap.Secrets[i].Value = value
				snap.Secrets[i].Deleted = false
				localstore.Touch(&snap.Secrets[i], account.UserID())
			}
		}
		if err := v.State.SetWorking(v.Env, snap, true); err != nil {
			return err
		}
		ui.Success("added %s (%s)", key, v.Env)
		ui.Hint("run: lv push")
		return nil
	},
}

func init() {
	addCmd.Flags().StringVarP(&envFlag, "env", "e", "", "environment")
	rootCmd.AddCommand(addCmd)
}
