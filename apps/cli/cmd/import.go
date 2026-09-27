package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/zain-23/local-vault/apps/cli/internal/account"
	"github.com/zain-23/local-vault/apps/cli/internal/localstore"
	"github.com/zain-23/local-vault/apps/cli/internal/lvcrypto"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var importCmd = &cobra.Command{
	Use:   "import FILE",
	Short: "Import secrets from a .env file into the working copy",
	Example: `  lv import .env.local
  lv import .env.production --env production`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			return fmt.Errorf("file not found: %s", filePath)
		}
		pairs, err := parseEnvFile(filePath)
		if err != nil {
			return err
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
		count := 0
		for key, value := range pairs {
			_, ok := snap.Get(key)
			if !ok {
				snap.Secrets = append(snap.Secrets, lvcrypto.Secret{Key: key})
			}
			for i := range snap.Secrets {
				if snap.Secrets[i].Key == key {
					snap.Secrets[i].Value = value
					snap.Secrets[i].Deleted = false
					localstore.Touch(&snap.Secrets[i], account.UserID())
				}
			}
			count++
		}
		if err := v.State.SetWorking(v.Env, snap, true); err != nil {
			return err
		}
		ui.Success("imported %d secrets (%s)", count, v.Env)
		ui.Hint("run: lv push")
		return nil
	},
}

func init() {
	importCmd.Flags().StringVarP(&envFlag, "env", "e", "", "environment")
	rootCmd.AddCommand(importCmd)
}
