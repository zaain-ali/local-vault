package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var importCmd = &cobra.Command{
	Use:   "import FILE",
	Short: "Import secrets from a .env file into vault",
	Example: `  lv import .env.local
  lv import .env.production --env production`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			return fmt.Errorf("file not found: %s", filePath)
		}

		dir, err := os.Getwd()
		if err != nil {
			return err
		}
		v, err := loadVault(dir)
		if err != nil {
			return err
		}

		count, err := v.ImportEnvFile(filePath, envFlag)
		if err != nil {
			return err
		}

		env := envFlag
		if env == "" {
			env = "all environments"
		}
		ui.Success("imported %d secrets (%s)", count, env)
		ui.Hint("you can now safely delete %s", filePath)

		secrets := v.List(envFlag)
		rows := make([][]string, 0, len(secrets))
		for _, s := range secrets {
			rows = append(rows, []string{s.Key})
		}
		if len(rows) > 0 {
			ui.Table([]string{"KEY"}, rows)
		}
		ui.Hint("run: lv push   to sync with peers")
		return nil
	},
}

func init() {
	importCmd.Flags().StringVarP(&envFlag, "env", "e", "", "environment to import into")
	rootCmd.AddCommand(importCmd)
}
