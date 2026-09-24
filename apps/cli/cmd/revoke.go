package cmd

import (
	"github.com/spf13/cobra"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var revokeCmd = &cobra.Command{
	Use:   "revoke EMAIL_OR_ID",
	Short: "Remove a vault member (alias of lv invite --revoke)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := requireVault(envFlag)
		if err != nil {
			return err
		}
		if err := revokeVaultMember(v, args[0]); err != nil {
			return err
		}
		ui.Hint("lv rekey --env <env>   then rotate secret values")
		return nil
	},
}

func init() {
	revokeCmd.Flags().StringVarP(&envFlag, "env", "e", "", "environment")
	rootCmd.AddCommand(revokeCmd)
}
