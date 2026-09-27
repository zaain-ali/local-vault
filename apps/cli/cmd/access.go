package cmd

import (
	"github.com/spf13/cobra"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var accessYes bool

var accessCmd = &cobra.Command{
	Use:   "access",
	Short: "Show or fulfill pending key grants",
}

var accessPendingCmd = &cobra.Command{
	Use:   "pending",
	Short: "List members and machines waiting for a key grant",
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := requireVault(envFlag)
		if err != nil {
			return err
		}
		pending, err := v.Client.PendingGrants(v.Project.Workspace, v.Project.Vault)
		if err != nil {
			return mapNotLoggedIn(err)
		}
		if len(pending) == 0 {
			ui.Success("no pending grants")
			return nil
		}
		rows := make([][]string, 0, len(pending))
		for _, p := range pending {
			rows = append(rows, []string{p.Env, p.Label, p.Email, p.Fingerprint, p.KeyType})
		}
		ui.Header("Pending grants")
		ui.Table([]string{"ENV", "LABEL", "EMAIL", "FINGERPRINT", "KEY"}, rows)
		ui.Hint("verify fingerprints, then: lv access grant")
		return nil
	},
}

var accessGrantCmd = &cobra.Command{
	Use:   "grant",
	Short: "Wrap the environment DEK to pending recipients (after fingerprint check)",
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := requireVault(envFlag)
		if err != nil {
			return err
		}
		return v.grantPending(accessYes)
	},
}

func init() {
	accessGrantCmd.Flags().BoolVarP(&accessYes, "yes", "y", false, "skip confirmation")
	accessCmd.AddCommand(accessPendingCmd, accessGrantCmd)
	accessCmd.RunE = accessPendingCmd.RunE
	rootCmd.AddCommand(accessCmd)
}
