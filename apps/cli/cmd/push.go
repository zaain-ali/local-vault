package cmd

import (
	"github.com/spf13/cobra"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var pushNote string

var pushCmd = &cobra.Command{
	Use:   "push",
	Short: "Push the working copy as a signed revision",
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := requireVault(envFlag)
		if err != nil {
			return err
		}
		if err := v.push(pushNote); err != nil {
			return err
		}
		ui.Hint("teammates pull with: lv pull")
		return nil
	},
}

func init() {
	pushCmd.Flags().StringVarP(&envFlag, "env", "e", "", "environment")
	pushCmd.Flags().StringVar(&pushNote, "note", "", "note for a protected-environment change request")
	rootCmd.AddCommand(pushCmd)
}
