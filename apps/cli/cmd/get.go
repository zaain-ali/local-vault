package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var getCmd = &cobra.Command{
	Use:   "get KEY",
	Short: "Get the value of a secret",
	Example: `  lv get DATABASE_URL
  lv get STRIPE_KEY --env production`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := requireVault(envFlag)
		if err != nil {
			return err
		}
		snap, err := v.State.Working(v.Env)
		if err != nil {
			return err
		}
		sec, ok := snap.Get(args[0])
		if !ok || sec.Deleted {
			return fmt.Errorf("secret %q not found", args[0])
		}
		fmt.Fprintln(os.Stdout, sec.Value)
		return nil
	},
}

func init() {
	getCmd.Flags().StringVarP(&envFlag, "env", "e", "", "environment")
	rootCmd.AddCommand(getCmd)
}
