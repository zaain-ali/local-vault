package cmd

// get.go handles the "lv get KEY" command
// Shows the actual value of a single secret
// Unlike list which shows all keys but hides values

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var getCmd = &cobra.Command{
	Use:   "get KEY",
	Short: "Get the value of a secret",
	Example: `  lv get DATABASE_URL
  lv get STRIPE_KEY --env production
  lv get API_KEY --env development`,
	Args: cobra.ExactArgs(1),

	RunE: func(cmd *cobra.Command, args []string) error {
		key := args[0]

		dir, err := os.Getwd()
		if err != nil {
			return err
		}

		// Use session key — no passphrase needed
		v, err := loadVault(dir)
		if err != nil {
			return err
		}

		value, err := v.Get(key, envFlag)
		if err != nil {
			return err
		}

		// Print clean value only
		// Allows piping: lv get DATABASE_URL | xclip
		fmt.Fprintln(os.Stdout, value)
		return nil
	},
}

func init() {
	getCmd.Flags().StringVarP(&envFlag, "env", "e", "", "environment (development/staging/production)")
	rootCmd.AddCommand(getCmd)
}
