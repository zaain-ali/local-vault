package cmd

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/zain-23/local-vault/apps/cli/internal/account"
	"github.com/zain-23/local-vault/apps/cli/internal/api"
	"github.com/zain-23/local-vault/apps/cli/internal/appstate"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show the logged-in account and fingerprint",
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := appstate.Load()
		if err != nil {
			return err
		}
		client := api.New(st.ServerURL)
		acct, err := client.Me()
		if err != nil {
			if errors.Is(err, api.ErrNotLoggedIn) {
				ui.Warn("not logged in")
				ui.Hint("run: lv login")
				return nil
			}
			return err
		}
		twofa := "disabled"
		if acct.TwoFactorEnabled {
			twofa = "enabled"
		}
		ui.Header("Account")
		ui.KeyValue("Name", acct.Name)
		ui.KeyValue("Email", acct.Email)
		ui.KeyValue("2FA", twofa)
		ui.KeyValue("Member since", acct.CreatedAt.Format("2006-01-02"))
		if f, err := account.Load(); err == nil {
			ui.KeyValue("Fingerprint", f.Bundle.Fingerprint)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(whoamiCmd)
}
