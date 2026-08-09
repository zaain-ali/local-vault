package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/zain-23/local-vault/apps/cli/internal/api"
	"github.com/zain-23/local-vault/apps/cli/internal/appstate"
	"github.com/zain-23/local-vault/apps/cli/internal/identity"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var whoamiDevice bool

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show the logged-in account (or --device for this vault's device identity)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if whoamiDevice {
			return showDeviceIdentity()
		}
		return showAccount()
	},
}

func showAccount() error {
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
	ui.KeyValue("Device", st.DeviceName)
	return nil
}

// showDeviceIdentity prints this directory's vault device identity (the old whoami).
func showDeviceIdentity() error {
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	lvDir := filepath.Join(dir, ".lv")
	id, err := identity.Load(lvDir)
	if err != nil {
		return err
	}

	ui.Header("Device Identity")
	ui.KeyValue("Device Name", id.DeviceName)
	ui.KeyValue("Device ID", id.DeviceID)
	ui.KeyValue("Created At", id.CreatedAt.Format("2006-01-02 15:04:05"))
	ui.Info("Public Key (safe to share):")
	fmt.Fprintln(os.Stderr, id.PublicKeyString())
	return nil
}

func init() {
	whoamiCmd.Flags().BoolVar(&whoamiDevice, "device", false, "show this vault's device identity instead of the account")
	rootCmd.AddCommand(whoamiCmd)
}
