package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/zain-23/local-vault/apps/cli/internal/api"
	"github.com/zain-23/local-vault/apps/cli/internal/config"
	"github.com/zain-23/local-vault/apps/cli/internal/identity"
	"github.com/zain-23/local-vault/apps/cli/internal/session"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
	"github.com/zain-23/local-vault/apps/cli/internal/vault"
)

var (
	initWorkspace string
	initName      string
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new vault in the current directory",
	RunE: func(cmd *cobra.Command, args []string) error {
		ui.Title("Initializing vault")

		client, err := requireAPI()
		if err != nil {
			return err
		}
		if _, err := client.Me(); err != nil {
			return mapNotLoggedIn(err)
		}

		list, err := client.ListWorkspaces()
		if err != nil {
			return mapNotLoggedIn(err)
		}
		workspaceID, err := resolveWorkspaceID(initWorkspace, list, stdinLine)
		if err != nil {
			return err
		}

		passphrase, err := ui.Passphrase("Enter passphrase")
		if err != nil {
			return err
		}
		confirm, err := ui.Passphrase("Confirm passphrase")
		if err != nil {
			return err
		}
		if passphrase != confirm {
			return fmt.Errorf("passphrases do not match")
		}
		if len(passphrase) < 8 {
			return fmt.Errorf("passphrase must be at least 8 characters")
		}

		dir, err := os.Getwd()
		if err != nil {
			return err
		}
		lvDir := filepath.Join(dir, ".lv")

		name := initName
		if name == "" {
			name = filepath.Base(dir)
		}

		if err := vault.Init(dir, passphrase); err != nil {
			return err
		}

		id, err := identity.Load(lvDir)
		if err != nil {
			return err
		}

		ui.Step("registering vault on server...")
		resp, err := client.CreateVault(workspaceID, api.CreateVaultRequest{
			Name:            name,
			OwnerDeviceID:   id.DeviceID,
			OwnerName:       id.DeviceName,
			PublicKey:       id.PublicKey,
			X25519PublicKey: id.X25519PublicKey,
		})
		if err != nil {
			if mapped := mapNotLoggedIn(err); errors.Is(mapped, api.ErrNotLoggedIn) {
				return mapped
			}
			return fmt.Errorf("server registration failed: %w\n  fix login/network, then remove .lv and re-run: lv init", err)
		}

		cfg, err := config.Load(lvDir)
		if err != nil {
			return err
		}
		cfg.WorkspaceID = workspaceID
		cfg.VaultID = resp.VaultID
		cfg.DeviceID = id.DeviceID
		if err := config.Save(lvDir, cfg); err != nil {
			return err
		}

		if v, err := vault.Load(dir, passphrase); err == nil {
			if err := session.Save(lvDir, v.GetKey()); err == nil {
				ui.Success("auto-unlocked for 12 hours")
			}
		}

		ui.Success("vault initialized — %s", resp.VaultID)
		ui.Hint("lv add DATABASE_URL=postgres://...")
		ui.Hint("lv push")
		ui.Hint("lv invite teammate@company.com")
		return nil
	},
}

func init() {
	initCmd.Flags().StringVar(&initWorkspace, "workspace", "", "workspace id (skips picker)")
	initCmd.Flags().StringVar(&initName, "name", "", "vault name (default: directory name)")
	rootCmd.AddCommand(initCmd)
}
