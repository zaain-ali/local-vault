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
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show vault status and sync info",
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := os.Getwd()
		if err != nil {
			return err
		}
		lvDir := filepath.Join(dir, ".lv")

		id, err := identity.Load(lvDir)
		if err != nil {
			return err
		}
		v, err := loadVault(dir)
		if err != nil {
			return err
		}

		secrets := v.List("")
		localPeers := v.GetPeers()

		envCounts := map[string]int{}
		for _, s := range secrets {
			env := s.Env
			if env == "" {
				env = "all"
			}
			envCounts[env]++
		}

		lockStatus := "Locked"
		if remaining, err := session.TimeRemaining(lvDir); err == nil {
			hours := int(remaining.Hours())
			minutes := int(remaining.Minutes()) % 60
			lockStatus = fmt.Sprintf("Unlocked (%dh %dm remaining)", hours, minutes)
		}

		cfg, _ := config.Load(lvDir)

		ui.Header("LocalVault Status")
		ui.KeyValue("Device", id.DeviceName)
		ui.KeyValue("Device ID", id.DeviceID)
		ui.KeyValue("Session", lockStatus)

		if cfg != nil && cfg.WorkspaceID != "" {
			ui.KeyValue("Workspace", cfg.WorkspaceID)
		} else {
			ui.KeyValue("Workspace", "not linked")
		}
		if cfg != nil && cfg.VaultID != "" {
			ui.KeyValue("Vault", cfg.VaultID)
		} else {
			ui.KeyValue("Vault", "not linked")
		}

		vaultName := ""
		serverPeerCount := -1
		if cfg != nil && cfg.WorkspaceID != "" && cfg.VaultID != "" {
			if client, cerr := requireAPI(); cerr == nil {
				if detail, gerr := client.GetVault(cfg.WorkspaceID, cfg.VaultID); gerr == nil {
					vaultName = detail.Name
					serverPeerCount = len(detail.Peers)
				} else if errors.Is(gerr, api.ErrNotLoggedIn) {
					ui.Warn("not logged in — server details skipped")
					ui.Hint("run: lv login")
				}
			}
		}
		if vaultName != "" {
			ui.KeyValue("Vault name", vaultName)
		}

		ui.KeyValue("Secrets", fmt.Sprintf("%d total", len(secrets)))
		for env, count := range envCounts {
			ui.KeyValue("  "+env, fmt.Sprintf("%d", count))
		}

		if serverPeerCount >= 0 {
			ui.KeyValue("Peers", fmt.Sprintf("%d on server (%d local)", serverPeerCount, len(localPeers)))
		} else {
			ui.KeyValue("Peers", fmt.Sprintf("%d trusted (local)", len(localPeers)))
		}
		for _, peer := range localPeers {
			ui.Info("  %s (%s)", peer.DeviceName, shortID(peer.DeviceID))
		}

		ui.Hint("lv sync   to pull latest secrets")
		ui.Hint("lv push   to send secrets to peers")
		ui.Hint("lv invite teammate@company.com")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
