package cmd

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/zain-23/local-vault/apps/cli/internal/api"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var peersCmd = &cobra.Command{
	Use:   "peers",
	Short: "List vault peers (devices with access)",
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := os.Getwd()
		if err != nil {
			return err
		}
		lvDir := filepath.Join(dir, ".lv")

		if cfg, err := requireLinkedConfig(lvDir); err == nil {
			if client, err := requireAPI(); err == nil {
				detail, err := client.GetVault(cfg.WorkspaceID, cfg.VaultID)
				if err != nil {
					return mapNotLoggedIn(err)
				}
				return printServerPeers(detail.Peers, cfg.DeviceID)
			}
		}

		v, err := loadVault(dir)
		if err != nil {
			return err
		}
		peers := v.GetPeers()
		if len(peers) == 0 {
			ui.Info("no trusted peers yet")
			ui.Hint("invite a teammate: lv invite teammate@company.com")
			return nil
		}

		rows := make([][]string, 0, len(peers))
		for _, peer := range peers {
			rows = append(rows, []string{
				peer.DeviceName,
				"—",
				"—",
				shortID(peer.DeviceID),
				peer.AddedAt.Format("2006-01-02"),
			})
		}
		ui.Header("Trusted Peers (local)")
		ui.Table([]string{"DEVICE", "NAME", "EMAIL", "ID", "ADDED"}, rows)
		ui.Info("%d peer(s) total", len(peers))
		ui.Hint("run lv login && lv sync to refresh from server")
		return nil
	},
}

func printServerPeers(peers []api.Peer, selfDeviceID string) error {
	if len(peers) == 0 {
		ui.Info("no peers on this vault yet")
		ui.Hint("invite a teammate: lv invite teammate@company.com")
		return nil
	}

	rows := make([][]string, 0, len(peers))
	for _, p := range peers {
		name := p.Name
		if name == "" {
			name = "—"
		}
		email := p.Email
		if email == "" {
			email = "—"
		}
		device := p.DeviceName
		if p.DeviceID == selfDeviceID {
			device = device + " (you)"
		}
		joined := "—"
		if !p.JoinedAt.IsZero() {
			joined = p.JoinedAt.Format("2006-01-02")
		}
		rows = append(rows, []string{device, name, email, shortID(p.DeviceID), joined})
	}
	ui.Header("Vault Peers")
	ui.Table([]string{"DEVICE", "NAME", "EMAIL", "ID", "JOINED"}, rows)
	ui.Info("%d peer(s) total", len(peers))
	return nil
}

func init() {
	rootCmd.AddCommand(peersCmd)
}
