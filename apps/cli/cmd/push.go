package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/zain-23/local-vault/apps/cli/internal/api"
	"github.com/zain-23/local-vault/apps/cli/internal/identity"
	internalsync "github.com/zain-23/local-vault/apps/cli/internal/sync"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
	"github.com/zain-23/local-vault/apps/cli/internal/vault"
)

var pushCmd = &cobra.Command{
	Use:   "push",
	Short: "Push secrets to server and all peers",
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
		cfg, err := requireLinkedConfig(lvDir)
		if err != nil {
			return err
		}
		v, err := loadVault(dir)
		if err != nil {
			return err
		}
		dek, err := v.EnsureDataKey()
		if err != nil {
			return err
		}

		client, err := requireAPI()
		if err != nil {
			return err
		}

		vaultSecrets := v.GetSecretEntries()
		syncSecrets := make([]internalsync.SecretEntry, len(vaultSecrets))
		for i, s := range vaultSecrets {
			syncSecrets[i] = internalsync.SecretEntry{
				Key: s.Key, Value: s.Value, Env: s.Env, UpdatedAt: s.UpdatedAt,
			}
		}

		detail, err := client.GetVault(cfg.WorkspaceID, cfg.VaultID)
		if err != nil {
			ui.Warn("using local peer list")
			_ = mapNotLoggedIn(err)
		} else {
			for _, sp := range detail.Peers {
				if sp.DeviceID == id.DeviceID {
					continue
				}
				if _, found := v.GetPeer(sp.DeviceID); !found {
					_ = v.AddPeer(apiPeerToVault(sp))
				}
			}
		}

		snapshot, err := internalsync.EncryptSnapshot(syncSecrets, dek)
		if err != nil {
			return err
		}
		if err := client.PushSnapshot(cfg.WorkspaceID, cfg.VaultID, id.DeviceID, snapshot); err != nil {
			return mapNotLoggedIn(err)
		}
		ui.Success("backed up %d secret(s) to server", len(syncSecrets))

		peers := v.GetPeers()
		if len(peers) == 0 {
			ui.Hint("no teammates yet — invite one: lv invite teammate@company.com")
			return nil
		}

		ui.Step("pushing to %d peer(s)...", len(peers))
		for _, peer := range peers {
			if peer.X25519PublicKey == nil {
				continue
			}
			payload, err := internalsync.EncryptForPeer(
				syncSecrets, id.X25519PrivateKey, peer.X25519PublicKey, id.DeviceID,
			)
			if err != nil {
				ui.Warn("failed to encrypt for %s", peer.DeviceName)
				continue
			}
			err = client.SendMessage(api.SendMessageRequest{
				ForDeviceID:   peer.DeviceID,
				FromDeviceID:  id.DeviceID,
				FromPublicKey: id.X25519PublicKey,
				Payload:       payload,
			})
			if err != nil {
				ui.Warn("failed to send to %s", peer.DeviceName)
				continue
			}
			ui.Success("sent to %s", peer.DeviceName)
		}

		for _, peer := range peers {
			if peer.X25519PublicKey == nil {
				continue
			}
			var otherPeers []vault.Peer
			for _, other := range peers {
				if other.DeviceID != peer.DeviceID {
					otherPeers = append(otherPeers, other)
				}
			}
			if len(otherPeers) == 0 {
				continue
			}
			peerJSON, _ := json.Marshal(otherPeers)
			_ = client.SendMessage(api.SendMessageRequest{
				ForDeviceID:   peer.DeviceID,
				FromDeviceID:  id.DeviceID,
				FromPublicKey: id.X25519PublicKey,
				Payload:       append([]byte("peers:"), peerJSON...),
			})
		}

		ui.Success("push complete")
		ui.Hint("peers receive secrets on next: lv sync")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(pushCmd)
}
