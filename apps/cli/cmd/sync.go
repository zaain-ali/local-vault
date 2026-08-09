package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/zain-23/local-vault/apps/cli/internal/identity"
	internalsync "github.com/zain-23/local-vault/apps/cli/internal/sync"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
	"github.com/zain-23/local-vault/apps/cli/internal/vault"
)

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Pull latest secrets from server and peers",
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

		client, err := requireAPI()
		if err != nil {
			return err
		}

		ui.Step("syncing...")
		totalMerged := 0

		detail, err := client.GetVault(cfg.WorkspaceID, cfg.VaultID)
		if err != nil {
			return mapNotLoggedIn(err)
		}
		newPeers := 0
		for _, sp := range detail.Peers {
			if sp.DeviceID == id.DeviceID {
				continue
			}
			if _, found := v.GetPeer(sp.DeviceID); !found {
				_ = v.AddPeer(apiPeerToVault(sp))
				newPeers++
				ui.Info("new peer: %s", sp.DeviceName)
			}
		}
		if newPeers > 0 {
			ui.Success("added %d new peer(s)", newPeers)
		}

		if dek := v.GetDataKey(); len(dek) > 0 {
			if snap, derr := client.PullSnapshot(cfg.WorkspaceID, cfg.VaultID, id.DeviceID); derr == nil && snap != nil && snap.Snapshot != nil {
				rawSecrets, serr := internalsync.DecryptSnapshot(snap.Snapshot, dek)
				if serr != nil {
					return fmt.Errorf("snapshot decryption failed — vault key mismatch")
				}
				secrets := make([]vault.SecretEntry, len(rawSecrets))
				for i, s := range rawSecrets {
					secrets[i] = vault.SecretEntry{
						Key: s.Key, Value: s.Value, Env: s.Env, UpdatedAt: s.UpdatedAt,
					}
				}
				count, merr := v.MergeSecrets(secrets)
				if merr != nil {
					return merr
				}
				if count > 0 {
					totalMerged += count
					ui.Success("%d secret(s) from snapshot", count)
				}
			}
		}

		msgs, err := client.GetMessages(id.DeviceID)
		if err != nil {
			return mapNotLoggedIn(err)
		}

		if msgs.Count == 0 {
			if totalMerged > 0 {
				ui.Success("synced %d secret(s)", totalMerged)
			} else {
				ui.Success("already up to date")
			}
			return nil
		}

		ui.Info("found %d message(s)", msgs.Count)

		for _, msg := range msgs.Messages {
			peer, found := v.GetPeer(msg.FromDeviceID)
			if !found {
				if msg.FromPublicKey != nil {
					_ = v.AddPeer(vault.Peer{
						DeviceID:        msg.FromDeviceID,
						DeviceName:      msg.FromDeviceID,
						PublicKey:       msg.FromPublicKey,
						X25519PublicKey: msg.FromPublicKey,
					})
					peer, _ = v.GetPeer(msg.FromDeviceID)
					ui.Success("new peer: %s", shortID(msg.FromDeviceID))
				} else {
					continue
				}
			}

			if string(msg.Payload) == "hello" {
				ui.Info("hello from %s", peer.DeviceName)
				continue
			}

			if bytes.HasPrefix(msg.Payload, []byte("peers:")) {
				peerJSON := msg.Payload[6:]
				var newPeers []vault.Peer
				if err := json.Unmarshal(peerJSON, &newPeers); err != nil {
					continue
				}
				discovered := 0
				for _, np := range newPeers {
					if _, exists := v.GetPeer(np.DeviceID); !exists {
						_ = v.AddPeer(np)
						discovered++
						ui.Info("discovered: %s", np.DeviceName)
					}
				}
				if discovered > 0 {
					ui.Success("added %d peer(s) to mesh", discovered)
				}
				continue
			}

			if peer.X25519PublicKey == nil {
				continue
			}

			rawSecrets, err := internalsync.DecryptFromPeer(
				msg.Payload, id.X25519PrivateKey, peer.X25519PublicKey,
			)
			if err != nil {
				ui.Warn("could not decrypt from %s", peer.DeviceName)
				continue
			}
			if len(rawSecrets) == 0 {
				continue
			}

			secrets := make([]vault.SecretEntry, len(rawSecrets))
			for i, s := range rawSecrets {
				secrets[i] = vault.SecretEntry{
					Key: s.Key, Value: s.Value, Env: s.Env, UpdatedAt: s.UpdatedAt,
				}
			}
			count, err := v.MergeSecrets(secrets)
			if err != nil {
				return err
			}
			totalMerged += count
			ui.Success("%d secret(s) from %s", count, peer.DeviceName)
		}

		if totalMerged > 0 {
			ui.Success("synced %d secret(s)", totalMerged)
		} else {
			ui.Success("no new changes")
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(syncCmd)
}
