package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/zain-23/local-vault/apps/cli/internal/api"
	"github.com/zain-23/local-vault/apps/cli/internal/identity"
	internalsync "github.com/zain-23/local-vault/apps/cli/internal/sync"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var revokeCmd = &cobra.Command{
	Use:   "revoke DEVICE_ID",
	Short: "Remove a peer's access to the vault",
	Example: `  lv revoke b427d8d8-8b7f-4605-9b5a-f8be956b168d

  Tip: run "lv peers" to see all device IDs`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		deviceID := args[0]
		dir, err := os.Getwd()
		if err != nil {
			return err
		}
		lvDir := filepath.Join(dir, ".lv")

		v, err := loadVault(dir)
		if err != nil {
			return err
		}

		peer, found := v.GetPeer(deviceID)
		if !found {
			return fmt.Errorf("peer not found: %s\nRun 'lv peers' to see all peers", deviceID)
		}

		force, _ := cmd.Flags().GetBool("force")
		if !force {
			ui.Warn("revoke access for %s (%s)?", peer.DeviceName, deviceID)
			ok, err := ui.Confirm("Continue")
			if err != nil {
				return err
			}
			if !ok {
				ui.Info("cancelled")
				return nil
			}
		}

		id, err := identity.Load(lvDir)
		if err != nil {
			return err
		}
		cfg, err := requireLinkedConfig(lvDir)
		if err != nil {
			return err
		}
		client, err := requireAPI()
		if err != nil {
			return err
		}

		if err := v.RemovePeer(deviceID); err != nil {
			return err
		}
		ui.Success("removed %s from local peers", peer.DeviceName)

		if err := client.RemovePeer(cfg.WorkspaceID, cfg.VaultID, deviceID); err != nil {
			ui.Warn("could not remove from server: %v", err)
			_ = mapNotLoggedIn(err)
		} else {
			ui.Success("removed %s from server", peer.DeviceName)
		}

		remainingPeers := v.GetPeers()
		if len(remainingPeers) == 0 {
			ui.Hint("no other peers to notify")
			printRevokeNextSteps(peer.DeviceName)
			return nil
		}

		vaultSecrets := v.GetSecretEntries()
		syncSecrets := make([]internalsync.SecretEntry, len(vaultSecrets))
		for i, s := range vaultSecrets {
			syncSecrets[i] = internalsync.SecretEntry{
				Key: s.Key, Value: s.Value, Env: s.Env, UpdatedAt: s.UpdatedAt,
			}
		}

		ui.Step("notifying %d remaining peer(s)...", len(remainingPeers))
		for _, p := range remainingPeers {
			if p.X25519PublicKey == nil {
				continue
			}
			payload, err := internalsync.EncryptForPeer(
				syncSecrets, id.X25519PrivateKey, p.X25519PublicKey, id.DeviceID,
			)
			if err != nil {
				ui.Warn("failed to encrypt for %s", p.DeviceName)
				continue
			}
			err = client.SendMessage(api.SendMessageRequest{
				ForDeviceID:   p.DeviceID,
				FromDeviceID:  id.DeviceID,
				FromPublicKey: id.X25519PublicKey,
				Payload:       payload,
			})
			if err != nil {
				ui.Warn("failed to notify %s", p.DeviceName)
				continue
			}
			ui.Success("notified %s", p.DeviceName)
		}

		printRevokeNextSteps(peer.DeviceName)
		return nil
	},
}

func printRevokeNextSteps(name string) {
	ui.Success("%s has been revoked", name)
	ui.Hint("lv rotate --all   then   lv push")
}

func init() {
	revokeCmd.Flags().BoolP("force", "f", false, "skip confirmation prompt")
	rootCmd.AddCommand(revokeCmd)
}
