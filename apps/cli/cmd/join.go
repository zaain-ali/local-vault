package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/zain-23/local-vault/apps/cli/internal/api"
	"github.com/zain-23/local-vault/apps/cli/internal/config"
	"github.com/zain-23/local-vault/apps/cli/internal/identity"
	internalsync "github.com/zain-23/local-vault/apps/cli/internal/sync"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
	"github.com/zain-23/local-vault/apps/cli/internal/vault"
)

var joinCmd = &cobra.Command{
	Use:   "join CODE",
	Short: "Join a vault using an emailed invite code",
	Example: `  lv join ABCD-1234

  Tip: you must be logged in and already a workspace member`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		code := strings.TrimSpace(args[0])
		if code == "" {
			return fmt.Errorf("provide the invite code from your email")
		}
		if strings.HasPrefix(strings.ToLower(code), "lv_join_") || strings.Contains(code, ".") {
			return fmt.Errorf("join tokens are no longer supported\n  Ask an owner/admin for a new invite: lv invite you@company.com\n  Then run: lv join ABCD-1234")
		}

		dir, err := os.Getwd()
		if err != nil {
			return err
		}
		lvDir := filepath.Join(dir, ".lv")

		id, err := identity.Load(lvDir)
		if err != nil {
			return err
		}
		client, err := requireAPI()
		if err != nil {
			return err
		}
		v, err := loadVault(dir)
		if err != nil {
			return err
		}

		code = normalizeJoinCode(code)
		ui.Step("joining vault...")
		resp, err := client.JoinByCode(api.JoinByCodeRequest{
			Code:            code,
			DeviceID:        id.DeviceID,
			DeviceName:      id.DeviceName,
			PublicKey:       id.PublicKey,
			X25519PublicKey: id.X25519PublicKey,
		})
		if err != nil {
			return mapNotLoggedIn(fmt.Errorf("failed to join: %w", err))
		}

		cfg, err := config.Load(lvDir)
		if err != nil {
			cfg = &config.Config{}
		}
		cfg.VaultID = resp.VaultID
		cfg.WorkspaceID = resp.WorkspaceID
		cfg.DeviceID = id.DeviceID
		if err := config.Save(lvDir, cfg); err != nil {
			return err
		}

		ui.Success("joined vault %s", resp.VaultID)
		if resp.Message != "" {
			ui.Info("%s", resp.Message)
		}
		for _, peer := range resp.Peers {
			if peer.DeviceID == id.DeviceID {
				continue
			}
			_ = v.AddPeer(apiPeerToVault(peer))
		}

		if resp.WrappedDEK == nil {
			return fmt.Errorf("invite is missing vault key — ask for a new invite")
		}
		dek, err := internalsync.UnwrapKey(resp.WrappedDEK, []byte(code))
		if err != nil {
			return fmt.Errorf("could not unwrap vault key — wrong code or corrupted invite")
		}
		if err := v.SetDataKey(dek); err != nil {
			return err
		}

		if resp.Snapshot != nil {
			ui.Step("downloading vault snapshot...")
			rawSecrets, err := internalsync.DecryptSnapshot(resp.Snapshot, dek)
			if err != nil {
				return fmt.Errorf("snapshot decryption failed — vault key mismatch")
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
			ui.Success("received %d secret(s)", count)
		} else {
			ui.Warn("no secrets pushed yet — they will arrive on: lv sync")
		}

		ui.Header("Joined")
		ui.KeyValue("Vault", resp.VaultID)
		ui.KeyValue("Workspace", resp.WorkspaceID)
		ui.Hint("lv sync / lv inject -- npm run dev")
		return nil
	},
}

func normalizeJoinCode(s string) string {
	s = strings.TrimSpace(strings.ToUpper(s))
	return strings.ReplaceAll(s, " ", "")
}

func init() {
	rootCmd.AddCommand(joinCmd)
}
