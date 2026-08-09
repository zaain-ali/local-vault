package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/zain-23/local-vault/apps/cli/internal/api"
	"github.com/zain-23/local-vault/apps/cli/internal/identity"
	internalsync "github.com/zain-23/local-vault/apps/cli/internal/sync"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
	"github.com/zain-23/local-vault/apps/cli/internal/vault"
	"golang.org/x/term"
)

var rotateCmd = &cobra.Command{
	Use:   "rotate [KEY...]",
	Short: "Rotate one or more secrets and push to all peers",
	Example: `  # Rotate single key
  lv rotate API_KEY

  # Rotate multiple keys at once
  lv rotate API_KEY STRIPE_KEY

  # Open all secrets in editor to pick which to rotate
  lv rotate --all

  # Rotate all in specific environment
  lv rotate --all --env production`,

	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := os.Getwd()
		if err != nil {
			return err
		}

		lvDir := filepath.Join(dir, ".lv")

		// Use session key — no passphrase needed
		v, err := loadVault(dir)
		if err != nil {
			return err
		}

		rotateAll, _ := cmd.Flags().GetBool("all")
		rotatedKeys := []string{}

		if rotateAll {
			// Open editor with all secrets
			changed, err := rotateWithEditor(v, envFlag)
			if err != nil {
				return err
			}
			rotatedKeys = changed
		} else if len(args) == 0 {
			return fmt.Errorf(
				"provide at least one key or use --all\n\nExamples:\n  lv rotate API_KEY\n  lv rotate API_KEY STRIPE_KEY\n  lv rotate --all",
			)
		} else {
			// Rotate specific keys one by one
			for _, key := range args {
				existing, err := v.Get(key, envFlag)
				if err != nil {
					ui.Warn("skipping %s — not found", key)
					continue
				}

				ui.KeyValue("Key", key)
				ui.KeyValue("Current", maskValue(existing))
				fmt.Fprint(os.Stderr, "New value: ")

				newValueBytes, err := term.ReadPassword(int(syscall.Stdin))
				fmt.Fprintln(os.Stderr)
				if err != nil {
					return err
				}

				newValue := string(newValueBytes)
				if newValue == "" {
					ui.Warn("empty value — skipping %s", key)
					continue
				}

				if err := v.Add(key, newValue, envFlag); err != nil {
					ui.Warn("failed to update %s: %v", key, err)
					continue
				}

				ui.Success("%s rotated", key)
				rotatedKeys = append(rotatedKeys, key)
			}
		}

		if len(rotatedKeys) == 0 {
			ui.Info("no secrets were rotated")
			return nil
		}

		ui.Success("rotated %d secret(s)", len(rotatedKeys))
		for _, k := range rotatedKeys {
			ui.Info("  → %s", k)
		}

		peers := v.GetPeers()
		if len(peers) == 0 {
			ui.Hint("no peers to notify")
			return nil
		}

		id, err := identity.Load(lvDir)
		if err != nil {
			return err
		}
		if _, err := requireLinkedConfig(lvDir); err != nil {
			ui.Warn("vault not linked — run lv push manually after linking")
			return nil
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

		ui.Step("notifying %d peer(s)...", len(peers))
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
				ui.Warn("failed to notify %s", peer.DeviceName)
				continue
			}
			ui.Success("notified %s", peer.DeviceName)
		}

		ui.Success("all done")
		ui.Hint("peers will get new values on next: lv sync")
		return nil
	},
}

// rotateWithEditor opens all secrets in terminal editor
func rotateWithEditor(v *vault.Vault, env string) ([]string, error) {
	secrets := v.List(env)
	if len(secrets) == 0 {
		ui.Info("no secrets found")
		return nil, nil
	}

	// Build editor file content
	var content strings.Builder
	content.WriteString("# LocalVault Secret Editor\n")
	content.WriteString("# ─────────────────────────────────────────\n")
	content.WriteString("# Edit the values you want to rotate\n")
	content.WriteString("# Lines starting with # are ignored\n")
	content.WriteString("# Leave a value unchanged to skip it\n")
	content.WriteString("# Save and close the editor to apply\n")
	content.WriteString("# ─────────────────────────────────────────\n")
	content.WriteString("\n")

	// Group by environment
	currentEnv := ""
	for _, s := range secrets {
		envLabel := s.Env
		if envLabel == "" {
			envLabel = "all"
		}
		if envLabel != currentEnv {
			if currentEnv != "" {
				content.WriteString("\n")
			}
			content.WriteString(fmt.Sprintf("# Environment: %s\n", envLabel))
			currentEnv = envLabel
		}
		content.WriteString(fmt.Sprintf("%s=%s\n", s.Key, s.Value))
	}

	// Snapshot original values to detect changes
	originalValues := map[string]string{}
	for _, s := range secrets {
		originalValues[s.Key] = s.Value
	}

	// Write to temp file
	tmpFile, err := os.CreateTemp("", "lv-rotate-*.env")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content.String()); err != nil {
		return nil, fmt.Errorf("failed to write temp file: %w", err)
	}
	tmpFile.Close()

	// Open editor
	editor := getEditor()
	ui.Step("opening %s...", editor)
	ui.Hint("edit values, save and close to apply changes")

	editorCmd := exec.Command(editor, tmpFile.Name())
	editorCmd.Stdin = os.Stdin
	editorCmd.Stdout = os.Stdout
	editorCmd.Stderr = os.Stderr

	if err := editorCmd.Run(); err != nil {
		return nil, fmt.Errorf("editor exited with error: %w", err)
	}

	// Read and parse edited file
	editedContent, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to read edited file: %w", err)
	}

	newValues := parseEnvContent(string(editedContent))

	// Apply only changed values
	rotatedKeys := []string{}
	for key, newValue := range newValues {
		originalValue, exists := originalValues[key]
		if !exists {
			ui.Warn("skipping new key %s — use lv add instead", key)
			continue
		}
		if newValue == originalValue {
			continue // unchanged — skip
		}
		if newValue == "" {
			ui.Warn("empty value for %s — skipping", key)
			continue
		}

		// Find original env for this key
		envValue := ""
		for _, s := range secrets {
			if s.Key == key {
				envValue = s.Env
				break
			}
		}

		if err := v.Add(key, newValue, envValue); err != nil {
			ui.Warn("failed to update %s: %v", key, err)
			continue
		}

		rotatedKeys = append(rotatedKeys, key)
	}

	return rotatedKeys, nil
}

// getEditor returns editor to use
// Checks $EDITOR then $VISUAL then common editors
func getEditor() string {
	if editor := os.Getenv("EDITOR"); editor != "" {
		return editor
	}
	if editor := os.Getenv("VISUAL"); editor != "" {
		return editor
	}

	fallback := "vi"
	editors := []string{"nano", "vim", "vi"}
	if runtime.GOOS == "windows" {
		fallback = "notepad"
		editors = []string{"nano", "vim", "notepad"}
	}
	for _, e := range editors {
		if _, err := exec.LookPath(e); err == nil {
			return e
		}
	}
	return fallback
}

// parseEnvContent parses KEY=VALUE lines ignoring comments
func parseEnvContent(content string) map[string]string {
	result := map[string]string{}
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key != "" {
			result[key] = value
		}
	}
	return result
}

// maskValue shows first 3 chars then asterisks
func maskValue(value string) string {
	if len(value) <= 3 {
		return "***"
	}
	masked := value[:3]
	for i := 3; i < len(value); i++ {
		masked += "*"
	}
	return masked
}

func init() {
	rotateCmd.Flags().StringVarP(&envFlag, "env", "e", "", "environment")
	rotateCmd.Flags().BoolP("all", "a", false, "open all secrets in editor")
	rootCmd.AddCommand(rotateCmd)
}
