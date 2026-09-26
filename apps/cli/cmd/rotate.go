package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/zain-23/local-vault/apps/cli/internal/account"
	"github.com/zain-23/local-vault/apps/cli/internal/localstore"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
	"golang.org/x/term"
)

var rotateCmd = &cobra.Command{
	Use:   "rotate [KEY...]",
	Short: "Rotate secret values in the working copy",
	Example: `  lv rotate API_KEY
  lv rotate --all --env production`,
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := requireVault(envFlag)
		if err != nil {
			return err
		}
		if err := v.syncGrants(); err != nil {
			return err
		}
		snap, err := v.State.Working(v.Env)
		if err != nil {
			return err
		}
		rotateAll, _ := cmd.Flags().GetBool("all")
		rotated := []string{}
		if rotateAll {
			rotated, err = rotateWithEditor(v)
			if err != nil {
				return err
			}
		} else if len(args) == 0 {
			return fmt.Errorf("provide at least one key or use --all")
		} else {
			for _, key := range args {
				sec, ok := snap.Get(key)
				if !ok || sec.Deleted {
					ui.Warn("skipping %s — not found", key)
					continue
				}
				ui.KeyValue("Key", key)
				ui.KeyValue("Current", maskValue(sec.Value))
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
				for i := range snap.Secrets {
					if snap.Secrets[i].Key == key {
						snap.Secrets[i].Value = newValue
						snap.Secrets[i].Deleted = false
						localstore.Touch(&snap.Secrets[i], account.UserID())
					}
				}
				rotated = append(rotated, key)
			}
			if err := v.State.SetWorking(v.Env, snap, true); err != nil {
				return err
			}
		}
		if len(rotated) == 0 {
			ui.Info("no secrets were rotated")
			return nil
		}
		ui.Success("rotated %d secret(s)", len(rotated))
		ui.Hint("run: lv push")
		return nil
	},
}

func rotateWithEditor(v *vaultCtx) ([]string, error) {
	working, err := v.State.Working(v.Env)
	if err != nil {
		return nil, err
	}
	secrets := localstore.ActiveSecrets(working)
	if len(secrets) == 0 {
		return nil, nil
	}
	var content strings.Builder
	content.WriteString("# Edit values, save and close\n\n")
	original := map[string]string{}
	for _, s := range secrets {
		content.WriteString(fmt.Sprintf("%s=%s\n", s.Key, s.Value))
		original[s.Key] = s.Value
	}
	tmp, err := os.CreateTemp("", "lv-rotate-*.env")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(content.String()); err != nil {
		return nil, err
	}
	tmp.Close()
	editor := getEditor()
	ec := exec.Command(editor, tmp.Name())
	ec.Stdin, ec.Stdout, ec.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := ec.Run(); err != nil {
		return nil, err
	}
	edited, err := os.ReadFile(tmp.Name())
	if err != nil {
		return nil, err
	}
	newValues := parseEnvContent(string(edited))
	rotated := []string{}
	for key, val := range newValues {
		if original[key] == val || val == "" {
			continue
		}
		for i := range working.Secrets {
			if working.Secrets[i].Key == key {
				working.Secrets[i].Value = val
				working.Secrets[i].Deleted = false
				localstore.Touch(&working.Secrets[i], account.UserID())
			}
		}
		rotated = append(rotated, key)
	}
	if err := v.State.SetWorking(v.Env, working, true); err != nil {
		return nil, err
	}
	return rotated, nil
}

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

func parseEnvContent(content string) map[string]string {
	result := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		if key != "" {
			result[key] = strings.TrimSpace(parts[1])
		}
	}
	return result
}

func maskValue(value string) string {
	if len(value) <= 3 {
		return "***"
	}
	return value[:3] + strings.Repeat("*", len(value)-3)
}

func init() {
	rotateCmd.Flags().StringVarP(&envFlag, "env", "e", "", "environment")
	rotateCmd.Flags().BoolP("all", "a", false, "open all secrets in editor")
	rootCmd.AddCommand(rotateCmd)
}
