package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/zain-23/local-vault/apps/cli/internal/localstore"
	"github.com/zain-23/local-vault/apps/cli/internal/lvcrypto"
	"github.com/zain-23/local-vault/apps/cli/internal/project"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var (
	initWorkspace string
	initName      string
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create a vault and write .lv.toml in the current directory",
	RunE: func(cmd *cobra.Command, args []string) error {
		ui.Title("Initializing vault")
		keys, err := requireAccount()
		if err != nil {
			return err
		}
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
		dir, err := os.Getwd()
		if err != nil {
			return err
		}
		name := initName
		if name == "" {
			name = filepath.Base(dir)
		}
		vid, err := newVaultID()
		if err != nil {
			return err
		}
		envs := []string{"development", "staging", "production"}
		grants := make([]map[string]any, 0, len(envs))
		st := &localstore.State{WorkspaceID: workspaceID, VaultID: vid, Name: name, Envs: map[string]localstore.EnvState{}}
		for _, env := range envs {
			dek, err := lvcrypto.NewDEK()
			if err != nil {
				return err
			}
			wrapped, err := lvcrypto.WrapX25519(dek, keys.X25519Public, lvcrypto.GrantInfo(vid, env, 1))
			if err != nil {
				return err
			}
			grants = append(grants, map[string]any{"env": env, "key_version": 1, "wrapped_key": wrapped})
			st.PutGrant(env, 1, wrapped)
		}
		ui.Step("registering vault on server...")
		detail, err := client.CreateVaultV4(workspaceID, map[string]any{
			"id": vid, "name": name, "environments": envs, "grants": grants,
		})
		if err != nil {
			return mapNotLoggedIn(fmt.Errorf("server registration failed: %w", err))
		}
		if err := st.Save(); err != nil {
			return err
		}
		if err := project.Write(dir, workspaceID, detail.ID, "development"); err != nil {
			return err
		}
		ui.Success("vault initialized — %s", detail.ID)
		ui.Hint("commit .lv.toml")
		ui.Hint("lv add DATABASE_URL=postgres://...")
		ui.Hint("lv push")
		return nil
	},
}

func init() {
	initCmd.Flags().StringVar(&initWorkspace, "workspace", "", "workspace id (skips picker)")
	initCmd.Flags().StringVar(&initName, "name", "", "vault name (default: directory name)")
	rootCmd.AddCommand(initCmd)
}
