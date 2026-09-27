package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/zain-23/local-vault/apps/cli/internal/project"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var (
	linkWorkspace string
	linkVault     string
	linkEnv       string
)

var linkCmd = &cobra.Command{
	Use:   "link",
	Short: "Link this directory to an existing vault (.lv.toml)",
	Example: `  lv link --vault vlt_abc
  lv link --workspace ws_x --vault vlt_abc --env development`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireAccount(); err != nil {
			return err
		}
		client, err := requireAPI()
		if err != nil {
			return err
		}
		list, err := client.ListWorkspaces()
		if err != nil {
			return mapNotLoggedIn(err)
		}
		workspaceID, err := resolveWorkspaceID(linkWorkspace, list, stdinLine)
		if err != nil {
			return err
		}
		vaultID := linkVault
		if vaultID == "" {
			vaults, err := client.ListVaults(workspaceID)
			if err != nil {
				return mapNotLoggedIn(err)
			}
			if len(vaults) == 0 {
				return fmt.Errorf("no vaults in this workspace — run: lv init")
			}
			if len(vaults) == 1 {
				vaultID = vaults[0].ID
			} else {
				ui.Info("select a vault:")
				for i, v := range vaults {
					ui.Info("  %d) %s (%s)", i+1, v.Name, v.ID)
				}
				line, err := stdinLine()
				if err != nil {
					return err
				}
				var n int
				if _, err := fmt.Sscanf(line, "%d", &n); err != nil || n < 1 || n > len(vaults) {
					return fmt.Errorf("invalid selection")
				}
				vaultID = vaults[n-1].ID
			}
		}
		detail, err := client.GetVaultV4(workspaceID, vaultID)
		if err != nil {
			return mapNotLoggedIn(err)
		}
		dir, err := os.Getwd()
		if err != nil {
			return err
		}
		env := linkEnv
		if env == "" {
			env = "development"
		}
		if err := project.Write(dir, workspaceID, vaultID, env); err != nil {
			return err
		}
		v, err := requireVault(env)
		if err != nil {
			return err
		}
		v.State.Name = detail.Name
		if _, _, err := v.pull(false); err != nil {
			ui.Warn("linked, but pull failed: %v", err)
			ui.Hint("ask an admin to grant you a key: lv access grant")
		}
		ui.Success("linked %s", vaultID)
		ui.Hint("commit .lv.toml")
		return nil
	},
}

func init() {
	linkCmd.Flags().StringVar(&linkWorkspace, "workspace", "", "workspace id")
	linkCmd.Flags().StringVar(&linkVault, "vault", "", "vault id")
	linkCmd.Flags().StringVar(&linkEnv, "env", "development", "default environment")
	rootCmd.AddCommand(linkCmd)
}
