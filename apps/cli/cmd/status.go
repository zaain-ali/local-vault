package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/zain-23/local-vault/apps/cli/internal/account"
	"github.com/zain-23/local-vault/apps/cli/internal/localstore"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show vault status and sync info",
	RunE: func(cmd *cobra.Command, args []string) error {
		f, err := account.Load()
		if err != nil {
			ui.Warn("no account keys — run: lv login")
		} else {
			ui.Header("Account")
			ui.KeyValue("Email", f.Email)
			ui.KeyValue("Fingerprint", f.Bundle.Fingerprint)
			if _, err := account.Keys(); err == nil {
				ui.KeyValue("Session", "Unlocked")
			} else {
				ui.KeyValue("Session", "Locked — lv unlock")
			}
		}

		v, err := requireVault(envFlag)
		if err != nil {
			ui.Hint("link a project: lv init or lv link")
			return nil
		}
		detail, gerr := v.Client.GetVaultV4(v.Project.Workspace, v.Project.Vault)
		if gerr != nil {
			_ = mapNotLoggedIn(gerr)
		}

		ui.Header("Project")
		ui.KeyValue("Workspace", v.Project.Workspace)
		ui.KeyValue("Vault", v.Project.Vault)
		if detail != nil {
			ui.KeyValue("Name", detail.Name)
			ui.KeyValue("Role", detail.MyRole)
		}
		ui.KeyValue("Default env", v.Project.DefaultEnv)

		if detail != nil {
			ui.Header("Environments")
			for _, e := range detail.Environments {
				st := v.State.Envs[e.Name]
				dirty := ""
				if st.Dirty {
					dirty = " dirty"
				}
				n := 0
				if snap, err := v.State.Working(e.Name); err == nil {
					n = len(localstore.ActiveSecrets(snap))
				}
				flag := ""
				if e.Protected {
					flag = " protected"
				}
				if e.RekeyRequired {
					flag += " rekey"
				}
				ui.KeyValue(e.Name, fmt.Sprintf("rev %d  kv %d  %d secrets%s%s", e.HeadRevision, e.KeyVersion, n, dirty, flag))
			}
		}
		ui.Hint("lv pull / lv push / lv access grant")
		return nil
	},
}

func init() {
	statusCmd.Flags().StringVarP(&envFlag, "env", "e", "", "environment")
	rootCmd.AddCommand(statusCmd)
}
