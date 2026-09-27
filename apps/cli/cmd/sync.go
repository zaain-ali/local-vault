package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/zain-23/local-vault/apps/cli/internal/localstore"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var pullTheirs bool

var pullCmd = &cobra.Command{
	Use:   "pull",
	Short: "Pull the latest revision and merge into the working copy",
	RunE:  runPull,
}

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Alias for lv pull",
	RunE:  runPull,
}

func runPull(cmd *cobra.Command, args []string) error {
	v, err := requireVault(envFlag)
	if err != nil {
		return err
	}
	snap, conflicts, err := v.pull(pullTheirs)
	if err != nil {
		return err
	}
	n := len(localstore.ActiveSecrets(snap))
	if len(conflicts) > 0 {
		ui.Warn("conflicts in %d key(s): %v", len(conflicts), conflicts)
		ui.Hint("local values were kept. re-push after resolving, or: lv pull --theirs")
		return fmt.Errorf("merge conflicts")
	}
	ui.Success("pulled %s — %d secret(s)", v.Env, n)
	return nil
}

func init() {
	for _, c := range []*cobra.Command{pullCmd, syncCmd} {
		c.Flags().StringVarP(&envFlag, "env", "e", "", "environment")
		c.Flags().BoolVar(&pullTheirs, "theirs", false, "on conflict, keep the remote value")
		rootCmd.AddCommand(c)
	}
}
