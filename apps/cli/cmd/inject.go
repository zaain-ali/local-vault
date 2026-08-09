package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var injectCmd = &cobra.Command{
	Use:   "inject [-- command]",
	Short: "Inject secrets into shell or run a command with secrets",
	Example: `  lv inject                    # print export statements
  lv inject -- npm run dev     # run command with secrets injected`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, _ := os.Getwd()
		v, err := loadVault(dir)
		if err != nil {
			return err
		}

		secrets := v.InjectMap(envFlag)
		if len(secrets) == 0 {
			ui.Info("no secrets found for this environment")
			ui.Hint("add secrets with: lv add KEY=value")
			return nil
		}

		// No command — raw export lines on stdout for eval $(lv inject)
		if len(args) == 0 {
			for key, value := range secrets {
				fmt.Printf("export %s=%q\n", key, value)
			}
			return nil
		}

		command := exec.Command(args[0], args[1:]...)
		command.Env = os.Environ()
		for key, value := range secrets {
			command.Env = append(command.Env, fmt.Sprintf("%s=%s", key, value))
		}
		command.Stdin = os.Stdin
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr

		ui.Step("injected %d secrets, starting: %s", len(secrets), args[0])

		if err := command.Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			return err
		}
		return nil
	},
}

func init() {
	injectCmd.Flags().StringVarP(&envFlag, "env", "e", "", "environment to inject")
	rootCmd.AddCommand(injectCmd)
}
