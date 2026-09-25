package cmd

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/zain-23/local-vault/apps/cli/internal/api"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var envFlag string

var (
	errNoWorkspace  = fmt.Errorf("no workspaces — create or join one in the app first")
	errBadWorkspace = fmt.Errorf("not a member of that workspace")
)

func promptPassphrase() (string, error) {
	return ui.Passphrase("Account passphrase")
}

func resolveWorkspaceID(flag string, memberships []api.WorkspaceMembership, readLine func() (string, error)) (string, error) {
	if flag != "" {
		for _, m := range memberships {
			if m.Workspace.ID == flag {
				return flag, nil
			}
		}
		return "", errBadWorkspace
	}
	switch len(memberships) {
	case 0:
		return "", errNoWorkspace
	case 1:
		return memberships[0].Workspace.ID, nil
	}
	if readLine == nil {
		return "", fmt.Errorf("multiple workspaces — pass --workspace")
	}
	ui.Info("select a workspace:")
	for i, m := range memberships {
		ui.Info("  %d) %s (%s)", i+1, m.Workspace.Name, m.Workspace.ID)
	}
	line, err := readLine()
	if err != nil {
		return "", err
	}
	n, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || n < 1 || n > len(memberships) {
		return "", fmt.Errorf("invalid selection")
	}
	return memberships[n-1].Workspace.ID, nil
}

func stdinLine() (string, error) {
	return bufio.NewReader(os.Stdin).ReadString('\n')
}

func runCommand(secrets map[string]string, args []string) error {
	command := exec.Command(args[0], args[1:]...)
	command.Env = make([]string, 0, len(os.Environ())+len(secrets))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !isLVCredentialEnv(key) {
			command.Env = append(command.Env, entry)
		}
	}
	for key, value := range secrets {
		if !isLVCredentialEnv(key) {
			command.Env = append(command.Env, fmt.Sprintf("%s=%s", key, value))
		}
	}
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return err
	}
	return nil
}

// These names are reserved for lv itself, including when present in a vault.
func isLVCredentialEnv(key string) bool {
	if runtime.GOOS == "windows" {
		key = strings.ToUpper(key)
	}
	switch key {
	case "LV_SERVICE_TOKEN", "LV_SERVICE_TOKEN_FILE", "LV_OIDC_TOKEN", "LV_MACHINE_KEY":
		return true
	default:
		return false
	}
}
