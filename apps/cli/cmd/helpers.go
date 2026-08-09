package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/zain-23/local-vault/apps/cli/internal/api"
	"github.com/zain-23/local-vault/apps/cli/internal/appstate"
	"github.com/zain-23/local-vault/apps/cli/internal/config"
	"github.com/zain-23/local-vault/apps/cli/internal/session"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
	"github.com/zain-23/local-vault/apps/cli/internal/vault"
)

var envFlag string

var (
	errNotLinked    = errors.New("vault not linked — run: lv init or lv join")
	errNoWorkspace  = errors.New("no workspaces — create or join one in the app first")
	errBadWorkspace = errors.New("not a member of that workspace")
)

func promptPassphrase() (string, error) {
	return ui.Passphrase("Passphrase")
}

func loadVault(dir string) (*vault.Vault, error) {
	lvDir := filepath.Join(dir, ".lv")
	key, err := session.Load(lvDir)
	if err == nil {
		return vault.LoadWithKey(dir, key)
	}
	return nil, fmt.Errorf("vault is locked\n\n  Run: lv unlock\n  (unlocks for 12 hours)")
}

func requireAPI() (*api.Client, error) {
	st, err := appstate.Load()
	if err != nil {
		return nil, err
	}
	return api.New(st.ServerURL), nil
}

func requireLinkedConfig(lvDir string) (*config.Config, error) {
	cfg, err := config.Load(lvDir)
	if err != nil {
		return nil, err
	}
	if cfg.WorkspaceID == "" || cfg.VaultID == "" {
		return nil, errNotLinked
	}
	return cfg, nil
}

// resolveWorkspaceID picks a workspace id from --workspace or the membership list.
// readLine is used only when len(memberships) > 1 and flag is empty; it should
// return a 1-based index as a string (e.g. "1").
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

func mapNotLoggedIn(err error) error {
	if errors.Is(err, api.ErrNotLoggedIn) {
		ui.Warn("not logged in")
		ui.Hint("run: lv login")
		return err
	}
	return err
}

func apiPeerToVault(sp api.Peer) vault.Peer {
	return vault.Peer{
		DeviceID:        sp.DeviceID,
		DeviceName:      sp.DeviceName,
		PublicKey:       sp.PublicKey,
		X25519PublicKey: sp.X25519PublicKey,
	}
}
