package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/zain-23/local-vault/apps/cli/internal/account"
	"github.com/zain-23/local-vault/apps/cli/internal/api"
	"github.com/zain-23/local-vault/apps/cli/internal/appstate"
	"github.com/zain-23/local-vault/apps/cli/internal/localstore"
	"github.com/zain-23/local-vault/apps/cli/internal/lvcrypto"
	"github.com/zain-23/local-vault/apps/cli/internal/project"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

type vaultCtx struct {
	Client  *api.Client
	Project *project.File
	State   *localstore.State
	Env     string
}

func requireAPI() (*api.Client, error) {
	st, err := appstate.Load()
	if err != nil {
		return nil, err
	}
	return api.New(st.ServerURL), nil
}

func requireAccount() (*lvcrypto.AccountKeys, error) {
	keys, err := account.Keys()
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func requireProject() (*project.File, error) {
	if v := os.Getenv("LV_VAULT"); v != "" {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		ws := os.Getenv("LV_WORKSPACE")
		if f, err := project.Find(cwd); err == nil {
			if ws == "" {
				ws = f.Workspace
			}
			return &project.File{Workspace: ws, Vault: v, DefaultEnv: f.DefaultEnv, Dir: f.Dir}, nil
		}
		return &project.File{Workspace: ws, Vault: v, DefaultEnv: "development", Dir: cwd}, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	return project.Find(cwd)
}

func requireVault(envFlag string) (*vaultCtx, error) {
	if _, err := requireAccount(); err != nil {
		return nil, err
	}
	proj, err := requireProject()
	if err != nil {
		return nil, err
	}
	st, err := localstore.Load(proj.Vault)
	if err != nil {
		return nil, err
	}
	if st.WorkspaceID == "" {
		st.WorkspaceID = proj.Workspace
	}
	client, err := requireAPI()
	if err != nil {
		return nil, err
	}
	return &vaultCtx{
		Client:  client,
		Project: proj,
		State:   st,
		Env:     project.EnvOr(envFlag, proj),
	}, nil
}

func mapNotLoggedIn(err error) error {
	if errors.Is(err, api.ErrNotLoggedIn) {
		ui.Warn("not logged in")
		ui.Hint("run: lv login")
		return err
	}
	return err
}

func newVaultID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "vlt_" + hex.EncodeToString(b), nil
}

func defaultEnvAccess(envs []string, role string) []api.EnvAccess {
	out := make([]api.EnvAccess, 0, len(envs))
	for _, e := range envs {
		perm := "read"
		if role == "admin" || e == "development" {
			perm = "write"
		}
		out = append(out, api.EnvAccess{Env: e, Permission: perm})
	}
	return out
}

func envNames(detail *api.VaultDetail) []string {
	out := make([]string, 0, len(detail.Environments))
	for _, e := range detail.Environments {
		out = append(out, e.Name)
	}
	return out
}

func parseEnvFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseEnvContent(string(data)), nil
}

func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8] + "..."
}

func promptNewPassphrase() (string, error) {
	pass, err := ui.Passphrase("Create account passphrase")
	if err != nil {
		return "", err
	}
	confirm, err := ui.Passphrase("Confirm passphrase")
	if err != nil {
		return "", err
	}
	if pass != confirm {
		return "", fmt.Errorf("passphrases do not match")
	}
	if len(pass) < 8 {
		return "", fmt.Errorf("passphrase must be at least 8 characters")
	}
	return pass, nil
}
