package cmd

import (
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/zain-23/local-vault/apps/cli/internal/lvcrypto"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var (
	machineName    string
	machineIssuer  string
	machineSubject string
	machineAud     string
)

var machineCmd = &cobra.Command{
	Use:   "machine",
	Short: "Create and manage machine identities",
}

var machineTokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Create a service token for one vault environment",
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := requireVault(envFlag)
		if err != nil {
			return err
		}
		if machineName == "" {
			return fmt.Errorf("--name is required")
		}
		if err := v.syncGrants(); err != nil {
			return err
		}
		st := v.State.Envs[v.Env]
		kv := st.KeyVersion
		if kv == 0 {
			kv = 1
		}
		dek, err := v.State.DEK(v.Env, kv)
		if err != nil {
			return err
		}
		mid, token, secret, err := lvcrypto.NewServiceToken()
		if err != nil {
			return err
		}
		wrapped, err := lvcrypto.WrapToken(dek, secret, lvcrypto.GrantInfo(v.Project.Vault, v.Env, kv))
		if err != nil {
			return err
		}
		out, err := v.Client.CreateMachine(v.Project.Workspace, v.Project.Vault, map[string]any{
			"id": mid, "name": machineName, "env": v.Env,
			"kind": "token", "key_type": "token",
			"token_verifier": lvcrypto.TokenVerifier(secret),
			"grant":          map[string]any{"key_version": kv, "wrapped_key": wrapped},
		})
		if err != nil {
			return mapNotLoggedIn(err)
		}
		ui.Success("machine created: %s", out.ID)
		ui.Warn("this token is shown once — store it in your secret manager")
		ui.Code(token)
		ui.Hint("LV_SERVICE_TOKEN=... lv run -- ./app")
		return nil
	},
}

var machineOIDCCmd = &cobra.Command{
	Use:   "oidc",
	Short: "Register an OIDC workload identity (GitHub Actions, K8s, GCP, Azure)",
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := requireVault(envFlag)
		if err != nil {
			return err
		}
		if machineName == "" || machineIssuer == "" || machineSubject == "" {
			return fmt.Errorf("--name, --issuer and --subject are required")
		}
		aud := machineAud
		if aud == "" {
			aud = "localvault"
		}
		if err := v.syncGrants(); err != nil {
			return err
		}
		st := v.State.Envs[v.Env]
		kv := st.KeyVersion
		if kv == 0 {
			kv = 1
		}
		dek, err := v.State.DEK(v.Env, kv)
		if err != nil {
			return err
		}
		body, privHex, err := oidcMachineBody(dek, v.Project.Vault, v.Env, kv, oidcMachineSpec{
			Name: machineName, Issuer: machineIssuer, Subject: machineSubject, Audience: aud,
		})
		if err != nil {
			return err
		}
		out, err := v.Client.CreateMachine(v.Project.Workspace, v.Project.Vault, body)
		if err != nil {
			return mapNotLoggedIn(err)
		}
		ui.Success("OIDC machine created: %s", out.ID)
		ui.Warn("this machine key is shown once — store it in your CI secret store as LV_MACHINE_KEY")
		ui.Code(privHex)
		ui.Hint("runtime: LV_MACHINE_ID=%s LV_MACHINE_KEY=... LV_OIDC_TOKEN=... lv run --oidc -- ./app", out.ID)
		ui.Hint("after a rekey, re-grant it with: lv access grant")
		return nil
	},
}

type oidcMachineSpec struct {
	Name, Issuer, Subject, Audience string
}

// oidcMachineBody builds the CreateMachine request for an OIDC identity. OIDC
// only authenticates the workload; the server has no key-upload route, so the
// creator mints the machine's X25519 key pair here, registers the public half,
// and wraps the current environment DEK to it in the same request. The private
// key is returned hex-encoded for LV_MACHINE_KEY and is never persisted locally.
func oidcMachineBody(dek []byte, vaultID, env string, kv int, spec oidcMachineSpec) (map[string]any, string, error) {
	priv, pub, err := lvcrypto.GenerateX25519()
	if err != nil {
		return nil, "", err
	}
	wrapped, err := lvcrypto.WrapX25519(dek, pub, lvcrypto.GrantInfo(vaultID, env, kv))
	if err != nil {
		return nil, "", err
	}
	body := map[string]any{
		"name": spec.Name, "env": env, "kind": "oidc", "key_type": "x25519",
		"public_key": pub,
		"oidc":       map[string]any{"issuer": spec.Issuer, "audience": spec.Audience, "subject": spec.Subject},
		"grant":      map[string]any{"key_version": kv, "wrapped_key": wrapped},
	}
	return body, hex.EncodeToString(priv), nil
}

var machineListCmd = &cobra.Command{
	Use:   "list",
	Short: "List machine identities on this vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := requireVault(envFlag)
		if err != nil {
			return err
		}
		list, err := v.Client.ListMachines(v.Project.Workspace, v.Project.Vault)
		if err != nil {
			return mapNotLoggedIn(err)
		}
		if len(list) == 0 {
			ui.Info("no machines")
			return nil
		}
		rows := make([][]string, 0, len(list))
		for _, m := range list {
			status := "active"
			if m.Revoked {
				status = "revoked"
			}
			rows = append(rows, []string{m.Name, m.ID, m.Env, m.Kind, status})
		}
		ui.Table([]string{"NAME", "ID", "ENV", "KIND", "STATUS"}, rows)
		return nil
	},
}

var machineRevokeCmd = &cobra.Command{
	Use:   "revoke MACHINE_ID",
	Short: "Revoke a machine identity",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := requireVault(envFlag)
		if err != nil {
			return err
		}
		if err := v.Client.RevokeMachine(v.Project.Workspace, v.Project.Vault, args[0]); err != nil {
			return mapNotLoggedIn(err)
		}
		ui.Success("revoked %s", args[0])
		ui.Hint("rekey the environment if the machine may have cached secrets: lv rekey")
		return nil
	},
}

func init() {
	for _, c := range []*cobra.Command{machineTokenCmd, machineOIDCCmd, machineListCmd} {
		c.Flags().StringVarP(&envFlag, "env", "e", "", "environment")
	}
	machineTokenCmd.Flags().StringVar(&machineName, "name", "", "machine name")
	machineOIDCCmd.Flags().StringVar(&machineName, "name", "", "machine name")
	machineOIDCCmd.Flags().StringVar(&machineIssuer, "issuer", "", "OIDC issuer URL")
	machineOIDCCmd.Flags().StringVar(&machineSubject, "subject", "", "OIDC subject (globs allowed)")
	machineOIDCCmd.Flags().StringVar(&machineAud, "audience", "localvault", "OIDC audience")
	machineCmd.AddCommand(machineTokenCmd, machineOIDCCmd, machineListCmd, machineRevokeCmd)
	rootCmd.AddCommand(machineCmd)
}
