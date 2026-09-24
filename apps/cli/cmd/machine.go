package cmd

import (
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
	machineRoleARN string
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
		out, err := v.Client.CreateMachine(v.Project.Workspace, v.Project.Vault, map[string]any{
			"name": machineName, "env": v.Env, "kind": "oidc", "key_type": "x25519",
			"oidc": map[string]any{"issuer": machineIssuer, "audience": aud, "subject": machineSubject},
		})
		if err != nil {
			return mapNotLoggedIn(err)
		}
		ui.Success("OIDC machine created: %s", out.ID)
		ui.Hint("grant it a key after it uploads a public key, or wrap with: lv access grant")
		ui.Hint("runtime: LV_MACHINE_ID=%s LV_OIDC_TOKEN=... lv run --oidc -- ./app", out.ID)
		return nil
	},
}

var machineAWSCmd = &cobra.Command{
	Use:   "aws",
	Short: "Register an AWS IAM role identity",
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := requireVault(envFlag)
		if err != nil {
			return err
		}
		if machineName == "" || machineRoleARN == "" {
			return fmt.Errorf("--name and --role-arn are required")
		}
		out, err := v.Client.CreateMachine(v.Project.Workspace, v.Project.Vault, map[string]any{
			"name": machineName, "env": v.Env, "kind": "aws", "key_type": "rsa-oaep-256",
			"aws": map[string]any{"role_arn": machineRoleARN},
		})
		if err != nil {
			return mapNotLoggedIn(err)
		}
		ui.Success("AWS machine created: %s", out.ID)
		ui.Hint("grant the KMS-wrapped DEK with: lv access grant")
		return nil
	},
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
	for _, c := range []*cobra.Command{machineTokenCmd, machineOIDCCmd, machineAWSCmd, machineListCmd} {
		c.Flags().StringVarP(&envFlag, "env", "e", "", "environment")
	}
	machineTokenCmd.Flags().StringVar(&machineName, "name", "", "machine name")
	machineOIDCCmd.Flags().StringVar(&machineName, "name", "", "machine name")
	machineOIDCCmd.Flags().StringVar(&machineIssuer, "issuer", "", "OIDC issuer URL")
	machineOIDCCmd.Flags().StringVar(&machineSubject, "subject", "", "OIDC subject (globs allowed)")
	machineOIDCCmd.Flags().StringVar(&machineAud, "audience", "localvault", "OIDC audience")
	machineAWSCmd.Flags().StringVar(&machineName, "name", "", "machine name")
	machineAWSCmd.Flags().StringVar(&machineRoleARN, "role-arn", "", "IAM role ARN")
	machineCmd.AddCommand(machineTokenCmd, machineOIDCCmd, machineAWSCmd, machineListCmd, machineRevokeCmd)
	rootCmd.AddCommand(machineCmd)
}
