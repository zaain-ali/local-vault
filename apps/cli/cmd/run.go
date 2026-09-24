package cmd

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/zain-23/local-vault/apps/cli/internal/api"
	"github.com/zain-23/local-vault/apps/cli/internal/appstate"
	"github.com/zain-23/local-vault/apps/cli/internal/localstore"
	"github.com/zain-23/local-vault/apps/cli/internal/lvcrypto"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var (
	runToken string
	runOIDC  bool
)

var runCmd = &cobra.Command{
	Use:   "run [-- command]",
	Short: "Decrypt secrets in memory and run a command (or export)",
	Example: `  lv run -- npm start
  lv run --env production -- node server.js
  LV_SERVICE_TOKEN=lv_st_... lv run -- ./app`,
	RunE: func(cmd *cobra.Command, args []string) error {
		token := runToken
		if token == "" {
			token = os.Getenv("LV_SERVICE_TOKEN")
		}
		if token != "" {
			return runMachineToken(token, args)
		}
		if runOIDC || os.Getenv("LV_OIDC_TOKEN") != "" {
			return runMachineOIDC(args)
		}
		v, err := requireVault(envFlag)
		if err != nil {
			return err
		}
		if _, _, err := v.pull(false); err != nil {
			ui.Warn("pull failed, using local working copy: %v", err)
		}
		snap, err := v.State.Working(v.Env)
		if err != nil {
			return err
		}
		secrets := localstore.InjectMap(snap)
		if len(args) > 0 {
			ui.Step("injected %d secrets, starting: %s", len(secrets), args[0])
		}
		return execWithSecrets(secrets, args)
	},
}

func runMachineToken(token string, args []string) error {
	mid, secret, err := lvcrypto.ParseServiceToken(token)
	if err != nil {
		return fmt.Errorf("invalid service token")
	}
	st, err := appstate.Load()
	if err != nil {
		return err
	}
	client := api.New(st.ServerURL)
	login, err := client.MachineLogin(mid, "token", lvcrypto.TokenVerifier(secret))
	if err != nil {
		return err
	}
	client.UseAccessToken(login.AccessToken)
	return decryptAndRun(client, secret, args)
}

func runMachineOIDC(args []string) error {
	mid := os.Getenv("LV_MACHINE_ID")
	jwt := os.Getenv("LV_OIDC_TOKEN")
	if mid == "" || jwt == "" {
		return fmt.Errorf("set LV_MACHINE_ID and LV_OIDC_TOKEN")
	}
	st, err := appstate.Load()
	if err != nil {
		return err
	}
	client := api.New(st.ServerURL)
	login, err := client.MachineOIDCLogin(mid, jwt)
	if err != nil {
		return err
	}
	client.UseAccessToken(login.AccessToken)
	return decryptAndRun(client, nil, args)
}

func decryptAndRun(client *api.Client, tokenSecret []byte, args []string) error {
	out, err := client.MachineSecrets()
	if err != nil {
		return err
	}
	info := lvcrypto.GrantInfo(out.VaultID, out.Env, out.KeyVersion)
	var dek []byte
	switch {
	case out.KeyType == "token" && len(tokenSecret) > 0:
		dek, err = lvcrypto.UnwrapToken(out.WrappedKey, tokenSecret, info)
	case out.KeyType == "x25519":
		raw := os.Getenv("LV_MACHINE_KEY")
		if raw == "" {
			return fmt.Errorf("set LV_MACHINE_KEY to the X25519 private key (hex)")
		}
		priv, derr := decodeHexKey(raw)
		if derr != nil {
			return derr
		}
		dek, err = lvcrypto.UnwrapX25519(out.WrappedKey, priv, info)
	default:
		return fmt.Errorf("unsupported machine key type %s", out.KeyType)
	}
	if err != nil {
		return fmt.Errorf("could not unwrap environment key: %w", err)
	}
	secrets := map[string]string{}
	if out.Revision != nil && len(out.Revision.Ciphertext) > 0 {
		snap, err := lvcrypto.DecryptRevision(dek, out.VaultID, out.Env, out.Revision.Revision, out.Revision.KeyVersion, out.Revision.Ciphertext)
		if err != nil {
			return err
		}
		secrets = localstore.InjectMap(snap)
	}
	if len(args) > 0 {
		ui.Step("injected %d secrets, starting: %s", len(secrets), args[0])
	}
	return execWithSecrets(secrets, args)
}

func decodeHexKey(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("LV_MACHINE_KEY must be 64 hex chars")
	}
	return b, nil
}

func init() {
	runCmd.Flags().StringVarP(&envFlag, "env", "e", "", "environment (user mode)")
	runCmd.Flags().StringVar(&runToken, "token", "", "service token (or LV_SERVICE_TOKEN)")
	runCmd.Flags().BoolVar(&runOIDC, "oidc", false, "authenticate with LV_OIDC_TOKEN + LV_MACHINE_ID")
	rootCmd.AddCommand(runCmd)
}
