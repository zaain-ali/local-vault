package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Run the real launcher and inspect the environment from inside its child.
func TestRunCommandDoesNotForwardLVCredentials(t *testing.T) {
	if output := os.Getenv("LV_TEST_CHILD_ENV_OUTPUT"); output != "" {
		data, err := json.Marshal(os.Environ())
		if err == nil {
			err = os.WriteFile(output, data, 0600)
		}
		if err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	output := filepath.Join(t.TempDir(), "child-env.json")
	t.Setenv("LV_TEST_CHILD_ENV_OUTPUT", output)
	credentials := []string{"LV_SERVICE_TOKEN", "LV_SERVICE_TOKEN_FILE", "LV_OIDC_TOKEN", "LV_MACHINE_KEY"}
	if runtime.GOOS == "windows" {
		// Windows environment names are case-insensitive, including vault entries.
		credentials = []string{"lv_service_token", "Lv_Service_Token_File", "lv_oidc_token", "Lv_Machine_Key"}
	}
	for _, key := range credentials {
		t.Setenv(key, "must-not-reach-child")
	}
	t.Setenv("APP_SETTING", "inherited")
	t.Setenv("DATABASE_URL", "old")
	secrets := map[string]string{"DATABASE_URL": "current", "LV_SERVICE_TOKEN": "also-must-not-reach-child"}
	if runtime.GOOS == "windows" {
		secrets["lV_mAcHiNe_KeY"] = "also-must-not-reach-child"
	}
	if err := runCommand(secrets, []string{os.Args[0], "-test.run=^TestRunCommandDoesNotForwardLVCredentials$"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var entries []string
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatal(err)
	}
	env := make(map[string]string)
	for _, entry := range entries {
		key, value, _ := strings.Cut(entry, "=")
		if runtime.GOOS == "windows" {
			key = strings.ToUpper(key)
		}
		env[key] = value
	}
	for _, key := range credentials {
		if runtime.GOOS == "windows" {
			key = strings.ToUpper(key)
		}
		if _, present := env[key]; present {
			t.Errorf("child inherited credential variable %s", key)
		}
	}
	if env["APP_SETTING"] != "inherited" || env["DATABASE_URL"] != "current" {
		t.Error("application environment was not preserved/overridden correctly")
	}
}
