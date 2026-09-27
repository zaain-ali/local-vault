package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/zain-23/local-vault/apps/cli/internal/lvcrypto"
)

func TestRunTokenSources(t *testing.T) {
	fileFlag := runCmd.Flags().Lookup("token-file")
	if fileFlag == nil {
		t.Fatal("lv run does not support protected token files")
	}
	oldToken, oldFile := runToken, fileFlag.Value.String()
	t.Cleanup(func() { runToken = oldToken; _ = fileFlag.Value.Set(oldFile) })
	mid, token, secret, err := lvcrypto.NewServiceToken()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"file flag", "file env", "token flag", "token env", "file flag overrides env", "token flag overrides env", "read-only file", "symlink mount"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			t.Setenv("APPDATA", t.TempDir())
			t.Setenv("HOME", t.TempDir())
			t.Setenv("LV_SERVICE_TOKEN", "")
			t.Setenv("LV_SERVICE_TOKEN_FILE", "")
			runToken = ""
			_ = fileFlag.Value.Set("")
			path := filepath.Join(t.TempDir(), "service-token")
			if err := os.WriteFile(path, []byte(token+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if mode == "read-only file" {
				if err := os.Chmod(path, 0400); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "symlink mount" {
				link := filepath.Join(t.TempDir(), "mounted-token")
				if err := os.Symlink(path, link); err != nil {
					if runtime.GOOS == "windows" {
						t.Skipf("symlink creation not available: %v", err)
					}
					t.Fatal(err)
				}
				path = link
			}
			switch mode {
			case "file flag", "file flag overrides env", "read-only file", "symlink mount":
				_ = fileFlag.Value.Set(path)
			case "file env":
				t.Setenv("LV_SERVICE_TOKEN_FILE", path)
			case "token flag", "token flag overrides env":
				runToken = token
			case "token env":
				t.Setenv("LV_SERVICE_TOKEN", token)
			}
			if strings.Contains(mode, "overrides") {
				t.Setenv("LV_SERVICE_TOKEN", "invalid ambient token")
				t.Setenv("LV_SERVICE_TOKEN_FILE", "missing ambient file")
			}
			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				var body struct {
					MachineID string `json:"machine_id"`
					Method    string `json:"method"`
					Verifier  string `json:"token_verifier"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if r.URL.Path != "/api/v1/machine/login" || body.MachineID != mid || body.Method != "token" || body.Verifier != lvcrypto.TokenVerifier(secret) {
					t.Error("did not authenticate with the selected token's derived verifier")
				}
				// End the request at authentication; no real vault or user login needed.
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"test login reached"}`))
			}))
			defer srv.Close()
			t.Setenv("SERVER_URL", srv.URL)
			err := runCmd.RunE(runCmd, []string{"not-executed"})
			if requests.Load() != 1 || err == nil || !strings.Contains(err.Error(), "test login reached") {
				t.Fatalf("expected machine login, got %d requests and %v", requests.Load(), err)
			}
		})
	}
}

func TestRunRejectsExplicitEmptyTokenFile(t *testing.T) {
	flag := runCmd.Flags().Lookup("token-file")
	if flag == nil {
		t.Fatal("lv run does not support protected token files")
	}
	oldValue, oldChanged := flag.Value.String(), flag.Changed
	t.Cleanup(func() {
		_ = flag.Value.Set(oldValue)
		flag.Changed = oldChanged
	})
	t.Setenv("LV_SERVICE_TOKEN", "must-not-be-used")
	if err := runCmd.ParseFlags([]string{"--token-file="}); err != nil {
		t.Fatal(err)
	}
	err := runCmd.RunE(runCmd, []string{"not-executed"})
	if err == nil || !strings.Contains(err.Error(), "non-empty path") {
		t.Fatalf("empty explicit token file did not fail closed: %v", err)
	}
}

func TestRunRejectsUnsafeTokenFilesWithoutFallback(t *testing.T) {
	fileFlag := runCmd.Flags().Lookup("token-file")
	if fileFlag == nil {
		t.Fatal("lv run does not support protected token files")
	}
	oldToken, oldFile := runToken, fileFlag.Value.String()
	t.Cleanup(func() { runToken = oldToken; _ = fileFlag.Value.Set(oldFile) })
	_, token, _, err := lvcrypto.NewServiceToken()
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"missing", "directory", "empty", "malformed", "oversized", "group readable", "world readable", "conflicting flags", "conflicting env"} {
		t.Run(scenario, func(t *testing.T) {
			if runtime.GOOS == "windows" && strings.Contains(scenario, "readable") {
				t.Skip("Windows uses ACLs instead of Unix mode bits")
			}
			path := filepath.Join(t.TempDir(), "service-token")
			content := token
			mode := os.FileMode(0600)
			switch scenario {
			case "empty":
				content = "\n"
			case "malformed":
				content = "sensitive-invalid-credential"
			case "oversized":
				content = strings.Repeat("x", 4097)
			case "group readable":
				mode = 0640
			case "world readable":
				mode = 0644
			case "directory":
				path = t.TempDir()
			}
			if scenario != "missing" && scenario != "directory" {
				if err := os.WriteFile(path, []byte(content), mode); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, mode); err != nil {
					t.Fatal(err)
				}
			}
			runToken = ""
			_ = fileFlag.Value.Set(path)
			t.Setenv("LV_SERVICE_TOKEN", token) // Must not fall back on a file error.
			t.Setenv("LV_SERVICE_TOKEN_FILE", "")
			if scenario == "conflicting flags" {
				runToken = token
			}
			if scenario == "conflicting env" {
				_ = fileFlag.Value.Set("")
				t.Setenv("LV_SERVICE_TOKEN_FILE", path)
			}
			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusForbidden)
			}))
			defer srv.Close()
			t.Setenv("SERVER_URL", srv.URL)
			err := runCmd.RunE(runCmd, []string{"not-executed"})
			if err == nil {
				t.Fatal("unsafe or ambiguous credentials accepted")
			}
			if requests.Load() != 0 {
				t.Error("attempted network authentication instead of rejecting credentials")
			}
			if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), "sensitive-invalid-credential") {
				t.Fatal("error exposes credential contents")
			}
		})
	}
}
