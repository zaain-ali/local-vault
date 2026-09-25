package cmd

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/zain-23/local-vault/apps/cli/internal/lvcrypto"
)

// Explicit flags override ambient credentials. Conflicts within a source are
// rejected, and a configured file must never silently fall back to user login.
func resolveRunToken(token, path string) (string, error) {
	if token == "" && path == "" {
		token = os.Getenv("LV_SERVICE_TOKEN")
		path = os.Getenv("LV_SERVICE_TOKEN_FILE")
	}
	if token != "" && path != "" {
		return "", fmt.Errorf("choose one service-token source: a token or a token file")
	}
	if path == "" {
		return token, nil
	}
	return readServiceTokenFile(path)
}

func readServiceTokenFile(path string) (string, error) {
	// Check before opening so an accidentally configured FIFO/device is rejected.
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("cannot access service-token file")
	}
	if err := checkServiceTokenFile(info); err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("cannot open service-token file")
	}
	defer f.Close()
	// Validate the opened file too, not just the earlier pathname lookup.
	info, err = f.Stat()
	if err != nil {
		return "", fmt.Errorf("cannot inspect service-token file")
	}
	if err := checkServiceTokenFile(info); err != nil {
		return "", err
	}
	const maxTokenFileBytes = 4096
	data, err := io.ReadAll(io.LimitReader(f, maxTokenFileBytes+1))
	if err != nil {
		return "", fmt.Errorf("cannot read service-token file")
	}
	if len(data) > maxTokenFileBytes {
		return "", fmt.Errorf("service-token file exceeds 4096 bytes")
	}
	token := strings.TrimSpace(string(data))
	if _, _, err := lvcrypto.ParseServiceToken(token); err != nil {
		return "", fmt.Errorf("service-token file must contain one valid service token")
	}
	return token, nil
}

func checkServiceTokenFile(info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("service-token file must be a regular file")
	}
	// Windows ACLs are not represented by Unix mode bits; operators must restrict
	// the file ACL to the service account and trusted administrators there.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("service-token file must not be accessible by group or others; use chmod 600 or 400")
	}
	return nil
}
