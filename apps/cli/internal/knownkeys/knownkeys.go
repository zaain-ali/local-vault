package knownkeys

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zain-23/local-vault/apps/cli/internal/appstate"
)

func path() (string, error) {
	dir, err := appstate.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "known_keys.json"), nil
}

func load() (map[string]string, error) {
	p, err := path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if m == nil {
		m = map[string]string{}
	}
	return m, nil
}

func save(m map[string]string) error {
	p, err := path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0600)
}

// Check pins fp on first sight. A later change is a hard error (TOFU).
func Check(userID, fp string) error {
	if userID == "" || fp == "" {
		return nil
	}
	m, err := load()
	if err != nil {
		return err
	}
	if prev, ok := m[userID]; ok && prev != fp {
		return fmt.Errorf("fingerprint changed for %s\n  pinned:  %s\n  server:  %s\n  refuse to grant until you verify this out of band", userID, prev, fp)
	}
	if _, ok := m[userID]; !ok {
		m[userID] = fp
		return save(m)
	}
	return nil
}

func Get(userID string) (string, bool) {
	m, err := load()
	if err != nil {
		return "", false
	}
	fp, ok := m[userID]
	return fp, ok
}
