package account

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zain-23/local-vault/apps/cli/internal/appstate"
	"github.com/zain-23/local-vault/apps/cli/internal/lvcrypto"
	"github.com/zain-23/local-vault/apps/cli/internal/session"
)

type File struct {
	UserID string          `json:"user_id"`
	Email  string          `json:"email"`
	Bundle lvcrypto.Bundle `json:"bundle"`
}

func path() (string, error) {
	dir, err := appstate.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "account.json"), nil
}

func Load() (*File, error) {
	p, err := path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

func Save(f *File) error {
	p, err := path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0600)
}

func Unlock(passphrase string) (*lvcrypto.AccountKeys, error) {
	f, err := Load()
	if err != nil {
		return nil, errors.New("no account keys — run: lv login")
	}
	kek, err := lvcrypto.BundleKEK(&f.Bundle, passphrase)
	if err != nil {
		return nil, err
	}
	keys, err := lvcrypto.OpenBundle(f.UserID, &f.Bundle, kek)
	if err != nil {
		return nil, errors.New("wrong passphrase")
	}
	dir, _ := appstate.Dir()
	_ = session.Save(filepath.Join(dir, "account-"+f.UserID), kek)
	return keys, nil
}

func Keys() (*lvcrypto.AccountKeys, error) {
	f, err := Load()
	if err != nil {
		return nil, errors.New("no account keys — run: lv login")
	}
	dir, err := appstate.Dir()
	if err != nil {
		return nil, err
	}
	kek, err := session.Load(filepath.Join(dir, "account-"+f.UserID))
	if err != nil {
		return nil, fmt.Errorf("account is locked\n\n  Run: lv unlock")
	}
	return lvcrypto.OpenBundle(f.UserID, &f.Bundle, kek)
}

func Lock() error {
	f, err := Load()
	if err != nil {
		return nil
	}
	dir, err := appstate.Dir()
	if err != nil {
		return err
	}
	return session.Delete(filepath.Join(dir, "account-"+f.UserID))
}

func UserID() string {
	f, err := Load()
	if err != nil {
		return ""
	}
	return f.UserID
}
