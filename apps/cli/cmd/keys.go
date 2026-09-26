package cmd

import (
	"errors"

	"github.com/zain-23/local-vault/apps/cli/internal/account"
	"github.com/zain-23/local-vault/apps/cli/internal/api"
	"github.com/zain-23/local-vault/apps/cli/internal/lvcrypto"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

func ensureAccountKeys(client *api.Client, userID, email string) error {
	bundle, err := client.GetKeys()
	if err != nil && !api.IsCode(err, "no_keys") {
		return err
	}
	if err == nil && bundle != nil && bundle.Fingerprint != "" {
		if err := account.Save(&account.File{UserID: userID, Email: email, Bundle: *bundle}); err != nil {
			return err
		}
		if _, uerr := account.Keys(); uerr == nil {
			ui.Success("account keys unlocked")
			ui.KeyValue("Fingerprint", bundle.Fingerprint)
			return nil
		}
		ui.Info("unlock account keys")
		pass, perr := ui.Passphrase("Account passphrase")
		if perr != nil {
			return perr
		}
		if _, uerr := account.Unlock(pass); uerr != nil {
			return uerr
		}
		ui.Success("account unlocked")
		ui.KeyValue("Fingerprint", bundle.Fingerprint)
		return nil
	}

	ui.Title("Create account keys")
	ui.Info("this passphrase encrypts your vault keys. it is never sent to the server.")
	pass, err := promptNewPassphrase()
	if err != nil {
		return err
	}
	keys, err := lvcrypto.GenerateAccountKeys()
	if err != nil {
		return err
	}
	sealed, kek, err := lvcrypto.SealBundle(userID, pass, keys)
	if err != nil {
		return err
	}
	if err := client.PutKeys(sealed); err != nil {
		if api.IsCode(err, "keys_exist") {
			return errors.New("account keys already exist on the server — run: lv login --force")
		}
		return err
	}
	if err := account.Save(&account.File{UserID: userID, Email: email, Bundle: *sealed}); err != nil {
		return err
	}
	_ = kek
	if _, err := account.Unlock(pass); err != nil {
		return err
	}
	ui.Success("account keys created")
	ui.KeyValue("Fingerprint", sealed.Fingerprint)
	return nil
}
