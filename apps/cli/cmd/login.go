package cmd

import (
	"context"
	"errors"
	"time"

	"github.com/spf13/cobra"

	"github.com/zain-23/local-vault/apps/cli/internal/api"
	"github.com/zain-23/local-vault/apps/cli/internal/appstate"
	"github.com/zain-23/local-vault/apps/cli/internal/authstore"
	"github.com/zain-23/local-vault/apps/cli/internal/browser"
	"github.com/zain-23/local-vault/apps/cli/internal/ui"
)

var loginForce bool

// errCodeExpired is a sentinel so tests can assert the expiry path.
var errCodeExpired = errors.New("code expired — run: lv login again")

// poller is the slice of *api.Client that pollForApproval needs (enables faking in tests).
type poller interface {
	DevicePoll(deviceCode string) (*api.DevicePollResponse, error)
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Log in to your LocalVault account",
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := appstate.Load()
		if err != nil {
			return err
		}
		client := api.New(st.ServerURL)

		if !loginForce {
			if _, err := authstore.Load(); err == nil {
				if acct, merr := client.Me(); merr == nil {
					ui.Success("already logged in as %s", acct.Email)
					ui.Hint("run: lv login --force   to switch accounts")
					return nil
				}
			}
		}

		auth, err := client.DeviceAuthorize(st.DeviceName, st.DeviceFingerprint)
		if err != nil {
			return err
		}

		ui.Title("Device login")
		ui.Info("enter this code in your browser:")
		ui.Code(auth.UserCode)
		ui.Info("verification URL: %s", auth.VerifyURL)
		if oerr := browser.Open(auth.VerifyURL); oerr != nil {
			ui.Hint("open this URL manually: %s", auth.VerifyURL)
		}
		ui.Step("waiting for approval...")

		tokens, err := pollForApproval(
			cmd.Context(), client, auth.DeviceCode,
			time.Duration(auth.Interval)*time.Second,
			time.Duration(auth.ExpiresIn)*time.Second,
			time.Now,
		)
		if err != nil {
			return err
		}

		if err := authstore.Save(tokens); err != nil {
			return err
		}
		client.UseTokens(tokens)

		acct, err := client.Me()
		if err != nil {
			ui.Success("logged in")
			return nil
		}
		ui.Success("logged in as %s <%s>", acct.Name, acct.Email)
		return ensureAccountKeys(client, acct.ID, acct.Email)
	},
}

// pollForApproval polls until the request is approved, denied, or expires.
func pollForApproval(ctx context.Context, p poller, deviceCode string, interval, expiresIn time.Duration, now func() time.Time) (*authstore.Tokens, error) {
	if interval <= 0 {
		interval = time.Second
	}
	deadline := now().Add(expiresIn)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		if now().After(deadline) {
			return nil, errCodeExpired
		}

		res, err := p.DevicePoll(deviceCode)
		if err != nil {
			var apiErr *api.APIError
			if errors.As(err, &apiErr) && apiErr.Status == 401 {
				return nil, errCodeExpired
			}
			return nil, err
		}

		switch res.Status {
		case "approved":
			return &authstore.Tokens{
				AccessToken:  res.AccessToken,
				RefreshToken: res.RefreshToken,
				DeviceID:     res.DeviceID,
			}, nil
		case "denied":
			return nil, errors.New("authorization denied")
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func init() {
	loginCmd.Flags().BoolVar(&loginForce, "force", false, "log in again even if already logged in")
	rootCmd.AddCommand(loginCmd)
}
