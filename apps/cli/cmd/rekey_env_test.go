package cmd

import (
	"testing"

	"github.com/zain-23/local-vault/apps/cli/internal/api"
)

func TestHasEnvAccessFiltersRekeyRecipients(t *testing.T) {
	access := []api.EnvAccess{{Env: "dev", Permission: "write"}, {Env: "staging", Permission: ""}}
	if !hasEnvAccess(access, "dev") {
		t.Fatal("member with write access to dev must be included")
	}
	if hasEnvAccess(access, "production") {
		t.Fatal("member without production access must be excluded from the production rekey")
	}
	if hasEnvAccess(access, "staging") {
		t.Fatal("an empty permission is not access")
	}
	if hasEnvAccess(nil, "dev") {
		t.Fatal("no access list means no access")
	}
}
