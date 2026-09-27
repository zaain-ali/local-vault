package cmd

import (
	"strings"
	"testing"

	"github.com/zain-23/local-vault/apps/cli/internal/localstore"
)

func TestRekeyRefusesDirtyWorkingCopy(t *testing.T) {
	err := checkRekeyable("production", localstore.EnvState{Dirty: true})
	if err == nil {
		t.Fatal("rekey must refuse a dirty working copy so unpushed edits are not dropped")
	}
	if !strings.Contains(err.Error(), "production") || !strings.Contains(err.Error(), "lv push") {
		t.Fatalf("error should name the env and how to proceed, got %q", err)
	}
}

func TestRekeyAllowsCleanWorkingCopy(t *testing.T) {
	if err := checkRekeyable("production", localstore.EnvState{Dirty: false}); err != nil {
		t.Fatalf("clean working copy must be rekeyable, got %v", err)
	}
}
