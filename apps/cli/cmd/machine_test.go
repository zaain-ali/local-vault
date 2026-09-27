package cmd

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/zain-23/local-vault/apps/cli/internal/lvcrypto"
)

func TestOIDCMachineBodyRegistersKeyAndGrant(t *testing.T) {
	dek := make([]byte, lvcrypto.KeySize)
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}
	body, privHex, err := oidcMachineBody(dek, "vlt_1", "production", 3, oidcMachineSpec{
		Name: "deploy", Issuer: "https://token.actions.githubusercontent.com", Subject: "repo:org/app:*", Audience: "localvault",
	})
	if err != nil {
		t.Fatal(err)
	}
	if body["kind"] != "oidc" || body["key_type"] != "x25519" || body["name"] != "deploy" || body["env"] != "production" {
		t.Fatalf("unexpected identity fields: %v", body)
	}
	pub, ok := body["public_key"].([]byte)
	if !ok || len(pub) != lvcrypto.KeySize {
		t.Fatalf("public_key must be a %d-byte X25519 key, got %v", lvcrypto.KeySize, body["public_key"])
	}
	priv, err := hex.DecodeString(privHex)
	if err != nil || len(priv) != lvcrypto.KeySize {
		t.Fatalf("private key must be %d hex-encoded bytes, got %q", lvcrypto.KeySize, privHex)
	}
	derived, err := lvcrypto.X25519Public(priv)
	if err != nil || !bytes.Equal(derived, pub) {
		t.Fatal("registered public key does not belong to the printed private key")
	}
	oidc, ok := body["oidc"].(map[string]any)
	if !ok || oidc["issuer"] != "https://token.actions.githubusercontent.com" || oidc["subject"] != "repo:org/app:*" || oidc["audience"] != "localvault" {
		t.Fatalf("unexpected oidc spec: %v", body["oidc"])
	}
	grant, ok := body["grant"].(map[string]any)
	if !ok || grant["key_version"] != 3 {
		t.Fatalf("grant must target key version 3, got %v", body["grant"])
	}
	wrapped, _ := grant["wrapped_key"].([]byte)
	got, err := lvcrypto.UnwrapX25519(wrapped, priv, lvcrypto.GrantInfo("vlt_1", "production", 3))
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("machine private key cannot unwrap the granted DEK: %v", err)
	}
}

func TestOIDCMachineBodyUsesFreshKeyPerMachine(t *testing.T) {
	dek := make([]byte, lvcrypto.KeySize)
	spec := oidcMachineSpec{Name: "a", Issuer: "https://issuer", Subject: "sub", Audience: "localvault"}
	_, first, err := oidcMachineBody(dek, "vlt_1", "dev", 1, spec)
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := oidcMachineBody(dek, "vlt_1", "dev", 1, spec)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("each OIDC machine must get its own key pair")
	}
}
