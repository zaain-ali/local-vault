package apperror

import "testing"

func TestBody(t *testing.T) {
	plain := New(404, "vault not found").Body()
	if plain["error"] != "vault not found" {
		t.Fatalf("error = %v", plain["error"])
	}
	if _, ok := plain["code"]; ok {
		t.Fatal("plain error must not carry a code")
	}

	coded := WithCode(409, "conflict", "base is not head").With("head_revision", 7).Body()
	if coded["code"] != "conflict" || coded["head_revision"] != 7 || coded["error"] != "base is not head" {
		t.Fatalf("coded body = %v", coded)
	}

	spoof := New(400, "x").With("error", "spoofed").With("code", "spoofed").Body()
	if spoof["error"] != "x" {
		t.Fatalf("extra overrode error: %v", spoof)
	}
	if _, ok := spoof["code"]; ok {
		t.Fatalf("extra injected a code: %v", spoof)
	}
}

func TestWithDoesNotMutateShared(t *testing.T) {
	base := WithCode(409, "conflict", "c")
	_ = base.With("head_revision", 1)
	if base.Extra != nil {
		t.Fatal("With mutated the receiver")
	}
}
