package localstore

import "testing"

func TestPutGrantDoesNotAdvanceBlobKeyVersion(t *testing.T) {
	s := &State{VaultID: "vlt_1", Envs: map[string]EnvState{}}
	s.PutGrant("production", 1, []byte("w1"))
	if s.Envs["production"].KeyVersion != 1 {
		t.Fatalf("first grant should initialise KeyVersion to 1, got %d", s.Envs["production"].KeyVersion)
	}
	// Simulate local blobs sealed under version 1, then a teammate's rekey
	// delivering a version-2 grant via syncGrants.
	st := s.Envs["production"]
	st.Working = []byte("sealed-under-v1")
	st.BaseCiphertext = []byte("sealed-under-v1")
	s.Envs["production"] = st
	s.PutGrant("production", 2, []byte("w2"))
	if s.Envs["production"].KeyVersion != 1 {
		t.Fatalf("adopting a newer grant must not move KeyVersion away from the version the local blobs are sealed under; got %d", s.Envs["production"].KeyVersion)
	}
	if got := s.LatestKeyVersion("production"); got != 2 {
		t.Fatalf("LatestKeyVersion = %d, want 2", got)
	}
}

func TestPutGrantReplacesSameVersion(t *testing.T) {
	s := &State{VaultID: "vlt_1", Envs: map[string]EnvState{}}
	s.PutGrant("dev", 3, []byte("old"))
	s.PutGrant("dev", 3, []byte("new"))
	g := s.Envs["dev"].Grants
	if len(g) != 1 || string(g[0].WrappedKey) != "new" {
		t.Fatalf("same-version grant should be replaced in place, got %+v", g)
	}
}

func TestLatestKeyVersionWithoutGrants(t *testing.T) {
	s := &State{VaultID: "vlt_1", Envs: map[string]EnvState{}}
	if got := s.LatestKeyVersion("dev"); got != 0 {
		t.Fatalf("LatestKeyVersion with no grants = %d, want 0", got)
	}
}
