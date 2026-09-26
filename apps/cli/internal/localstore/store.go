package localstore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/zain-23/local-vault/apps/cli/internal/account"
	"github.com/zain-23/local-vault/apps/cli/internal/appstate"
	"github.com/zain-23/local-vault/apps/cli/internal/lvcrypto"
)

var ErrNoGrant = errors.New("no key grant for this environment — run: lv pull")

type Grant struct {
	KeyVersion int    `json:"key_version"`
	WrappedKey []byte `json:"wrapped_key"`
}

type EnvState struct {
	KeyVersion     int     `json:"key_version"`
	BaseRevision   int     `json:"base_revision"`
	BaseCiphertext []byte  `json:"base_ciphertext,omitempty"`
	Working        []byte  `json:"working,omitempty"`
	Dirty          bool    `json:"dirty"`
	Grants         []Grant `json:"grants"`
}

type State struct {
	WorkspaceID string              `json:"workspace_id"`
	VaultID     string              `json:"vault_id"`
	Name        string              `json:"name"`
	Envs        map[string]EnvState `json:"envs"`
}

func dir(vaultID string) (string, error) {
	base, err := appstate.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "vaults", vaultID), nil
}

func Load(vaultID string) (*State, error) {
	d, err := dir(vaultID)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(d, "state.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return &State{VaultID: vaultID, Envs: map[string]EnvState{}}, nil
		}
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	if s.Envs == nil {
		s.Envs = map[string]EnvState{}
	}
	return &s, nil
}

func (s *State) Save() error {
	d, err := dir(s.VaultID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(d, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(d, "state.json"), data, 0600)
}

func (s *State) DEK(env string, kv int) ([]byte, error) {
	keys, err := account.Keys()
	if err != nil {
		return nil, err
	}
	st := s.Envs[env]
	if kv == 0 {
		kv = st.KeyVersion
	}
	if kv == 0 {
		kv = 1
	}
	info := lvcrypto.GrantInfo(s.VaultID, env, kv)
	for _, g := range st.Grants {
		if g.KeyVersion == kv {
			return lvcrypto.UnwrapX25519(g.WrappedKey, keys.X25519Private, info)
		}
	}
	return nil, ErrNoGrant
}

func (s *State) PutGrant(env string, kv int, wrapped []byte) {
	st := s.Envs[env]
	found := false
	for i := range st.Grants {
		if st.Grants[i].KeyVersion == kv {
			st.Grants[i].WrappedKey = wrapped
			found = true
		}
	}
	if !found {
		st.Grants = append(st.Grants, Grant{KeyVersion: kv, WrappedKey: wrapped})
	}
	if st.KeyVersion == 0 || kv > st.KeyVersion {
		st.KeyVersion = kv
	}
	s.Envs[env] = st
}

func (s *State) Working(env string) (*lvcrypto.Snapshot, error) {
	st := s.Envs[env]
	if len(st.Working) == 0 {
		return &lvcrypto.Snapshot{Version: lvcrypto.SnapshotVersion}, nil
	}
	dek, err := s.DEK(env, st.KeyVersion)
	if err != nil {
		return nil, err
	}
	return lvcrypto.DecryptLocal(dek, s.VaultID, env, st.Working)
}

func (s *State) Base(env string) (*lvcrypto.Snapshot, error) {
	st := s.Envs[env]
	if len(st.BaseCiphertext) == 0 {
		return &lvcrypto.Snapshot{Version: lvcrypto.SnapshotVersion}, nil
	}
	dek, err := s.DEK(env, st.KeyVersion)
	if err != nil {
		return nil, err
	}
	return lvcrypto.DecryptRevision(dek, s.VaultID, env, st.BaseRevision, st.KeyVersion, st.BaseCiphertext)
}

func (s *State) SetWorking(env string, snap *lvcrypto.Snapshot, dirty bool) error {
	st := s.Envs[env]
	if st.KeyVersion == 0 {
		st.KeyVersion = 1
	}
	dek, err := s.DEK(env, st.KeyVersion)
	if err != nil {
		return err
	}
	blob, err := lvcrypto.EncryptLocal(dek, s.VaultID, env, snap)
	if err != nil {
		return err
	}
	st.Working = blob
	st.Dirty = dirty
	s.Envs[env] = st
	return s.Save()
}

func (s *State) SetBase(env string, rev, kv int, ciphertext []byte) {
	st := s.Envs[env]
	st.BaseRevision = rev
	st.KeyVersion = kv
	st.BaseCiphertext = ciphertext
	s.Envs[env] = st
}

func Touch(s *lvcrypto.Secret, userID string) {
	s.UpdatedAt = time.Now().UTC()
	s.UpdatedBy = userID
}

func ActiveSecrets(snap *lvcrypto.Snapshot) []lvcrypto.Secret {
	if snap == nil {
		return nil
	}
	out := make([]lvcrypto.Secret, 0, len(snap.Secrets))
	for _, s := range snap.Secrets {
		if !s.Deleted {
			out = append(out, s)
		}
	}
	return out
}

func InjectMap(snap *lvcrypto.Snapshot) map[string]string {
	m := map[string]string{}
	for _, s := range ActiveSecrets(snap) {
		m[s.Key] = s.Value
	}
	return m
}
