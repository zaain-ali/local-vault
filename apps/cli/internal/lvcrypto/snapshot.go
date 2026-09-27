package lvcrypto

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

const SnapshotVersion = 1

// Secret is one entry of a snapshot. Deletes are tombstones (Deleted, empty Value).
type Secret struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
	Deleted   bool      `json:"deleted"`
}

// Snapshot is the plaintext content of a revision.
type Snapshot struct {
	Version int      `json:"version"`
	Secrets []Secret `json:"secrets"`
}

// Normalize sorts entries by key, removes duplicate keys (last wins) and
// clears tombstone values.
func (s *Snapshot) Normalize() {
	if s.Version == 0 {
		s.Version = SnapshotVersion
	}
	idx := make(map[string]int, len(s.Secrets))
	out := make([]Secret, 0, len(s.Secrets))
	for _, sec := range s.Secrets {
		if sec.Deleted {
			sec.Value = ""
		}
		if i, ok := idx[sec.Key]; ok {
			out[i] = sec
			continue
		}
		idx[sec.Key] = len(out)
		out = append(out, sec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	s.Secrets = out
}

// Get returns the entry for key (including tombstones).
func (s *Snapshot) Get(key string) (Secret, bool) {
	for _, sec := range s.Secrets {
		if sec.Key == key {
			return sec, true
		}
	}
	return Secret{}, false
}

// PruneTombstones drops tombstones last updated before cutoff.
func (s *Snapshot) PruneTombstones(cutoff time.Time) {
	out := s.Secrets[:0]
	for _, sec := range s.Secrets {
		if sec.Deleted && sec.UpdatedAt.Before(cutoff) {
			continue
		}
		out = append(out, sec)
	}
	s.Secrets = out
}

func (s *Snapshot) clone() *Snapshot {
	if s == nil {
		return &Snapshot{Version: SnapshotVersion}
	}
	return &Snapshot{Version: s.Version, Secrets: append([]Secret(nil), s.Secrets...)}
}

// MarshalSnapshot returns the normalized snapshot JSON (s is not modified).
func MarshalSnapshot(s *Snapshot) ([]byte, error) {
	c := s.clone()
	c.Normalize()
	if c.Version != SnapshotVersion {
		return nil, fmt.Errorf("lvcrypto: unsupported snapshot version %d", c.Version)
	}
	if c.Secrets == nil {
		c.Secrets = []Secret{}
	}
	return json.Marshal(c)
}

// UnmarshalSnapshot parses and normalizes snapshot JSON.
func UnmarshalSnapshot(data []byte) (*Snapshot, error) {
	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, errors.New("lvcrypto: malformed snapshot")
	}
	if s.Version != SnapshotVersion {
		return nil, fmt.Errorf("lvcrypto: unsupported snapshot version %d", s.Version)
	}
	s.Normalize()
	return &s, nil
}
