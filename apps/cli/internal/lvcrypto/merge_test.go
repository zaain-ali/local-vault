package lvcrypto

import (
	"reflect"
	"testing"
)

// e builds a snapshot entry; value "-" means tombstone.
func e(key, value string) Secret {
	if value == "-" {
		return Secret{Key: key, Deleted: true, UpdatedBy: "tomb"}
	}
	return Secret{Key: key, Value: value}
}

func snap(entries ...Secret) *Snapshot { return &Snapshot{Version: 1, Secrets: entries} }

func live(s *Snapshot) map[string]string {
	m := map[string]string{}
	for _, sec := range s.Secrets {
		if sec.Deleted {
			m[sec.Key] = "-"
		} else {
			m[sec.Key] = sec.Value
		}
	}
	return m
}

func TestMerge(t *testing.T) {
	tests := []struct {
		name                string
		base, local, remote *Snapshot
		want                map[string]string
		conflicts           []string
	}{
		{"nothing changed", snap(e("A", "1")), snap(e("A", "1")), snap(e("A", "1")), map[string]string{"A": "1"}, nil},
		{"remote changed", snap(e("A", "1")), snap(e("A", "1")), snap(e("A", "2")), map[string]string{"A": "2"}, nil},
		{"local changed", snap(e("A", "1")), snap(e("A", "2")), snap(e("A", "1")), map[string]string{"A": "2"}, nil},
		{"both same change", snap(e("A", "1")), snap(e("A", "3")), snap(e("A", "3")), map[string]string{"A": "3"}, nil},
		{"both differ", snap(e("A", "1")), snap(e("A", "2")), snap(e("A", "3")), map[string]string{"A": "2"}, []string{"A"}},
		{"local added", snap(), snap(e("A", "1")), snap(), map[string]string{"A": "1"}, nil},
		{"remote added", snap(), snap(), snap(e("B", "1")), map[string]string{"B": "1"}, nil},
		{"both added same", snap(), snap(e("A", "1")), snap(e("A", "1")), map[string]string{"A": "1"}, nil},
		{"both added differ", snap(), snap(e("A", "1")), snap(e("A", "2")), map[string]string{"A": "1"}, []string{"A"}},
		{"local tombstone", snap(e("A", "1")), snap(e("A", "-")), snap(e("A", "1")), map[string]string{"A": "-"}, nil},
		{"remote tombstone", snap(e("A", "1")), snap(e("A", "1")), snap(e("A", "-")), map[string]string{"A": "-"}, nil},
		{"both tombstone", snap(e("A", "1")), snap(e("A", "-")), snap(e("A", "-")), map[string]string{"A": "-"}, nil},
		{"delete vs edit", snap(e("A", "1")), snap(e("A", "-")), snap(e("A", "2")), map[string]string{"A": "-"}, []string{"A"}},
		{"edit vs delete", snap(e("A", "1")), snap(e("A", "2")), snap(e("A", "-")), map[string]string{"A": "2"}, []string{"A"}},
		{"tombstone vs pruned", snap(e("A", "1")), snap(e("A", "-")), snap(), map[string]string{"A": "-"}, nil},
		{"remote pruned tombstone", snap(e("A", "-")), snap(e("A", "-")), snap(), map[string]string{}, nil},
		{"resurrect remote", snap(e("A", "-")), snap(e("A", "-")), snap(e("A", "5")), map[string]string{"A": "5"}, nil},
		{"nil base", nil, snap(e("A", "1")), snap(e("B", "2")), map[string]string{"A": "1", "B": "2"}, nil},
		{"multi", snap(e("A", "1"), e("B", "1"), e("C", "1")),
			snap(e("A", "2"), e("B", "1"), e("C", "9"), e("D", "1")),
			snap(e("A", "1"), e("B", "-"), e("C", "8")),
			map[string]string{"A": "2", "B": "-", "C": "9", "D": "1"}, []string{"C"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			merged, conflicts := Merge(tt.base, tt.local, tt.remote)
			if got := live(merged); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("merged = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(conflicts, tt.conflicts) {
				t.Errorf("conflicts = %v, want %v", conflicts, tt.conflicts)
			}
			for i := 1; i < len(merged.Secrets); i++ {
				if merged.Secrets[i-1].Key >= merged.Secrets[i].Key {
					t.Fatal("merged not sorted")
				}
			}
		})
	}
}

func TestResolve(t *testing.T) {
	base := snap(e("A", "1"), e("B", "1"), e("C", "1"))
	local := snap(e("A", "2"), e("B", "2"), e("C", "2"))
	remote := snap(e("A", "3"), e("B", "-"))
	merged, conflicts := Merge(base, local, remote)
	if !reflect.DeepEqual(conflicts, []string{"A", "B", "C"}) {
		t.Fatalf("conflicts %v", conflicts)
	}
	ours := Resolve(merged, remote, conflicts, false)
	if got := live(ours); !reflect.DeepEqual(got, map[string]string{"A": "2", "B": "2", "C": "2"}) {
		t.Fatalf("ours %v", got)
	}
	theirs := Resolve(merged, remote, conflicts, true)
	if got := live(theirs); !reflect.DeepEqual(got, map[string]string{"A": "3", "B": "-"}) {
		t.Fatalf("theirs %v", got)
	}
	if got := live(merged); got["A"] != "2" {
		t.Fatal("Resolve modified merged")
	}
}
