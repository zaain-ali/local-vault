package lvcrypto

import "sort"

// entryState is the comparable part of an entry. A missing key and a
// tombstone are both "deleted" so pruned tombstones don't cause conflicts.
type entryState struct {
	deleted bool
	value   string
}

func stateOf(m map[string]Secret, key string) entryState {
	sec, ok := m[key]
	if !ok || sec.Deleted {
		return entryState{deleted: true}
	}
	return entryState{value: sec.Value}
}

func index(s *Snapshot) map[string]Secret {
	m := map[string]Secret{}
	if s == nil {
		return m
	}
	for _, sec := range s.Secrets {
		m[sec.Key] = sec
	}
	return m
}

// Merge does a per-key three-way merge. Keys changed on one side take that
// side; keys changed identically on both take local; keys changed
// differently are conflicts, kept as local in merged and listed (sorted).
func Merge(base, local, remote *Snapshot) (merged *Snapshot, conflicts []string) {
	b, l, r := index(base), index(local), index(remote)
	keys := map[string]struct{}{}
	for _, m := range []map[string]Secret{b, l, r} {
		for k := range m {
			keys[k] = struct{}{}
		}
	}

	merged = &Snapshot{Version: SnapshotVersion}
	take := func(m map[string]Secret, k string) {
		if sec, ok := m[k]; ok {
			merged.Secrets = append(merged.Secrets, sec)
		}
	}
	for k := range keys {
		bs, ls, rs := stateOf(b, k), stateOf(l, k), stateOf(r, k)
		switch {
		case ls == bs:
			take(r, k)
		case rs == bs, ls == rs:
			take(l, k)
		default:
			take(l, k)
			conflicts = append(conflicts, k)
		}
	}
	merged.Normalize()
	sort.Strings(conflicts)
	return merged, conflicts
}

// Resolve settles conflicts: preferRemote replaces each conflicting key in
// merged with remote's entry (dropping it if remote lacks it); otherwise
// merged (local) wins. merged is not modified.
func Resolve(merged, remote *Snapshot, conflicts []string, preferRemote bool) *Snapshot {
	out := merged.clone()
	if !preferRemote || len(conflicts) == 0 {
		out.Normalize()
		return out
	}
	r := index(remote)
	drop := map[string]bool{}
	for _, k := range conflicts {
		drop[k] = true
	}
	kept := out.Secrets[:0]
	for _, sec := range out.Secrets {
		if !drop[sec.Key] {
			kept = append(kept, sec)
		}
	}
	out.Secrets = kept
	for _, k := range conflicts {
		if sec, ok := r[k]; ok {
			out.Secrets = append(out.Secrets, sec)
		}
	}
	out.Normalize()
	return out
}
