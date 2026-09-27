package machine

import (
	"testing"
	"time"
)

func TestIdentityUsable(t *testing.T) {
	now := time.Now()
	past, future := now.Add(-time.Minute), now.Add(time.Minute)
	base := Identity{ID: "mi_1", VaultID: "vlt_1", Env: "production"}

	cases := []struct {
		name string
		m    *Identity
		want bool
	}{
		{"active", &base, true},
		{"missing", nil, false},
		{"revoked", func() *Identity { m := base; m.Revoked = true; return &m }(), false},
		{"expired", func() *Identity { m := base; m.ExpiresAt = &past; return &m }(), false},
		{"not yet expired", func() *Identity { m := base; m.ExpiresAt = &future; return &m }(), true},
		{"other vault", func() *Identity { m := base; m.VaultID = "vlt_2"; return &m }(), false},
		{"other env", func() *Identity { m := base; m.Env = "staging"; return &m }(), false},
	}
	for _, c := range cases {
		if got := c.m.usable(now, "vlt_1", "production"); got != c.want {
			t.Errorf("%s: usable = %v, want %v", c.name, got, c.want)
		}
	}
}
