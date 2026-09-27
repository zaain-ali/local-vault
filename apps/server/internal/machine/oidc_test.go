package machine

import (
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

func TestOIDCClaimsRequireExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	spec := &OIDCSpec{Issuer: "https://issuer.example", Audience: "localvault", Subject: "repo:org/app:*"}
	good := func() jwtlib.MapClaims {
		return jwtlib.MapClaims{
			"iss": "https://issuer.example", "aud": "localvault", "sub": "repo:org/app:ref:refs/heads/main",
			"exp": float64(now.Add(time.Minute).Unix()),
		}
	}

	cases := []struct {
		name   string
		mutate func(jwtlib.MapClaims)
		want   bool
	}{
		{"valid", func(jwtlib.MapClaims) {}, true},
		{"missing exp", func(c jwtlib.MapClaims) { delete(c, "exp") }, false},
		{"expired", func(c jwtlib.MapClaims) { c["exp"] = float64(now.Add(-time.Second).Unix()) }, false},
		{"exp not numeric", func(c jwtlib.MapClaims) { c["exp"] = "later" }, false},
		{"wrong issuer", func(c jwtlib.MapClaims) { c["iss"] = "https://other.example" }, false},
		{"wrong audience", func(c jwtlib.MapClaims) { c["aud"] = "someone-else" }, false},
		{"audience list", func(c jwtlib.MapClaims) { c["aud"] = []any{"x", "localvault"} }, true},
		{"wrong subject", func(c jwtlib.MapClaims) { c["sub"] = "repo:other/app:main" }, false},
	}
	for _, c := range cases {
		claims := good()
		c.mutate(claims)
		if got := oidcClaimsOK(claims, spec, now); got != c.want {
			t.Errorf("%s: oidcClaimsOK = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestOIDCClaimsCustomClaimBinding(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	spec := &OIDCSpec{Issuer: "i", Subject: "s", Claims: map[string]string{"environment": "production"}}
	claims := jwtlib.MapClaims{"iss": "i", "sub": "s", "exp": float64(now.Add(time.Minute).Unix()), "environment": "staging"}
	if oidcClaimsOK(claims, spec, now) {
		t.Fatal("mismatched bound claim must be rejected")
	}
	claims["environment"] = "production"
	if !oidcClaimsOK(claims, spec, now) {
		t.Fatal("matching bound claim must be accepted")
	}
}
