package machine

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

type oidcDiscovery struct {
	JWKSURI string `json:"jwks_uri"`
}

type jwks struct {
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		N   string `json:"n"`
		E   string `json:"e"`
		Use string `json:"use"`
		Alg string `json:"alg"`
	} `json:"keys"`
}

func verifyOIDC(client *http.Client, raw string, spec *OIDCSpec) bool {
	if spec == nil || raw == "" || spec.Issuer == "" {
		return false
	}
	parser := jwtlib.NewParser(jwtlib.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256"}))
	tok, _, err := parser.ParseUnverified(raw, jwtlib.MapClaims{})
	if err != nil {
		return false
	}
	claims, ok := tok.Claims.(jwtlib.MapClaims)
	if !ok {
		return false
	}
	iss, _ := claims["iss"].(string)
	if iss != spec.Issuer {
		return false
	}
	if !audienceOK(claims["aud"], spec.Audience) {
		return false
	}
	sub, _ := claims["sub"].(string)
	if !subjectMatch(spec.Subject, sub) {
		return false
	}
	for k, want := range spec.Claims {
		got, _ := claims[k].(string)
		if got != want {
			return false
		}
	}
	if exp, ok := claims["exp"].(float64); ok && time.Now().Unix() > int64(exp) {
		return false
	}
	// Signature: fetch JWKS and verify.
	discURL := strings.TrimRight(spec.Issuer, "/") + "/.well-known/openid-configuration"
	resp, err := client.Get(discURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var disc oidcDiscovery
	if json.NewDecoder(resp.Body).Decode(&disc) != nil || disc.JWKSURI == "" {
		return false
	}
	jw, err := client.Get(disc.JWKSURI)
	if err != nil {
		return false
	}
	defer jw.Body.Close()
	var set jwks
	if json.NewDecoder(jw.Body).Decode(&set) != nil {
		return false
	}
	kid, _ := tok.Header["kid"].(string)
	parsed, err := jwtlib.Parse(raw, func(t *jwtlib.Token) (any, error) {
		return rsaFromJWK(set, kid)
	})
	return err == nil && parsed != nil && parsed.Valid
}

func audienceOK(aud any, want string) bool {
	if want == "" {
		return true
	}
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func subjectMatch(pattern, sub string) bool {
	if pattern == sub {
		return true
	}
	if strings.Contains(pattern, "*") {
		pre, post, _ := strings.Cut(pattern, "*")
		return strings.HasPrefix(sub, pre) && strings.HasSuffix(sub, post)
	}
	return false
}
