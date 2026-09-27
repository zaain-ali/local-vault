package machine

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

func rsaFromJWK(set jwks, kid string) (any, error) {
	for _, k := range set.Keys {
		if kid != "" && k.Kid != kid {
			continue
		}
		if k.Kty != "RSA" || k.N == "" || k.E == "" {
			continue
		}
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		e := 0
		for _, b := range eb {
			e = e<<8 | int(b)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, nil
	}
	return nil, jwtlib.ErrTokenUnverifiable
}
