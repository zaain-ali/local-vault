package config

import (
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	strong := strings.Repeat("x", minJWTSecretLen)

	cases := []struct {
		name    string
		env     string
		secret  string
		wantErr bool
	}{
		{"dev allows fallback", "development", devJWTSecret, false},
		{"dev allows empty", "development", "", false},
		{"prod rejects empty", "production", "", true},
		{"prod rejects dev default", "production", devJWTSecret, true},
		{"prod rejects short", "production", strong[:minJWTSecretLen-1], true},
		{"prod accepts strong", "production", strong, false},
		{"prod alias rejects dev default", "prod", devJWTSecret, true},
		{"prod alias accepts strong", "prod", strong, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Config{Env: tc.env, JWTSecret: tc.secret}.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
