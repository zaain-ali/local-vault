package jwt

import (
	"errors"
	"time"

	// import alias "jwtlib" — avoids conflict with our package name "jwt"
	jwtlib "github.com/golang-jwt/jwt/v5"
)

// Claims = the data inside a JWT token — decoded when we verify the token
type Claims struct {
	jwtlib.RegisteredClaims                 
	Email    string `json:"email"`           
	Type     string `json:"type"`
	DeviceID    string `json:"device_id,omitempty"`
	SID         string `json:"sid,omitempty"` // session id — ties the token to a sessions row
	WorkspaceID string `json:"workspace_id,omitempty"`
	VaultID     string `json:"vault_id,omitempty"`
	Env         string `json:"env,omitempty"`
}

// Service creates and validates JWT tokens
type Service struct {
	secret       []byte        // key used to sign tokens — must be same for sign and verify
	accessExpiry time.Duration // how long until access token expires
}

// NewService creates JWT service — called once at startup
func NewService(secret string, accessExpiry time.Duration) *Service {
	return &Service{
		secret:       []byte(secret), // []byte() converts string to bytes — JWT library needs bytes
		accessExpiry: accessExpiry,
	}
}

// GenerateAccessToken creates a signed JWT for an authenticated user
func (s *Service) GenerateAccessToken(userID, email, deviceID, sessionID string) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   userID,                                          // "sub" — who this token belongs to
			IssuedAt:  jwtlib.NewNumericDate(now),                      // "iat" — when created
			ExpiresAt: jwtlib.NewNumericDate(now.Add(s.accessExpiry)),  // "exp" — when it stops working
		},
		Email:    email,
		Type:     "access",
		DeviceID: deviceID,
		SID: 	  sessionID,
	}

	// HS256 = HMAC-SHA256 — symmetric signing (same secret for sign + verify)
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
	// SignedString produces the final "eyJ..." string sent to client
	return token.SignedString(s.secret)
}

// GenerateMachineToken creates a 15-minute token for a machine identity.
func (s *Service) GenerateMachineToken(machineID, workspaceID, vaultID, env string) (string, time.Time, error) {
	now := time.Now()
	exp := now.Add(15 * time.Minute)
	claims := Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   machineID,
			IssuedAt:  jwtlib.NewNumericDate(now),
			ExpiresAt: jwtlib.NewNumericDate(exp),
		},
		Type:        "machine",
		WorkspaceID: workspaceID,
		VaultID:     vaultID,
		Env:         env,
	}
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
	signed, err := token.SignedString(s.secret)
	return signed, exp, err
}

// GenerateTempToken creates a 5-minute token for 2FA — just long enough to enter the code
func (s *Service) GenerateTempToken(userID string) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwtlib.NewNumericDate(now),
			ExpiresAt: jwtlib.NewNumericDate(now.Add(5 * time.Minute)),
		},
		Type: "2fa_temp",
	}
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
	return token.SignedString(s.secret)
}

// ValidateToken checks if token is valid (not expired, not tampered) and returns its data
func (s *Service) ValidateToken(tokenString string) (*Claims, error) {
	// ParseWithClaims verifies signature + expiry and fills Claims struct
	token, err := jwtlib.ParseWithClaims(tokenString, &Claims{}, func(token *jwtlib.Token) (any, error) {
		if _, ok := token.Method.(*jwtlib.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.secret, nil
	})
	if err != nil {
		return nil, err
	}

	// Type assertion: convert from interface to our Claims type
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}