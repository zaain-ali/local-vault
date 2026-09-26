package middleware

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/zain-23/local-vault/apps/server/internal/common/apperror"
	"github.com/zain-23/local-vault/apps/server/internal/common/jwt"
	"github.com/zain-23/local-vault/apps/server/internal/common/reqctx"
)

// AuthUser = user info extracted from JWT — handlers access via c.Locals("user")
type AuthUser struct {
	ID       	string
	Email    	string
	DeviceID 	string
	SessionID	string
}

// Auth returns Fiber middleware that validates JWT tokens on protected routes
func Auth(jwtService *jwt.Service) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var token string

		if header := c.Get("Authorization"); header != "" {
			parts := strings.SplitN(header, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				return apperror.New(401, "invalid authorization format, use: Bearer <token>")
			}
			token = parts[1]
		} else {
			// fallback: the HTTPOnly cookie the web app recevies at login
			token = c.Cookies("access_token")
		}

		if token == "" {
			return apperror.New(401, "missing authentication token")
		}

		// Validate the token — checks signature, expiry, and extracts claims
		claims, err := jwtService.ValidateToken(token)
		if err != nil {
			return apperror.New(401, "invalid or expired token")
		}

		// Reject temp tokens — only access tokens allowed on protected routes
		if claims.Type != "access" {
			return apperror.New(401, "invalid token type")
		}

		// Store user info in Locals — any handler after this can read it
		c.Locals("user", AuthUser{
			ID:       	claims.Subject,
			Email:    	claims.Email,
			DeviceID: 	claims.DeviceID,
			SessionID:	claims.SID,
		})

		// Also stash identity on the request context so downstream services can
		// record audit events without every method taking ip/device params
		c.SetUserContext(reqctx.With(c.UserContext(), reqctx.Info{
			ActorID: 	claims.Subject,
			DeviceID: 	claims.DeviceID,
			IP: 		c.IP(),
		}))

		// c.Next() passes control to the next handler in the chain
		return c.Next()
	}
}

// GetUser extracts AuthUser from Locals — only works after Auth middleware
func GetUser(c *fiber.Ctx) AuthUser {
	// .(AuthUser) is a type assertion — converts from any to AuthUser
	return c.Locals("user").(AuthUser)
}

// MachineIdentity is stashed by MachineAuth.
type MachineIdentity struct {
	ID          string
	WorkspaceID string
	VaultID     string
	Env         string
}

// MachineAuth accepts type=machine JWTs for /machine/* routes.
func MachineAuth(jwtService *jwt.Service) fiber.Handler {
	return func(c *fiber.Ctx) error {
		header := c.Get("Authorization")
		parts := strings.SplitN(header, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			return apperror.New(401, "invalid authorization format, use: Bearer <token>")
		}
		claims, err := jwtService.ValidateToken(parts[1])
		if err != nil || claims.Type != "machine" {
			return apperror.New(401, "invalid or expired token")
		}
		c.Locals("machine", MachineIdentity{
			ID: claims.Subject, WorkspaceID: claims.WorkspaceID,
			VaultID: claims.VaultID, Env: claims.Env,
		})
		return c.Next()
	}
}

func GetMachine(c *fiber.Ctx) MachineIdentity {
	return c.Locals("machine").(MachineIdentity)
}
